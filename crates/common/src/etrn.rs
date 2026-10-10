//! Remote queue starting (SMTP ETRN, RFC 1985).
//!
//! The SMTP server records a request as `<mail_root>/outbound/etrn/<node>`
//! and answers at once; the outbound worker picks the requests up between
//! claims and makes the matching queued messages due now (see
//! `rmail_queue_manager::start_queue_runs`). Requests are named after their
//! node, so asking twice before the worker gets to it is one request, and
//! their number is capped so a client cannot fill the disk with them.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use anyhow::Result;

/// Pending requests above which new ones are refused (458).
pub const MAX_PENDING_REQUESTS: usize = 256;

/// The node an ETRN names.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Node {
    /// `ETRN example.com`: mail for exactly this domain.
    Domain(String),
    /// `ETRN @example.com`: this domain and its subdomains.
    Subdomains(String),
}

impl Node {
    /// The ETRN argument naming this node.
    pub fn display(&self) -> String {
        match self {
            Node::Domain(domain) => domain.clone(),
            Node::Subdomains(domain) => format!("@{domain}"),
        }
    }

    pub fn domain(&self) -> &str {
        match self {
            Node::Domain(domain) | Node::Subdomains(domain) => domain,
        }
    }

    /// Whether mail for `domain` (canonical, lower case) belongs to the node.
    pub fn matches(&self, domain: &str) -> bool {
        let domain = domain.trim_end_matches('.');
        match self {
            Node::Domain(node) => domain.eq_ignore_ascii_case(node),
            Node::Subdomains(node) => {
                domain.eq_ignore_ascii_case(node)
                    || (domain.len() > node.len()
                        && domain.as_bytes()[domain.len() - node.len() - 1] == b'.'
                        && domain[domain.len() - node.len()..].eq_ignore_ascii_case(node))
            }
        }
    }

    /// Request file name; canonical domains are `[a-z0-9.-]`.
    fn file_name(&self) -> String {
        match self {
            Node::Domain(domain) => format!("d_{domain}"),
            Node::Subdomains(domain) => format!("s_{domain}"),
        }
    }

    fn from_file_name(name: &str) -> Option<Self> {
        let (kind, domain) = name.split_once('_')?;
        let domain = crate::domain::canonicalize_domain(domain).ok()?;
        match kind {
            "d" => Some(Node::Domain(domain)),
            "s" => Some(Node::Subdomains(domain)),
            _ => None,
        }
    }
}

fn requests_dir(mail_root: &Path) -> PathBuf {
    mail_root.join("outbound").join("etrn")
}

/// Ask the outbound worker to start a queue run for `node`. False when too
/// many requests are already waiting.
pub fn request(mail_root: &Path, node: &Node) -> Result<bool> {
    let dir = requests_dir(mail_root);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(node.file_name());
    if path.exists() {
        return Ok(true);
    }
    if std::fs::read_dir(&dir)?.count() >= MAX_PENDING_REQUESTS {
        return Ok(false);
    }
    std::fs::write(&path, b"")?;
    Ok(true)
}

/// Take every pending request, removing them.
pub fn take_requests(mail_root: &Path) -> Result<Vec<Node>> {
    let dir = requests_dir(mail_root);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut nodes = Vec::new();
    for entry in entries.filter_map(|entry| entry.ok()) {
        let path = entry.path();
        // Removing first means a request is handled once even if two
        // workers look at the same time.
        if std::fs::remove_file(&path).is_err() {
            continue;
        }
        if let Some(node) = entry.file_name().to_str().and_then(Node::from_file_name)
            && !nodes.contains(&node)
        {
            nodes.push(node);
        }
    }
    Ok(nodes)
}

/// Messages in the outbound queue for the node.
pub fn queued_count(mail_root: &Path, node: &Node) -> Result<usize> {
    let queue = mail_root.join("outbound").join("maildrop").join("queue");
    let entries = match std::fs::read_dir(&queue) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.into()),
    };
    let mut count = 0;
    for entry in entries.filter_map(|entry| entry.ok()) {
        let path = entry.path();
        if path.extension().is_none_or(|extension| extension != "eml") {
            continue;
        }
        if envelope_domain(&path).is_some_and(|domain| node.matches(&domain)) {
            count += 1;
        }
    }
    Ok(count)
}

/// The recipient domain from a queued message's spool metadata.
fn envelope_domain(path: &Path) -> Option<String> {
    let reader = BufReader::new(std::fs::File::open(path).ok()?);
    for line in reader.lines() {
        let line = line.ok()?;
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            return None;
        }
        if let Some(recipient) = line.strip_prefix("X-RMail-Envelope-To:") {
            return recipient
                .trim()
                .rsplit_once('@')
                .map(|(_, domain)| domain.to_ascii_lowercase());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subdomain_nodes_match_on_label_boundaries() {
        let node = Node::Subdomains("example.com".into());
        assert!(node.matches("example.com"));
        assert!(node.matches("mx.example.com"));
        assert!(!node.matches("badexample.com"));
        assert!(!node.matches("example.org"));
        let exact = Node::Domain("example.com".into());
        assert!(exact.matches("EXAMPLE.com"));
        assert!(!exact.matches("mx.example.com"));
    }

    #[test]
    fn requests_collapse_per_node_are_capped_and_taken_once() {
        let temp = tempfile::tempdir().unwrap();
        let node = Node::Subdomains("example.com".into());
        assert!(request(temp.path(), &node).unwrap());
        assert!(request(temp.path(), &node).unwrap());
        assert!(request(temp.path(), &Node::Domain("example.org".into())).unwrap());
        let mut taken = take_requests(temp.path()).unwrap();
        taken.sort_by_key(Node::display);
        assert_eq!(
            taken,
            vec![node.clone(), Node::Domain("example.org".into())]
        );
        assert!(take_requests(temp.path()).unwrap().is_empty());

        for index in 0..MAX_PENDING_REQUESTS {
            assert!(request(temp.path(), &Node::Domain(format!("d{index}.test"))).unwrap());
        }
        assert!(!request(temp.path(), &Node::Domain("one-more.test".into())).unwrap());
        // A node that is already waiting is still accepted.
        assert!(request(temp.path(), &Node::Domain("d0.test".into())).unwrap());
    }

    #[test]
    fn queued_messages_are_counted_per_node() {
        let temp = tempfile::tempdir().unwrap();
        for recipient in ["a@example.com", "b@mx.example.com", "c@example.org"] {
            crate::outbound::queue_outbound(
                temp.path(),
                recipient,
                b"Subject: t\r\n\r\nbody\r\n",
                None,
            )
            .unwrap();
        }
        let count = |node: Node| queued_count(temp.path(), &node).unwrap();
        assert_eq!(count(Node::Domain("example.com".into())), 1);
        assert_eq!(count(Node::Subdomains("example.com".into())), 2);
        assert_eq!(count(Node::Domain("example.net".into())), 0);
    }
}
