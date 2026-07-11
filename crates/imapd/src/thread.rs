use std::collections::{HashMap, HashSet};

use crate::sort::{base_subject, decode_rfc2047, first_header, normalized_string, parse_headers};

#[derive(Debug, Clone)]
pub(crate) struct ThreadMessage {
    pub(crate) seq: u64,
    pub(crate) uid: u64,
    date: i64,
    subject: String,
    reply_or_forward: bool,
    message_id: Option<String>,
    references: Vec<String>,
}

impl ThreadMessage {
    pub(crate) fn from_message(seq: u64, uid: u64, internal_date: i64, data: &[u8]) -> Self {
        let headers = parse_headers(data);
        let raw_subject = first_header(&headers, "subject")
            .map(decode_rfc2047)
            .unwrap_or_default();
        let lowered = raw_subject.trim_start().to_ascii_lowercase();
        let reply_or_forward = ["re:", "fw:", "fwd:"]
            .iter()
            .any(|prefix| lowered.starts_with(prefix));
        let subject = normalized_string(&base_subject(&raw_subject));
        let date = first_header(&headers, "date")
            .and_then(|value| chrono::DateTime::parse_from_rfc2822(value).ok())
            .map(|date| date.timestamp())
            .unwrap_or(internal_date);
        let message_id = first_header(&headers, "message-id")
            .and_then(|value| extract_message_ids(value).into_iter().next());
        let mut references = first_header(&headers, "references")
            .map(extract_message_ids)
            .unwrap_or_default();
        if references.is_empty() {
            references = first_header(&headers, "in-reply-to")
                .map(extract_message_ids)
                .unwrap_or_default();
        }
        Self {
            seq,
            uid,
            date,
            subject,
            reply_or_forward,
            message_id,
            references,
        }
    }
}

#[derive(Debug, Clone)]
struct Node {
    value: Option<(u64, u64)>,
    date: i64,
    subject: String,
    reply_or_forward: bool,
    parent: Option<usize>,
    children: Vec<usize>,
}

impl Node {
    fn dummy() -> Self {
        Self {
            value: None,
            date: 0,
            subject: String::new(),
            reply_or_forward: false,
            parent: None,
            children: Vec::new(),
        }
    }
}

pub(crate) fn ordered_subject(messages: &[ThreadMessage], uid_mode: bool) -> String {
    let mut sorted = messages.to_vec();
    sorted.sort_by(|left, right| {
        left.subject
            .cmp(&right.subject)
            .then(left.date.cmp(&right.date))
            .then(left.uid.cmp(&right.uid))
    });
    let mut groups: Vec<Vec<&ThreadMessage>> = Vec::new();
    for message in &sorted {
        if groups
            .last()
            .and_then(|group| group.first())
            .is_none_or(|first| first.subject != message.subject)
        {
            groups.push(Vec::new());
        }
        groups.last_mut().expect("group exists").push(message);
    }
    groups.sort_by(|left, right| {
        left[0]
            .date
            .cmp(&right[0].date)
            .then(left[0].uid.cmp(&right[0].uid))
    });
    let mut response = String::new();
    for group in groups {
        let ids = group
            .iter()
            .map(|message| if uid_mode { message.uid } else { message.seq })
            .collect::<Vec<_>>();
        match ids.as_slice() {
            [only] => response.push_str(&format!("({})", only)),
            [first, second] => response.push_str(&format!("({} {})", first, second)),
            [first, rest @ ..] => {
                response.push_str(&format!("({} ", first));
                for id in rest {
                    response.push_str(&format!("({})", id));
                }
                response.push(')');
            }
            [] => {}
        }
    }
    response
}

pub(crate) fn references(messages: &[ThreadMessage], uid_mode: bool) -> String {
    references_with_subject_merging(messages, uid_mode, true)
}

pub(crate) fn refs(messages: &[ThreadMessage], uid_mode: bool) -> String {
    references_with_subject_merging(messages, uid_mode, false)
}

fn references_with_subject_merging(
    messages: &[ThreadMessage],
    uid_mode: bool,
    merge_subjects: bool,
) -> String {
    let mut nodes = Vec::<Node>::new();
    let mut by_id = HashMap::<String, usize>::new();
    let mut used_message_ids = HashSet::new();

    for message in messages {
        let mut chain = Vec::new();
        for reference in &message.references {
            let index = *by_id.entry(reference.clone()).or_insert_with(|| {
                nodes.push(Node::dummy());
                nodes.len() - 1
            });
            if chain.last().copied() != Some(index) {
                chain.push(index);
            }
        }
        for pair in chain.windows(2) {
            link(&mut nodes, pair[0], pair[1]);
        }

        let index = if let Some(message_id) = message
            .message_id
            .as_ref()
            .filter(|message_id| used_message_ids.insert((*message_id).clone()))
        {
            *by_id.entry(message_id.clone()).or_insert_with(|| {
                nodes.push(Node::dummy());
                nodes.len() - 1
            })
        } else {
            nodes.push(Node::dummy());
            nodes.len() - 1
        };
        nodes[index].value = Some((message.seq, message.uid));
        nodes[index].date = message.date;
        nodes[index].subject = message.subject.clone();
        nodes[index].reply_or_forward = message.reply_or_forward;
        if let Some(parent) = chain.last().copied() {
            link(&mut nodes, parent, index);
        }
    }

    if merge_subjects {
        merge_roots_by_subject(&mut nodes);
    }
    let mut roots = (0..nodes.len())
        .filter(|index| nodes[*index].parent.is_none())
        .collect::<Vec<_>>();
    roots = prune_nodes(&mut nodes, roots);
    sort_tree(&mut nodes, &mut roots);
    render_children(&nodes, &roots, true, uid_mode)
}

fn link(nodes: &mut [Node], parent: usize, child: usize) {
    if parent == child || nodes[child].parent.is_some() || is_ancestor(nodes, child, parent) {
        return;
    }
    nodes[child].parent = Some(parent);
    if !nodes[parent].children.contains(&child) {
        nodes[parent].children.push(child);
    }
}

fn is_ancestor(nodes: &[Node], candidate: usize, mut node: usize) -> bool {
    while let Some(parent) = nodes[node].parent {
        if parent == candidate {
            return true;
        }
        node = parent;
    }
    false
}

fn merge_roots_by_subject(nodes: &mut [Node]) {
    let roots = (0..nodes.len())
        .filter(|index| nodes[*index].parent.is_none())
        .collect::<Vec<_>>();
    let mut subjects = HashMap::<String, usize>::new();
    for root in roots {
        let Some((subject, reply_or_forward)) = representative_subject(nodes, root) else {
            continue;
        };
        if let Some(existing) = subjects.get(&subject).copied() {
            if nodes[existing].value.is_none() && nodes[root].value.is_none() {
                let children = std::mem::take(&mut nodes[root].children);
                for child in children {
                    nodes[child].parent = None;
                    link(nodes, existing, child);
                }
            } else if nodes[root].value.is_none()
                || (nodes[existing].reply_or_forward && !reply_or_forward)
            {
                link(nodes, root, existing);
                subjects.insert(subject, root);
            } else {
                link(nodes, existing, root);
            }
        } else {
            subjects.insert(subject, root);
        }
    }
}

fn representative_subject(nodes: &[Node], index: usize) -> Option<(String, bool)> {
    if nodes[index].value.is_some() {
        return (!nodes[index].subject.is_empty())
            .then(|| (nodes[index].subject.clone(), nodes[index].reply_or_forward));
    }
    nodes[index]
        .children
        .iter()
        .filter_map(|child| {
            representative_subject(nodes, *child)
                .map(|subject| (node_sort_key(nodes, *child), subject))
        })
        .min_by_key(|(key, _)| *key)
        .map(|(_, subject)| subject)
}

fn prune_nodes(nodes: &mut [Node], indices: Vec<usize>) -> Vec<usize> {
    let mut output = Vec::new();
    for index in indices {
        let children = std::mem::take(&mut nodes[index].children);
        nodes[index].children = prune_nodes(nodes, children);
        if nodes[index].value.is_none() {
            match nodes[index].children.len() {
                0 => continue,
                1 => {
                    let child = nodes[index].children[0];
                    nodes[child].parent = nodes[index].parent;
                    output.push(child);
                    continue;
                }
                _ => {}
            }
        }
        output.push(index);
    }
    output
}

fn sort_tree(nodes: &mut [Node], indices: &mut Vec<usize>) {
    indices.sort_by(|left, right| node_sort_key(nodes, *left).cmp(&node_sort_key(nodes, *right)));
    for index in indices.clone() {
        let mut children = std::mem::take(&mut nodes[index].children);
        sort_tree(nodes, &mut children);
        nodes[index].children = children;
    }
}

fn node_sort_key(nodes: &[Node], index: usize) -> (i64, u64) {
    if let Some((_, uid)) = nodes[index].value {
        (nodes[index].date, uid)
    } else {
        nodes[index]
            .children
            .iter()
            .map(|child| node_sort_key(nodes, *child))
            .min()
            .unwrap_or((0, 0))
    }
}

fn render_children(nodes: &[Node], indices: &[usize], root: bool, uid_mode: bool) -> String {
    if indices.len() == 1 && !root {
        let node = &nodes[indices[0]];
        let mut output = node
            .value
            .map(|(seq, uid)| if uid_mode { uid } else { seq })
            .map(|id| id.to_string())
            .unwrap_or_default();
        if !node.children.is_empty() {
            if !output.is_empty() {
                output.push(' ');
            }
            output.push_str(&render_children(nodes, &node.children, false, uid_mode));
        }
        return output;
    }
    let mut output = String::new();
    for index in indices {
        let node = &nodes[*index];
        let id = node
            .value
            .map(|(seq, uid)| if uid_mode { uid } else { seq });
        if node.children.is_empty() {
            if let Some(id) = id {
                output.push_str(&format!("({})", id));
            }
        } else {
            output.push('(');
            if let Some(id) = id {
                output.push_str(&format!("{} ", id));
            }
            output.push_str(&render_children(nodes, &node.children, false, uid_mode));
            output.push(')');
        }
    }
    output
}

fn extract_message_ids(value: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut rest = value;
    while let Some(start) = rest.find('<') {
        let tail = &rest[start + 1..];
        let Some(end) = tail.find('>') else {
            break;
        };
        let id = tail[..end].trim();
        if !id.is_empty() && !id.bytes().any(|byte| byte.is_ascii_whitespace()) {
            ids.push(id.to_string());
        }
        rest = &tail[end + 1..];
    }
    ids
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(seq: u64, raw: &[u8]) -> ThreadMessage {
        ThreadMessage::from_message(seq, seq, seq as i64, raw)
    }

    #[test]
    fn references_builds_nested_tree_and_prunes_missing_ancestors() {
        let messages = vec![
            message(1, b"Message-ID: <root@x>\r\nSubject: Topic\r\n\r\n"),
            message(2, b"Message-ID: <child@x>\r\nReferences: <root@x>\r\nSubject: Re: Topic\r\n\r\n"),
            message(3, b"Message-ID: <leaf@x>\r\nReferences: <missing@x> <child@x>\r\nSubject: Re: Topic\r\n\r\n"),
        ];
        assert_eq!(references(&messages, false), "(1 2 3)");
    }

    #[test]
    fn orderedsubject_groups_siblings_in_date_order() {
        let messages = vec![
            message(
                2,
                b"Date: Tue, 2 Jan 2024 00:00:00 +0000\r\nSubject: Re: Topic\r\n\r\n",
            ),
            message(
                1,
                b"Date: Mon, 1 Jan 2024 00:00:00 +0000\r\nSubject: Topic\r\n\r\n",
            ),
            message(
                3,
                b"Date: Wed, 3 Jan 2024 00:00:00 +0000\r\nSubject: Other\r\n\r\n",
            ),
        ];
        assert_eq!(ordered_subject(&messages, false), "(1 2)(3)");
    }

    #[test]
    fn refs_preserves_same_subject_roots_that_references_merges() {
        let messages = vec![
            message(1, b"Message-ID: <first@x>\r\nSubject: Topic\r\n\r\n"),
            message(2, b"Message-ID: <second@x>\r\nSubject: Re: Topic\r\n\r\n"),
        ];
        assert_eq!(references(&messages, false), "(1 2)");
        assert_eq!(refs(&messages, false), "(1)(2)");
    }
}
