use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD as BASE64_NO_PAD;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Ensure Maildir directories exist: tmp/new/cur
pub fn ensure_maildir(path: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(path.join("tmp"))?;
    fs::create_dir_all(path.join("new"))?;
    fs::create_dir_all(path.join("cur"))?;
    Ok(())
}

/// Deliver email bytes to Maildir using atomic tmp->new move.
/// This follows classic Maildir semantics (tmp -> new).
pub fn deliver(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    data: &[u8],
) -> anyhow::Result<PathBuf> {
    // Sanity-check domain and localpart to avoid path traversal attacks
    for s in [domain, localpart] {
        if s.contains('/') || s.contains('\\') || s.contains('\0') || s.contains("..") {
            return Err(anyhow::anyhow!("invalid mailbox name"));
        }
    }

    let mailbox_dir = maildir_root.join(domain).join(localpart).join("Maildir");
    ensure_maildir(&mailbox_dir)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let pid = std::process::id();
    // include a short random component to reduce collision risk across processes
    let rand: u64 = rand::random();
    let filename = format!("{}.{}.{}", now, pid, rand);
    let tmp_path = mailbox_dir.join("tmp").join(&filename);
    let new_path = mailbox_dir.join("new").join(&filename);
    let mut f = File::create(&tmp_path)?;
    f.write_all(data)?;
    fs::rename(&tmp_path, &new_path)?;
    Ok(new_path)
}

/// Deliver to quarantine Maildir under a quarantine/ prefix inside the mailroot.
pub fn deliver_quarantine(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    data: &[u8],
) -> anyhow::Result<PathBuf> {
    let qroot = maildir_root.join("quarantine");
    deliver(&qroot, domain, localpart, data)
}

/// Count messages in Maildir (new + cur). Used by IMAP SELECT to report EXISTS.
pub fn count_messages(maildir_root: &Path, domain: &str, localpart: &str) -> anyhow::Result<usize> {
    let mailbox_dir = maildir_root.join(domain).join(localpart).join("Maildir");
    ensure_maildir(&mailbox_dir)?;
    let mut count = 0usize;
    for sub in &["new", "cur"] {
        let dir = mailbox_dir.join(sub);
        if dir.exists() && dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let e = entry?;
                if e.file_type()?.is_file() {
                    count += 1;
                }
            }
        }
    }
    Ok(count)
}

/// List all message file paths in Maildir (new + cur), sorted by filename for stable ordering.
pub fn list_messages(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
) -> anyhow::Result<Vec<PathBuf>> {
    let mailbox_dir = maildir_root.join(domain).join(localpart).join("Maildir");
    ensure_maildir(&mailbox_dir)?;
    let mut msgs = Vec::new();
    for sub in &["new", "cur"] {
        let dir = mailbox_dir.join(sub);
        if dir.exists() && dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let e = entry?;
                if e.file_type()?.is_file() {
                    msgs.push(e.path());
                }
            }
        }
    }
    // Sort by filename to provide stable ordering for IMAP sequence numbers
    msgs.sort_by_key(|p| {
        p.file_name()
            .and_then(|n| n.to_str().map(|s| s.to_owned()))
            .unwrap_or_default()
    });
    Ok(msgs)
}

/// Read the message bytes at the given zero-based index from the Maildir (combined new+cur ordering).
pub fn read_message(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    index: usize,
) -> anyhow::Result<Vec<u8>> {
    let msgs = list_messages(maildir_root, domain, localpart)?;
    if let Some(path) = msgs.get(index) {
        let data = fs::read(path)?;
        Ok(data)
    } else {
        Err(anyhow::anyhow!("no message at index"))
    }
}

pub const STANDARD_FOLDERS: &[(&str, &str)] = &[
    ("INBOX", ""),
    ("Sent", "\\Sent"),
    ("Drafts", "\\Drafts"),
    ("Trash", "\\Trash"),
    ("Junk", "\\Junk"),
    ("Archive", "\\Archive"),
];

fn account_maildir(maildir_root: &Path, domain: &str, localpart: &str) -> PathBuf {
    maildir_root.join(domain).join(localpart).join("Maildir")
}

pub fn mailbox_dir(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
) -> anyhow::Result<PathBuf> {
    for s in [domain, localpart] {
        if s.contains('/') || s.contains('\\') || s.contains('\0') || s.contains("..") {
            return Err(anyhow::anyhow!("invalid mailbox name"));
        }
    }
    let normalized = normalize_mailbox_name(mailbox)?;
    let root = account_maildir(maildir_root, domain, localpart);
    if normalized.eq_ignore_ascii_case("INBOX") {
        Ok(root)
    } else {
        Ok(root.join(format!(".{}", normalized)))
    }
}

pub fn normalize_mailbox_name(mailbox: &str) -> anyhow::Result<String> {
    let mailbox = mailbox.trim();
    if mailbox.eq_ignore_ascii_case("INBOX") {
        return Ok("INBOX".to_string());
    }
    if mailbox.is_empty()
        || mailbox.contains('\\')
        || mailbox.contains('\0')
        || mailbox.contains("..")
        || mailbox.starts_with('/')
        || mailbox.ends_with('/')
    {
        return Err(anyhow::anyhow!("invalid mailbox name"));
    }
    if mailbox
        .split('/')
        .any(|part| part.is_empty() || part.starts_with('.') || part.eq_ignore_ascii_case("INBOX"))
    {
        return Err(anyhow::anyhow!("invalid mailbox name"));
    }
    Ok(mailbox.to_string())
}

fn is_imap_utf7_direct_char(ch: char) -> bool {
    matches!(ch, '\u{20}'..='\u{25}' | '\u{27}'..='\u{7e}')
}

fn push_encoded_utf16_segment(out: &mut String, segment: &str) -> anyhow::Result<()> {
    if segment.is_empty() {
        return Ok(());
    }
    let mut utf16_bytes = Vec::new();
    for unit in segment.encode_utf16() {
        utf16_bytes.extend_from_slice(&unit.to_be_bytes());
    }
    let encoded = BASE64_NO_PAD.encode(&utf16_bytes).replace('/', ",");
    out.push('&');
    out.push_str(&encoded);
    out.push('-');
    Ok(())
}

pub fn utf8_to_imap_utf7(input: &str) -> anyhow::Result<String> {
    let mut out = String::new();
    let mut shifted = String::new();
    for ch in input.chars() {
        if ch == '&' {
            push_encoded_utf16_segment(&mut out, &shifted)?;
            shifted.clear();
            out.push_str("&-");
        } else if is_imap_utf7_direct_char(ch) {
            push_encoded_utf16_segment(&mut out, &shifted)?;
            shifted.clear();
            out.push(ch);
        } else {
            shifted.push(ch);
        }
    }
    push_encoded_utf16_segment(&mut out, &shifted)?;
    Ok(out)
}

pub fn imap_utf7_to_utf8(input: &str) -> anyhow::Result<String> {
    let mut out = String::new();
    let mut rest = input;
    while let Some(shift_start) = rest.find('&') {
        out.push_str(&rest[..shift_start]);
        rest = &rest[shift_start + 1..];
        if let Some(after_ampersand) = rest.strip_prefix('-') {
            out.push('&');
            rest = after_ampersand;
            continue;
        }
        let Some(shift_end) = rest.find('-') else {
            anyhow::bail!("mailbox name is not valid modified UTF-7");
        };
        let encoded = &rest[..shift_end];
        if encoded.is_empty() || encoded.contains('&') {
            anyhow::bail!("mailbox name is not valid modified UTF-7");
        }
        let b64 = encoded.replace(',', "/");
        let bytes = BASE64_NO_PAD
            .decode(b64.as_bytes())
            .map_err(|_| anyhow::anyhow!("mailbox name is not valid modified UTF-7"))?;
        if bytes.is_empty() || bytes.len() % 2 != 0 {
            anyhow::bail!("mailbox name is not valid modified UTF-7");
        }
        let units = bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();
        let decoded = String::from_utf16(&units)
            .map_err(|_| anyhow::anyhow!("mailbox name is not valid modified UTF-7"))?;
        out.push_str(&decoded);
        rest = &rest[shift_end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

pub fn ensure_account_standard_mailboxes(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
) -> anyhow::Result<()> {
    crate::imap_state::init_account(maildir_root, domain, localpart)
}

pub fn mailbox_exists(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
) -> anyhow::Result<bool> {
    crate::imap_state::folder_exists(maildir_root, domain, localpart, mailbox)
}

pub fn list_mailboxes(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
) -> anyhow::Result<Vec<(String, Option<String>)>> {
    Ok(
        crate::imap_state::list_folders(maildir_root, domain, localpart)?
            .into_iter()
            .map(|folder| (folder.name, folder.special_use))
            .collect(),
    )
}

pub fn list_subscribed_mailboxes(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
) -> anyhow::Result<Vec<(String, Option<String>)>> {
    Ok(
        crate::imap_state::list_subscribed_folders(maildir_root, domain, localpart)?
            .into_iter()
            .map(|folder| (folder.name, folder.special_use))
            .collect(),
    )
}

pub fn create_mailbox(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
) -> anyhow::Result<()> {
    crate::imap_state::create_folder(maildir_root, domain, localpart, mailbox)
}

pub fn delete_mailbox(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
) -> anyhow::Result<()> {
    crate::imap_state::delete_folder(maildir_root, domain, localpart, mailbox)
}

pub fn rename_mailbox(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    source_mailbox: &str,
    destination_mailbox: &str,
) -> anyhow::Result<()> {
    crate::imap_state::rename_folder(
        maildir_root,
        domain,
        localpart,
        source_mailbox,
        destination_mailbox,
    )
}

pub fn set_mailbox_subscription(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
    subscribed: bool,
) -> anyhow::Result<()> {
    crate::imap_state::set_subscription(maildir_root, domain, localpart, mailbox, subscribed)
}

/// Load or create persistent IMAP state for a Maildir-backed mailbox.
pub fn load_uid_map(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
) -> anyhow::Result<(u64, Vec<(u64, PathBuf, Vec<String>)>)> {
    load_uid_map_for_mailbox(maildir_root, domain, localpart, "INBOX")
}

pub fn load_uid_map_for_mailbox(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
) -> anyhow::Result<(u64, Vec<(u64, PathBuf, Vec<String>)>)> {
    let (folder, messages) =
        crate::imap_state::load_folder(maildir_root, domain, localpart, mailbox)?;
    Ok((
        folder.uidvalidity,
        messages
            .into_iter()
            .map(|message| (message.uid, message.path, message.flags))
            .collect(),
    ))
}

/// Get path for a given UID if it exists in new/cur
pub fn uid_to_path(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    uid: u64,
) -> anyhow::Result<Option<PathBuf>> {
    crate::imap_state::uid_to_path(maildir_root, domain, localpart, "INBOX", uid)
}

/// Set flags for a uid (overwrites existing flags for the UID)
pub fn set_uid_flags(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    uid: u64,
    flags: Vec<String>,
) -> anyhow::Result<()> {
    set_uid_flags_for_mailbox(maildir_root, domain, localpart, "INBOX", uid, flags).map(|_| ())
}

pub fn set_uid_flags_for_mailbox(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
    uid: u64,
    flags: Vec<String>,
) -> anyhow::Result<u64> {
    crate::imap_state::set_uid_flags(maildir_root, domain, localpart, mailbox, uid, flags)
}

/// Delete a message by UID from disk and SQLite IMAP state.
pub fn delete_message_by_uid(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    uid: u64,
) -> anyhow::Result<()> {
    delete_message_by_uid_for_mailbox(maildir_root, domain, localpart, "INBOX", uid)
}

pub fn delete_message_by_uid_for_mailbox(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
    uid: u64,
) -> anyhow::Result<()> {
    crate::imap_state::delete_message_by_uid(maildir_root, domain, localpart, mailbox, uid)
}

pub fn move_message_by_uid_for_mailbox(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    source_mailbox: &str,
    uid: u64,
    destination_mailbox: &str,
) -> anyhow::Result<Option<u64>> {
    crate::imap_state::move_message_by_uid(
        maildir_root,
        domain,
        localpart,
        source_mailbox,
        uid,
        destination_mailbox,
    )
}

pub fn delete_or_trash_message_by_uid_for_mailbox(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
    uid: u64,
) -> anyhow::Result<()> {
    crate::imap_state::delete_or_trash_message_by_uid(maildir_root, domain, localpart, mailbox, uid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imap_modified_utf7_matches_other_examples() {
        let examples = [
            ("&&x&&", "&-&-x&-&-"),
            ("~peter/mail/台北/日本語", "~peter/mail/&U,BTFw-/&ZeVnLIqe-"),
            ("tietä&jä&", "tiet&AOQ-&-j&AOQ-&-"),
        ];
        for (utf8, imap_utf7) in examples {
            assert_eq!(utf8_to_imap_utf7(utf8).unwrap(), imap_utf7);
            assert_eq!(imap_utf7_to_utf8(imap_utf7).unwrap(), utf8);
        }
        assert_eq!(
            normalize_mailbox_name("旅行 & Stuff").unwrap(),
            "旅行 & Stuff"
        );
        assert!(imap_utf7_to_utf8("&").is_err());
        assert!(imap_utf7_to_utf8("&Jjo").is_err());
        assert!(imap_utf7_to_utf8("&Jjo!").is_err());
    }
}
