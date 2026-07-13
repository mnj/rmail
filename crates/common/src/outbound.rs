use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QueueControl {
    #[serde(default = "new_message_tracking_id")]
    pub tracking_id: String,
    pub attempts: u32,
    pub max_attempts: u32,
    pub priority: i32,
    pub next_try: Option<i64>,
    pub last_error: Option<String>,
    #[serde(default)]
    pub last_smtp_code: Option<u16>,
    #[serde(default)]
    pub last_enhanced_status: Option<String>,
    #[serde(default)]
    pub delay_notification_sent: bool,
    pub created_at: i64,
}

impl QueueControl {
    pub fn new(max_attempts: u32, priority: i32) -> Self {
        Self::new_with_tracking_id(max_attempts, priority, new_message_tracking_id())
    }

    pub fn new_with_tracking_id(max_attempts: u32, priority: i32, tracking_id: String) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        QueueControl {
            tracking_id,
            attempts: 0,
            max_attempts,
            priority,
            next_try: None,
            last_error: None,
            last_smtp_code: None,
            last_enhanced_status: None,
            delay_notification_sent: false,
            created_at: now,
        }
    }
    pub fn default_with_timestamp(ts: i64) -> Self {
        QueueControl {
            tracking_id: new_message_tracking_id(),
            attempts: 0,
            max_attempts: 5,
            priority: 0,
            next_try: None,
            last_error: None,
            last_smtp_code: None,
            last_enhanced_status: None,
            delay_notification_sent: false,
            created_at: ts,
        }
    }
}

fn new_message_tracking_id() -> String {
    crate::tracking::new_tracking_id("message")
}

pub fn control_path_for_eml(eml_path: &Path) -> PathBuf {
    let parent = eml_path.parent().unwrap_or_else(|| Path::new("."));
    let fname = eml_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("message.eml");
    parent.join(format!("{}.json", fname))
}

/// Simple outbound queue: writes email files into <mail_root>/outbound/maildrop/queue with an atomic tmp->final move.
/// This is intentionally minimal — a more complete MTA would implement retry/backoff, SMTP delivery workers, and per-domain queuing.
pub fn queue_outbound(
    maildir_root: &Path,
    recipient: &str,
    data: &[u8],
    envelope_from: Option<&str>,
) -> anyhow::Result<PathBuf> {
    queue_outbound_with_options(
        maildir_root,
        recipient,
        data,
        envelope_from,
        QueueOptions::default(),
    )
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueueOptions {
    pub require_tls: bool,
    pub tracking_id: Option<String>,
    pub dsn: DsnOptions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DsnReturn {
    Full,
    Headers,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DsnNotify {
    pub success: bool,
    pub failure: bool,
    pub delay: bool,
    pub never: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DsnOptions {
    /// Decoded RFC 3461 ENVID xtext value.
    pub envelope_id: Option<String>,
    pub return_content: Option<DsnReturn>,
    pub notify: Option<DsnNotify>,
    /// `(address-type, decoded generic-address)` from ORCPT.
    pub original_recipient: Option<(String, String)>,
}

pub fn encode_xtext(value: &str) -> anyhow::Result<String> {
    if value.is_empty() || value.len() > 500 {
        anyhow::bail!("DSN xtext value must contain 1-500 UTF-8 bytes");
    }
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if (33..=126).contains(&byte) && byte != b'+' && byte != b'=' {
            encoded.push(byte as char);
        } else {
            use std::fmt::Write as _;
            write!(&mut encoded, "+{byte:02X}").expect("writing to String cannot fail");
        }
    }
    Ok(encoded)
}

pub fn decode_xtext(value: &str) -> anyhow::Result<String> {
    if value.is_empty() || value.len() > 1500 || !value.is_ascii() {
        anyhow::bail!("invalid DSN xtext length or encoding");
    }
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                let hex = bytes
                    .get(index + 1..index + 3)
                    .context("truncated DSN xtext escape")?;
                let hex = std::str::from_utf8(hex)?;
                let byte = u8::from_str_radix(hex, 16).context("invalid DSN xtext escape")?;
                if byte == 0 || byte == b'\r' || byte == b'\n' {
                    anyhow::bail!("DSN xtext contains a prohibited control byte");
                }
                decoded.push(byte);
                index += 3;
            }
            byte if (33..=126).contains(&byte) && byte != b'=' => {
                decoded.push(byte);
                index += 1;
            }
            _ => anyhow::bail!("invalid unescaped byte in DSN xtext"),
        }
    }
    String::from_utf8(decoded).context("DSN xtext is not valid UTF-8")
}

pub fn queue_outbound_with_options(
    maildir_root: &Path,
    recipient: &str,
    data: &[u8],
    envelope_from: Option<&str>,
    options: QueueOptions,
) -> anyhow::Result<PathBuf> {
    let recipient = crate::domain::canonicalize_mailbox_address(recipient)?;
    let envelope_from = envelope_from
        .map(crate::domain::canonicalize_mailbox_address)
        .transpose()?;
    if recipient.contains(['\r', '\n'])
        || envelope_from
            .as_deref()
            .is_some_and(|sender| sender.contains(['\r', '\n']))
    {
        anyhow::bail!("envelope addresses must not contain line breaks");
    }
    let data = crate::mail_auth::sign_outbound(maildir_root, data, envelope_from.as_deref())?;
    let outbound_dir = maildir_root.join("outbound").join("maildrop");
    let tmp_dir = outbound_dir.join("tmp");
    let queue_dir = outbound_dir.join("queue");
    fs::create_dir_all(&tmp_dir)?;
    fs::create_dir_all(&queue_dir)?;

    // sanitize recipient for filename (keeps only alnum and replaces others with underscore)
    let safe: String = recipient
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let pid = std::process::id();
    let rand: u64 = rand::random();
    let filename = format!("{}.{}.{}.{}.eml", now, pid, rand, safe);
    let tmp_path = tmp_dir.join(&filename);
    let final_path = queue_dir.join(&filename);
    let mut f = File::create(&tmp_path)?;

    // Persist envelope metadata as an internal header so the outbound worker can reconstruct the SMTP envelope.
    // These headers are a spool format, not RFC 5322 headers, and are stripped by the delivery worker.
    if let Some(env) = envelope_from.as_deref() {
        write!(f, "X-RMail-Envelope-From: {env}\r\n")?;
    }
    if options.require_tls {
        write!(f, "X-RMail-Require-TLS: yes\r\n")?;
    }
    if let Some(envelope_id) = options.dsn.envelope_id.as_deref() {
        writeln!(
            f,
            "X-RMail-DSN-Envelope-ID: {}\r",
            encode_xtext(envelope_id)?
        )?;
    }
    if let Some(return_content) = options.dsn.return_content {
        writeln!(
            f,
            "X-RMail-DSN-Return: {}\r",
            if return_content == DsnReturn::Full {
                "FULL"
            } else {
                "HDRS"
            }
        )?;
    }
    if let Some(notify) = options.dsn.notify.as_ref() {
        let requested = notify.success || notify.failure || notify.delay;
        if notify.never == requested {
            anyhow::bail!("DSN NOTIFY must be NEVER or one or more notification conditions");
        }
        let value = if notify.never {
            "NEVER".to_string()
        } else {
            [
                (notify.success, "SUCCESS"),
                (notify.failure, "FAILURE"),
                (notify.delay, "DELAY"),
            ]
            .into_iter()
            .filter_map(|(enabled, name)| enabled.then_some(name))
            .collect::<Vec<_>>()
            .join(",")
        };
        writeln!(f, "X-RMail-DSN-Notify: {value}\r")?;
    }
    if let Some((address_type, address)) = options.dsn.original_recipient.as_ref() {
        if address_type.is_empty()
            || !address_type
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            anyhow::bail!("invalid DSN original-recipient address type");
        }
        writeln!(
            f,
            "X-RMail-DSN-Original-Recipient: {};{}\r",
            address_type,
            encode_xtext(address)?
        )?;
    }
    write!(f, "X-RMail-Envelope-To: {recipient}\r\n\r\n")?;

    // write the original message bytes unchanged
    f.write_all(&data)?;
    // ensure data is flushed to disk before moving
    f.sync_all()?;

    // Write and sync the sidecar before publishing the message. The message rename is the
    // commit marker: a queue reader never sees an `.eml` without its control record.
    let control = QueueControl::new_with_tracking_id(
        5,
        0,
        options.tracking_id.unwrap_or_else(new_message_tracking_id),
    );
    let control_json = serde_json::to_string(&control)?;
    let tmp_json = control_path_for_eml(&tmp_path);
    let mut control_file = File::create(&tmp_json)?;
    control_file.write_all(control_json.as_bytes())?;
    control_file.sync_all()?;

    let final_json = control_path_for_eml(&final_path);
    fs::rename(&tmp_json, &final_json)?;
    if let Err(error) = fs::rename(&tmp_path, &final_path) {
        let _ = fs::rename(&final_json, &tmp_json);
        return Err(error).context("publishing queued message");
    }
    // Persist directory entries as well as file contents before acknowledging the queue write.
    File::open(&queue_dir)?.sync_all()?;
    Ok(final_path)
}

#[cfg(test)]
mod tests {
    use super::{
        DsnNotify, DsnOptions, DsnReturn, QueueOptions, control_path_for_eml, decode_xtext,
        encode_xtext, queue_outbound, queue_outbound_with_options,
    };
    use std::path::Path;

    #[test]
    fn control_sidecar_uses_eml_json_suffix() {
        let path = Path::new("/tmp/message.eml");
        assert_eq!(
            control_path_for_eml(path),
            Path::new("/tmp/message.eml.json")
        );
    }

    #[test]
    fn queue_metadata_canonicalizes_idn_envelope_domains() {
        let temp = tempfile::tempdir().unwrap();
        let queued = queue_outbound(
            temp.path(),
            "to@BÜCHER.example",
            b"Subject: test\r\n\r\nbody\r\n",
            Some("from@BÜCHER.example"),
        )
        .unwrap();
        let data = std::fs::read_to_string(queued).unwrap();
        assert!(data.starts_with(
            "X-RMail-Envelope-From: from@xn--bcher-kva.example\r\nX-RMail-Envelope-To: to@xn--bcher-kva.example\r\n\r\n"
        ));
        assert!(data.contains("X-RMail-Envelope-From: from@xn--bcher-kva.example"));
        assert!(data.contains("X-RMail-Envelope-To: to@xn--bcher-kva.example"));
    }

    #[test]
    fn requiretls_is_persisted_in_private_queue_metadata() {
        let temp = tempfile::tempdir().unwrap();
        let queued = queue_outbound_with_options(
            temp.path(),
            "to@example.test",
            b"Subject: secure\r\n\r\nbody\r\n",
            Some("from@example.test"),
            QueueOptions {
                require_tls: true,
                tracking_id: None,
                dsn: DsnOptions::default(),
            },
        )
        .unwrap();
        let data = std::fs::read_to_string(queued).unwrap();
        assert!(data.starts_with(
            "X-RMail-Envelope-From: from@example.test\r\nX-RMail-Require-TLS: yes\r\nX-RMail-Envelope-To: to@example.test\r\n\r\n"
        ));
    }

    #[test]
    fn dsn_xtext_round_trips_and_rejects_injection() {
        let encoded = encode_xtext("id + equals= space").unwrap();
        assert_eq!(encoded, "id+20+2B+20equals+3D+20space");
        assert_eq!(decode_xtext(&encoded).unwrap(), "id + equals= space");
        assert!(decode_xtext("bad+0Avalue").is_err());
        assert!(decode_xtext("bad raw space").is_err());
        assert!(decode_xtext("truncated+").is_err());
    }

    #[test]
    fn dsn_preferences_are_private_spool_metadata() {
        let temp = tempfile::tempdir().unwrap();
        let queued = queue_outbound_with_options(
            temp.path(),
            "to@example.test",
            b"Subject: DSN\r\n\r\nbody\r\n",
            Some("from@example.test"),
            QueueOptions {
                require_tls: false,
                tracking_id: None,
                dsn: DsnOptions {
                    envelope_id: Some("job + 7".into()),
                    return_content: Some(DsnReturn::Headers),
                    notify: Some(DsnNotify {
                        success: true,
                        failure: true,
                        delay: false,
                        never: false,
                    }),
                    original_recipient: Some(("rfc822".into(), "alias@example.test".into())),
                },
            },
        )
        .unwrap();
        let data = std::fs::read_to_string(queued).unwrap();
        assert!(data.contains("X-RMail-DSN-Envelope-ID: job+20+2B+207\r\n"));
        assert!(data.contains("X-RMail-DSN-Return: HDRS\r\n"));
        assert!(data.contains("X-RMail-DSN-Notify: SUCCESS,FAILURE\r\n"));
        assert!(data.contains("X-RMail-DSN-Original-Recipient: rfc822;alias@example.test\r\n"));
    }
}
