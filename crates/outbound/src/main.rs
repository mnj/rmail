use anyhow::Context;
use chrono::Utc;
use native_tls::TlsConnector as NativeTlsConnector;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{error::Error, fmt};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, lookup_host};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio_native_tls::TlsConnector as TokioTlsConnector;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::error::ResolveErrorKind;
mod dane_blocking;
mod tlsa;

// Trait object helper so the outbound worker can swap plain and TLS streams dynamically.
trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + ?Sized> AsyncStream for T {}

const MAX_QUEUE_METADATA_BYTES: usize = 64 * 1024;
const BDAT_CHUNK_BYTES: usize = 64 * 1024;
const MAX_MTA_STS_POLICY_BYTES: usize = 64 * 1024;
const MAX_MTA_STS_CACHE_ENTRIES: usize = 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MtaStsMode {
    Enforce,
    Testing,
    None,
}

#[derive(Debug, Clone)]
struct MtaStsPolicy {
    mode: MtaStsMode,
    mx: Vec<String>,
    max_age: Duration,
}

#[derive(Debug, Clone)]
struct CachedMtaStsPolicy {
    policy: MtaStsPolicy,
    expires: Instant,
}

static MTA_STS_CACHE: Lazy<Mutex<HashMap<String, CachedMtaStsPolicy>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct MessageRequirements {
    smtp_utf8: bool,
    eight_bit_mime: bool,
    binary_mime: bool,
}

#[derive(Debug)]
struct QueuedMessage {
    envelope_from: Option<String>,
    envelope_to: String,
    body_offset: u64,
    body_len: u64,
    requirements: MessageRequirements,
    require_tls: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DestinationKey {
    host: String,
    port: u16,
}

struct SmtpConnection {
    reader: BufReader<Box<dyn AsyncStream>>,
    capabilities: SmtpCapabilities,
    encrypted: bool,
}

#[derive(Clone)]
struct ConnectionPool {
    idle: Arc<Mutex<HashMap<DestinationKey, Vec<SmtpConnection>>>>,
    max_per_destination: usize,
    max_total: usize,
}

impl ConnectionPool {
    fn new(max_per_destination: usize, max_total: usize) -> Self {
        Self {
            idle: Arc::new(Mutex::new(HashMap::new())),
            max_per_destination,
            max_total,
        }
    }

    async fn take(&self, key: &DestinationKey) -> Option<SmtpConnection> {
        let mut idle = self.idle.lock().await;
        let connection = idle.get_mut(key).and_then(Vec::pop);
        if idle.get(key).is_some_and(Vec::is_empty) {
            idle.remove(key);
        }
        connection
    }

    async fn recycle(&self, key: DestinationKey, connection: SmtpConnection) {
        let mut idle = self.idle.lock().await;
        let total = idle.values().map(Vec::len).sum::<usize>();
        if total >= self.max_total {
            return;
        }
        let connections = idle.entry(key).or_default();
        if connections.len() < self.max_per_destination {
            connections.push(connection);
        }
    }
}

// Simple outbound delivery worker: scans <mail_root>/outbound/queue, moves files to inflight,
// parses envelope metadata (X-RMail-Envelope-From/To) and performs a minimal SMTP conversation
// to the recipient domain. Failures are moved to failed/ for manual inspection / retry.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mail_root = std::env::var("RMAIL_MAIL_ROOT").unwrap_or_else(|_| "./mail".to_string());
    let base = PathBuf::from(mail_root);
    rmail_common::runtime::redirect_stdio_to_log(&base, "outbound").context("redirecting logs")?;
    let maildrop_dir = base.join("outbound").join("maildrop");
    let queue_dir = maildrop_dir.join("queue");
    let inflight_dir = maildrop_dir.join("inflight");
    let sent_dir = base.join("outbound").join("sent");
    let failed_dir = base.join("outbound").join("failed");

    tokio::fs::create_dir_all(&queue_dir).await?;
    tokio::fs::create_dir_all(&inflight_dir).await?;
    tokio::fs::create_dir_all(&sent_dir).await?;
    tokio::fs::create_dir_all(&failed_dir).await?;

    let recovered = tokio::task::spawn_blocking({
        let maildrop_dir = maildrop_dir.clone();
        move || rmail_queue_manager::recover_abandoned_inflight(&maildrop_dir)
    })
    .await
    .context("joining inflight recovery task")??;
    if recovered != 0 {
        println!("recovered {} abandoned inflight messages", recovered);
    }

    println!("Using on-disk outbound queue: {}", queue_dir.display());
    let per_dest_limit = positive_env("RMAIL_PER_DEST_LIMIT", 5);
    let max_concurrent_deliveries = positive_env("RMAIL_OUTBOUND_CONCURRENCY", 20);
    let max_idle_per_destination = positive_env("RMAIL_IDLE_CONNECTIONS_PER_DEST", 2);
    let max_idle_connections =
        positive_env("RMAIL_MAX_IDLE_CONNECTIONS", max_concurrent_deliveries);
    let dead_letter_days: u64 = std::env::var("RMAIL_DEAD_LETTER_DAYS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);
    let dead_letter_secs = (dead_letter_days.saturating_mul(24 * 3600)) as i64;
    println!(
        "outbound delivery concurrency={} per_destination_limit={} idle_connections={}/destination, {} total",
        max_concurrent_deliveries, per_dest_limit, max_idle_per_destination, max_idle_connections
    );

    let mut deliveries = JoinSet::new();
    let connections = ConnectionPool::new(max_idle_per_destination, max_idle_connections);
    let mut next_metrics = Instant::now();
    let mut next_dead_letter_cleanup = Instant::now() + Duration::from_secs(60);
    loop {
        let now = Instant::now();
        if now >= next_metrics {
            let md = maildrop_dir.clone();
            tokio::task::spawn_blocking(move || match rmail_queue_manager::collect_metrics(&md) {
                Ok(metrics) => println!(
                    "metrics queued={} inflight={} sent={} failed={} dead={}",
                    metrics.queued, metrics.inflight, metrics.sent, metrics.failed, metrics.dead
                ),
                Err(e) => eprintln!("metrics collection error: {}", e),
            });
            next_metrics = now + Duration::from_secs(60);
        }
        if now >= next_dead_letter_cleanup {
            let md = maildrop_dir.clone();
            let secs = dead_letter_secs;
            tokio::task::spawn_blocking(move || {
                match rmail_queue_manager::dead_letter_cleanup(&md, secs) {
                    Ok(moved) => println!("dead-letter cleanup moved {} messages", moved),
                    Err(e) => eprintln!("dead-letter cleanup error: {}", e),
                }
            });
            next_dead_letter_cleanup = now + Duration::from_secs(60);
        }

        while deliveries.len() < max_concurrent_deliveries {
            let Some((inflight_eml, inflight_json)) =
                claim_one(&maildrop_dir, per_dest_limit).await
            else {
                break;
            };
            deliveries.spawn(process_claim(
                inflight_eml,
                inflight_json,
                base.clone(),
                queue_dir.clone(),
                sent_dir.clone(),
                failed_dir.clone(),
                connections.clone(),
            ));
        }

        if deliveries.is_empty() {
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }

        let next_maintenance = next_metrics.min(next_dead_letter_cleanup);
        tokio::select! {
            completed = deliveries.join_next() => {
                if let Some(Err(error)) = completed {
                    eprintln!("outbound delivery task failed to join: {error}");
                }
            }
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(next_maintenance)) => {}
        }
    }
}

fn positive_env(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

/// Choose a retry delay from the SMTP reply class, with longer minimum delays
/// for conditions that are unlikely to clear quickly. The three-digit reply is
/// authoritative for transient/permanent classification; enhanced status only
/// refines retry pacing for transient replies.
fn retry_backoff_seconds(attempts: u32, enhanced_status: Option<&str>) -> i64 {
    let exponential = rmail_queue_manager::next_backoff_seconds(attempts);
    match enhanced_status {
        Some(status) if status.starts_with("4.2.") => exponential.max(15 * 60),
        Some(status) if status.starts_with("4.7.") => exponential.max(5 * 60),
        Some(status) if status.starts_with("4.4.") => exponential.max(2 * 60),
        _ => exponential,
    }
}

async fn claim_one(maildrop_dir: &Path, per_dest_limit: usize) -> Option<(PathBuf, PathBuf)> {
    let maildrop_dir = maildrop_dir.to_path_buf();
    match tokio::task::spawn_blocking(move || {
        rmail_queue_manager::claim_one_with_limit(&maildrop_dir, per_dest_limit)
    })
    .await
    {
        Ok(Ok(claimed)) => claimed,
        Ok(Err(error)) => {
            eprintln!("queue-manager claim_one failed: {error}");
            None
        }
        Err(error) => {
            eprintln!("claim task join failed: {error}");
            None
        }
    }
}

async fn write_control(
    path: &Path,
    control: &rmail_common::outbound::QueueControl,
) -> anyhow::Result<()> {
    let path = path.to_path_buf();
    let control = control.clone();
    tokio::task::spawn_blocking(move || rmail_queue_manager::write_control_atomic(&path, &control))
        .await
        .context("joining control-sidecar write")??;
    Ok(())
}

async fn move_spool_message(source: &Path, destination: &Path) -> anyhow::Result<()> {
    let source = source.to_path_buf();
    let destination = destination.to_path_buf();
    tokio::task::spawn_blocking(move || {
        rmail_queue_manager::move_message_and_control(&source, &destination)
    })
    .await
    .context("joining spool transition")??;
    Ok(())
}

async fn process_claim(
    inflight_eml: PathBuf,
    inflight_json: PathBuf,
    base: PathBuf,
    queue_dir: PathBuf,
    sent_dir: PathBuf,
    failed_dir: PathBuf,
    connections: ConnectionPool,
) {
    let fname = inflight_eml
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown")
        .to_string();
    let mut control = match tokio::fs::read_to_string(&inflight_json).await {
        Ok(serialized) => serde_json::from_str(&serialized)
            .unwrap_or_else(|_| rmail_common::outbound::QueueControl::default_with_timestamp(0)),
        Err(_) => rmail_common::outbound::QueueControl::default_with_timestamp(0),
    };
    control.attempts = control.attempts.saturating_add(1);
    if let Err(error) = write_control(&inflight_json, &control).await {
        eprintln!("failed to persist attempt for {fname}: {error}");
        let destination = queue_dir.join(&fname);
        if let Err(error) = move_spool_message(&inflight_eml, &destination).await {
            eprintln!("failed to return {fname} to queue after control-write failure: {error}");
        }
        return;
    }

    match process_file(&inflight_eml, &base, &connections).await {
        Ok(()) => {
            let destination = sent_dir.join(&fname);
            if let Err(error) = move_spool_message(&inflight_eml, &destination).await {
                eprintln!("failed to move delivered message {fname} to sent: {error}");
            }
        }
        Err(failure) => {
            let smtp_failure = failure
                .chain()
                .find_map(|cause| cause.downcast_ref::<SmtpReplyError>());
            let policy_failure = failure
                .chain()
                .find_map(|cause| cause.downcast_ref::<PermanentDeliveryError>());
            let permanent =
                smtp_failure.is_some_and(SmtpReplyError::is_permanent) || policy_failure.is_some();
            control.last_smtp_code = smtp_failure.map(|failure| failure.code);
            control.last_enhanced_status = smtp_failure
                .and_then(|failure| failure.enhanced_status.clone())
                .or_else(|| policy_failure.and_then(|failure| failure.enhanced_status.clone()));
            let error_message = failure.to_string();
            control.last_error = Some(error_message.clone());
            eprintln!("delivery failed for {fname}: {error_message}");

            let terminal = permanent || control.attempts >= control.max_attempts;
            let destination = if terminal {
                control.next_try = None;
                failed_dir.join(&fname)
            } else {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                control.next_try = Some(
                    now + retry_backoff_seconds(
                        control.attempts,
                        control.last_enhanced_status.as_deref(),
                    ),
                );
                queue_dir.join(&fname)
            };

            if let Err(error) = write_control(&inflight_json, &control).await {
                eprintln!("failed to persist failure state for {fname}: {error}");
                return;
            }
            match move_spool_message(&inflight_eml, &destination).await {
                Ok(()) if terminal => {
                    if let Err(error) =
                        queue_failure_notification(&base, &destination, &control).await
                    {
                        eprintln!("failed to queue delivery notification for {fname}: {error}");
                    }
                }
                Ok(()) => {}
                Err(error) => {
                    eprintln!("failed to transition {fname} after delivery failure: {error}");
                }
            }
        }
    }
}

async fn process_file(
    path: &Path,
    base: &Path,
    connections: &ConnectionPool,
) -> anyhow::Result<()> {
    let message = inspect_queued_message(path).await?;
    deliver_to_remote(base, path, message, connections).await
}

async fn inspect_queued_message(path: &Path) -> anyhow::Result<QueuedMessage> {
    let file = File::open(path)
        .await
        .with_context(|| format!("opening queued message {}", path.display()))?;
    let file_len = file.metadata().await?.len();
    let mut reader = BufReader::new(file);
    let metadata = read_queue_metadata(&mut reader).await?;
    let body_offset = metadata.len() as u64;
    if body_offset > file_len {
        anyhow::bail!("queued message metadata extends beyond the file");
    }
    let (envelope_from, envelope_to, require_tls) = parse_queue_metadata(&metadata)?;
    let body_len = file_len - body_offset;
    let requirements =
        scan_message_requirements(path, body_offset, envelope_from.as_deref(), &envelope_to)
            .await?;
    Ok(QueuedMessage {
        envelope_from,
        envelope_to,
        body_offset,
        body_len,
        requirements,
        require_tls,
    })
}

async fn read_queue_metadata(reader: &mut BufReader<File>) -> anyhow::Result<Vec<u8>> {
    let mut metadata = Vec::new();
    loop {
        let (consumed, complete) = {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                anyhow::bail!("queued message has no metadata terminator");
            }
            if metadata.len() >= MAX_QUEUE_METADATA_BYTES {
                anyhow::bail!("queued message metadata is too large");
            }
            let remaining = MAX_QUEUE_METADATA_BYTES - metadata.len();
            let mut consumed = 0;
            let mut complete = false;
            for byte in available.iter().copied().take(remaining) {
                metadata.push(byte);
                consumed += 1;
                if metadata.ends_with(b"\r\n\r\n") || metadata.ends_with(b"\n\n") {
                    complete = true;
                    break;
                }
            }
            (consumed, complete)
        };
        reader.consume(consumed);
        if complete {
            return Ok(metadata);
        }
        if metadata.len() >= MAX_QUEUE_METADATA_BYTES {
            anyhow::bail!("queued message metadata is too large");
        }
    }
}

fn parse_queue_metadata(metadata: &[u8]) -> anyhow::Result<(Option<String>, String, bool)> {
    let metadata =
        std::str::from_utf8(metadata).context("queued message metadata is not valid UTF-8")?;
    let mut envelope_from = None;
    let mut envelope_to = None;
    let mut require_tls = false;
    for raw_line in metadata.split('\n') {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.is_empty() {
            break;
        }
        if line.contains('\r') || line.starts_with([' ', '\t']) {
            anyhow::bail!("invalid queued message metadata line");
        }
        if let Some(value) = line.strip_prefix("X-RMail-Envelope-From:") {
            if envelope_from.is_some() {
                anyhow::bail!("queued message has multiple envelope senders");
            }
            let value = value.trim();
            if value.is_empty() {
                anyhow::bail!("queued message envelope sender is empty");
            }
            envelope_from = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("X-RMail-Envelope-To:") {
            if envelope_to.is_some() {
                anyhow::bail!("queued message has multiple envelope recipients");
            }
            let value = value.trim();
            if value.is_empty() {
                anyhow::bail!("queued message envelope recipient is empty");
            }
            envelope_to = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("X-RMail-Require-TLS:") {
            if require_tls || !value.trim().eq_ignore_ascii_case("yes") {
                anyhow::bail!("invalid or duplicate REQUIRETLS queue metadata");
            }
            require_tls = true;
        }
    }
    let envelope_to = envelope_to
        .ok_or_else(|| anyhow::anyhow!("no envelope recipient found in queued message"))?;
    Ok((envelope_from, envelope_to, require_tls))
}

struct MessageAnalyzer {
    header_complete: bool,
    previous_header_bytes: [u8; 3],
    header_contains_non_ascii: bool,
    contains_non_ascii: bool,
    requires_binarymime: bool,
    pending_cr: bool,
    line_len: usize,
}

impl MessageAnalyzer {
    fn observe(&mut self, byte: u8) {
        if byte > 0x7f {
            self.contains_non_ascii = true;
            if !self.header_complete {
                self.header_contains_non_ascii = true;
            }
        }
        if !self.header_complete {
            if byte == b'\n'
                && (self.previous_header_bytes[2] == b'\n'
                    || self.previous_header_bytes == [b'\r', b'\n', b'\r'])
            {
                self.header_complete = true;
            }
            self.previous_header_bytes = [
                self.previous_header_bytes[1],
                self.previous_header_bytes[2],
                byte,
            ];
        }

        if self.requires_binarymime {
            return;
        }
        if self.pending_cr {
            self.pending_cr = false;
            if byte == b'\n' {
                if self.line_len > 998 {
                    self.requires_binarymime = true;
                }
                self.line_len = 0;
                return;
            }
            self.requires_binarymime = true;
        }
        match byte {
            b'\r' => self.pending_cr = true,
            b'\n' | 0 => self.requires_binarymime = true,
            _ => {
                self.line_len = self.line_len.saturating_add(1);
                if self.line_len > 998 {
                    self.requires_binarymime = true;
                }
            }
        }
    }

    fn finish(mut self, envelope_from: Option<&str>, recipient: &str) -> MessageRequirements {
        if self.pending_cr || self.line_len > 998 {
            self.requires_binarymime = true;
        }
        MessageRequirements {
            smtp_utf8: envelope_from.is_some_and(|sender| !sender.is_ascii())
                || !recipient.is_ascii()
                || self.header_contains_non_ascii,
            eight_bit_mime: self.contains_non_ascii && !self.requires_binarymime,
            binary_mime: self.requires_binarymime,
        }
    }
}

async fn scan_message_requirements(
    path: &Path,
    body_offset: u64,
    envelope_from: Option<&str>,
    recipient: &str,
) -> anyhow::Result<MessageRequirements> {
    let mut file = open_message_body(path, body_offset).await?;
    let mut analyzer = MessageAnalyzer {
        header_complete: false,
        previous_header_bytes: [0; 3],
        header_contains_non_ascii: false,
        contains_non_ascii: false,
        requires_binarymime: false,
        pending_cr: false,
        line_len: 0,
    };
    let mut buffer = [0u8; BDAT_CHUNK_BYTES];
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        for byte in &buffer[..read] {
            analyzer.observe(*byte);
        }
    }
    Ok(analyzer.finish(envelope_from, recipient))
}

async fn open_message_body(path: &Path, body_offset: u64) -> anyhow::Result<File> {
    let mut file = File::open(path)
        .await
        .with_context(|| format!("opening queued message body {}", path.display()))?;
    file.seek(SeekFrom::Start(body_offset)).await?;
    Ok(file)
}

async fn queue_failure_notification(
    mail_root: &Path,
    failed_message: &Path,
    control: &rmail_common::outbound::QueueControl,
) -> anyhow::Result<()> {
    let message = inspect_queued_message(failed_message).await?;
    let Some(original_sender) = message.envelope_from else {
        // RFC 5321 null reverse paths are used for bounces specifically to
        // prevent notification loops. Do not generate a second notification.
        return Ok(());
    };
    let original_headers = match read_original_headers(failed_message, message.body_offset).await {
        Ok(headers) => headers,
        Err(error) => {
            eprintln!(
                "unable to include original headers in delivery notification for {}: {}",
                failed_message.display(),
                error
            );
            Vec::new()
        }
    };
    let notification = build_failure_notification(
        &original_sender,
        &message.envelope_to,
        control,
        &original_headers,
    );
    let mail_root = mail_root.to_path_buf();
    tokio::task::spawn_blocking(move || {
        rmail_common::outbound::queue_outbound(&mail_root, &original_sender, &notification, None)
    })
    .await
    .context("joining delivery-notification queue operation")??;
    Ok(())
}

async fn read_original_headers(path: &Path, body_offset: u64) -> anyhow::Result<Vec<u8>> {
    let file = open_message_body(path, body_offset).await?;
    let mut reader = BufReader::new(file);
    read_queue_metadata(&mut reader).await
}

fn build_failure_notification(
    original_sender: &str,
    final_recipient: &str,
    control: &rmail_common::outbound::QueueControl,
    original_headers: &[u8],
) -> Vec<u8> {
    let date = Utc::now().to_rfc2822();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let boundary = format!("rmail-dsn-{}-{nonce}", std::process::id());
    let status = control.last_enhanced_status.as_deref().unwrap_or_else(|| {
        if control.last_smtp_code.is_some_and(|code| code / 100 == 5) {
            "5.0.0"
        } else {
            "4.4.7"
        }
    });
    let diagnostic = control
        .last_error
        .as_deref()
        .map(sanitize_header_value)
        .unwrap_or_else(|| "delivery failed without a diagnostic response".to_string());
    let sender = sanitize_header_value(original_sender);
    let recipient = sanitize_header_value(final_recipient);
    let mut notification = format!(
        "From: Mail Delivery Subsystem <MAILER-DAEMON@localhost>\r\n\
         To: <{sender}>\r\n\
         Subject: Delivery Status Notification (Failure)\r\n\
         Date: {date}\r\n\
         Auto-Submitted: auto-replied\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: multipart/report; report-type=delivery-status; boundary=\"{boundary}\"\r\n\
         \r\n\
         --{boundary}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Transfer-Encoding: 8bit\r\n\
         \r\n\
         This is an automatically generated Delivery Status Notification.\r\n\
         Delivery to <{recipient}> failed.\r\n\
         \r\n\
         --{boundary}\r\n\
         Content-Type: message/delivery-status\r\n\
         \r\n\
         Reporting-MTA: dns; rmail\r\n\
         Arrival-Date: {date}\r\n\
         \r\n\
         Final-Recipient: rfc822; {recipient}\r\n\
         Action: failed\r\n\
         Status: {status}\r\n\
         Diagnostic-Code: smtp; {diagnostic}\r\n\
         \r\n\
         --{boundary}\r\n\
         Content-Type: message/rfc822-headers\r\n\
         \r\n"
    )
    .into_bytes();
    notification.extend_from_slice(original_headers);
    if !original_headers.is_empty() && !original_headers.ends_with(b"\n") {
        notification.extend_from_slice(b"\r\n");
    }
    notification.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    notification
}

fn sanitize_header_value(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len());
    let mut previous_was_space = false;
    for character in value.chars() {
        let character = if character == '\r' || character == '\n' || character.is_control() {
            ' '
        } else {
            character
        };
        if character == ' ' && previous_was_space {
            continue;
        }
        sanitized.push(character);
        previous_was_space = character == ' ';
        if sanitized.len() >= 900 {
            break;
        }
    }
    sanitized.trim().to_string()
}

async fn read_response<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> anyhow::Result<(u16, String)> {
    let mut full = String::new();
    let mut expected_code = None;
    for _ in 0..100 {
        let line = tokio::time::timeout(Duration::from_secs(60), read_reply_line(reader))
            .await
            .map_err(|_| anyhow::anyhow!("timed out waiting for SMTP reply"))??;
        let line = std::str::from_utf8(&line)
            .map_err(|_| anyhow::anyhow!("SMTP reply is not valid ASCII/UTF-8"))?;
        full.push_str(line);
        let code = std::str::from_utf8(&line.as_bytes()[..3])
            .ok()
            .and_then(|code| code.parse::<u16>().ok())
            .ok_or_else(|| anyhow::anyhow!("invalid SMTP reply code"))?;
        if !(200..=599).contains(&code) {
            anyhow::bail!("SMTP reply code is outside the valid range");
        }
        if expected_code
            .replace(code)
            .is_some_and(|expected| expected != code)
        {
            anyhow::bail!("inconsistent SMTP multiline reply codes");
        }
        match line.as_bytes()[3] {
            b' ' => return Ok((code, full)),
            b'-' => {}
            _ => anyhow::bail!("invalid SMTP reply separator"),
        }
    }
    anyhow::bail!("SMTP multiline reply has too many lines")
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SmtpReplyError {
    command: &'static str,
    code: u16,
    enhanced_status: Option<String>,
    response: String,
}

impl SmtpReplyError {
    fn new(command: &'static str, code: u16, response: String) -> Self {
        Self {
            command,
            code,
            enhanced_status: parse_enhanced_status(&response),
            response,
        }
    }

    fn is_permanent(&self) -> bool {
        self.code / 100 == 5
    }
}

impl fmt::Display for SmtpReplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} rejected: {}", self.command, self.code)?;
        if let Some(status) = &self.enhanced_status {
            write!(formatter, " {status}")?;
        }
        let detail = self.response.lines().last().unwrap_or("");
        let detail = detail.get(4..).unwrap_or("").trim();
        if !detail.is_empty() {
            write!(formatter, " ({detail})")?;
        }
        Ok(())
    }
}

impl Error for SmtpReplyError {}

#[derive(Debug)]
struct PermanentDeliveryError {
    message: String,
    enhanced_status: Option<String>,
}

impl fmt::Display for PermanentDeliveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for PermanentDeliveryError {}

fn permanent_delivery_error(
    message: impl Into<String>,
    enhanced_status: Option<&str>,
) -> anyhow::Error {
    PermanentDeliveryError {
        message: message.into(),
        enhanced_status: enhanced_status.map(str::to_string),
    }
    .into()
}

fn parse_enhanced_status(response: &str) -> Option<String> {
    response.lines().find_map(|line| {
        line.get(4..)?.split_ascii_whitespace().find_map(|token| {
            let token = token.trim_matches(|c: char| !c.is_ascii_digit() && c != '.');
            let mut parts = token.split('.');
            let class = parts.next()?;
            let subject = parts.next()?;
            let detail = parts.next()?;
            if parts.next().is_none()
                && matches!(class, "2" | "4" | "5")
                && !subject.is_empty()
                && !detail.is_empty()
                && subject.chars().all(|c| c.is_ascii_digit())
                && detail.chars().all(|c| c.is_ascii_digit())
            {
                Some(format!("{class}.{subject}.{detail}"))
            } else {
                None
            }
        })
    })
}

fn rejected(command: &'static str, code: u16, response: String) -> anyhow::Error {
    SmtpReplyError::new(command, code, response).into()
}

async fn read_reply_line<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> anyhow::Result<Vec<u8>> {
    const MAX_REPLY_LINE_BYTES: usize = 512;
    let mut line = Vec::new();
    loop {
        let (consumed, newline) = {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                anyhow::bail!("connection closed in SMTP reply");
            }
            let consumed = available
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(available.len(), |index| index + 1);
            if line.len().saturating_add(consumed) > MAX_REPLY_LINE_BYTES {
                anyhow::bail!("SMTP reply line is too long");
            }
            line.extend_from_slice(&available[..consumed]);
            (consumed, available[..consumed].ends_with(b"\n"))
        };
        reader.consume(consumed);
        if newline {
            if !line.ends_with(b"\r\n") || line.len() < 6 {
                anyhow::bail!("malformed SMTP reply line");
            }
            return Ok(line);
        }
    }
}

#[cfg(test)]
async fn smtp_send_with_reader(
    reader: &mut BufReader<Box<dyn AsyncStream>>,
    envelope_from: Option<&str>,
    recipient: &str,
    body: &[u8],
    capabilities: &SmtpCapabilities,
) -> anyhow::Result<()> {
    let requirements = requirements_for_bytes(envelope_from, recipient, body);
    smtp_begin_transaction(
        reader,
        envelope_from,
        recipient,
        &requirements,
        false,
        capabilities,
    )
    .await?;

    if capabilities.chunking {
        let command = format!("BDAT {} LAST\r\n", body.len());
        reader.get_mut().write_all(command.as_bytes()).await?;
        reader.get_mut().write_all(body).await?;
        reader.get_mut().flush().await?;
        let (code, resp) = read_response(&mut *reader).await?;
        if code / 100 != 2 {
            return Err(rejected("BDAT", code, resp));
        }
    } else {
        // DATA fallback for servers that do not advertise RFC 3030 CHUNKING.
        reader.get_mut().write_all(b"DATA\r\n").await?;
        reader.get_mut().flush().await?;
        let (code, resp) = read_response(&mut *reader).await?;
        if code != 354 {
            return Err(rejected("DATA", code, resp));
        }

        for segment in body.split_inclusive(|b| *b == b'\n') {
            let mut line = segment;
            if line.ends_with(b"\n") {
                line = &line[..line.len() - 1];
                if line.ends_with(b"\r") {
                    line = &line[..line.len() - 1];
                }
            }
            if line.starts_with(b".") {
                reader.get_mut().write_all(b".").await?;
            }
            reader.get_mut().write_all(line).await?;
            reader.get_mut().write_all(b"\r\n").await?;
        }
        reader.get_mut().write_all(b".\r\n").await?;
        reader.get_mut().flush().await?;

        let (code, resp) = read_response(&mut *reader).await?;
        if code / 100 != 2 {
            return Err(rejected("DATA body", code, resp));
        }
    }

    smtp_quit(reader).await;

    Ok(())
}

async fn smtp_send_file_with_reader(
    reader: &mut BufReader<Box<dyn AsyncStream>>,
    message_path: &Path,
    message: &QueuedMessage,
    envelope_from: Option<&str>,
    recipient: &str,
    capabilities: &SmtpCapabilities,
) -> anyhow::Result<()> {
    smtp_begin_transaction(
        reader,
        envelope_from,
        recipient,
        &message.requirements,
        message.require_tls,
        capabilities,
    )
    .await?;

    if capabilities.chunking {
        stream_bdat_file(reader, message_path, message.body_offset, message.body_len).await
    } else {
        stream_data_file(reader, message_path, message.body_offset).await
    }
}

async fn smtp_begin_transaction(
    reader: &mut BufReader<Box<dyn AsyncStream>>,
    envelope_from: Option<&str>,
    recipient: &str,
    requirements: &MessageRequirements,
    require_tls: bool,
    capabilities: &SmtpCapabilities,
) -> anyhow::Result<()> {
    let mailcmd = build_mail_from_command_for_requirements(
        envelope_from,
        requirements,
        require_tls,
        capabilities,
    )?;

    reader.get_mut().write_all(mailcmd.as_bytes()).await?;
    reader.get_mut().flush().await?;
    let (code, resp) = read_response(&mut *reader).await?;
    if code / 100 != 2 {
        return Err(rejected("MAIL FROM", code, resp));
    }

    let rcptcmd = format!("RCPT TO:<{}>\r\n", recipient);
    reader.get_mut().write_all(rcptcmd.as_bytes()).await?;
    reader.get_mut().flush().await?;
    let (code, resp) = read_response(&mut *reader).await?;
    if code / 100 != 2 {
        return Err(rejected("RCPT TO", code, resp));
    }

    Ok(())
}

#[cfg(test)]
async fn smtp_quit(reader: &mut BufReader<Box<dyn AsyncStream>>) {
    if reader.get_mut().write_all(b"QUIT\r\n").await.is_ok()
        && reader.get_mut().flush().await.is_ok()
    {
        let _ = read_response(&mut *reader).await;
    }
}

async fn stream_bdat_file(
    reader: &mut BufReader<Box<dyn AsyncStream>>,
    message_path: &Path,
    body_offset: u64,
    body_len: u64,
) -> anyhow::Result<()> {
    let mut file = open_message_body(message_path, body_offset).await?;
    let mut remaining = body_len;
    let mut buffer = [0u8; BDAT_CHUNK_BYTES];
    loop {
        let chunk_len = remaining.min(buffer.len() as u64) as usize;
        let last = remaining == chunk_len as u64;
        let command = if last {
            format!("BDAT {chunk_len} LAST\r\n")
        } else {
            format!("BDAT {chunk_len}\r\n")
        };
        reader.get_mut().write_all(command.as_bytes()).await?;
        if chunk_len != 0 {
            file.read_exact(&mut buffer[..chunk_len]).await?;
            reader.get_mut().write_all(&buffer[..chunk_len]).await?;
        }
        reader.get_mut().flush().await?;
        let (code, response) = read_response(&mut *reader).await?;
        if code / 100 != 2 {
            return Err(rejected("BDAT", code, response));
        }
        if last {
            return Ok(());
        }
        remaining -= chunk_len as u64;
    }
}

async fn stream_data_file(
    reader: &mut BufReader<Box<dyn AsyncStream>>,
    message_path: &Path,
    body_offset: u64,
) -> anyhow::Result<()> {
    let file = open_message_body(message_path, body_offset).await?;
    let mut body = BufReader::new(file);
    reader.get_mut().write_all(b"DATA\r\n").await?;
    reader.get_mut().flush().await?;
    let (code, response) = read_response(&mut *reader).await?;
    if code != 354 {
        return Err(rejected("DATA", code, response));
    }

    let mut line = Vec::with_capacity(1_000);
    loop {
        if !read_data_line(&mut body, &mut line).await? {
            break;
        }
        let line = if line.ends_with(b"\r\n") {
            &line[..line.len() - 2]
        } else {
            // The requirements scan only permits DATA for canonical CRLF lines or
            // a final unterminated line. A different shape means the spool changed.
            if line.ends_with(b"\n") || line.contains(&0) {
                anyhow::bail!("queued message changed while streaming DATA");
            }
            line.as_slice()
        };
        if line.starts_with(b".") {
            reader.get_mut().write_all(b".").await?;
        }
        reader.get_mut().write_all(line).await?;
        reader.get_mut().write_all(b"\r\n").await?;
    }
    reader.get_mut().write_all(b".\r\n").await?;
    reader.get_mut().flush().await?;
    let (code, response) = read_response(&mut *reader).await?;
    if code / 100 != 2 {
        return Err(rejected("DATA body", code, response));
    }

    Ok(())
}

async fn read_data_line(reader: &mut BufReader<File>, line: &mut Vec<u8>) -> anyhow::Result<bool> {
    const MAX_DATA_LINE_BYTES: usize = 1_000;
    line.clear();
    loop {
        let (consumed, found_newline, eof) = {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                (0, false, true)
            } else {
                let consumed = available
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map_or(available.len(), |index| index + 1);
                if line.len().saturating_add(consumed) > MAX_DATA_LINE_BYTES {
                    anyhow::bail!("queued DATA line is too long");
                }
                line.extend_from_slice(&available[..consumed]);
                (consumed, available[..consumed].ends_with(b"\n"), false)
            }
        };
        if eof {
            return Ok(!line.is_empty());
        }
        reader.consume(consumed);
        if found_newline {
            return Ok(true);
        }
    }
}

#[cfg(test)]
fn build_mail_from_command(
    envelope_from: Option<&str>,
    recipient: &str,
    body: &[u8],
    capabilities: &SmtpCapabilities,
) -> anyhow::Result<String> {
    let requirements = requirements_for_bytes(envelope_from, recipient, body);
    build_mail_from_command_for_requirements(envelope_from, &requirements, false, capabilities)
}

#[cfg(test)]
fn requirements_for_bytes(
    envelope_from: Option<&str>,
    recipient: &str,
    body: &[u8],
) -> MessageRequirements {
    let mut analyzer = MessageAnalyzer {
        header_complete: false,
        previous_header_bytes: [0; 3],
        header_contains_non_ascii: false,
        contains_non_ascii: false,
        requires_binarymime: false,
        pending_cr: false,
        line_len: 0,
    };
    for byte in body {
        analyzer.observe(*byte);
    }
    analyzer.finish(envelope_from, recipient)
}

fn build_mail_from_command_for_requirements(
    envelope_from: Option<&str>,
    requirements: &MessageRequirements,
    require_tls: bool,
    capabilities: &SmtpCapabilities,
) -> anyhow::Result<String> {
    if requirements.smtp_utf8 && !capabilities.smtp_utf8 {
        anyhow::bail!("remote server does not support required SMTPUTF8");
    }
    if requirements.eight_bit_mime && !capabilities.eight_bit_mime {
        anyhow::bail!("remote server does not support required 8BITMIME");
    }
    if requirements.binary_mime && (!capabilities.chunking || !capabilities.binary_mime) {
        anyhow::bail!("remote server does not support required CHUNKING and BINARYMIME");
    }
    if require_tls && !capabilities.require_tls {
        return Err(permanent_delivery_error(
            "remote server does not advertise REQUIRETLS",
            Some("5.7.30"),
        ));
    }

    let mfrom = envelope_from.unwrap_or("");
    let mut mailcmd = format!("MAIL FROM:<{mfrom}>");
    if requirements.binary_mime {
        mailcmd.push_str(" BODY=BINARYMIME");
    } else if requirements.eight_bit_mime {
        mailcmd.push_str(" BODY=8BITMIME");
    }
    if requirements.smtp_utf8 {
        mailcmd.push_str(" SMTPUTF8");
    }
    if require_tls {
        mailcmd.push_str(" REQUIRETLS");
    }
    mailcmd.push_str("\r\n");
    Ok(mailcmd)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct SmtpCapabilities {
    eight_bit_mime: bool,
    smtp_utf8: bool,
    starttls: bool,
    chunking: bool,
    binary_mime: bool,
    require_tls: bool,
}

fn parse_ehlo_capabilities(response: &str) -> SmtpCapabilities {
    let mut capabilities = SmtpCapabilities::default();
    for line in response.lines() {
        if line.len() < 4 || !line.as_bytes().starts_with(b"250") {
            continue;
        }
        let keyword = line
            .get(4..)
            .unwrap_or("")
            .split_ascii_whitespace()
            .next()
            .unwrap_or("");
        if keyword.eq_ignore_ascii_case("8BITMIME") {
            capabilities.eight_bit_mime = true;
        } else if keyword.eq_ignore_ascii_case("SMTPUTF8") {
            capabilities.smtp_utf8 = true;
        } else if keyword.eq_ignore_ascii_case("STARTTLS") {
            capabilities.starttls = true;
        } else if keyword.eq_ignore_ascii_case("CHUNKING") {
            capabilities.chunking = true;
        } else if keyword.eq_ignore_ascii_case("BINARYMIME") {
            capabilities.binary_mime = true;
        } else if keyword.eq_ignore_ascii_case("REQUIRETLS") {
            capabilities.require_tls = true;
        }
    }
    capabilities
}

fn parse_mta_sts_dns_id(records: &[String]) -> Option<String> {
    let mut ids = records.iter().filter_map(|record| {
        let mut version = false;
        let mut id = None;
        for field in record.split(';').map(str::trim) {
            if field.eq_ignore_ascii_case("v=STSv1") {
                version = true;
            } else if let Some((name, value)) = field.split_once('=')
                && name.eq_ignore_ascii_case("id")
                && !value.is_empty()
                && value.len() <= 64
                && value.bytes().all(|byte| byte.is_ascii_graphic())
            {
                id = Some(value.to_string());
            }
        }
        version.then_some(id).flatten()
    });
    let id = ids.next()?;
    ids.next().is_none().then_some(id)
}

fn parse_mta_sts_policy(text: &str) -> anyhow::Result<MtaStsPolicy> {
    let mut version = None;
    let mut mode = None;
    let mut mx = Vec::new();
    let mut max_age = None;
    for raw_line in text.lines() {
        let line = raw_line.trim_end_matches('\r').trim();
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("invalid MTA-STS policy line"))?;
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "version" if version.is_none() => version = Some(value.to_string()),
            "mode" if mode.is_none() => {
                mode = Some(match value.to_ascii_lowercase().as_str() {
                    "enforce" => MtaStsMode::Enforce,
                    "testing" => MtaStsMode::Testing,
                    "none" => MtaStsMode::None,
                    _ => anyhow::bail!("invalid MTA-STS mode"),
                });
            }
            "mx" => {
                let raw_pattern = value.trim_end_matches('.').to_ascii_lowercase();
                let wildcard = raw_pattern.starts_with("*.");
                let suffix = raw_pattern.strip_prefix("*.").unwrap_or(&raw_pattern);
                if raw_pattern.is_empty() || suffix.contains('*') {
                    anyhow::bail!("invalid MTA-STS MX pattern");
                }
                let suffix = rmail_common::domain::canonicalize_domain(suffix)?;
                mx.push(if wildcard {
                    format!("*.{suffix}")
                } else {
                    suffix
                });
            }
            "max_age" if max_age.is_none() => {
                max_age = Some(Duration::from_secs(value.parse::<u64>()?));
            }
            _ => {}
        }
    }
    if version.as_deref() != Some("STSv1") {
        anyhow::bail!("unsupported MTA-STS policy version");
    }
    let mode = mode.ok_or_else(|| anyhow::anyhow!("MTA-STS policy has no mode"))?;
    let max_age = max_age.ok_or_else(|| anyhow::anyhow!("MTA-STS policy has no max_age"))?;
    if mode != MtaStsMode::None && mx.is_empty() {
        anyhow::bail!("MTA-STS enforce/testing policy has no MX patterns");
    }
    Ok(MtaStsPolicy { mode, mx, max_age })
}

fn mta_sts_matches_mx(policy: &MtaStsPolicy, host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    policy.mx.iter().any(|pattern| {
        if let Some(suffix) = pattern.strip_prefix("*.") {
            host.strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1)
        } else {
            host == *pattern
        }
    })
}

async fn mta_sts_policy_for_domain(
    resolver: &TokioAsyncResolver,
    domain: &str,
) -> Option<MtaStsPolicy> {
    let now = Instant::now();
    if let Some(cached) = MTA_STS_CACHE.lock().await.get(domain).cloned()
        && cached.expires > now
    {
        return Some(cached.policy);
    }
    let lookup = resolver
        .txt_lookup(format!("_mta-sts.{domain}"))
        .await
        .ok()?;
    let records = lookup
        .iter()
        .map(|record| {
            record
                .txt_data()
                .iter()
                .flat_map(|part| part.iter().copied())
                .map(char::from)
                .collect::<String>()
        })
        .collect::<Vec<_>>();
    let _id = parse_mta_sts_dns_id(&records)?;
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .ok()?
        .get(format!("https://mta-sts.{domain}/.well-known/mta-sts.txt"))
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?;
    if !response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("text/plain"))
        })
    {
        return None;
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_MTA_STS_POLICY_BYTES as u64)
    {
        return None;
    }
    let bytes = response.bytes().await.ok()?;
    if bytes.len() > MAX_MTA_STS_POLICY_BYTES {
        return None;
    }
    let policy = parse_mta_sts_policy(std::str::from_utf8(&bytes).ok()?).ok()?;
    let mut cache = MTA_STS_CACHE.lock().await;
    cache.retain(|_, entry| entry.expires > now);
    if cache.len() >= MAX_MTA_STS_CACHE_ENTRIES
        && let Some(oldest) = cache
            .iter()
            .min_by_key(|(_, entry)| entry.expires)
            .map(|(domain, _)| domain.clone())
    {
        cache.remove(&oldest);
    }
    let expires = now.checked_add(policy.max_age).unwrap_or(now);
    cache.insert(
        domain.to_string(),
        CachedMtaStsPolicy {
            policy: policy.clone(),
            expires,
        },
    );
    Some(policy)
}

async fn tls_report_recipients(resolver: &TokioAsyncResolver, domain: &str) -> Vec<String> {
    let Ok(lookup) = resolver.txt_lookup(format!("_smtp._tls.{domain}")).await else {
        return Vec::new();
    };
    let valid_records = lookup
        .iter()
        .filter_map(|record| {
            let value = record
                .txt_data()
                .iter()
                .flat_map(|part| part.iter().copied())
                .map(char::from)
                .collect::<String>();
            let mut valid_version = false;
            let mut recipients = Vec::new();
            for field in value.split(';').map(str::trim) {
                if field.eq_ignore_ascii_case("v=TLSRPTv1") {
                    valid_version = true;
                } else if let Some((name, addresses)) = field.split_once('=')
                    && name.eq_ignore_ascii_case("rua")
                {
                    recipients.extend(addresses.split(',').filter_map(|uri| {
                        uri.trim()
                            .strip_prefix("mailto:")
                            .map(str::trim)
                            .filter(|address| !address.is_empty())
                            .and_then(|address| {
                                rmail_common::domain::canonicalize_mailbox_address(address).ok()
                            })
                    }));
                }
            }
            valid_version.then_some(recipients)
        })
        .collect::<Vec<_>>();
    if valid_records.len() != 1 {
        return Vec::new();
    }
    let candidates = valid_records.into_iter().flatten().take(10);
    let mut authorized = Vec::new();
    for recipient in candidates {
        let Some((_, report_domain)) = recipient.rsplit_once('@') else {
            continue;
        };
        if report_domain.eq_ignore_ascii_case(domain) {
            authorized.push(recipient);
            continue;
        }
        let authorization_name = format!("{domain}._report._smtp._tls.{report_domain}");
        let permitted = resolver
            .txt_lookup(authorization_name)
            .await
            .ok()
            .is_some_and(|records| {
                records.iter().any(|record| {
                    let value = record
                        .txt_data()
                        .iter()
                        .flat_map(|part| part.iter().copied())
                        .map(char::from)
                        .collect::<String>();
                    value
                        .split(';')
                        .map(str::trim)
                        .any(|field| field.eq_ignore_ascii_case("v=TLSRPTv1"))
                })
            });
        if permitted {
            authorized.push(recipient);
        }
    }
    authorized
}

async fn queue_tls_failure_report(
    mail_root: &Path,
    resolver: &TokioAsyncResolver,
    domain: &str,
    mx_host: Option<&str>,
    policy_type: &str,
    diagnostic: &str,
) {
    let recipients = tls_report_recipients(resolver, domain).await;
    if recipients.is_empty() {
        return;
    }
    let (report_id, encoded) =
        build_tls_failure_report_json(domain, mx_host, policy_type, diagnostic, Utc::now());
    for recipient in recipients {
        let mut message = format!(
            "From: Mail Delivery Subsystem <MAILER-DAEMON@localhost>\r\nTo: <{recipient}>\r\nSubject: Report Domain: {domain} Submitter: rMail Report-ID: {report_id}\r\nAuto-Submitted: auto-generated\r\nMIME-Version: 1.0\r\nContent-Type: application/tlsrpt+json\r\n\r\n"
        )
        .into_bytes();
        message.extend_from_slice(&encoded);
        message.extend_from_slice(b"\r\n");
        let mail_root = mail_root.to_path_buf();
        let result = tokio::task::spawn_blocking(move || {
            rmail_common::outbound::queue_outbound(&mail_root, &recipient, &message, None)
        })
        .await;
        match result {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => eprintln!("failed to queue TLS-RPT report: {error}"),
            Err(error) => eprintln!("failed to join TLS-RPT queue operation: {error}"),
        }
    }
}

fn build_tls_failure_report_json(
    domain: &str,
    mx_host: Option<&str>,
    policy_type: &str,
    diagnostic: &str,
    now: chrono::DateTime<Utc>,
) -> (String, Vec<u8>) {
    let report_id = format!("{}-{}", now.timestamp(), std::process::id());
    let report = serde_json::json!({
        "organization-name": "rMail",
        "date-range": {
            "start-datetime": now.to_rfc3339(),
            "end-datetime": now.to_rfc3339()
        },
        "contact-info": "postmaster@localhost",
        "report-id": report_id,
        "policies": [{
            "policy": {
                "policy-type": policy_type,
                "policy-string": [],
                "policy-domain": domain,
                "mx-host": mx_host.into_iter().collect::<Vec<_>>()
            },
            "summary": { "total-successful-session-count": 0, "total-failure-session-count": 1 },
            "failure-details": [{
                "result-type": if diagnostic.contains("does not offer STARTTLS") {
                    "starttls-not-supported"
                } else if diagnostic.to_ascii_lowercase().contains("certificate") {
                    "certificate-not-trusted"
                } else {
                    "validation-failure"
                },
                "receiving-mx-hostname": mx_host.unwrap_or(domain),
                "failed-session-count": 1,
                "additional-information": diagnostic
            }]
        }]
    });
    (
        report_id,
        serde_json::to_vec_pretty(&report).unwrap_or_default(),
    )
}

async fn deliver_to_remote(
    base: &Path,
    message_path: &Path,
    message: QueuedMessage,
    connections: &ConnectionPool,
) -> anyhow::Result<()> {
    let recipient = rmail_common::domain::canonicalize_mailbox_address(&message.envelope_to)
        .context("canonicalizing recipient IDN")?;
    let envelope_from = message
        .envelope_from
        .as_deref()
        .map(rmail_common::domain::canonicalize_mailbox_address)
        .transpose()
        .context("canonicalizing sender IDN")?;
    let at = recipient
        .rfind('@')
        .ok_or_else(|| anyhow::anyhow!("invalid recipient address"))?;
    let domain = &recipient[at + 1..];

    // Resolve MX records using system DNS configuration. If RMAIL_REQUIRE_DNSSEC=1, enable DNSSEC validation in resolver options.
    let require_dnssec_on_init = std::env::var("RMAIL_REQUIRE_DNSSEC")
        .map(|v| {
            let v = v.to_ascii_lowercase();
            !(v == "0" || v == "false")
        })
        .unwrap_or(false);
    let (conf, mut opts) =
        trust_dns_resolver::system_conf::read_system_conf().context("reading system dns config")?;
    if require_dnssec_on_init {
        opts.validate = true;
    }
    let resolver = TokioAsyncResolver::tokio(conf, opts).context("creating dns resolver")?;
    // transport may indicate implicit TLS (smtps) or explicit SMTP. Track optional port.
    let mut targets: Vec<(String, Option<u16>)> = Vec::new();
    match rmail_common::transport::lookup_transport(base, domain) {
        Ok(rmail_common::transport::Transport::Smtp(Some(h))) => {
            targets.push((h, None));
        }
        Ok(rmail_common::transport::Transport::Smtp(None)) => { /* fallthrough to MX lookup */ }
        Ok(rmail_common::transport::Transport::Smtps(Some(h))) => {
            targets.push((h, Some(465)));
        }
        Ok(rmail_common::transport::Transport::Smtps(None)) => { /* fallthrough to MX lookup */ }
        Ok(rmail_common::transport::Transport::Error(msg)) => {
            return Err(anyhow::anyhow!(format!(
                "transport map error for {}: {}",
                domain, msg
            )));
        }
        Err(e) => {
            eprintln!("transport map lookup failed for {}: {}", domain, e);
        }
    }

    // If transport map didn't provide a next-hop, perform MX lookup.
    if targets.is_empty() {
        match resolver.mx_lookup(domain).await {
            Ok(mx) => {
                let mut mxs: Vec<(u16, String)> = mx
                    .iter()
                    .map(|r| (r.preference(), r.exchange().to_utf8()))
                    .collect();
                mxs.sort_by_key(|(p, _)| *p);
                for (_pref, host) in mxs {
                    if host == "." {
                        return Err(permanent_delivery_error(
                            format!("recipient domain {domain} publishes a Null MX record"),
                            Some("5.1.10"),
                        ));
                    }
                    targets.push((host.trim_end_matches('.').to_string(), None));
                }
            }
            Err(error) if matches!(error.kind(), ResolveErrorKind::NoRecordsFound { .. }) => {
                // RFC 5321 implicit-MX fallback applies only when MX records are
                // absent, never when DNS itself is unavailable or fails validation.
                targets.push((domain.to_string(), None));
            }
            Err(error) => return Err(error).context("resolving recipient MX records"),
        }
    }

    if targets.is_empty() {
        targets.push((domain.to_string(), None));
    }

    let mta_sts_policy = mta_sts_policy_for_domain(&resolver, domain).await;
    let mta_sts_enforced = mta_sts_policy
        .as_ref()
        .is_some_and(|policy| policy.mode == MtaStsMode::Enforce);
    if let Some(policy) = mta_sts_policy.as_ref()
        && policy.mode != MtaStsMode::None
    {
        let mismatched = targets
            .iter()
            .filter(|(host, _)| !mta_sts_matches_mx(policy, host))
            .map(|(host, _)| host.clone())
            .collect::<Vec<_>>();
        if policy.mode == MtaStsMode::Enforce {
            targets.retain(|(host, _)| mta_sts_matches_mx(policy, host));
            if targets.is_empty() {
                let diagnostic = format!(
                    "no recipient MX matches the active MTA-STS policy (rejected: {})",
                    mismatched.join(", ")
                );
                if envelope_from.is_some() {
                    queue_tls_failure_report(base, &resolver, domain, None, "sts", &diagnostic)
                        .await;
                }
                anyhow::bail!(diagnostic);
            }
        } else if !mismatched.is_empty() {
            eprintln!(
                "MTA-STS testing policy mismatch for {domain}: {}",
                mismatched.join(", ")
            );
        }
    }
    let transport_tls_required = message.require_tls || mta_sts_enforced;

    // Reuse an idle session for the selected destination when possible. Each
    // connection stays owned by one delivery task at a time, while the worker's
    // task limit bounds simultaneous connections and transactions.
    let mut last_delivery_error = None;
    for (host, port_opt) in &targets {
        let port = port_opt.unwrap_or(25);
        let key = DestinationKey {
            host: host.trim_end_matches('.').to_ascii_lowercase(),
            port,
        };
        let connection = match connections.take(&key).await {
            Some(mut connection) if !transport_tls_required || connection.encrypted => {
                match smtp_noop(&mut connection).await {
                    Ok(()) => Ok(connection),
                    Err(error) => {
                        eprintln!(
                            "discarding stale SMTP session for {}:{}: {}",
                            key.host, key.port, error
                        );
                        establish_smtp_connection(
                            &key.host,
                            key.port,
                            transport_tls_required,
                            message.require_tls,
                        )
                        .await
                    }
                }
            }
            Some(_) | None => {
                establish_smtp_connection(
                    &key.host,
                    key.port,
                    transport_tls_required,
                    message.require_tls,
                )
                .await
            }
        };
        let mut connection = match connection {
            Ok(connection) => connection,
            Err(error) => {
                last_delivery_error = Some(error);
                continue;
            }
        };
        match smtp_send_file_with_reader(
            &mut connection.reader,
            message_path,
            &message,
            envelope_from.as_deref(),
            &recipient,
            &connection.capabilities,
        )
        .await
        {
            Ok(()) => {
                connections.recycle(key, connection).await;
                return Ok(());
            }
            Err(error) => {
                // A definitive 5xx/policy failure applies to the recipient and
                // must not be hidden by trying a lower-priority MX. Transient
                // replies and transport failures should fall through to the
                // remaining MX hosts before the message is queued for retry.
                let permanent_reply = error
                    .chain()
                    .find_map(|cause| cause.downcast_ref::<SmtpReplyError>())
                    .is_some_and(SmtpReplyError::is_permanent);
                let permanent_policy = error
                    .chain()
                    .any(|cause| cause.downcast_ref::<PermanentDeliveryError>().is_some());
                if permanent_reply || permanent_policy {
                    if transport_tls_required && envelope_from.is_some() {
                        queue_tls_failure_report(
                            base,
                            &resolver,
                            domain,
                            Some(&key.host),
                            if mta_sts_enforced {
                                "sts"
                            } else {
                                "no-policy-found"
                            },
                            &error.to_string(),
                        )
                        .await;
                    }
                    return Err(error);
                }
                last_delivery_error = Some(error);
            }
        }
    }

    let error = last_delivery_error
        .unwrap_or_else(|| anyhow::anyhow!("failed to connect to any MX/A host"));
    if transport_tls_required && envelope_from.is_some() {
        queue_tls_failure_report(
            base,
            &resolver,
            domain,
            None,
            if mta_sts_enforced {
                "sts"
            } else {
                "no-policy-found"
            },
            &error.to_string(),
        )
        .await;
    }
    Err(error)
}

async fn smtp_noop(connection: &mut SmtpConnection) -> anyhow::Result<()> {
    connection.reader.get_mut().write_all(b"NOOP\r\n").await?;
    connection.reader.get_mut().flush().await?;
    let (code, response) = read_response(&mut connection.reader).await?;
    if code / 100 != 2 {
        return Err(rejected("NOOP", code, response));
    }
    Ok(())
}

async fn establish_smtp_connection(
    host: &str,
    port: u16,
    require_encryption: bool,
    requiretls_message: bool,
) -> anyhow::Result<SmtpConnection> {
    let stream = connect_host_with_fallback(host, port).await?;
    let mut encrypted = port == 465;
    let boxed_stream: Box<dyn AsyncStream> = if encrypted {
        let native = NativeTlsConnector::builder()
            .build()
            .context("building native TLS connector")?;
        let tls_stream = TokioTlsConnector::from(native)
            .connect(host, stream)
            .await
            .context("TLS connect failed (implicit)")?;
        Box::new(tls_stream)
    } else {
        Box::new(stream)
    };
    let mut reader = BufReader::new(boxed_stream);

    let (code, banner) = read_response(&mut reader).await?;
    if code != 220 {
        return Err(rejected("connection greeting", code, banner));
    }

    reader.get_mut().write_all(b"EHLO rmail\r\n").await?;
    reader.get_mut().flush().await?;
    let (code, ehlo_response) = read_response(&mut reader).await?;
    let mut capabilities = if code != 250 {
        reader.get_mut().write_all(b"HELO rmail\r\n").await?;
        reader.get_mut().flush().await?;
        let (code, response) = read_response(&mut reader).await?;
        if code != 250 {
            return Err(rejected("HELO", code, response));
        }
        SmtpCapabilities::default()
    } else {
        parse_ehlo_capabilities(&ehlo_response)
    };

    if port != 465 && capabilities.starttls {
        reader.get_mut().write_all(b"STARTTLS\r\n").await?;
        reader.get_mut().flush().await?;
        let (code, response) = read_response(&mut reader).await?;
        if code != 220 {
            return Err(rejected("STARTTLS", code, response));
        }
        let inner = reader.into_inner();
        let native = NativeTlsConnector::builder()
            .build()
            .context("building native TLS connector")?;
        let tls_stream = TokioTlsConnector::from(native)
            .connect(host, inner)
            .await
            .context("TLS connect failed")?;
        reader = BufReader::new(Box::new(tls_stream));
        encrypted = true;

        reader.get_mut().write_all(b"EHLO rmail\r\n").await?;
        reader.get_mut().flush().await?;
        let (code, ehlo_response) = read_response(&mut reader).await?;
        if code != 250 {
            reader.get_mut().write_all(b"HELO rmail\r\n").await?;
            reader.get_mut().flush().await?;
            let (code, response) = read_response(&mut reader).await?;
            if code != 250 {
                return Err(rejected("HELO after STARTTLS", code, response));
            }
            capabilities = SmtpCapabilities::default();
        } else {
            capabilities = parse_ehlo_capabilities(&ehlo_response);
        }
    }

    if require_encryption && !encrypted {
        if requiretls_message {
            return Err(permanent_delivery_error(
                format!("remote host {host} does not offer STARTTLS required by REQUIRETLS"),
                Some("5.7.30"),
            ));
        }
        anyhow::bail!("remote host {host} does not offer STARTTLS required by MTA-STS");
    }

    Ok(SmtpConnection {
        reader,
        capabilities,
        encrypted,
    })
}

async fn connect_host_with_fallback(host: &str, port: u16) -> anyhow::Result<TcpStream> {
    const HOST_CONNECT_BUDGET: Duration = Duration::from_secs(30);
    const ADDRESS_CONNECT_BUDGET: Duration = Duration::from_secs(10);
    let addresses = tokio::time::timeout(Duration::from_secs(10), lookup_host((host, port)))
        .await
        .map_err(|_| anyhow::anyhow!("timed out resolving {host}:{port}"))??
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        anyhow::bail!("no addresses found for {host}:{port}");
    }

    let deadline = tokio::time::Instant::now() + HOST_CONNECT_BUDGET;
    let mut failures = Vec::new();
    for address in addresses {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let budget = remaining.min(ADDRESS_CONNECT_BUDGET);
        match tokio::time::timeout(budget, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => failures.push(format!("{address}: {error}")),
            Err(_) => failures.push(format!("{address}: timed out after {}s", budget.as_secs())),
        }
    }
    anyhow::bail!(
        "failed to connect to {host}:{port} at any resolved address ({})",
        failures.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[test]
    fn smtp_reply_classification_preserves_enhanced_status() {
        let transient = SmtpReplyError::new(
            "RCPT TO",
            450,
            "450 4.2.0 mailbox temporarily unavailable\r\n".into(),
        );
        assert!(!transient.is_permanent());
        assert_eq!(transient.enhanced_status.as_deref(), Some("4.2.0"));
        assert!(transient.to_string().contains("4.2.0"));

        let permanent = SmtpReplyError::new("RCPT TO", 550, "550 5.1.1 no such user\r\n".into());
        assert!(permanent.is_permanent());
        assert_eq!(permanent.enhanced_status.as_deref(), Some("5.1.1"));

        let legacy_transient = SmtpReplyError::new("DATA", 451, "451 try later\r\n".into());
        assert!(!legacy_transient.is_permanent());
        let legacy_permanent = SmtpReplyError::new("DATA", 554, "554 rejected\r\n".into());
        assert!(legacy_permanent.is_permanent());

        // The SMTP reply code, not a contradictory enhanced code, determines
        // whether a queue item may be retried.
        let contradictory = SmtpReplyError::new(
            "RCPT TO",
            450,
            "450 5.1.1 temporary transport error\r\n".into(),
        );
        assert!(!contradictory.is_permanent());
        assert_eq!(retry_backoff_seconds(1, Some("4.2.2")), 15 * 60);
        assert_eq!(retry_backoff_seconds(1, Some("4.7.0")), 5 * 60);
        assert_eq!(retry_backoff_seconds(2, Some("4.1.0")), 120);
    }

    #[test]
    fn failure_notification_is_a_loop_safe_delivery_status_report() {
        let mut control = rmail_common::outbound::QueueControl::new(5, 0);
        control.last_smtp_code = Some(550);
        control.last_enhanced_status = Some("5.1.1".to_string());
        control.last_error = Some("RCPT TO rejected: 550 5.1.1 no such user".to_string());
        let notification = build_failure_notification(
            "sender@example.test",
            "missing@example.test",
            &control,
            b"Subject: original\r\nMessage-ID: <original@example.test>\r\n\r\n",
        );
        let notification = String::from_utf8(notification).unwrap();
        assert!(notification.contains("Auto-Submitted: auto-replied\r\n"));
        assert!(
            notification.contains("Content-Type: multipart/report; report-type=delivery-status")
        );
        assert!(notification.contains("Final-Recipient: rfc822; missing@example.test\r\n"));
        assert!(notification.contains("Action: failed\r\nStatus: 5.1.1\r\n"));
        assert!(notification.contains("Content-Type: message/rfc822-headers\r\n"));
        assert!(notification.contains("Subject: original\r\n"));
    }

    #[test]
    fn ehlo_capabilities_are_parsed_by_keyword_not_response_substrings() {
        let capabilities = parse_ehlo_capabilities(
            "250-mail.example\r\n250-8bitmime\r\n250-SMTPUTF8\r\n250-CHUNKING\r\n250-BINARYMIME\r\n250 STARTTLS\r\n",
        );
        assert!(capabilities.eight_bit_mime);
        assert!(capabilities.smtp_utf8);
        assert!(capabilities.starttls);
        assert!(capabilities.chunking);
        assert!(capabilities.binary_mime);
        assert_eq!(
            parse_ehlo_capabilities("250 mail without STARTTLS support"),
            SmtpCapabilities::default()
        );
    }

    #[test]
    fn mail_command_handles_null_sender_and_required_content_extensions() {
        let all = SmtpCapabilities {
            eight_bit_mime: true,
            smtp_utf8: true,
            starttls: false,
            chunking: true,
            binary_mime: true,
            require_tls: true,
        };
        assert_eq!(
            build_mail_from_command(None, "user@example.test", b"Subject: x\r\n\r\nbody", &all)
                .unwrap(),
            "MAIL FROM:<>\r\n"
        );
        assert_eq!(
            build_mail_from_command(
                Some("séndér@example.test"),
                "user@example.test",
                "Subject: héj\r\n\r\nbody: ø".as_bytes(),
                &all,
            )
            .unwrap(),
            "MAIL FROM:<séndér@example.test> BODY=8BITMIME SMTPUTF8\r\n"
        );
        assert!(
            build_mail_from_command(
                None,
                "user@example.test",
                b"Subject: x\r\n\r\nbody:\xff",
                &SmtpCapabilities::default(),
            )
            .is_err()
        );
        assert_eq!(
            build_mail_from_command(
                None,
                "user@example.test",
                b"Subject: x\r\n\r\nbinary\0body\r\n",
                &all,
            )
            .unwrap(),
            "MAIL FROM:<> BODY=BINARYMIME\r\n"
        );
        assert!(
            build_mail_from_command(
                None,
                "user@example.test",
                b"Subject: x\r\n\r\nbinary\0body\r\n",
                &SmtpCapabilities::default(),
            )
            .is_err()
        );
        let requiretls = build_mail_from_command_for_requirements(
            Some("sender@example.test"),
            &MessageRequirements::default(),
            true,
            &all,
        )
        .unwrap();
        assert_eq!(requiretls, "MAIL FROM:<sender@example.test> REQUIRETLS\r\n");
        let unsupported = build_mail_from_command_for_requirements(
            Some("sender@example.test"),
            &MessageRequirements::default(),
            true,
            &SmtpCapabilities::default(),
        )
        .unwrap_err();
        assert!(
            unsupported
                .downcast_ref::<PermanentDeliveryError>()
                .is_some()
        );
    }

    #[test]
    fn mta_sts_policy_parser_and_mx_matching_are_strict() {
        let policy = parse_mta_sts_policy(
            "version: STSv1\r\nmode: enforce\r\nmx: mx.example.test\r\nmx: *.mail.example.test\r\nmax_age: 86400\r\n",
        )
        .unwrap();
        assert_eq!(policy.mode, MtaStsMode::Enforce);
        assert!(mta_sts_matches_mx(&policy, "mx.example.test."));
        assert!(mta_sts_matches_mx(&policy, "a.mail.example.test"));
        assert!(!mta_sts_matches_mx(&policy, "mail.example.test"));
        assert!(!mta_sts_matches_mx(&policy, "evilmail.example.test"));
        assert!(parse_mta_sts_policy("version: STSv1\nmode: enforce\nmax_age: 1\n").is_err());
        assert!(parse_mta_sts_policy("version: STSv2\nmode: none\nmax_age: 1\n").is_err());
    }

    #[test]
    fn mta_sts_dns_record_requires_one_valid_policy_id() {
        assert_eq!(
            parse_mta_sts_dns_id(&["v=STSv1; id=20260713".to_string()]),
            Some("20260713".to_string())
        );
        assert_eq!(
            parse_mta_sts_dns_id(&["v=STSv1; id=one".to_string(), "v=STSv1; id=two".to_string()]),
            None
        );
        assert_eq!(parse_mta_sts_dns_id(&["v=other; id=x".to_string()]), None);
    }

    #[test]
    fn tls_failure_report_has_rfc8460_shape() {
        let now = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let (report_id, encoded) = build_tls_failure_report_json(
            "example.test",
            Some("mx.example.test"),
            "sts",
            "certificate validation failed",
            now,
        );
        assert!(report_id.starts_with("1700000000-"));
        let report: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(report["policies"][0]["policy"]["policy-type"], "sts");
        assert_eq!(
            report["policies"][0]["failure-details"][0]["result-type"],
            "certificate-not-trusted"
        );
        assert_eq!(
            report["policies"][0]["summary"]["total-failure-session-count"],
            1
        );
    }

    #[tokio::test]
    async fn reply_parser_enforces_crlf_bounds_and_multiline_code_consistency() {
        let mut valid = BufReader::new(&b"250-mail.example\r\n250-8BITMIME\r\n250 OK\r\n"[..]);
        let (code, response) = read_response(&mut valid).await.unwrap();
        assert_eq!(code, 250);
        assert!(response.contains("8BITMIME"));

        let mut inconsistent = BufReader::new(&b"250-first\r\n251 second\r\n"[..]);
        assert!(read_response(&mut inconsistent).await.is_err());
        let mut bare_lf = BufReader::new(&b"250 OK\n"[..]);
        assert!(read_response(&mut bare_lf).await.is_err());
        let overlong = format!("250 {}\r\n", "x".repeat(509));
        let mut overlong = BufReader::new(overlong.as_bytes());
        assert!(read_response(&mut overlong).await.is_err());
    }

    #[tokio::test]
    async fn queued_message_parser_strips_legacy_lf_metadata() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("message.eml");
        let body = b"Subject: streamed\r\n\r\nbody\r\n";
        let metadata = b"X-RMail-Envelope-From: sender@example.test\nX-RMail-Envelope-To: user@example.test\n\n";
        let mut queued = metadata.to_vec();
        queued.extend_from_slice(body);
        std::fs::write(&path, &queued).unwrap();

        let message = inspect_queued_message(&path).await.unwrap();
        assert_eq!(
            message.envelope_from.as_deref(),
            Some("sender@example.test")
        );
        assert_eq!(message.envelope_to, "user@example.test");
        assert_eq!(message.body_offset as usize, metadata.len());
        assert_eq!(message.body_len as usize, body.len());
        assert_eq!(message.requirements, MessageRequirements::default());

        let mut body_file = open_message_body(&path, message.body_offset).await.unwrap();
        let mut streamed = Vec::new();
        body_file.read_to_end(&mut streamed).await.unwrap();
        assert_eq!(streamed, body);
    }

    #[tokio::test]
    async fn queued_message_streams_bdat_in_bounded_chunks() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("message.eml");
        let metadata = b"X-RMail-Envelope-To: user@example.test\r\n\r\n";
        let mut body = b"Subject: stream\r\n\r\n".to_vec();
        body.extend((0..(BDAT_CHUNK_BYTES + 17)).map(|index| (index % 251) as u8));
        *body.last_mut().unwrap() = 0;
        let mut queued = metadata.to_vec();
        queued.extend_from_slice(&body);
        std::fs::write(&path, &queued).unwrap();
        let message = inspect_queued_message(&path).await.unwrap();
        assert!(message.requirements.binary_mime);

        let expected = body.clone();
        let (client, server) = tokio::io::duplex(BDAT_CHUNK_BYTES * 2);
        let server_task = tokio::spawn(async move {
            let mut server = BufReader::new(server);
            for expected_command in [
                "MAIL FROM:<> BODY=BINARYMIME\r\n",
                "RCPT TO:<user@example.test>\r\n",
            ] {
                let mut line = String::new();
                server.read_line(&mut line).await.unwrap();
                assert_eq!(line, expected_command);
                server
                    .get_mut()
                    .write_all(b"250 2.0.0 OK\r\n")
                    .await
                    .unwrap();
                server.get_mut().flush().await.unwrap();
            }

            let mut offset = 0;
            while offset < expected.len() {
                let remaining = expected.len() - offset;
                let chunk_len = remaining.min(BDAT_CHUNK_BYTES);
                let mut command = String::new();
                server.read_line(&mut command).await.unwrap();
                let expected_command = if chunk_len == remaining {
                    format!("BDAT {chunk_len} LAST\r\n")
                } else {
                    format!("BDAT {chunk_len}\r\n")
                };
                assert_eq!(command, expected_command);
                let mut received = vec![0; chunk_len];
                server.read_exact(&mut received).await.unwrap();
                assert_eq!(received, expected[offset..offset + chunk_len]);
                server
                    .get_mut()
                    .write_all(b"250 2.0.0 accepted\r\n")
                    .await
                    .unwrap();
                server.get_mut().flush().await.unwrap();
                offset += chunk_len;
            }
        });

        let stream: Box<dyn AsyncStream> = Box::new(client);
        let mut reader = BufReader::new(stream);
        smtp_send_file_with_reader(
            &mut reader,
            &path,
            &message,
            None,
            "user@example.test",
            &SmtpCapabilities {
                eight_bit_mime: true,
                smtp_utf8: true,
                starttls: false,
                chunking: true,
                binary_mime: true,
                require_tls: false,
            },
        )
        .await
        .unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn idle_connection_pool_is_destination_keyed_and_bounded() {
        let pool = ConnectionPool::new(1, 1);
        let key = DestinationKey {
            host: "mx.example.test".to_string(),
            port: 25,
        };
        let (first_client, _first_server) = tokio::io::duplex(64);
        pool.recycle(
            key.clone(),
            SmtpConnection {
                reader: BufReader::new(Box::new(first_client)),
                capabilities: SmtpCapabilities::default(),
                encrypted: false,
            },
        )
        .await;
        let (second_client, _second_server) = tokio::io::duplex(64);
        pool.recycle(
            key.clone(),
            SmtpConnection {
                reader: BufReader::new(Box::new(second_client)),
                capabilities: SmtpCapabilities::default(),
                encrypted: false,
            },
        )
        .await;

        assert!(
            pool.take(&DestinationKey {
                host: "other-mx.example.test".to_string(),
                port: 25,
            })
            .await
            .is_none()
        );
        assert!(pool.take(&key).await.is_some());
        assert!(pool.take(&key).await.is_none());
    }

    #[tokio::test]
    async fn chunking_relay_sends_exact_binary_bdat_payload() {
        let (client, server) = tokio::io::duplex(4096);
        let body = b"Subject: binary\r\n\r\nzero:\0byte\r\n".to_vec();
        let expected = body.clone();
        let server_task = tokio::spawn(async move {
            let mut server = BufReader::new(server);
            for expected_command in [
                "MAIL FROM:<> BODY=BINARYMIME\r\n",
                "RCPT TO:<user@example.test>\r\n",
            ] {
                let mut line = String::new();
                server.read_line(&mut line).await.unwrap();
                assert_eq!(line, expected_command);
                server
                    .get_mut()
                    .write_all(b"250 2.0.0 OK\r\n")
                    .await
                    .unwrap();
                server.get_mut().flush().await.unwrap();
            }
            let mut line = String::new();
            server.read_line(&mut line).await.unwrap();
            assert_eq!(line, format!("BDAT {} LAST\r\n", expected.len()));
            let mut received = vec![0; expected.len()];
            server.read_exact(&mut received).await.unwrap();
            assert_eq!(received, expected);
            server
                .get_mut()
                .write_all(b"250 2.0.0 accepted\r\n")
                .await
                .unwrap();
            server.get_mut().flush().await.unwrap();
            line.clear();
            server.read_line(&mut line).await.unwrap();
            assert_eq!(line, "QUIT\r\n");
            server
                .get_mut()
                .write_all(b"221 2.0.0 bye\r\n")
                .await
                .unwrap();
        });
        let stream: Box<dyn AsyncStream> = Box::new(client);
        let mut reader = BufReader::new(stream);
        smtp_send_with_reader(
            &mut reader,
            None,
            "user@example.test",
            &body,
            &SmtpCapabilities {
                eight_bit_mime: true,
                smtp_utf8: true,
                starttls: false,
                chunking: true,
                binary_mime: true,
                require_tls: false,
            },
        )
        .await
        .unwrap();
        server_task.await.unwrap();
    }
}
