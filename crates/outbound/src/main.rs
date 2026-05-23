use anyhow::Context;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use trust_dns_resolver::TokioAsyncResolver;
use tokio_native_tls::TlsConnector as TokioTlsConnector;
use native_tls::TlsConnector as NativeTlsConnector;
use rmail_common::db;
use rmail_common::transport;
use std::collections::HashSet;
mod tlsa;
mod dane_blocking;
use trust_dns_resolver::proto::rr::RecordType;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::X509;
use openssl::pkey::PKey;
use openssl::sha::{sha256, sha512};
use hex;

// Trait object helper so the outbound worker can swap plain and TLS streams dynamically.
trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized> AsyncStream for T {}

// Simple outbound delivery worker: scans <mail_root>/outbound/queue, moves files to inflight,
// parses envelope metadata (X-RMail-Envelope-From/To) and performs a minimal SMTP conversation
// to the recipient domain. Failures are moved to failed/ for manual inspection / retry.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mail_root = std::env::var("RMAIL_MAIL_ROOT").unwrap_or_else(|_| "./mail".to_string());
    let base = PathBuf::from(mail_root);
    let maildrop_dir = base.join("outbound").join("maildrop");
    let queue_dir = maildrop_dir.join("queue");
    let inflight_dir = maildrop_dir.join("inflight");
    let sent_dir = base.join("outbound").join("sent");
    let failed_dir = base.join("outbound").join("failed");

    tokio::fs::create_dir_all(&queue_dir).await?;
    tokio::fs::create_dir_all(&inflight_dir).await?;
    tokio::fs::create_dir_all(&sent_dir).await?;
    tokio::fs::create_dir_all(&failed_dir).await?;

    println!("Using on-disk outbound queue: {}", queue_dir.display());
    loop {
        // Try to claim an eligible message using the shared queue-manager library (blocking fs ops)
        let claim_res = tokio::task::spawn_blocking({
            let md = maildrop_dir.clone();
            move || rmail_queue_manager::claim_one(&md)
        }).await;

        let claimed = match claim_res {
            Ok(Ok(Some((inflight_eml, inflight_json)))) => Some((inflight_eml, inflight_json)),
            Ok(Ok(None)) => None,
            Ok(Err(e)) => {
                eprintln!("queue-manager claim_one failed: {}", e);
                None
            }
            Err(e) => {
                eprintln!("claim task join failed: {}", e);
                None
            }
        };

        let (inflight_eml, inflight_json) = match claimed {
            Some((e, j)) => (e, j),
            None => {
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        let fname = inflight_eml.file_name().and_then(|n| n.to_str()).unwrap_or("unknown").to_string();

        // read control JSON from inflight and increment attempts
        let mut control: rmail_common::outbound::QueueControl = match tokio::fs::read_to_string(&inflight_json).await {
            Ok(s) => serde_json::from_str(&s).unwrap_or_else(|_| rmail_common::outbound::QueueControl::default_with_timestamp(0)),
            Err(_) => rmail_common::outbound::QueueControl::default_with_timestamp(0),
        };
        control.attempts = control.attempts.saturating_add(1);
        tokio::fs::write(&inflight_json, serde_json::to_string(&control)?).await?;

        // Process
        let res = process_file(&inflight_eml, &base).await;

        if res.is_ok() {
            let sent_eml = sent_dir.join(&fname);
            let sent_json = sent_eml.with_extension("json");
            if let Err(e) = tokio::fs::rename(&inflight_eml, &sent_eml).await {
                eprintln!("failed to move to sent {}: {}", fname, e);
            } else {
                let _ = tokio::fs::rename(&inflight_json, &sent_json).await;
            }
        } else {
            let err = res.err().map(|e| e.to_string()).unwrap_or_else(|| "unknown".to_string());
            eprintln!("delivery failed for {}: {}", fname, err);
            if control.attempts >= control.max_attempts {
                let failed_eml = failed_dir.join(&fname);
                let failed_json = failed_eml.with_extension("json");
                if let Err(e) = tokio::fs::rename(&inflight_eml, &failed_eml).await {
                    eprintln!("failed to move to failed {}: {}", fname, e);
                } else {
                    let mut c = control.clone();
                    c.last_error = Some(err.clone());
                    let _ = tokio::fs::write(&failed_json, serde_json::to_string(&c)?).await;
                }
            } else {
                // exponential backoff using shared helper
                let backoff = rmail_queue_manager::next_backoff_seconds(control.attempts);
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() as i64;
                let next_try = now + backoff;
                control.next_try = Some(next_try);
                control.last_error = Some(err.clone());
                let queue_eml = queue_dir.join(&fname);
                let queue_json = queue_eml.with_extension("json");
                if let Err(e) = tokio::fs::write(&queue_json, serde_json::to_string(&control)?).await {
                    eprintln!("failed to write control json for retry {}: {}", fname, e);
                }
                if let Err(e) = tokio::fs::rename(&inflight_eml, &queue_eml).await {
                    eprintln!("failed to move back to queue {}: {}", fname, e);
                }
            }
        }

        // small delay to avoid tight-loop
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn process_file(path: &Path, base: &Path) -> anyhow::Result<()> {
    let data = tokio::fs::read(path).await?;
    // Find header/body split (we write metadata headers followed by CRLF CRLF)
    let split_seq = b"\r\n\r\n";
    let header_end = data.windows(split_seq.len()).position(|w| w == split_seq).map(|p| p + split_seq.len());
    let (headers_bytes, body_bytes) = if let Some(hend) = header_end {
        (&data[..hend], &data[hend..])
    } else {
        // no metadata headers; treat entire file as body
        (&[][..], &data[..])
    };

    // Parse headers lines
    let headers = String::from_utf8_lossy(headers_bytes);
    let mut envelope_from: Option<String> = None;
    let mut envelope_to: Option<String> = None;
    for line in headers.lines() {
        if let Some(rest) = line.strip_prefix("X-RMail-Envelope-From:") {
            envelope_from = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("X-RMail-Envelope-To:") {
            envelope_to = Some(rest.trim().to_string());
        }
    }

    let rcpt = if let Some(r) = envelope_to { r } else {
        return Err(anyhow::anyhow!("no envelope recipient found in queued message"));
    };

    // Attempt delivery
    deliver_to_remote(base, envelope_from.as_deref(), &rcpt, body_bytes).await
}

async fn read_response<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> anyhow::Result<(u16, String)> {
    let mut full = String::new();
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 { return Err(anyhow::anyhow!("connection closed by peer")); }
        full.push_str(&line);
        // Look for end of multiline reply ("<code><space>")
        if line.len() >= 4 {
            if let Ok(code) = line[0..3].parse::<u16>() {
                if line.as_bytes()[3] == b' ' {
                    return Ok((code, full));
                }
            }
        }
    }
}

async fn smtp_send_with_reader(reader: &mut BufReader<Box<dyn AsyncStream>>, envelope_from: Option<&str>, recipient: &str, body: &[u8]) -> anyhow::Result<()> {
    // MAIL FROM
    let mfrom = envelope_from.unwrap_or("<>");
    let mailcmd = format!("MAIL FROM:<{}>\r\n", mfrom);
    reader.get_mut().write_all(mailcmd.as_bytes()).await?;
    reader.get_mut().flush().await?;
    let (code, _resp) = read_response(&mut *reader).await?;
    if code >= 400 { return Err(anyhow::anyhow!("MAIL FROM rejected: {}", code)); }

    // RCPT TO
    let rcptcmd = format!("RCPT TO:<{}>\r\n", recipient);
    reader.get_mut().write_all(rcptcmd.as_bytes()).await?;
    reader.get_mut().flush().await?;
    let (code, _resp) = read_response(&mut *reader).await?;
    if code >= 400 { return Err(anyhow::anyhow!("RCPT TO rejected: {}", code)); }

    // DATA
    reader.get_mut().write_all(b"DATA\r\n").await?;
    reader.get_mut().flush().await?;
    let (code, _resp) = read_response(&mut *reader).await?;
    if code != 354 { return Err(anyhow::anyhow!("DATA not accepted: {}", code)); }

    // Prepare body with dot-stuffing. Use lossily-decoded string to keep implementation simple.
    let body_str = String::from_utf8_lossy(body);
    let mut stuffed = body_str.replace("\r\n.", "\r\n..");
    if stuffed.starts_with('.') { stuffed.insert(0, '.'); }
    if !stuffed.ends_with("\r\n") { stuffed.push_str("\r\n"); }

    reader.get_mut().write_all(stuffed.as_bytes()).await?;
    reader.get_mut().write_all(b".\r\n").await?;
    reader.get_mut().flush().await?;

    let (code, _resp) = read_response(&mut *reader).await?;
    if code >= 400 { return Err(anyhow::anyhow!("DATA not accepted after sending body: {}", code)); }

    // QUIT
    reader.get_mut().write_all(b"QUIT\r\n").await?;
    reader.get_mut().flush().await?;
    let _ = read_response(&mut *reader).await;

    Ok(())
}

async fn deliver_to_remote(base: &Path, envelope_from: Option<&str>, recipient: &str, body: &[u8]) -> anyhow::Result<()> {
    let at = recipient.rfind('@').ok_or_else(|| anyhow::anyhow!("invalid recipient address"))?;
    let domain = &recipient[at+1..];

    // Resolve MX records using system DNS configuration. If RMAIL_REQUIRE_DNSSEC=1, enable DNSSEC validation in resolver options.
    let require_dnssec_on_init = std::env::var("RMAIL_REQUIRE_DNSSEC").map(|v| {
        let v = v.to_ascii_lowercase();
        !(v == "0" || v == "false")
    }).unwrap_or(false);
    let (conf, mut opts) = trust_dns_resolver::system_conf::read_system_conf().context("reading system dns config")?;
    if require_dnssec_on_init {
        opts.validate = true;
    }
    let resolver = TokioAsyncResolver::tokio(conf, opts).context("creating dns resolver")?;
    // transport may indicate implicit TLS (smtps) or explicit SMTP. Track optional port.
    let mut targets: Vec<(String, Option<u16>)> = Vec::new();
    match rmail_common::transport::lookup_transport(base, domain) {
        Ok(rmail_common::transport::Transport::Smtp(Some(h))) => { targets.push((h, None)); }
        Ok(rmail_common::transport::Transport::Smtp(None)) => { /* fallthrough to MX lookup */ }
        Ok(rmail_common::transport::Transport::Smtps(Some(h))) => { targets.push((h, Some(465))); }
        Ok(rmail_common::transport::Transport::Smtps(None)) => { /* fallthrough to MX lookup */ }
        Ok(rmail_common::transport::Transport::Error(msg)) => { return Err(anyhow::anyhow!(format!("transport map error for {}: {}", domain, msg))); }
        Err(e) => { eprintln!("transport map lookup failed for {}: {}", domain, e); }
    }

    // If transport map didn't provide a next-hop, perform MX lookup.
    if targets.is_empty() {
        if let Ok(mx) = resolver.mx_lookup(domain).await {
            let mut mxs: Vec<(u16, String)> = mx.iter().map(|r| (r.preference(), r.exchange().to_utf8())).collect();
            mxs.sort_by_key(|(p, _)| *p);
            for (_pref, host) in mxs {
                targets.push((host.trim_end_matches('.').to_string(), None));
            }
        }
    }

    if targets.is_empty() { targets.push((domain.to_string(), None)); }

    // Try targets in order (connect to specified port if provided)
    let mut stream_opt: Option<TcpStream> = None;
    let mut selected_host = String::new();
    let mut selected_port: u16 = 25;
    for (host, port_opt) in &targets {
        let port = port_opt.unwrap_or(25);
        let addr = format!("{}:{}", host, port);
        match tokio::time::timeout(Duration::from_secs(30), TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => {
                stream_opt = Some(s);
                selected_host = host.clone();
                selected_port = port;
                break;
            }
            _ => continue,
        }
    }
    let stream = stream_opt.ok_or_else(|| anyhow::anyhow!("failed to connect to any MX/A host"))?;

    // Create boxed stream: implicit TLS on port 465, otherwise plain stream
    let boxed_stream: Box<dyn AsyncStream> = if selected_port == 465 {
        let native = NativeTlsConnector::builder().build().context("building native tls connector")?;
        let connector = TokioTlsConnector::from(native);
        let server_name = selected_host.trim_end_matches('.');
        let tls_stream = connector.connect(server_name, stream).await.context("TLS connect failed (implicit)")?;
        Box::new(tls_stream)
    } else {
        Box::new(stream)
    };

    let mut reader = BufReader::new(boxed_stream);

    // Read banner
    let (code, _banner) = read_response(&mut reader).await?;
    if code >= 400 { return Err(anyhow::anyhow!("remote server error on connect: {}", code)); }

    // EHLO
    let helo = format!("EHLO rmail\r\n");
    reader.get_mut().write_all(helo.as_bytes()).await?;
    reader.get_mut().flush().await?;
    let (code, ehlo_resp) = read_response(&mut reader).await?;
    if code >= 400 {
        // Try HELO if EHLO failed
        let helo = format!("HELO rmail\r\n");
        reader.get_mut().write_all(helo.as_bytes()).await?;
        reader.get_mut().flush().await?;
        let (code2, _helor) = read_response(&mut reader).await?;
        if code2 >= 400 { return Err(anyhow::anyhow!("HELO failed: {}", code2)); }
    }

    // If we did not use implicit TLS and server supports STARTTLS, upgrade
    if selected_port != 465 && ehlo_resp.to_uppercase().contains("STARTTLS") {
        reader.get_mut().write_all(b"STARTTLS\r\n").await?;
        reader.get_mut().flush().await?;
        let (code, _resp) = read_response(&mut reader).await?;
        if code != 220 { return Err(anyhow::anyhow!("STARTTLS rejected: {}", code)); }

        let inner = reader.into_inner();
        let native = NativeTlsConnector::builder().build().context("building native tls connector")?;
        let connector = TokioTlsConnector::from(native);
        let server_name = selected_host.trim_end_matches('.');
        let tls_stream = connector.connect(server_name, inner).await.context("TLS connect failed")?;
        let boxed_tls: Box<dyn AsyncStream> = Box::new(tls_stream);
        reader = BufReader::new(boxed_tls);

        // EHLO again over TLS
        let helo = format!("EHLO rmail\r\n");
        reader.get_mut().write_all(helo.as_bytes()).await?;
        reader.get_mut().flush().await?;
        let (code, _ehlo2) = read_response(&mut reader).await?;
        if code >= 400 {
            let helo = format!("HELO rmail\r\n");
            reader.get_mut().write_all(helo.as_bytes()).await?;
            reader.get_mut().flush().await?;
            let (code2, _helor) = read_response(&mut reader).await?;
            if code2 >= 400 { return Err(anyhow::anyhow!("HELO failed after STARTTLS: {}", code2)); }
        }
    }

    // Send the mail over the established reader (plain or TLS)
    smtp_send_with_reader(&mut reader, envelope_from, recipient, body).await?;

    Ok(())
}
