use anyhow::Context;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

// Simple outbound delivery worker: scans <mail_root>/outbound/queue, moves files to inflight,
// parses envelope metadata (X-RMail-Envelope-From/To) and performs a minimal SMTP conversation
// to the recipient domain. Failures are moved to failed/ for manual inspection / retry.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mail_root = std::env::var("RMAIL_MAIL_ROOT").unwrap_or_else(|_| "./mail".to_string());
    let base = PathBuf::from(mail_root);
    let queue_dir = base.join("outbound").join("queue");
    let inflight_dir = base.join("outbound").join("inflight");
    let sent_dir = base.join("outbound").join("sent");
    let failed_dir = base.join("outbound").join("failed");

    tokio::fs::create_dir_all(&queue_dir).await?;
    tokio::fs::create_dir_all(&inflight_dir).await?;
    tokio::fs::create_dir_all(&sent_dir).await?;
    tokio::fs::create_dir_all(&failed_dir).await?;

    loop {
        // Read queue directory
        let mut entries = tokio::fs::read_dir(&queue_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let p = entry.path();
            if !p.is_file() { continue; }
            let fname = p.file_name().and_then(|n| n.to_str()).unwrap_or("unknown").to_string();
            let inflight = inflight_dir.join(&fname);
            // Atomically move into inflight to claim work
            match tokio::fs::rename(&p, &inflight).await {
                Ok(_) => {}
                Err(e) => { eprintln!("rename to inflight failed {}: {}", fname, e); continue; }
            }

            // Process the file
            let res = process_file(&inflight).await;
            if res.is_ok() {
                let sentp = sent_dir.join(&fname);
                if let Err(e) = tokio::fs::rename(&inflight, &sentp).await {
                    eprintln!("failed to move to sent {}: {}", fname, e);
                }
            } else {
                eprintln!("delivery failed for {}: {:?}", fname, res.err());
                let failedp = failed_dir.join(&fname);
                if let Err(e) = tokio::fs::rename(&inflight, &failedp).await {
                    eprintln!("failed to move to failed {}: {}", fname, e);
                }
            }
        }

        // Sleep between polls
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn process_file(path: &Path) -> anyhow::Result<()> {
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
    deliver_to_remote(envelope_from.as_deref(), &rcpt, body_bytes).await
}

async fn read_response(reader: &mut BufReader<TcpStream>) -> anyhow::Result<(u16, String)> {
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

async fn deliver_to_remote(envelope_from: Option<&str>, recipient: &str, body: &[u8]) -> anyhow::Result<()> {
    let at = recipient.rfind('@').ok_or_else(|| anyhow::anyhow!("invalid recipient address"))?;
    let domain = &recipient[at+1..];
    let addr = format!("{}:25", domain);

    // Connect with timeout
    let stream = match tokio::time::timeout(Duration::from_secs(30), TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(anyhow::anyhow!("connect error: {}", e)),
        Err(_) => return Err(anyhow::anyhow!("connect timeout")),
    };

    let mut reader = BufReader::new(stream);

    // Read banner
    let (code, _banner) = read_response(&mut reader).await?;
    if code >= 400 { return Err(anyhow::anyhow!("remote server error on connect: {}", code)); }

    let helo = format!("EHLO rmail\r\n");
    reader.get_mut().write_all(helo.as_bytes()).await?;
    reader.get_mut().flush().await?;
    let (code, _ehlo) = read_response(&mut reader).await?;
    if code >= 400 {
        // Try HELO if EHLO failed
        let helo = format!("HELO rmail\r\n");
        reader.get_mut().write_all(helo.as_bytes()).await?;
        reader.get_mut().flush().await?;
        let (code2, _helor) = read_response(&mut reader).await?;
        if code2 >= 400 { return Err(anyhow::anyhow!("HELO failed: {}", code2)); }
    }

    // MAIL FROM
    let mfrom = envelope_from.unwrap_or("<>");
    let mailcmd = format!("MAIL FROM:<{}>\r\n", mfrom);
    reader.get_mut().write_all(mailcmd.as_bytes()).await?;
    reader.get_mut().flush().await?;
    let (code, _resp) = read_response(&mut reader).await?;
    if code >= 400 { return Err(anyhow::anyhow!("MAIL FROM rejected: {}", code)); }

    // RCPT TO
    let rcptcmd = format!("RCPT TO:<{}>\r\n", recipient);
    reader.get_mut().write_all(rcptcmd.as_bytes()).await?;
    reader.get_mut().flush().await?;
    let (code, _resp) = read_response(&mut reader).await?;
    if code >= 400 { return Err(anyhow::anyhow!("RCPT TO rejected: {}", code)); }

    // DATA
    reader.get_mut().write_all(b"DATA\r\n").await?;
    reader.get_mut().flush().await?;
    let (code, _resp) = read_response(&mut reader).await?;
    if code != 354 { return Err(anyhow::anyhow!("DATA not accepted: {}", code)); }

    // Prepare body with dot-stuffing. Use lossily-decoded string to keep implementation simple.
    let body_str = String::from_utf8_lossy(body);
    let mut stuffed = body_str.replace("\r\n.", "\r\n..");
    if stuffed.starts_with('.') { stuffed.insert(0, '.'); }
    if !stuffed.ends_with("\r\n") { stuffed.push_str("\r\n"); }

    reader.get_mut().write_all(stuffed.as_bytes()).await?;
    reader.get_mut().write_all(b".\r\n").await?;
    reader.get_mut().flush().await?;

    let (code, _resp) = read_response(&mut reader).await?;
    if code >= 400 { return Err(anyhow::anyhow!("DATA not accepted after sending body: {}", code)); }

    // QUIT
    reader.get_mut().write_all(b"QUIT\r\n").await?;
    reader.get_mut().flush().await?;
    let _ = read_response(&mut reader).await;

    Ok(())
}
