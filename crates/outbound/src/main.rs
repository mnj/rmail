use anyhow::Context;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use trust_dns_resolver::TokioAsyncResolver;
use tokio_native_tls::TlsConnector as TokioTlsConnector;
use native_tls::TlsConnector as NativeTlsConnector;
use rmail_common::db;
mod tlsa;
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
    let queue_dir = base.join("outbound").join("queue");
    let inflight_dir = base.join("outbound").join("inflight");
    let sent_dir = base.join("outbound").join("sent");
    let failed_dir = base.join("outbound").join("failed");

    tokio::fs::create_dir_all(&queue_dir).await?;
    tokio::fs::create_dir_all(&inflight_dir).await?;
    tokio::fs::create_dir_all(&sent_dir).await?;
    tokio::fs::create_dir_all(&failed_dir).await?;

    println!("Using on-disk outbound queue: {}", queue_dir.display());
    loop {
        // Collect candidate .eml files with optional control JSON
        let mut candidates: Vec<(PathBuf, Option<PathBuf>, i64, i32, u32, u32, Option<i64>)> = Vec::new();
        let mut entries = tokio::fs::read_dir(&queue_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let p = entry.path();
            if !p.is_file() { continue; }
            // only consider .eml files
            if p.extension().and_then(|e| e.to_str()).unwrap_or("") != "eml" { continue; }
            let jsonp = p.with_extension("json");
            // read control if present
            let control = if tokio::fs::metadata(&jsonp).await.is_ok() {
                match tokio::fs::read_to_string(&jsonp).await {
                    Ok(s) => match serde_json::from_str::<rmail_common::outbound::QueueControl>(&s) {
                        Ok(c) => c,
                        Err(_) => rmail_common::outbound::QueueControl::default_with_timestamp(0),
                    },
                    Err(_) => rmail_common::outbound::QueueControl::default_with_timestamp(0),
                }
            } else {
                rmail_common::outbound::QueueControl::default_with_timestamp(0)
            };
            let created_at = if control.created_at != 0 { control.created_at } else {
                match tokio::fs::metadata(&p).await.and_then(|m| m.modified()) {
                    Ok(t) => t.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0),
                    Err(_) => 0,
                }
            };
            candidates.push((p, if tokio::fs::metadata(&jsonp).await.is_ok() { Some(jsonp) } else { None }, created_at, control.priority, control.attempts, control.max_attempts, control.next_try));
        }

        // filter and sort by priority desc, next_try asc, created_at asc
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() as i64;
        candidates.retain(|c| if let Some(nt) = c.6 { nt <= now } else { true });
        candidates.sort_by(|a, b| {
            let pa = a.3;
            let pb = b.3;
            pb.cmp(&pa)
                .then_with(|| a.6.unwrap_or(0).cmp(&b.6.unwrap_or(0)))
                .then_with(|| a.2.cmp(&b.2))
        });

        if candidates.is_empty() {
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }

        // Claim the first candidate
        let (eml_path, json_path_opt, _created_at, _priority, _attempts, _max_attempts, _next_try) = candidates.remove(0);
        let fname = eml_path.file_name().and_then(|n| n.to_str()).unwrap_or("unknown").to_string();
        let inflight_eml = inflight_dir.join(&fname);
        if let Err(e) = tokio::fs::rename(&eml_path, &inflight_eml).await {
            eprintln!("claim rename failed for {}: {}", fname, e);
            continue;
        }
        let inflight_json = inflight_eml.with_extension("json");
        if let Some(jp) = &json_path_opt {
            if let Err(e) = tokio::fs::rename(jp, &inflight_json).await {
                eprintln!("failed to move control json to inflight for {}: {}", fname, e);
            }
        } else {
            let control = rmail_common::outbound::QueueControl::new(5, 0);
            let _ = tokio::fs::write(&inflight_json, serde_json::to_string(&control)?).await;
        }

        // increment attempts in inflight control
        let mut control: rmail_common::outbound::QueueControl = match tokio::fs::read_to_string(&inflight_json).await {
            Ok(s) => serde_json::from_str(&s).unwrap_or_else(|_| rmail_common::outbound::QueueControl::default_with_timestamp(0)),
            Err(_) => rmail_common::outbound::QueueControl::default_with_timestamp(0),
        };
        control.attempts = control.attempts.saturating_add(1);
        tokio::fs::write(&inflight_json, serde_json::to_string(&control)?).await?;

        // Process
        let res = process_file(&inflight_eml).await;

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
                // exponential backoff
                let base: u64 = 60;
                let backoff = base.saturating_mul(2u64.pow((control.attempts.saturating_sub(1)) as u32));
                let next_try = now + backoff as i64;
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

async fn deliver_to_remote(envelope_from: Option<&str>, recipient: &str, body: &[u8]) -> anyhow::Result<()> {
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
    let mut targets: Vec<String> = Vec::new();
    if let Ok(mx) = resolver.mx_lookup(domain).await {
        let mut mxs: Vec<(u16, String)> = mx.iter().map(|r| (r.preference(), r.exchange().to_utf8())).collect();
        mxs.sort_by_key(|(p, _)| *p);
        for (_pref, host) in mxs {
            targets.push(host.trim_end_matches('.').to_string());
        }
    }
    if targets.is_empty() { targets.push(domain.to_string()); }

    // Try targets in order
    let mut stream_opt: Option<TcpStream> = None;
    let mut selected_host = String::new();
    for host in &targets {
        let addr = format!("{}:25", host);
        match tokio::time::timeout(Duration::from_secs(30), TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => {
                stream_opt = Some(s);
                selected_host = host.clone();
                break;
            }
            _ => continue,
        }
    }
    let stream = stream_opt.ok_or_else(|| anyhow::anyhow!("failed to connect to any MX/A host"))?;

    // Use a boxed trait object so we can swap in a TLS stream after STARTTLS
    let boxed: Box<dyn AsyncStream> = Box::new(stream);
    let mut reader = BufReader::new(boxed);

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

    // If remote advertises STARTTLS, attempt upgrade
    if ehlo_resp.to_uppercase().contains("STARTTLS") {
        reader.get_mut().write_all(b"STARTTLS\r\n").await?;
        reader.get_mut().flush().await?;
        let (code, _resp) = read_response(&mut reader).await?;
        if code != 220 { return Err(anyhow::anyhow!("STARTTLS rejected: {}", code)); }

        // perform optional DANE/TLSA verification if requested
        let enable_dane = std::env::var("RMAIL_ENABLE_DANE").map(|v| {
            let v = v.to_ascii_lowercase();
            !(v == "0" || v == "false")
        }).unwrap_or(false);

        if enable_dane {
            // Lookup TLSA records for _port._tcp.hostname
            let port: u16 = 25;
            let tlsa_name = format!("_{}._tcp.{}", port, selected_host);
            let mut tlsa_records: Vec<tlsa::TlsaRecord> = Vec::new();
            match resolver.lookup(tlsa_name.as_str(), RecordType::TLSA).await {
                Ok(lookup) => {
                    // iterate resource records and extract TLSA RData directly (DNSSEC validation is handled by resolver options if requested)
                    for record in lookup.record_iter() {
                        if let Some(rdata) = record.data() {
                            use trust_dns_resolver::proto::rr::RData;
                            match rdata {
                                RData::TLSA(t) => {
                                    // TLSA fields: usage, selector, matching, certificate (Vec<u8>)
                                    // trust-dns TLSA RData accessors return enums; convert to u8 for our TlsaRecord
                                    let usage: u8 = t.cert_usage().into();
                                    let selector: u8 = t.selector().into();
                                    let mtype: u8 = t.matching().into();
                                    let data = t.cert_data().to_vec();
                                    tlsa_records.push(tlsa::TlsaRecord { usage, selector, mtype, data });
                                }
                                _ => {}
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("TLSA lookup failed for {}: {}", tlsa_name, e);
                }
            }

            if !tlsa_records.is_empty() {
                // perform a blocking TLS handshake (no cert verification) to obtain peer cert/SPKI
                let host_clone = selected_host.clone();
                let addr = format!("{}:{}", host_clone, port);
                let res = tokio::task::spawn_blocking(move || -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
                    let tcp = std::net::TcpStream::connect(addr)?;
                    tcp.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
                    tcp.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;
                    let mut b = SslConnector::builder(SslMethod::tls())?;
                    b.set_verify(SslVerifyMode::NONE);
                    let conn = b.build();
                    let ssl_stream = conn.connect(host_clone.as_str(), tcp)?;
                    let cert = ssl_stream.ssl().peer_certificate().ok_or_else(|| anyhow::anyhow!("no peer certificate"))?;
                    let cert_der = cert.to_der()?;
                    let pubkey = cert.public_key()?;
                    let spki_der = pubkey.public_key_to_der()?;
                    Ok((cert_der, spki_der))
                }).await;

                let (cert_der, spki_der) = match res {
                    Ok(Ok(v)) => v,
                    Ok(Err(e)) => { eprintln!("DANE TLS handshake failed: {}", e); return Err(e); }
                    Err(e) => { return Err(anyhow::anyhow!("spawn_blocking join error: {:?}", e)); }
                };

                // match TLSA records using helper
                if !tlsa::match_tlsa_records(&tlsa_records, &cert_der, &spki_der) {
                    return Err(anyhow::anyhow!("DANE/TLSA verification failed for {}", selected_host));
                }
            }
        }

        // proceed with normal TLS handshake using system cert store
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
    } else {
        // No STARTTLS: optionally attempt implicit TLS on port 465 if configured
        let try_implicit = std::env::var("RMAIL_TRY_IMPLICIT_TLS").map(|v| {
            let v = v.to_ascii_lowercase();
            !(v == "0" || v == "false")
        }).unwrap_or(true);

        if try_implicit {
            // close the plain connection and attempt TLS on port 465
            let host = selected_host.clone();
            match tokio::time::timeout(Duration::from_secs(30), TcpStream::connect(format!("{}:465", host))).await {
                Ok(Ok(tcp)) => {
                    // perform optional DANE/TLSA verification for port 465
                    let enable_dane = std::env::var("RMAIL_ENABLE_DANE").map(|v| { let v = v.to_ascii_lowercase(); !(v == "0" || v == "false") }).unwrap_or(false);
                    if enable_dane {
                        let port: u16 = 465;
                        let tlsa_name = format!("_{}._tcp.{}", port, host);
                        let mut tlsa_records: Vec<tlsa::TlsaRecord> = Vec::new();
                        match resolver.lookup(tlsa_name.as_str(), RecordType::TLSA).await {
                            Ok(lookup) => {
                                // iterate resource records and extract TLSA RData directly (DNSSEC validation is handled by resolver options if requested)
                                for record in lookup.record_iter() {
                                    if let Some(rdata) = record.data() {
                                        use trust_dns_resolver::proto::rr::RData;
                                        match rdata {
                                            RData::TLSA(t) => {
                                                let usage: u8 = t.cert_usage().into();
                                                let selector: u8 = t.selector().into();
                                                let mtype: u8 = t.matching().into();
                                                let data = t.cert_data().to_vec();
                                                tlsa_records.push(tlsa::TlsaRecord { usage, selector, mtype, data });
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                            Err(e) => { eprintln!("TLSA lookup failed for {}: {}", tlsa_name, e); }
                        }

                        if !tlsa_records.is_empty() {
                            let host_clone = host.clone();
                            let addr = format!("{}:{}", host_clone, port);
                            let res = tokio::task::spawn_blocking(move || -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
                                let tcp = std::net::TcpStream::connect(addr)?;
                                tcp.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
                                tcp.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;
                                let mut b = SslConnector::builder(SslMethod::tls())?;
                                b.set_verify(SslVerifyMode::NONE);
                                let conn = b.build();
                                let ssl_stream = conn.connect(host_clone.as_str(), tcp)?;
                                let cert = ssl_stream.ssl().peer_certificate().ok_or_else(|| anyhow::anyhow!("no peer certificate"))?;
                                let cert_der = cert.to_der()?;
                                let pubkey = cert.public_key()?;
                                let spki_der = pubkey.public_key_to_der()?;
                                Ok((cert_der, spki_der))
                            }).await;

                            let (cert_der, spki_der) = match res {
                                Ok(Ok(v)) => v,
                                Ok(Err(e)) => { eprintln!("DANE TLS handshake failed: {}", e); return Err(e); }
                                Err(e) => { return Err(anyhow::anyhow!("spawn_blocking join error: {:?}", e)); }
                            };

                            if !tlsa::match_tlsa_records(&tlsa_records, &cert_der, &spki_der) {
                                return Err(anyhow::anyhow!("DANE/TLSA verification failed for {}", host));
                            }
                        }
                    }

                    // proceed with normal TLS handshake
                    let native = NativeTlsConnector::builder().build().context("building native tls connector")?;
                    let connector = TokioTlsConnector::from(native);
                    let server_name = host.trim_end_matches('.');
                    let tls_stream = connector.connect(server_name, tcp).await.context("TLS connect failed (implicit)")?;
                    let boxed_tls: Box<dyn AsyncStream> = Box::new(tls_stream);
                    reader = BufReader::new(boxed_tls);

                    // Read banner over TLS
                    let (code, _banner) = read_response(&mut reader).await?;
                    if code >= 400 { return Err(anyhow::anyhow!("remote server error on implicit TLS connect: {}", code)); }

                    // EHLO over TLS
                    let helo = format!("EHLO rmail\r\n");
                    reader.get_mut().write_all(helo.as_bytes()).await?;
                    reader.get_mut().flush().await?;
                    let (code, _ehlo2) = read_response(&mut reader).await?;
                    if code >= 400 { return Err(anyhow::anyhow!("HELO/EHLO failed after implicit TLS: {}", code)); }
                }
                _ => {
                    // implicit TLS not available; continue with plain connection
                }
            }
        }
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
