use anyhow::Result;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;

// Synchronous OpenSSL-backed delivery used when DANE/TLSA (usage 2/3) indicates we should trust the TLS
// even if PKIX verification would fail. This function performs a blocking TLS handshake (verify NONE)
// and runs the SMTP conversation synchronously on the TLS socket.

#[allow(dead_code)]
pub fn deliver_blocking(
    host: &str,
    port: u16,
    envelope_from: Option<&str>,
    recipient: &str,
    body: &[u8],
) -> Result<()> {
    let addr = format!("{}:{}", host, port);
    let tcp = TcpStream::connect(&addr)?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    tcp.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;

    let mut b = SslConnector::builder(SslMethod::tls())?;
    b.set_verify(SslVerifyMode::NONE);
    let conn = b.build();
    let ssl_stream = conn.connect(host, tcp)?;

    let mut reader = BufReader::new(ssl_stream);

    fn read_response_blocking<R: BufRead>(r: &mut R) -> Result<(u16, String)> {
        let mut full = String::new();
        loop {
            let mut line = String::new();
            let n = r.read_line(&mut line)?;
            if n == 0 {
                return Err(anyhow::anyhow!("connection closed by peer"));
            }
            full.push_str(&line);
            if line.len() >= 4
                && let Ok(code) = line[0..3].parse::<u16>()
                && line.as_bytes()[3] == b' '
            {
                return Ok((code, full));
            }
        }
    }

    // Read banner
    let (code, _banner) = read_response_blocking(&mut reader)?;
    if code >= 400 {
        return Err(anyhow::anyhow!("remote server error on connect: {}", code));
    }

    // EHLO
    reader.get_mut().write_all(b"EHLO rmail\r\n")?;
    reader.get_mut().flush()?;
    let (code, _resp) = read_response_blocking(&mut reader)?;
    if code >= 400 {
        reader.get_mut().write_all(b"HELO rmail\r\n")?;
        reader.get_mut().flush()?;
        let (code2, _r2) = read_response_blocking(&mut reader)?;
        if code2 >= 400 {
            return Err(anyhow::anyhow!("HELO failed: {}", code2));
        }
    }

    // MAIL FROM
    let mfrom = envelope_from.unwrap_or("<>");
    reader
        .get_mut()
        .write_all(format!("MAIL FROM:<{}>\r\n", mfrom).as_bytes())?;
    reader.get_mut().flush()?;
    let (code, _resp) = read_response_blocking(&mut reader)?;
    if code >= 400 {
        return Err(anyhow::anyhow!("MAIL FROM rejected: {}", code));
    }

    // RCPT TO
    reader
        .get_mut()
        .write_all(format!("RCPT TO:<{}>\r\n", recipient).as_bytes())?;
    reader.get_mut().flush()?;
    let (code, _resp) = read_response_blocking(&mut reader)?;
    if code >= 400 {
        return Err(anyhow::anyhow!("RCPT TO rejected: {}", code));
    }

    // DATA
    reader.get_mut().write_all(b"DATA\r\n")?;
    reader.get_mut().flush()?;
    let (code, _resp) = read_response_blocking(&mut reader)?;
    if code != 354 {
        return Err(anyhow::anyhow!("DATA not accepted: {}", code));
    }

    // dot-stuff body
    let body_str = String::from_utf8_lossy(body);
    let mut stuffed = body_str.replace("\r\n.", "\r\n..");
    if stuffed.starts_with('.') {
        stuffed.insert(0, '.');
    }
    if !stuffed.ends_with("\r\n") {
        stuffed.push_str("\r\n");
    }

    reader.get_mut().write_all(stuffed.as_bytes())?;
    reader.get_mut().write_all(b".\r\n")?;
    reader.get_mut().flush()?;

    let (code, _resp) = read_response_blocking(&mut reader)?;
    if code >= 400 {
        return Err(anyhow::anyhow!(
            "DATA not accepted after sending body: {}",
            code
        ));
    }

    // QUIT
    reader.get_mut().write_all(b"QUIT\r\n")?;
    reader.get_mut().flush()?;
    let _ = read_response_blocking(&mut reader).ok();

    Ok(())
}
