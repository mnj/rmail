use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use rmail_common::{config::Config, maildir};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> Result<()> {
    // load config (example path)
    let cfg = match Config::from_file("config/example.toml") {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load config/example.toml: {}", e);
            return Err(e);
        }
    };

    let mut allowed: HashSet<String> = HashSet::new();
    if let Some(mboxes) = &cfg.mailboxes {
        for m in mboxes {
            allowed.insert(m.address.to_ascii_lowercase());
        }
    }
    let catchalls: HashMap<String, String> = cfg.catchalls.clone().unwrap_or_default();
    let mail_root = cfg.global.mail_root.clone();

    let listen_addr = "127.0.0.1:2525";
    let listener = TcpListener::bind(listen_addr).await?;
    println!("rMail SMTPD listening on {}", listen_addr);

    loop {
        let (stream, _peer) = listener.accept().await?;
        let allowed = allowed.clone();
        let catchalls = catchalls.clone();
        let mail_root = mail_root.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, allowed, catchalls, mail_root).await {
                eprintln!("client error: {}", e);
            }
        });
    }
}

async fn handle_client(
    stream: TcpStream,
    allowed: HashSet<String>,
    catchalls: HashMap<String, String>,
    mail_root: String,
) -> Result<()> {
    let peer = stream.peer_addr()?;
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r).lines();
    w.write_all(b"220 rMail SMTPD ready\r\n").await?;
    let mut rcpts: Vec<String> = Vec::new();
    while let Some(line) = reader.next_line().await? {
        let cmd = line.trim_end().to_string();
        let up = cmd.to_ascii_uppercase();
        if up.starts_with("HELO") || up.starts_with("EHLO") {
            w.write_all(b"250 Hello\r\n").await?;
        } else if up.starts_with("MAIL FROM:") {
            w.write_all(b"250 OK\r\n").await?;
        } else if up.starts_with("RCPT TO:") {
            let addr_raw = cmd[8..].trim();
            let addr = addr_raw.trim_matches(|c| c == '<' || c == '>' || c == ' ');
            let addr_l = addr.to_ascii_lowercase();
            if allowed.contains(&addr_l) {
                rcpts.push(addr.to_string());
                w.write_all(b"250 OK\r\n").await?;
            } else if let Some(at) = addr_l.find('@') {
                let domain = &addr_l[at + 1..];
                if let Some(target) = catchalls.get(domain) {
                    // redirect to the configured catchall target
                    rcpts.push(target.clone());
                    w.write_all(b"250 OK\r\n").await?;
                } else {
                    w.write_all(b"550 No such user\r\n").await?;
                }
            } else {
                w.write_all(b"550 Bad address\r\n").await?;
            }
        } else if up.starts_with("DATA") {
            if rcpts.is_empty() {
                w.write_all(b"554 No recipients\r\n").await?;
                continue;
            }
            w.write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n").await?;
            let mut data: Vec<u8> = Vec::new();
            while let Some(dline) = reader.next_line().await? {
                if dline == "." {
                    break;
                }
                data.extend_from_slice(dline.as_bytes());
                data.extend_from_slice(b"\r\n");
            }
            for rcpt in &rcpts {
                if let Some(at) = rcpt.find('@') {
                    let local = &rcpt[..at];
                    let domain = &rcpt[at + 1..];
                    let mr = PathBuf::from(&mail_root);
                    match maildir::deliver(&mr, domain, local, &data) {
                        Ok(path) => println!("Delivered to {} -> {:?}", rcpt, path),
                        Err(e) => eprintln!("deliver error for {}: {}", rcpt, e),
                    }
                }
            }
            rcpts.clear();
            w.write_all(b"250 OK\r\n").await?;
        } else if up.starts_with("QUIT") {
            w.write_all(b"221 Bye\r\n").await?;
            break;
        } else {
            w.write_all(b"502 Command not implemented\r\n").await?;
        }
    }
    println!("Connection from {} closed", peer);
    Ok(())
}
