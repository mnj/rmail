use anyhow::Result;
use rmail_common::config::Config;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = match Config::from_file("config/example.toml") {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load config/example.toml: {}", e);
            return Err(e);
        }
    };

    let imap_port = cfg.global.imap_port.unwrap_or(2143);
    let listen_addr = format!("127.0.0.1:{}", imap_port);
    let listener = TcpListener::bind(&listen_addr).await?;
    println!("rMail IMAPD listening on {}", listen_addr);

    loop {
        let (stream, _peer) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream).await {
                eprintln!("IMAP client error: {}", e);
            }
        });
    }
}

async fn handle_client(mut stream: tokio::net::TcpStream) -> Result<()> {
    stream.write_all(b"* OK rMail IMAPD ready\r\n").await?;
    let _ = stream.shutdown().await;
    Ok(())
}
