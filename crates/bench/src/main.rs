use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use serde::Serialize;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::rustls::client::{ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::{
    Certificate, ClientConfig, Error as TlsError, RootCertStore, ServerName,
};

#[derive(Parser)]
#[command(about = "Live-daemon performance workloads for rMail")]
struct Cli {
    #[command(subcommand)]
    command: Command,
    /// Emit one JSON result object instead of human-readable text.
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Measure authenticated IMAP SEARCH and FETCH command latency.
    ImapCommands(ImapCommands),
    /// Measure notification fanout to concurrent IMAP IDLE sessions.
    ImapIdle(ImapIdle),
    /// Measure SMTP DATA or BDAT throughput and recipient fanout.
    Smtp(Smtp),
    /// Observe an already-running outbound worker draining its queue.
    QueueDrain(QueueDrain),
}

#[derive(clap::Args, Clone)]
struct ImapConnection {
    #[arg(long, default_value = "127.0.0.1:993")]
    address: String,
    #[arg(long)]
    username: String,
    /// Environment variable containing the password.
    #[arg(long, default_value = "RMAIL_BENCH_PASSWORD")]
    password_env: String,
    /// Direct password input for controlled tests; prefer --password-env.
    #[arg(long, hide = true)]
    password: Option<String>,
    /// PEM CA certificate used to verify the IMAPS listener.
    #[arg(long)]
    ca_cert: Option<PathBuf>,
    /// PEM leaf certificate to match byte-for-byte for an isolated self-signed listener.
    #[arg(long, conflicts_with = "ca_cert")]
    pinned_cert: Option<PathBuf>,
    #[arg(long, default_value = "localhost")]
    server_name: String,
}

#[derive(clap::Args)]
struct ImapCommands {
    #[command(flatten)]
    connection: ImapConnection,
    #[arg(long, default_value = "INBOX")]
    mailbox: String,
    #[arg(long, default_value_t = 100)]
    iterations: u32,
    #[arg(long, default_value = "ALL")]
    search: String,
    #[arg(long, default_value = "1:* (FLAGS RFC822.SIZE)")]
    fetch: String,
}

#[derive(clap::Args)]
struct ImapIdle {
    #[command(flatten)]
    connection: ImapConnection,
    #[arg(long, default_value = "INBOX")]
    mailbox: String,
    #[arg(long, default_value_t = 100)]
    connections: usize,
    #[arg(long, default_value_t = 10)]
    rounds: u32,
    #[arg(long, default_value_t = 10)]
    timeout_seconds: u64,
}

#[derive(clap::Args)]
struct Smtp {
    #[arg(long, default_value = "127.0.0.1:25")]
    address: String,
    #[arg(long, default_value = "bench.example")]
    helo: String,
    #[arg(long, default_value = "sender@bench.example")]
    sender: String,
    /// Comma-separated recipients accepted by the benchmark server.
    #[arg(long, value_delimiter = ',', required = true)]
    recipients: Vec<String>,
    #[arg(long, default_value_t = 100)]
    iterations: u32,
    #[arg(long, default_value_t = 1024 * 1024)]
    payload_bytes: usize,
    /// Send each message as one BDAT LAST chunk instead of DATA.
    #[arg(long)]
    bdat: bool,
}

#[derive(clap::Args)]
struct QueueDrain {
    #[arg(long)]
    mail_root: PathBuf,
    #[arg(long, default_value_t = 300)]
    timeout_seconds: u64,
    #[arg(long, default_value_t = 100)]
    poll_millis: u64,
}

#[derive(Serialize)]
struct ResultRow {
    workload: &'static str,
    operations: u64,
    elapsed_seconds: f64,
    operations_per_second: f64,
    bytes: Option<u64>,
    bytes_per_second: Option<f64>,
    p50_milliseconds: Option<f64>,
    p95_milliseconds: Option<f64>,
    detail: String,
}

trait AsyncStream: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite + ?Sized> AsyncStream for T {}
type Stream = Box<dyn AsyncStream + Unpin + Send>;

struct TimedStream(Stream);

impl AsyncRead for TimedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(context, buffer)
    }
}

impl AsyncWrite for TimedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(context, bytes)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(context)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let row = match cli.command {
        Command::ImapCommands(args) => benchmark_imap_commands(args).await?,
        Command::ImapIdle(args) => benchmark_imap_idle(args).await?,
        Command::Smtp(args) => benchmark_smtp(args).await?,
        Command::QueueDrain(args) => benchmark_queue_drain(args).await?,
    };
    if cli.json {
        println!("{}", serde_json::to_string(&row)?);
    } else {
        println!(
            "{}: {} operations in {:.3}s ({:.2} ops/s){}{}\n{}",
            row.workload,
            row.operations,
            row.elapsed_seconds,
            row.operations_per_second,
            row.bytes_per_second
                .map(|rate| format!(", {:.2} MiB/s", rate / 1024.0 / 1024.0))
                .unwrap_or_default(),
            row.p95_milliseconds
                .map(|p95| format!(", p95 {:.3} ms", p95))
                .unwrap_or_default(),
            row.detail
        );
    }
    Ok(())
}

async fn imaps_connect(connection: &ImapConnection) -> Result<BufReader<TimedStream>> {
    let certificate_path = connection
        .ca_cert
        .as_ref()
        .or(connection.pinned_cert.as_ref())
        .context("either --ca-cert or --pinned-cert is required")?;
    let pem = tokio::fs::read(certificate_path)
        .await
        .with_context(|| format!("reading certificate {}", certificate_path.display()))?;
    let certificates =
        rustls_pemfile::certs(&mut Cursor::new(pem)).context("parsing CA certificate")?;
    if certificates.is_empty() {
        bail!("CA certificate file contains no certificates");
    }
    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(if connection.ca_cert.is_some() {
            let mut roots = RootCertStore::empty();
            let (added, _) = roots.add_parsable_certificates(&certificates);
            if added == 0 {
                bail!("CA certificate file contains no usable certificates");
            }
            roots
        } else {
            RootCertStore::empty()
        })
        .with_no_client_auth();
    if connection.pinned_cert.is_some() {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(PinnedCertificate(certificates[0].clone())));
    }
    let tcp = TcpStream::connect(&connection.address)
        .await
        .with_context(|| format!("connecting to {}", connection.address))?;
    tcp.set_nodelay(true)?;
    let name = ServerName::try_from(connection.server_name.as_str())
        .map_err(|_| anyhow!("invalid TLS server name"))?;
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .context("IMAPS TLS handshake")?;
    let mut reader = BufReader::new(TimedStream(Box::new(tls)));
    read_line_required(&mut reader).await?;
    read_line_required(&mut reader).await?;
    let password = connection
        .password
        .clone()
        .or_else(|| std::env::var(&connection.password_env).ok())
        .with_context(|| {
            format!(
                "IMAP password is not set; export {} or use --password-env",
                connection.password_env
            )
        })?;
    let login = format!(
        "B000 LOGIN {} {}\r\n",
        imap_quote(&connection.username),
        imap_quote(&password)
    );
    reader.get_mut().write_all(login.as_bytes()).await?;
    reader.get_mut().flush().await?;
    read_imap_tag(&mut reader, "B000").await?;
    Ok(reader)
}

struct PinnedCertificate(Vec<u8>);

impl ServerCertVerifier for PinnedCertificate {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        if end_entity.0 == self.0 {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General(
                "IMAPS peer certificate does not match --pinned-cert".to_string(),
            ))
        }
    }
}

async fn benchmark_imap_commands(args: ImapCommands) -> Result<ResultRow> {
    let mut reader = imaps_connect(&args.connection).await?;
    imap_command(
        &mut reader,
        "B001",
        &format!("SELECT {}", imap_quote(&args.mailbox)),
    )
    .await?;
    let mut latencies = Vec::with_capacity(args.iterations as usize * 2);
    let started = Instant::now();
    for iteration in 0..args.iterations {
        let search_tag = format!("S{iteration:08}");
        let began = Instant::now();
        imap_command(
            &mut reader,
            &search_tag,
            &format!("UID SEARCH {}", args.search),
        )
        .await?;
        latencies.push(began.elapsed());
        let fetch_tag = format!("F{iteration:08}");
        let began = Instant::now();
        imap_command(
            &mut reader,
            &fetch_tag,
            &format!("UID FETCH {}", args.fetch),
        )
        .await?;
        latencies.push(began.elapsed());
    }
    let elapsed = started.elapsed();
    let (p50, p95) = percentiles(&mut latencies);
    Ok(result(
        "imap-commands",
        u64::from(args.iterations) * 2,
        elapsed,
        None,
        Some(p50),
        Some(p95),
        format!(
            "mailbox={} search={:?} fetch={:?}",
            args.mailbox, args.search, args.fetch
        ),
    ))
}

async fn benchmark_imap_idle(args: ImapIdle) -> Result<ResultRow> {
    if args.connections == 0 || args.rounds == 0 {
        bail!("connections and rounds must be greater than zero");
    }
    let mut sessions = Vec::with_capacity(args.connections);
    for index in 0..args.connections {
        let mut session = imaps_connect(&args.connection).await?;
        imap_command(
            &mut session,
            &format!("S{index:08}"),
            &format!("SELECT {}", imap_quote(&args.mailbox)),
        )
        .await?;
        let tag = format!("I{index:08}");
        session
            .get_mut()
            .write_all(format!("{tag} IDLE\r\n").as_bytes())
            .await?;
        session.get_mut().flush().await?;
        read_until_contains(&mut session, "+ idling").await?;
        sessions.push((session, tag));
    }
    let mut producer = imaps_connect(&args.connection).await?;
    let timeout = Duration::from_secs(args.timeout_seconds);
    let mut latencies = Vec::with_capacity(args.rounds as usize);
    let started = Instant::now();
    for round in 0..args.rounds {
        let body = format!("Subject: benchmark round {round}\r\n\r\n{round}\r\n");
        let tag = format!("A{round:08}");
        let command = format!(
            "{tag} APPEND {} {{{}+}}\r\n{}",
            imap_quote(&args.mailbox),
            body.len(),
            body
        );
        let began = Instant::now();
        producer.get_mut().write_all(command.as_bytes()).await?;
        producer.get_mut().flush().await?;
        read_imap_tag(&mut producer, &tag).await?;
        for (session, _) in &mut sessions {
            tokio::time::timeout(timeout, read_until_contains(session, " EXISTS"))
                .await
                .context("waiting for IDLE EXISTS notification")??;
        }
        latencies.push(began.elapsed());
    }
    let elapsed = started.elapsed();
    for (mut session, tag) in sessions {
        session.get_mut().write_all(b"DONE\r\n").await?;
        session.get_mut().flush().await?;
        read_imap_tag(&mut session, &tag).await?;
    }
    let (p50, p95) = percentiles(&mut latencies);
    Ok(result(
        "imap-idle",
        u64::from(args.rounds) * args.connections as u64,
        elapsed,
        None,
        Some(p50),
        Some(p95),
        format!(
            "{} sessions, {} delivery rounds, fanout latency includes all notifications",
            args.connections, args.rounds
        ),
    ))
}

async fn benchmark_smtp(args: Smtp) -> Result<ResultRow> {
    if args.iterations == 0 || args.payload_bytes == 0 || args.recipients.is_empty() {
        bail!("iterations, payload bytes, and recipients must be non-zero");
    }
    let stream = TcpStream::connect(&args.address)
        .await
        .with_context(|| format!("connecting to {}", args.address))?;
    stream.set_nodelay(true)?;
    let mut reader = BufReader::new(stream);
    expect_smtp(&mut reader, 220).await?;
    smtp_write(&mut reader, &format!("EHLO {}\r\n", args.helo)).await?;
    let capabilities = read_smtp_reply(&mut reader, 250).await?;
    if args.bdat && !capabilities.iter().any(|line| line.contains("CHUNKING")) {
        bail!("server does not advertise CHUNKING");
    }
    let mut payload = format!(
        "From: <{}>\r\nTo: <{}>\r\nSubject: rMail benchmark\r\n\r\n",
        args.sender, args.recipients[0]
    )
    .into_bytes();
    payload.resize(args.payload_bytes.max(payload.len() + 2), b'x');
    payload.extend_from_slice(b"\r\n");
    let started = Instant::now();
    let mut latencies = Vec::with_capacity(args.iterations as usize);
    for _ in 0..args.iterations {
        let began = Instant::now();
        smtp_write(&mut reader, &format!("MAIL FROM:<{}>\r\n", args.sender)).await?;
        expect_smtp(&mut reader, 250).await?;
        for recipient in &args.recipients {
            smtp_write(&mut reader, &format!("RCPT TO:<{recipient}>\r\n")).await?;
            expect_smtp(&mut reader, 250).await?;
        }
        if args.bdat {
            smtp_write(&mut reader, &format!("BDAT {} LAST\r\n", payload.len())).await?;
            reader.get_mut().write_all(&payload).await?;
            reader.get_mut().flush().await?;
            expect_smtp(&mut reader, 250).await?;
        } else {
            smtp_write(&mut reader, "DATA\r\n").await?;
            expect_smtp(&mut reader, 354).await?;
            write_dot_stuffed(reader.get_mut(), &payload).await?;
            expect_smtp(&mut reader, 250).await?;
        }
        latencies.push(began.elapsed());
    }
    let elapsed = started.elapsed();
    smtp_write(&mut reader, "QUIT\r\n").await?;
    expect_smtp(&mut reader, 221).await?;
    let bytes = payload.len() as u64 * u64::from(args.iterations);
    let (p50, p95) = percentiles(&mut latencies);
    Ok(result(
        if args.bdat { "smtp-bdat" } else { "smtp-data" },
        u64::from(args.iterations),
        elapsed,
        Some(bytes),
        Some(p50),
        Some(p95),
        format!(
            "{} recipients/message, {} payload bytes/message",
            args.recipients.len(),
            payload.len()
        ),
    ))
}

async fn benchmark_queue_drain(args: QueueDrain) -> Result<ResultRow> {
    let directories = ["maildrop/queue", "maildrop/inflight"];
    let initial = count_eml(&args.mail_root, &directories).await?;
    if initial == 0 {
        bail!("queue and inflight directories contain no .eml files");
    }
    let started = Instant::now();
    let timeout = Duration::from_secs(args.timeout_seconds);
    loop {
        let remaining = count_eml(&args.mail_root, &directories).await?;
        if remaining == 0 {
            break;
        }
        if started.elapsed() >= timeout {
            bail!("queue drain timed out with {remaining} messages remaining");
        }
        tokio::time::sleep(Duration::from_millis(args.poll_millis.max(1))).await;
    }
    Ok(result(
        "queue-drain",
        initial,
        started.elapsed(),
        None,
        None,
        None,
        format!(
            "observed {} until queue and inflight were empty",
            args.mail_root.display()
        ),
    ))
}

async fn count_eml(mail_root: &Path, directories: &[&str]) -> Result<u64> {
    let mut count = 0u64;
    for relative in directories {
        let path = mail_root.join("outbound").join(relative);
        let mut entries = match tokio::fs::read_dir(&path).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
        };
        while let Some(entry) = entries.next_entry().await? {
            if entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "eml")
            {
                count += 1;
            }
        }
    }
    Ok(count)
}

async fn imap_command(
    reader: &mut BufReader<TimedStream>,
    tag: &str,
    command: &str,
) -> Result<Vec<String>> {
    reader
        .get_mut()
        .write_all(format!("{tag} {command}\r\n").as_bytes())
        .await?;
    reader.get_mut().flush().await?;
    read_imap_tag(reader, tag).await
}

async fn read_imap_tag(reader: &mut BufReader<TimedStream>, tag: &str) -> Result<Vec<String>> {
    let lines = read_until_contains(reader, &format!("{tag} ")).await?;
    let final_line = lines.last().context("missing tagged IMAP response")?;
    if !final_line.starts_with(&format!("{tag} OK")) {
        bail!("IMAP command failed: {}", final_line.trim_end());
    }
    Ok(lines)
}

async fn read_until_contains<R>(reader: &mut R, needle: &str) -> Result<Vec<String>>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    let mut lines = Vec::new();
    loop {
        let line = read_line_required(reader).await?;
        let done = line.contains(needle);
        lines.push(line);
        if done {
            return Ok(lines);
        }
    }
}

async fn read_line_required<R>(reader: &mut R) -> Result<String>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    let mut line = String::new();
    let read = reader.read_line(&mut line).await?;
    if read == 0 {
        bail!("peer disconnected");
    }
    Ok(line)
}

async fn smtp_write(reader: &mut BufReader<TcpStream>, command: &str) -> Result<()> {
    reader.get_mut().write_all(command.as_bytes()).await?;
    reader.get_mut().flush().await?;
    Ok(())
}

async fn expect_smtp(reader: &mut BufReader<TcpStream>, expected: u16) -> Result<Vec<String>> {
    read_smtp_reply(reader, expected).await
}

async fn read_smtp_reply(reader: &mut BufReader<TcpStream>, expected: u16) -> Result<Vec<String>> {
    let mut lines = Vec::new();
    loop {
        let line = read_line_required(reader).await?;
        let code = line
            .get(..3)
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or_else(|| anyhow!("malformed SMTP response: {:?}", line.trim_end()))?;
        if code != expected {
            bail!("expected SMTP {expected}, received {}", line.trim_end());
        }
        let complete = line.as_bytes().get(3) == Some(&b' ');
        lines.push(line);
        if complete {
            return Ok(lines);
        }
    }
}

async fn write_dot_stuffed(stream: &mut TcpStream, payload: &[u8]) -> Result<()> {
    let mut framed = Vec::with_capacity(payload.len() + payload.len() / 80 + 5);
    let mut at_line_start = true;
    for byte in payload {
        if at_line_start && *byte == b'.' {
            framed.push(b'.');
        }
        framed.push(*byte);
        at_line_start = *byte == b'\n';
    }
    if !payload.ends_with(b"\r\n") {
        framed.extend_from_slice(b"\r\n");
    }
    framed.extend_from_slice(b".\r\n");
    stream.write_all(&framed).await?;
    stream.flush().await?;
    Ok(())
}

fn imap_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn percentiles(values: &mut [Duration]) -> (Duration, Duration) {
    values.sort_unstable();
    let percentile = |numerator: usize| {
        let index = values
            .len()
            .saturating_mul(numerator)
            .div_ceil(100)
            .saturating_sub(1)
            .min(values.len().saturating_sub(1));
        values[index]
    };
    (percentile(50), percentile(95))
}

fn result(
    workload: &'static str,
    operations: u64,
    elapsed: Duration,
    bytes: Option<u64>,
    p50: Option<Duration>,
    p95: Option<Duration>,
    detail: String,
) -> ResultRow {
    let seconds = elapsed.as_secs_f64();
    ResultRow {
        workload,
        operations,
        elapsed_seconds: seconds,
        operations_per_second: operations as f64 / seconds,
        bytes,
        bytes_per_second: bytes.map(|bytes| bytes as f64 / seconds),
        p50_milliseconds: p50.map(|duration| duration.as_secs_f64() * 1000.0),
        p95_milliseconds: p95.map(|duration| duration.as_secs_f64() * 1000.0),
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    #[test]
    fn percentile_selection_is_stable_for_small_samples() {
        let mut values = [
            Duration::from_millis(5),
            Duration::from_millis(1),
            Duration::from_millis(3),
            Duration::from_millis(2),
            Duration::from_millis(4),
        ];
        assert_eq!(
            percentiles(&mut values),
            (Duration::from_millis(3), Duration::from_millis(5))
        );
    }

    #[test]
    fn imap_quoting_escapes_protocol_delimiters() {
        assert_eq!(imap_quote("a\\\"b"), "\"a\\\\\\\"b\"");
    }

    async fn fake_smtp_server(listener: TcpListener, expect_bdat: bool, expected_bytes: usize) {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        reader
            .get_mut()
            .write_all(b"220 bench ready\r\n")
            .await
            .unwrap();
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("EHLO "));
        reader
            .get_mut()
            .write_all(b"250-bench\r\n250-CHUNKING\r\n250 ENHANCEDSTATUSCODES\r\n")
            .await
            .unwrap();
        loop {
            line.clear();
            if reader.read_line(&mut line).await.unwrap() == 0 {
                break;
            }
            if line.starts_with("MAIL FROM:") || line.starts_with("RCPT TO:") {
                reader
                    .get_mut()
                    .write_all(b"250 2.0.0 ok\r\n")
                    .await
                    .unwrap();
            } else if line == "DATA\r\n" {
                assert!(!expect_bdat);
                reader
                    .get_mut()
                    .write_all(b"354 send data\r\n")
                    .await
                    .unwrap();
                let mut received = 0usize;
                loop {
                    line.clear();
                    reader.read_line(&mut line).await.unwrap();
                    if line == ".\r\n" {
                        break;
                    }
                    received += line.len();
                }
                assert!(received >= expected_bytes);
                reader
                    .get_mut()
                    .write_all(b"250 2.0.0 ok\r\n")
                    .await
                    .unwrap();
            } else if let Some(marker) = line.strip_prefix("BDAT ") {
                assert!(expect_bdat);
                let length = marker
                    .split_ascii_whitespace()
                    .next()
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                assert!(length >= expected_bytes);
                let mut payload = vec![0; length];
                reader.read_exact(&mut payload).await.unwrap();
                reader
                    .get_mut()
                    .write_all(b"250 2.0.0 ok\r\n")
                    .await
                    .unwrap();
            } else if line == "QUIT\r\n" {
                reader
                    .get_mut()
                    .write_all(b"221 2.0.0 bye\r\n")
                    .await
                    .unwrap();
                reader.get_mut().flush().await.unwrap();
                break;
            } else {
                panic!("unexpected SMTP command {line:?}");
            }
            reader.get_mut().flush().await.unwrap();
        }
    }

    #[tokio::test]
    async fn smtp_workloads_frame_data_and_bdat_transactions() {
        for bdat in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap().to_string();
            let server = tokio::spawn(fake_smtp_server(listener, bdat, 4096));
            let row = benchmark_smtp(Smtp {
                address,
                helo: "bench.example".to_string(),
                sender: "sender@bench.example".to_string(),
                recipients: vec!["user@example.test".to_string()],
                iterations: 1,
                payload_bytes: 4096,
                bdat,
            })
            .await
            .unwrap();
            assert_eq!(row.operations, 1);
            assert!(row.bytes.unwrap() >= 4096);
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn queue_drain_observes_queue_and_inflight_until_empty() {
        let temp = tempfile::tempdir().unwrap();
        let queue = temp.path().join("outbound/maildrop/queue");
        let inflight = temp.path().join("outbound/maildrop/inflight");
        tokio::fs::create_dir_all(&queue).await.unwrap();
        tokio::fs::create_dir_all(&inflight).await.unwrap();
        tokio::fs::write(queue.join("one.eml"), b"one")
            .await
            .unwrap();
        tokio::fs::write(inflight.join("two.eml"), b"two")
            .await
            .unwrap();
        let queue_copy = queue.clone();
        let inflight_copy = inflight.clone();
        let remover = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            tokio::fs::remove_file(queue_copy.join("one.eml"))
                .await
                .unwrap();
            tokio::fs::remove_file(inflight_copy.join("two.eml"))
                .await
                .unwrap();
        });
        let row = benchmark_queue_drain(QueueDrain {
            mail_root: temp.path().to_path_buf(),
            timeout_seconds: 1,
            poll_millis: 5,
        })
        .await
        .unwrap();
        assert_eq!(row.operations, 2);
        remover.await.unwrap();
    }
}
