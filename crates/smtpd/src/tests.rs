//! Session-level tests driving `process_stream` over in-memory streams.
use super::{
    ConnectionTrace, MAX_MESSAGE_BYTES, ReplyTraceState, ReplyTrackingStream, SmtpService,
    TRACKING_TEST_EVENTS, is_forwarded_recipient, parse_mail_from_arg, process_stream,
    received_header,
};
use crate::protocol;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use rmail_common::config::{ScannerFailureAction, SecurityConfig};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, duplex};
use tokio::net::UnixListener;

async fn read_until<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R, needle: &str) -> String {
    let mut output = String::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await.expect("read response");
        if line.is_empty() {
            return output;
        }
        output.push_str(&line);
        if line.contains(needle) {
            return output;
        }
    }
}

async fn oauth_introspection_server(
    body: &'static str,
) -> (String, tokio::task::JoinHandle<String>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut byte = [0_u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
        }
        let headers = String::from_utf8_lossy(&request);
        let length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then_some(value.trim())
            })
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let mut form = vec![0; length];
        stream.read_exact(&mut form).await.unwrap();
        stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(), body
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        String::from_utf8(form).unwrap()
    });
    (format!("http://{address}/introspect"), task)
}

#[tokio::test]
async fn reply_tracking_counts_wire_bytes_and_stops_below_starttls() {
    let (server, mut client) = duplex(4096);
    let trace = ConnectionTrace {
        id: "reply-tracking-test".into(),
        local_addr: Some("192.0.2.10:25".parse().unwrap()),
        state: Arc::new(ReplyTraceState::default()),
    };
    trace.set_message_id(Some("message-reply-test".into()));
    let mut tracked = ReplyTrackingStream::new(
        Box::new(server),
        trace.clone(),
        Some("192.0.2.20:40000".parse().unwrap()),
    );

    client.write_all(b"NOOP\r\n").await.unwrap();
    let mut command = [0_u8; 6];
    tracked.read_exact(&mut command).await.unwrap();
    tracked.write_all(b"250-first line\r\n250 ").await.unwrap();
    tracked.write_all(b"2.0.0 OK\r\n").await.unwrap();
    tracked.flush().await.unwrap();
    let mut replies = vec![0_u8; 30];
    client.read_exact(&mut replies).await.unwrap();

    assert_eq!(trace.state.bytes_in.load(Ordering::Relaxed), 6);
    assert_eq!(trace.state.bytes_out.load(Ordering::Relaxed), 30);
    {
        let events = TRACKING_TEST_EVENTS.lock().unwrap();
        let replies = events
            .iter()
            .filter(|event| event.connection_id == "reply-tracking-test")
            .collect::<Vec<_>>();
        assert_eq!(replies.len(), 2);
        assert!(replies.iter().all(|event| event.smtp_code == Some(250)));
        assert!(
            replies
                .iter()
                .all(|event| event.message_id.as_deref() == Some("message-reply-test"))
        );
        assert_eq!(replies.last().unwrap().bytes_in, 6);
        assert_eq!(replies.last().unwrap().bytes_out, 30);
    }

    tracked.disable();
    tracked
        .write_all(b"encrypted transport bytes")
        .await
        .unwrap();
    assert_eq!(trace.state.bytes_out.load(Ordering::Relaxed), 30);
}

fn scram_client_final(password: &str, client_first_bare: &str, server_first: &str) -> String {
    use hmac::Mac;
    use hmac::digest::KeyInit;
    use pbkdf2::pbkdf2;
    use sha2::{Digest, Sha256};

    type HmacSha256 = hmac::Hmac<Sha256>;
    let attribute = |name: &str| {
        server_first
            .split(',')
            .find_map(|part| part.strip_prefix(name))
            .expect("SCRAM attribute")
    };
    let salt = BASE64_ENGINE.decode(attribute("s=")).expect("salt");
    let iterations = attribute("i=").parse::<u32>().expect("iterations");
    let nonce = attribute("r=");
    let without_proof = format!("c=biws,r={nonce}");
    let auth_message = format!("{client_first_bare},{server_first},{without_proof}");
    let mut salted_password = [0u8; 32];
    pbkdf2::<HmacSha256>(password.as_bytes(), &salt, iterations, &mut salted_password)
        .expect("derive password");
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&salted_password).unwrap();
    mac.update(b"Client Key");
    let client_key = mac.finalize().into_bytes();
    let stored_key = Sha256::digest(client_key);
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&stored_key).unwrap();
    mac.update(auth_message.as_bytes());
    let signature = mac.finalize().into_bytes();
    let proof = client_key
        .iter()
        .zip(signature.iter())
        .map(|(left, right)| left ^ right)
        .collect::<Vec<_>>();
    format!("{without_proof},p={}", BASE64_ENGINE.encode(proof))
}

#[test]
fn forwarding_origin_is_scoped_to_the_current_smtp_transaction() {
    let recipients = HashMap::from([("remote@example.net".to_string(), 7_u64)]);
    assert!(is_forwarded_recipient(&recipients, "remote@example.net", 7));
    assert!(!is_forwarded_recipient(
        &recipients,
        "remote@example.net",
        8
    ));
    assert!(!is_forwarded_recipient(
        &recipients,
        "direct@example.net",
        7
    ));
}

fn setup_mailbox() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let td = tempfile::tempdir().expect("tempdir");
    let mail_root = td.path().join("mail");
    let db_path = td.path().join("config.db");
    rmail_common::db::init_db(&db_path).expect("init db");
    let scram =
        rmail_common::auth::create_scram_verifier("password", 4096).expect("SCRAM verifier");
    rmail_common::db::add_mailbox(
        &db_path,
        "user@example.test",
        Some("plain:password"),
        None,
        Some(&scram),
    )
    .expect("add mailbox");
    rmail_common::db::add_mailbox(
        &db_path,
        "postmaster@example.test",
        Some("plain:password"),
        None,
        None,
    )
    .expect("add postmaster mailbox");
    rmail_common::db::add_alias(
        &db_path,
        "team@example.test",
        &["user@example.test", "postmaster@example.test"],
    )
    .expect("add team alias");
    (td, mail_root, db_path)
}

async fn run_session(input: Vec<u8>, capacity: usize) -> (Vec<String>, tempfile::TempDir) {
    run_session_with_security(input, capacity, SecurityConfig::default()).await
}

async fn run_session_with_security(
    input: Vec<u8>,
    capacity: usize,
    security: SecurityConfig,
) -> (Vec<String>, tempfile::TempDir) {
    run_session_with_policy(input, capacity, security, false, SmtpService::Mta).await
}

async fn run_session_with_policy(
    input: Vec<u8>,
    capacity: usize,
    security: SecurityConfig,
    encrypted: bool,
    service: SmtpService,
) -> (Vec<String>, tempfile::TempDir) {
    let (td, mail_root, db_path) = setup_mailbox();
    run_prepared_session(
        input, capacity, security, encrypted, service, td, mail_root, db_path,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_prepared_session(
    input: Vec<u8>,
    capacity: usize,
    security: SecurityConfig,
    encrypted: bool,
    service: SmtpService,
    td: tempfile::TempDir,
    mail_root: std::path::PathBuf,
    db_path: std::path::PathBuf,
) -> (Vec<String>, tempfile::TempDir) {
    let (client, server) = duplex(capacity);
    let server_task = tokio::spawn(async move {
        process_stream(
            Box::new(server),
            mail_root.to_string_lossy().to_string(),
            None,
            Some(db_path.to_string_lossy().to_string()),
            None,
            encrypted,
            false,
            true,
            Arc::new(security),
            service,
            None,
        )
        .await
    });

    let mut reader = BufReader::new(client);
    let mut line = String::new();
    reader.read_line(&mut line).await.expect("greeting");
    assert!(line.starts_with("220 "));
    reader.get_mut().write_all(&input).await.expect("write");
    reader.get_mut().flush().await.expect("flush");

    let mut responses = Vec::new();
    loop {
        let mut resp = String::new();
        reader.read_line(&mut resp).await.expect("read response");
        if resp.is_empty() {
            break;
        }
        let is_bye = resp.starts_with("221 2.0.0 Bye");
        responses.push(resp);
        if is_bye {
            break;
        }
    }
    server_task.await.expect("join").expect("server");
    (responses, td)
}

#[tokio::test]
async fn submission_requires_tls_authentication_and_sender_ownership() {
    let (plaintext, _) = run_session_with_policy(
        b"EHLO localhost\r\nAUTH PLAIN =\r\nQUIT\r\n".to_vec(),
        4096,
        SecurityConfig::default(),
        false,
        SmtpService::Submission,
    )
    .await;
    assert!(
        plaintext
            .iter()
            .any(|line| line.starts_with("530 5.7.0 Must issue STARTTLS"))
    );

    let (encrypted, _) = run_session_with_policy(
            b"EHLO localhost\r\nMAIL FROM:<user@example.test>\r\nAUTH PLAIN AHVzZXJAZXhhbXBsZS50ZXN0AHBhc3N3b3Jk\r\nMAIL FROM:<other@example.test>\r\nMAIL FROM:<user@example.test>\r\nQUIT\r\n".to_vec(),
            8192,
            SecurityConfig::default(),
            true,
            SmtpService::Submission,
        )
        .await;
    assert!(
        encrypted
            .iter()
            .any(|line| line.starts_with("530 5.7.0 Authentication required"))
    );
    assert!(encrypted.iter().any(|line| line.starts_with("235 2.7.0")));
    assert!(
        encrypted
            .iter()
            .any(|line| line.starts_with("553 5.7.1 Sender address not owned"))
    );
    assert!(
        encrypted
            .iter()
            .any(|line| line.starts_with("250 2.1.0 Sender OK"))
    );
}

#[tokio::test]
async fn submission_xoauth2_authenticates_through_the_configured_authority() {
    let (introspection_url, introspection) =
        oauth_introspection_server(r#"{"active":true,"username":"user@example.test"}"#).await;
    let security = SecurityConfig {
        smtp_sasl_mechanisms: vec!["XOAUTH2".into()],
        oauth: Some(rmail_common::config::OAuthConfig {
            introspection_url,
            client_id: None,
            client_secret: None,
            required_scopes: Vec::new(),
            identity_claim: "username".into(),
            issuer: None,
            audience: None,
            timeout_ms: 2_000,
            allow_insecure_http: true,
        }),
        ..Default::default()
    };
    let response =
        BASE64_ENGINE.encode(b"user=user@example.test\x01auth=Bearer good-token\x01\x01");
    let (responses, _) = run_session_with_policy(
        format!("EHLO localhost\r\nAUTH XOAUTH2 {response}\r\nQUIT\r\n").into_bytes(),
        16 * 1024,
        security,
        true,
        SmtpService::Submission,
    )
    .await;
    assert!(responses.iter().any(|line| line.contains("AUTH XOAUTH2")));
    assert!(responses.iter().any(|line| line.starts_with("235 2.7.0")));
    assert_eq!(
        introspection.await.unwrap(),
        "token=good-token&token_type_hint=access_token"
    );
}

#[tokio::test]
async fn local_delivery_rejects_storage_quota_without_publishing_message() {
    let (td, mail_root, db_path) = setup_mailbox();
    rmail_common::db::set_mailbox_quota(&db_path, "user@example.test", Some(5)).expect("set quota");
    let server_mail_root = mail_root.clone();
    let (client, server) = duplex(16 * 1024);
    let server_task = tokio::spawn(async move {
        process_stream(
            Box::new(server),
            server_mail_root.to_string_lossy().to_string(),
            None,
            Some(db_path.to_string_lossy().to_string()),
            None,
            false,
            false,
            true,
            Arc::new(SecurityConfig::default()),
            SmtpService::Mta,
            None,
        )
        .await
    });
    let mut reader = BufReader::new(client);
    let mut greeting = String::new();
    reader.read_line(&mut greeting).await.expect("greeting");
    reader
            .get_mut()
            .write_all(
                b"EHLO sender.example\r\nMAIL FROM:<sender@sender.example>\r\nRCPT TO:<user@example.test>\r\nDATA\r\nSubject: too large\r\n\r\n123456\r\n.\r\nQUIT\r\n",
            )
            .await
            .expect("commands");
    reader.get_mut().flush().await.expect("flush");
    let responses = read_until(&mut reader, "221 2.0.0 Bye").await;
    assert!(responses.contains("452 4.2.2 Mailbox storage limit exceeded"));
    server_task.await.expect("join").expect("server");
    assert_eq!(
        rmail_common::imap_state::storage_quota(mail_root.as_path(), "example.test", "user")
            .expect("quota state"),
        (0, Some(5))
    );
    drop(td);
}

#[tokio::test]
async fn submission_option_enforces_visible_from_for_data_and_bdat() {
    let security = SecurityConfig {
        submission_require_from_alignment: true,
        ..SecurityConfig::default()
    };
    let auth = "AUTH PLAIN AHVzZXJAZXhhbXBsZS50ZXN0AHBhc3N3b3Jk\r\n";
    let transaction = "MAIL FROM:<user@example.test>\r\nRCPT TO:<user@example.test>\r\n";

    let data_input = format!(
        "EHLO localhost\r\n{auth}{transaction}DATA\r\nFrom: Other <other@example.test>\r\nSubject: forged\r\n\r\nbody\r\n.\r\n{transaction}DATA\r\nFrom: User <user@example.test>\r\nSubject: aligned\r\n\r\nbody\r\n.\r\nQUIT\r\n"
    );
    let (data_responses, _) = run_session_with_policy(
        data_input.into_bytes(),
        16 * 1024,
        security.clone(),
        true,
        SmtpService::Submission,
    )
    .await;
    assert!(data_responses.iter().any(|line| {
        line.starts_with("553 5.7.1 From address not owned by authenticated user")
    }));
    assert!(
        data_responses
            .iter()
            .any(|line| line.starts_with("250 2.0.0 Message accepted"))
    );

    let message = b"From: Other <other@example.test>\r\nSubject: forged\r\n\r\nbody\r\n";
    let mut bdat_input = format!(
        "EHLO localhost\r\n{auth}{transaction}BDAT {} LAST\r\n",
        message.len()
    )
    .into_bytes();
    bdat_input.extend_from_slice(message);
    bdat_input.extend_from_slice(b"QUIT\r\n");
    let (bdat_responses, _) = run_session_with_policy(
        bdat_input,
        16 * 1024,
        security,
        true,
        SmtpService::Submission,
    )
    .await;
    assert!(bdat_responses.iter().any(|line| {
        line.starts_with("553 5.7.1 From address not owned by authenticated user")
    }));
}

#[tokio::test]
async fn command_rate_limit_closes_abusive_sessions() {
    let security = SecurityConfig {
        smtp_max_commands_per_minute: 2,
        ..SecurityConfig::default()
    };
    let (responses, _) = run_session_with_security(
        b"EHLO localhost\r\nNOOP\r\nNOOP\r\n".to_vec(),
        4096,
        security,
    )
    .await;
    assert!(
        responses
            .iter()
            .any(|line| line.starts_with("421 4.7.0 Command rate limit"))
    );
}

#[test]
fn submission_message_quota_is_account_keyed() {
    let first = "quota-first@example.test";
    let second = "quota-second@example.test";
    assert!(super::submission_quota_available(first, 1));
    super::record_submission_message(first);
    assert!(!super::submission_quota_available(first, 1));
    assert!(super::submission_quota_available(second, 1));
}

#[test]
fn connection_rate_limit_is_source_keyed() {
    let first: std::net::IpAddr = "192.0.2.10".parse().unwrap();
    let second: std::net::IpAddr = "192.0.2.11".parse().unwrap();
    assert!(super::accept_connection_from(first, 1));
    assert!(!super::accept_connection_from(first, 1));
    assert!(super::accept_connection_from(second, 1));
}

async fn run_encrypted_session(input: Vec<u8>, capacity: usize) -> Vec<String> {
    let (_td, mail_root, db_path) = setup_mailbox();
    let (client, server) = duplex(capacity);
    let server_task = tokio::spawn(async move {
        process_stream(
            Box::new(server),
            mail_root.to_string_lossy().to_string(),
            None,
            Some(db_path.to_string_lossy().to_string()),
            None,
            true,
            false,
            true,
            Arc::new(SecurityConfig::default()),
            SmtpService::Mta,
            None,
        )
        .await
    });
    let mut reader = BufReader::new(client);
    let mut greeting = String::new();
    reader.read_line(&mut greeting).await.expect("greeting");
    reader.get_mut().write_all(&input).await.expect("commands");
    reader.get_mut().flush().await.expect("flush");
    let mut responses = Vec::new();
    loop {
        let mut response = String::new();
        reader.read_line(&mut response).await.expect("response");
        if response.is_empty() {
            break;
        }
        let finished = response.starts_with("221 ");
        responses.push(response);
        if finished {
            break;
        }
    }
    server_task.await.expect("join").expect("server");
    responses
}

async fn read_clamav_stream<S: AsyncReadExt + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut command = vec![0u8; b"zINSTREAM\0".len()];
    stream.read_exact(&mut command).await.expect("command");
    assert_eq!(command, b"zINSTREAM\0");
    let mut body = Vec::new();
    loop {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await.expect("chunk len");
        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 {
            break;
        }
        let start = body.len();
        body.resize(start + len, 0);
        stream.read_exact(&mut body[start..]).await.expect("chunk");
    }
    body
}

#[test]
fn parse_mail_from_accepts_null_sender() {
    assert_eq!(parse_mail_from_arg("MAIL FROM:<>"), Some(None));
}

#[test]
fn parse_mail_from_accepts_normal_address() {
    assert_eq!(
        parse_mail_from_arg("MAIL FROM:<User@Example.com>"),
        Some(Some("User@example.com".to_string()))
    );
}

#[test]
fn received_trace_identifies_smtp_transport_and_authentication_phase() {
    let smtp = String::from_utf8(received_header(
        None,
        Some("client"),
        SmtpService::Mta,
        false,
        false,
        false,
    ))
    .unwrap();
    assert!(smtp.contains(" with SMTP;"));
    let submission = String::from_utf8(received_header(
        None,
        Some("client"),
        SmtpService::Submission,
        true,
        true,
        true,
    ))
    .unwrap();
    assert!(submission.contains(" with ESMTPSA;"));
    assert!(!submission.contains(" id local"));
    let lmtp = String::from_utf8(received_header(
        None,
        Some("local-mta"),
        SmtpService::Lmtp,
        true,
        false,
        false,
    ))
    .unwrap();
    assert!(lmtp.contains(" with LMTP;"));
}

#[tokio::test]
async fn smtp_data_preserves_non_utf8_bytes() {
    let (responses, td) = run_session(
            b"EHLO localhost\r\nMAIL FROM:<> BODY=8BITMIME\r\nRCPT TO:<user@example.test>\r\nDATA\r\nSubject: hi\r\n\r\nbinary:\xff\r\n.\r\nQUIT\r\n".to_vec(),
            16 * 1024,
        )
        .await;
    assert!(responses.iter().any(|r| r.starts_with("250 ")));
    assert!(responses.iter().any(|r| r.starts_with("221 2.0.0 Bye")));

    let delivered_dir = td.path().join("mail/example.test/user/Maildir/new");
    let entries: Vec<_> = std::fs::read_dir(&delivered_dir)
        .expect("read maildir")
        .map(|e| e.expect("entry").path())
        .collect();
    assert_eq!(entries.len(), 1);
    let body = std::fs::read(&entries[0]).expect("read message");
    assert!(body.starts_with(b"Received: from localhost by rMail SMTPD with ESMTP;"));
    assert!(body.windows(8).any(|w| w == b"binary:\xff"));
    assert!(Path::new(&entries[0]).exists());
}

#[tokio::test]
async fn data_enforces_8bitmime_smtputf8_and_binarymime_declarations() {
    let (seven_bit, seven_bit_td) = run_session(
            b"EHLO localhost\r\nMAIL FROM:<>\r\nRCPT TO:<user@example.test>\r\nDATA\r\nSubject: hi\r\n\r\nbody:\xff\r\n.\r\nQUIT\r\n"
                .to_vec(),
            16 * 1024,
        )
        .await;
    assert!(
        seven_bit
            .iter()
            .any(|response| response.starts_with("554 5.6.3 8-bit content"))
    );
    assert!(
        !seven_bit_td
            .path()
            .join("mail/example.test/user/Maildir/new")
            .exists()
    );

    let (utf8_header, utf8_header_td) = run_session(
            b"EHLO localhost\r\nMAIL FROM:<> BODY=8BITMIME\r\nRCPT TO:<user@example.test>\r\nDATA\r\nSubject: h\xff\r\n\r\nbody\r\n.\r\nQUIT\r\n"
                .to_vec(),
            16 * 1024,
        )
        .await;
    assert!(
        utf8_header
            .iter()
            .any(|response| response.starts_with("554 5.6.7 UTF-8 headers"))
    );
    assert!(
        !utf8_header_td
            .path()
            .join("mail/example.test/user/Maildir/new")
            .exists()
    );

    let (binary, binary_td) = run_session(
            b"EHLO localhost\r\nMAIL FROM:<> BODY=8BITMIME SMTPUTF8\r\nRCPT TO:<user@example.test>\r\nDATA\r\nSubject: hi\r\n\r\nbin:\0\r\n.\r\nQUIT\r\n"
                .to_vec(),
            16 * 1024,
        )
        .await;
    assert!(
        binary
            .iter()
            .any(|response| response.starts_with("554 5.6.3 NUL requires BINARYMIME"))
    );
    assert!(
        !binary_td
            .path()
            .join("mail/example.test/user/Maildir/new")
            .exists()
    );

    let (accepted, accepted_td) = run_session(
            "EHLO localhost\r\nMAIL FROM:<> BODY=8BITMIME SMTPUTF8\r\nRCPT TO:<user@example.test>\r\nDATA\r\nSubject: héj\r\n\r\nbody: ø\r\n.\r\nQUIT\r\n"
                .as_bytes()
                .to_vec(),
            16 * 1024,
        )
        .await;
    assert!(accepted.iter().any(|response| response.starts_with("250 ")));
    assert_eq!(
        std::fs::read_dir(
            accepted_td
                .path()
                .join("mail/example.test/user/Maildir/new")
        )
        .expect("maildir")
        .count(),
        1
    );
}

#[tokio::test]
async fn bdat_accepts_multiple_binary_chunks_and_data_cannot_mix_with_them() {
    let first = b"Subject: binary\r\n\r\npart";
    let second = b"\0two\r\n";
    let mut commands = format!(
            "EHLO localhost\r\nMAIL FROM:<> BODY=BINARYMIME\r\nRCPT TO:<user@example.test>\r\nBDAT {}\r\n",
            first.len()
        )
        .into_bytes();
    commands.extend_from_slice(first);
    commands.extend_from_slice(format!("BDAT {} LAST\r\n", second.len()).as_bytes());
    commands.extend_from_slice(second);
    commands.extend_from_slice(b"QUIT\r\n");

    let (responses, td) = run_session(commands, 16 * 1024).await;
    assert!(
        responses
            .iter()
            .any(|response| response.contains("BDAT chunk received"))
    );
    assert!(
        responses
            .iter()
            .any(|response| response.contains("Message accepted"))
    );
    let delivered_dir = td.path().join("mail/example.test/user/Maildir/new");
    let path = std::fs::read_dir(delivered_dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let delivered = std::fs::read(path).unwrap();
    assert!(
        delivered
            .windows(first.len() + second.len())
            .any(|window| { window == [first.as_slice(), second.as_slice()].concat().as_slice() })
    );

    let (mixed, _) = run_session(
            b"EHLO localhost\r\nMAIL FROM:<>\r\nRCPT TO:<user@example.test>\r\nBDAT 0\r\nDATA\r\nRSET\r\nQUIT\r\n".to_vec(),
            16 * 1024,
        )
        .await;
    assert!(
        mixed
            .iter()
            .any(|response| response.contains("DATA not permitted after BDAT"))
    );
}

#[tokio::test]
async fn envelope_extensions_accept_dsn_and_classify_other_errors() {
    let (responses, _td) = run_session(
            b"HELO localhost\r\nMAIL FROM:<a@example.test> SIZE=1\r\nEHLO localhost\r\nMAIL FROM:<a@example.test> UNKNOWN=x\r\nMAIL FROM:<a..b@example.test>\r\nMAIL FROM:<a@example.test> ENVID=job+207 RET=FULL\r\nRCPT TO:<user@example.test> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;alias+40example.test\r\nRCPT TO:<user@example.test> UNKNOWN=x\r\nQUIT\r\n"
                .to_vec(),
            16 * 1024,
        )
        .await;
    assert!(
        responses
            .iter()
            .any(|response| response.starts_with("555 5.5.4 ESMTP parameters require EHLO"))
    );
    assert!(
        responses
            .iter()
            .any(|response| response.starts_with("555 5.5.4 Unsupported MAIL FROM parameter"))
    );
    assert!(
        responses
            .iter()
            .any(|response| response.starts_with("501 5.5.2 Syntax: MAIL FROM"))
    );
    assert!(
        responses
            .iter()
            .any(|response| response.starts_with("555 5.5.4 Unsupported RCPT TO parameter"))
    );
    assert!(responses.iter().any(|response| response == "250-DSN\r\n"));
    assert!(
        responses
            .iter()
            .filter(|response| response.starts_with("250 2.1."))
            .count()
            >= 2
    );
}

#[tokio::test]
async fn local_delivery_honors_requested_success_dsn_with_null_reverse_path() {
    let (responses, td) = run_session(
            b"EHLO localhost\r\nMAIL FROM:<sender@remote.test> ENVID=job+207 RET=HDRS\r\nRCPT TO:<user@example.test> NOTIFY=SUCCESS ORCPT=rfc822;alias+40example.test\r\nDATA\r\nSubject: delivered\r\n\r\nmessage\r\n.\r\nQUIT\r\n"
                .to_vec(),
            16 * 1024,
        )
        .await;
    assert!(
        responses
            .iter()
            .any(|response| response.starts_with("250 2.0.0 Message accepted"))
    );
    let queue = td.path().join("mail/outbound/maildrop/queue");
    let dsn_path = std::fs::read_dir(queue)
        .unwrap()
        .find_map(|entry| {
            let path = entry.ok()?.path();
            (path.extension().and_then(|ext| ext.to_str()) == Some("eml")).then_some(path)
        })
        .expect("success DSN queued");
    let dsn = std::fs::read_to_string(dsn_path).unwrap();
    assert!(dsn.starts_with("X-RMail-Envelope-To: sender@remote.test\r\n\r\n"));
    assert!(dsn.contains("Subject: Delivery Status Notification (Success)\r\n"));
    assert!(dsn.contains("Original-Envelope-Id: job 7\r\n"));
    assert!(dsn.contains("Original-Recipient: rfc822; alias@example.test\r\n"));
    assert!(dsn.contains("Action: delivered\r\nStatus: 2.0.0\r\n"));
}

#[tokio::test]
async fn bare_postmaster_forward_path_resolves_to_local_postmaster_mailbox() {
    let (responses, td) = run_session(
            b"EHLO localhost\r\nMAIL FROM:<>\r\nRCPT TO:<Postmaster>\r\nDATA\r\nSubject: postmaster\r\n\r\nmessage\r\n.\r\nQUIT\r\n"
                .to_vec(),
            16 * 1024,
        )
        .await;
    assert!(
        responses
            .iter()
            .any(|response| response.starts_with("250 "))
    );
    assert_eq!(
        std::fs::read_dir(td.path().join("mail/example.test/postmaster/Maildir/new"))
            .expect("postmaster maildir")
            .count(),
        1
    );
}

#[tokio::test]
async fn multi_target_alias_emits_one_rcpt_reply_and_delivers_atomically() {
    let (responses, td) = run_session(
            b"EHLO localhost\r\nMAIL FROM:<>\r\nRCPT TO:<team@example.test>\r\nDATA\r\nSubject: team\r\n\r\nmessage\r\n.\r\nQUIT\r\n"
                .to_vec(),
            16 * 1024,
        )
        .await;
    for expected in [
        "250 2.1.0 Sender OK",
        "250 2.1.5 Recipient OK",
        "250 2.0.0 Message accepted",
    ] {
        assert_eq!(
            responses
                .iter()
                .filter(|response| response.starts_with(expected))
                .count(),
            1,
            "{expected}"
        );
    }
    for localpart in ["user", "postmaster"] {
        assert_eq!(
            std::fs::read_dir(
                td.path()
                    .join(format!("mail/example.test/{localpart}/Maildir/new"))
            )
            .expect("alias target maildir")
            .count(),
            1
        );
    }
}

#[tokio::test]
async fn remote_alias_is_arc_sealed_before_queue_publication() {
    use std::os::unix::fs::PermissionsExt;

    let (td, mail_root, db_path) = setup_mailbox();
    rmail_common::db::add_alias(&db_path, "forward@example.test", &["recipient@example.net"])
        .unwrap();
    std::fs::create_dir_all(&mail_root).unwrap();
    let key = mail_root.join("arc.pem");
    std::fs::write(&key, include_str!("../testdata/arc-test-key.pem")).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(
            mail_root.join("dkim.toml"),
            format!(
                "[arc_signer]\ndomain = \"forwarder.example\"\nselector = \"arc1\"\nprivate_key = {:?}\nheaders = [\"From\", \"To\", \"Subject\"]\n",
                key.to_string_lossy()
            ),
        )
        .unwrap();

    let (responses, td) = run_prepared_session(
            b"EHLO localhost\r\nMAIL FROM:<>\r\nRCPT TO:<forward@example.test>\r\nDATA\r\nFrom: sender@localhost\r\nTo: forward@example.test\r\nSubject: forwarded\r\n\r\nmessage\r\n.\r\nQUIT\r\n"
                .to_vec(),
            32 * 1024,
            SecurityConfig::default(),
            false,
            SmtpService::Mta,
            td,
            mail_root,
            db_path,
        )
        .await;
    assert!(
        responses
            .iter()
            .any(|response| response.starts_with("250 2.0.0 Message accepted")),
        "{responses:?}"
    );
    let queue = td.path().join("mail/outbound/maildrop/queue");
    // The spool also holds a .eml.json control sidecar; directory order is unspecified.
    let queued = std::fs::read_dir(queue)
        .unwrap()
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .find(|path| path.extension().is_some_and(|ext| ext == "eml"))
        .expect("forwarded queue entry");
    let message = std::fs::read_to_string(queued).unwrap();
    assert_eq!(message.matches("ARC-Seal: i=1;").count(), 1, "{message}");
    assert_eq!(message.matches("ARC-Message-Signature: i=1;").count(), 1);
    assert_eq!(
        message.matches("ARC-Authentication-Results: i=1;").count(),
        1
    );
}

#[tokio::test]
async fn lmtp_requires_lhlo_and_reports_each_recipient_delivery() {
    let (td, mail_root, db_path) = setup_mailbox();
    rmail_common::db::add_alias(
        &db_path,
        "remote-alias@example.test",
        &["recipient@example.net"],
    )
    .unwrap();
    rmail_common::db::set_mailbox_quota(&db_path, "postmaster@example.test", Some(1)).unwrap();
    let (responses, td) = run_prepared_session(
            b"EHLO localhost\r\nLHLO localhost\r\nMAIL FROM:<sender@example.test>\r\nRCPT TO:<user@example.test>\r\nRCPT TO:<postmaster@example.test>\r\nRCPT TO:<remote-alias@example.test>\r\nDATA\r\nFrom: sender@example.test\r\nSubject: LMTP\r\n\r\nmessage\r\n.\r\nQUIT\r\n"
                .to_vec(),
            32 * 1024,
            SecurityConfig::default(),
            false,
            SmtpService::Lmtp,
            td,
            mail_root,
            db_path,
        )
        .await;

    assert!(
        responses
            .iter()
            .any(|line| line == "500 5.5.1 LMTP requires LHLO\r\n")
    );
    assert!(
        responses
            .iter()
            .any(|line| line.starts_with("250-rMail Hello"))
    );
    assert!(
        responses
            .iter()
            .any(|line| { line == "250 2.1.5 Delivered <user@example.test>\r\n" })
    );
    assert!(
        responses
            .iter()
            .any(|line| { line == "550 5.1.1 LMTP alias has a non-local target\r\n" })
    );
    assert!(responses.iter().any(|line| {
        line == "452 4.2.2 Mailbox storage limit exceeded <postmaster@example.test>\r\n"
    }));
    assert_eq!(
        std::fs::read_dir(td.path().join("mail/example.test/user/Maildir/new"))
            .unwrap()
            .count(),
        1
    );
    assert!(!td.path().join("mail/outbound/maildrop/queue").exists());
}

#[tokio::test]
async fn disabled_scanners_preserve_delivery() {
    let (responses, td) = run_session_with_security(
            b"EHLO localhost\r\nMAIL FROM:<>\r\nRCPT TO:<user@example.test>\r\nDATA\r\nSubject: hi\r\n\r\nbody\r\n.\r\nQUIT\r\n".to_vec(),
            16 * 1024,
            SecurityConfig {
                clamav_enabled: false,
                rspamd_enabled: false,
                ..SecurityConfig::default()
            },
        )
        .await;
    assert!(responses.iter().any(|r| r.starts_with("250 ")));
    let delivered_dir = td.path().join("mail/example.test/user/Maildir/new");
    assert_eq!(
        std::fs::read_dir(delivered_dir).expect("maildir").count(),
        1
    );
}

#[tokio::test]
async fn scanner_size_limit_tempfails_by_default() {
    let (responses, td) = run_session_with_security(
            b"EHLO localhost\r\nMAIL FROM:<>\r\nRCPT TO:<user@example.test>\r\nDATA\r\nSubject: hi\r\n\r\nbody\r\n.\r\nQUIT\r\n".to_vec(),
            16 * 1024,
            SecurityConfig {
                rspamd_enabled: true,
                scanner_max_message_bytes: 1,
                ..SecurityConfig::default()
            },
        )
        .await;
    assert!(
        responses
            .iter()
            .any(|r| r.starts_with("451 4.7.1 Message scanner unavailable"))
    );
    let delivered_dir = td.path().join("mail/example.test/user/Maildir/new");
    assert!(!delivered_dir.exists());
}

#[tokio::test]
async fn scanner_size_limit_accept_policy_delivers() {
    let (responses, td) = run_session_with_security(
            b"EHLO localhost\r\nMAIL FROM:<>\r\nRCPT TO:<user@example.test>\r\nDATA\r\nSubject: hi\r\n\r\nbody\r\n.\r\nQUIT\r\n".to_vec(),
            16 * 1024,
            SecurityConfig {
                rspamd_enabled: true,
                scanner_max_message_bytes: 1,
                scanner_failure_action: ScannerFailureAction::Accept,
                ..SecurityConfig::default()
            },
        )
        .await;
    assert!(responses.iter().any(|r| r.starts_with("250 ")));
    let delivered_dir = td.path().join("mail/example.test/user/Maildir/new");
    assert_eq!(
        std::fs::read_dir(delivered_dir).expect("maildir").count(),
        1
    );
}

#[tokio::test]
async fn clamav_infected_rejects_data_and_does_not_deliver() {
    let td = tempfile::tempdir().expect("tempdir");
    let sock = td.path().join("clamd.sock");
    let listener = UnixListener::bind(&sock).expect("bind");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let body = read_clamav_stream(&mut stream).await;
        assert!(body.starts_with(b"Received:"));
        stream
            .write_all(b"stream: Eicar-Test-Signature FOUND\0")
            .await
            .expect("write");
    });
    let (responses, mail_td) = run_session_with_security(
            b"EHLO localhost\r\nMAIL FROM:<>\r\nRCPT TO:<user@example.test>\r\nDATA\r\nSubject: hi\r\n\r\nbody\r\n.\r\nQUIT\r\n".to_vec(),
            16 * 1024,
            SecurityConfig {
                clamav_enabled: true,
                clamav_endpoint: format!("unix:{}", sock.display()),
                ..SecurityConfig::default()
            },
        )
        .await;
    assert!(
        responses
            .iter()
            .any(|r| r.starts_with("554 5.7.1 Message rejected: malware detected"))
    );
    let delivered_dir = mail_td.path().join("mail/example.test/user/Maildir/new");
    assert!(!delivered_dir.exists());
    server.await.expect("server");
}

#[tokio::test]
async fn oversized_data_is_drained_before_next_command() {
    let mut input =
        b"EHLO localhost\r\nMAIL FROM:<>\r\nRCPT TO:<user@example.test>\r\nDATA\r\n".to_vec();
    while input.len() < MAX_MESSAGE_BYTES + 4096 {
        input.extend(std::iter::repeat_n(b'a', 900));
        input.extend_from_slice(b"\r\n");
    }
    input.extend_from_slice(b".\r\nQUIT\r\n");
    let (responses, _td) = run_session(input, MAX_MESSAGE_BYTES + 4096).await;
    let oversized = responses
        .iter()
        .filter(|r| r.starts_with("552 5.3.4"))
        .count();
    assert_eq!(oversized, 1);
    assert!(responses.iter().any(|r| r.starts_with("221 2.0.0 Bye")));
}

#[tokio::test]
async fn overlong_data_line_is_drained_before_next_command() {
    let mut input =
        b"EHLO localhost\r\nMAIL FROM:<>\r\nRCPT TO:<user@example.test>\r\nDATA\r\n".to_vec();
    input.extend(std::iter::repeat_n(b'a', 1001));
    input.extend_from_slice(b"\r\nQUIT\r\n.\r\nQUIT\r\n");
    let (responses, _td) = run_session(input, 16 * 1024).await;
    let line_too_long = responses
        .iter()
        .filter(|r| r.starts_with("500 5.5.2"))
        .count();
    assert_eq!(line_too_long, 1);
    assert!(responses.iter().any(|r| r.starts_with("221 2.0.0 Bye")));
}

#[tokio::test]
async fn bare_lf_data_is_drained_and_rejected_without_command_desynchronization() {
    // Bare LF inside the content fails the message, but only the real
    // <CRLF>.<CRLF> ends it; the lines in between are never commands.
    let input = b"EHLO localhost\r\nMAIL FROM:<>\r\nRCPT TO:<user@example.test>\r\nDATA\r\nSubject: bad\n\nbody\nNOOP\r\n.\r\nQUIT\r\n"
            .to_vec();
    let (responses, td) = run_session(input, 16 * 1024).await;
    assert_eq!(
        responses
            .iter()
            .filter(|response| response.starts_with("554 5.6.0"))
            .count(),
        1
    );
    // The NOOP inside the drained content was not executed.
    assert!(
        !responses
            .iter()
            .any(|response| response.starts_with("250 2.0.0 OK"))
    );
    assert!(
        responses
            .iter()
            .any(|response| response.starts_with("221 2.0.0 Bye"))
    );
    assert!(
        !td.path()
            .join("mail/example.test/user/Maildir/new")
            .exists()
    );
}

#[tokio::test]
async fn smtp_smuggling_with_non_canonical_end_of_data_is_not_delivered() {
    for terminator in [
        "\r\n.\n",
        "\n.\n",
        "\n.\r\n",
        "\r\n.\r",
        "\r.\r\n",
        "\r\n\r.\r\n",
    ] {
        let input = format!(
            "EHLO localhost\r\nMAIL FROM:<>\r\nRCPT TO:<user@example.test>\r\nDATA\r\nSubject: first\r\n\r\nbody{terminator}MAIL FROM:<ceo@example.test>\r\nRCPT TO:<user@example.test>\r\nDATA\r\nSubject: smuggled\r\n\r\nsmuggled\r\n.\r\nQUIT\r\n"
        );
        let (responses, td) = run_session(input.into_bytes(), 16 * 1024).await;
        assert_eq!(
            responses
                .iter()
                .filter(|response| response.starts_with("250 2.1.0"))
                .count(),
            1,
            "{terminator:?}: {responses:?}"
        );
        assert!(
            responses
                .iter()
                .any(|response| response.starts_with("554 ")),
            "{terminator:?}: {responses:?}"
        );
        assert_eq!(
            responses
                .iter()
                .filter(|response| response.starts_with("354 "))
                .count(),
            1,
            "{terminator:?}: {responses:?}"
        );
        assert!(
            !td.path()
                .join("mail/example.test/user/Maildir/new")
                .exists(),
            "{terminator:?}: smuggled message delivered"
        );
    }
}

#[tokio::test]
async fn nested_mail_is_rejected_and_a_rejected_mail_leaves_no_transaction() {
    let (responses, td) = run_session(
        b"EHLO localhost\r\nMAIL FROM:<a..b@example.test>\r\nMAIL FROM:<first@example.test>\r\nMAIL FROM:<second@example.test>\r\nRCPT TO:<user@example.test>\r\nDATA\r\nSubject: x\r\n\r\nbody\r\n.\r\nMAIL FROM:<third@example.test>\r\nRSET\r\nMAIL FROM:<fourth@example.test>\r\nQUIT\r\n"
            .to_vec(),
        16 * 1024,
    )
    .await;
    let replies = responses
        .iter()
        .filter(|response| !response.starts_with("250-") && !response.starts_with("250 ENH"))
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert_eq!(
        replies,
        [
            "501 5.5.2 Syntax: MAIL FROM:<address>\r\n",
            "250 2.1.0 Sender OK\r\n",
            "503 5.5.1 Nested MAIL command\r\n",
            "250 2.1.5 Recipient OK\r\n",
            "354 End data with <CR><LF>.<CR><LF>\r\n",
            "250 2.0.0 Message accepted\r\n",
            "250 2.1.0 Sender OK\r\n",
            "250 2.0.0 Reset state\r\n",
            "250 2.1.0 Sender OK\r\n",
            "221 2.0.0 Bye\r\n",
        ]
    );
    assert_eq!(
        std::fs::read_dir(td.path().join("mail/example.test/user/Maildir/new"))
            .unwrap()
            .count(),
        1
    );
}

#[tokio::test]
async fn dsn_parameters_may_extend_mail_and_rcpt_beyond_512_octets() {
    let envid = "e".repeat(100);
    let orcpt = format!("rfc822;{}+40example.test", "o".repeat(60));
    let mail = format!(
        "MAIL FROM:<{}@example.test> SIZE=100 BODY=8BITMIME ENVID={envid} RET=HDRS",
        "s".repeat(60)
    );
    let rcpt = format!("RCPT TO:<user@example.test> NOTIFY=SUCCESS,FAILURE,DELAY ORCPT={orcpt}");
    let padded_rcpt = format!("{rcpt}{}", " ".repeat(600 - rcpt.len()));
    let padded_mail = format!("{mail}{}", " ".repeat(600 - mail.len()));
    let noop = format!("NOOP {}", "x".repeat(600));
    let (responses, _td) = run_session(
        format!("EHLO localhost\r\n{padded_mail}\r\n{padded_rcpt}\r\n{noop}\r\nQUIT\r\n")
            .into_bytes(),
        16 * 1024,
    )
    .await;
    assert!(
        responses
            .iter()
            .any(|response| response == "250 2.1.0 Sender OK\r\n"),
        "{responses:?}"
    );
    assert!(
        responses
            .iter()
            .any(|response| response == "250 2.1.5 Recipient OK\r\n"),
        "{responses:?}"
    );
    assert!(
        responses
            .iter()
            .any(|response| response == "500 5.5.2 Line too long\r\n"),
        "{responses:?}"
    );
}

#[tokio::test]
async fn mail_auth_parameter_is_accepted_when_auth_is_supported() {
    let responses = run_encrypted_session(
        b"EHLO localhost\r\nMAIL FROM:<a@example.test> AUTH=<>\r\nRSET\r\nMAIL FROM:<a@example.test> AUTH=someone+2Belse@example.test\r\nRSET\r\nMAIL FROM:<a@example.test> AUTH=<> AUTH=<>\r\nMAIL FROM:<a@example.test> AUTH=bad+ZZ\r\nQUIT\r\n"
            .to_vec(),
        16 * 1024,
    )
    .await;
    assert_eq!(
        responses
            .iter()
            .filter(|response| response.as_str() == "250 2.1.0 Sender OK\r\n")
            .count(),
        2,
        "{responses:?}"
    );
    assert_eq!(
        responses
            .iter()
            .filter(|response| response.starts_with("501 5.5.2"))
            .count(),
        2,
        "{responses:?}"
    );

    // Without TLS the AUTH extension is not offered, so neither is AUTH=.
    let (plaintext, _td) = run_session(
        b"EHLO localhost\r\nMAIL FROM:<a@example.test> AUTH=<>\r\nQUIT\r\n".to_vec(),
        16 * 1024,
    )
    .await;
    assert!(
        plaintext
            .iter()
            .any(|response| response.starts_with("555 5.5.4 AUTH parameter")),
        "{plaintext:?}"
    );
}

#[tokio::test]
async fn requiretls_is_only_offered_and_accepted_over_tls() {
    let (plaintext, _td) = run_session(
        b"EHLO localhost\r\nMAIL FROM:<a@example.test> REQUIRETLS\r\nQUIT\r\n".to_vec(),
        16 * 1024,
    )
    .await;
    assert!(!plaintext.iter().any(|line| line == "250-REQUIRETLS\r\n"));
    assert!(
        plaintext
            .iter()
            .any(|line| line.starts_with("530 5.7.10 REQUIRETLS")),
        "{plaintext:?}"
    );

    let encrypted = run_encrypted_session(
        b"EHLO localhost\r\nMAIL FROM:<a@example.test> REQUIRETLS\r\nQUIT\r\n".to_vec(),
        16 * 1024,
    )
    .await;
    assert!(encrypted.iter().any(|line| line == "250-REQUIRETLS\r\n"));
    assert!(
        encrypted
            .iter()
            .any(|line| line == "250 2.1.0 Sender OK\r\n"),
        "{encrypted:?}"
    );
}

#[tokio::test]
async fn helo_reply_help_and_plaintext_submission_rset() {
    let (responses, _td) = run_session(
        b"HELO client.example\r\nHELP\r\nHELP MAIL\r\nQUIT\r\n".to_vec(),
        16 * 1024,
    )
    .await;
    let helo = &responses[0];
    assert!(helo.starts_with("250 "), "{helo:?}");
    assert!(!helo.starts_with("250 2."), "{helo:?}");
    assert_eq!(
        responses
            .iter()
            .filter(|line| line.starts_with("214 "))
            .count(),
        2
    );

    let (submission, _td) = run_session_with_policy(
        b"EHLO localhost\r\nRSET\r\nHELP\r\nMAIL FROM:<user@example.test>\r\nQUIT\r\n".to_vec(),
        16 * 1024,
        SecurityConfig::default(),
        false,
        SmtpService::Submission,
    )
    .await;
    assert!(
        submission
            .iter()
            .any(|line| line == "250 2.0.0 Reset state\r\n")
    );
    assert!(submission.iter().any(|line| line.starts_with("214 ")));
    assert!(
        submission
            .iter()
            .any(|line| line.starts_with("530 5.7.0 Must issue STARTTLS"))
    );
}

#[tokio::test]
async fn strict_commands_and_mail_parameters() {
    let (responses, _td) = run_session(
            b"EHLO localhost\r\nDATA junk\r\nQUITzzz\r\nMAIL FROM:<user@example.test> SIZE=42 BODY=8BITMIME SMTPUTF8\r\nQUIT\r\n".to_vec(),
            16 * 1024,
        )
        .await;
    assert_eq!(
        responses
            .iter()
            .filter(|r| r.starts_with("501 5.5.2"))
            .count(),
        1
    );
    assert!(
        responses
            .iter()
            .any(|response| response.starts_with("500 5.5.2 Command unrecognized"))
    );
    assert!(responses.iter().any(|r| r.starts_with("250 ")));
    assert!(responses.iter().any(|r| r.starts_with("221 2.0.0 Bye")));
}

#[tokio::test]
async fn advertised_enhanced_status_codes_are_used_for_command_replies() {
    let (responses, _td) = run_session(
            b"EHLO localhost\r\nMAIL FROM:<>\r\nRCPT TO:<missing@example.test>\r\nRSET\r\nVRFY user@example.test\r\nNOOP\r\nQUIT\r\n"
                .to_vec(),
            16 * 1024,
        )
        .await;
    assert!(
        responses
            .iter()
            .any(|response| response == "250 ENHANCEDSTATUSCODES\r\n")
    );
    assert!(
        !responses
            .iter()
            .any(|response| response == "250-REQUIRETLS\r\n")
    );
    for response in responses.iter().filter(|response| {
        !response.starts_with("250-") && response.as_str() != "250 ENHANCEDSTATUSCODES\r\n"
    }) {
        let status = response.split_ascii_whitespace().nth(1).unwrap_or_default();
        let components = status.split('.').collect::<Vec<_>>();
        assert_eq!(components.len(), 3, "{response:?}");
        assert!(
            components.iter().all(|component| !component.is_empty()
                && component.bytes().all(|byte| byte.is_ascii_digit())),
            "{response:?}"
        );
    }
}

#[tokio::test]
async fn bare_lf_command_is_rejected_without_losing_following_crlf_commands() {
    let (responses, _td) = run_session(
        b"EHLO localhost\nEHLO localhost\r\nNOOP\r\nQUIT\r\n".to_vec(),
        16 * 1024,
    )
    .await;
    assert!(
        responses
            .iter()
            .any(|response| response.starts_with("500 5.5.2 Command line must end with CRLF"))
    );
    assert!(
        responses
            .iter()
            .any(|response| response.starts_with("250-rMail Hello"))
    );
    assert!(
        responses
            .iter()
            .any(|response| response.starts_with("250 "))
    );
    assert!(
        responses
            .iter()
            .any(|response| response.starts_with("221 2.0.0 Bye"))
    );
}

#[tokio::test]
async fn command_preflight_enforces_greeting_transaction_and_auth_order() {
    let (responses, _td) = run_session(
            b"MAIL FROM:<user@example.test>\r\nSTARTTLS\r\nEHLO localhost\r\nMAIL FROM:<user@example.test>\r\nAUTH PLAIN =\r\nRSET\r\nAUTH PLAIN =\r\nQUIT\r\n"
                .to_vec(),
            16 * 1024,
        )
        .await;
    assert!(
        responses
            .iter()
            .any(|response| response.starts_with("503 5.5.1 Send HELO/EHLO first"))
    );
    assert!(
        responses
            .iter()
            .any(|response| response.starts_with("503 5.5.1 Send EHLO before STARTTLS"))
    );
    assert!(responses.iter().any(|response| {
        response.starts_with("503 5.5.1 AUTH not permitted during a mail transaction")
    }));
    assert!(
        responses
            .iter()
            .any(|response| response.starts_with("538 5.7.11 Encryption required"))
    );
    assert!(
        responses
            .iter()
            .any(|response| response.starts_with("221 2.0.0 Bye"))
    );
}

#[tokio::test]
async fn starttls_rejects_pipelined_plaintext_without_losing_commands() {
    let (td, mail_root, db_path) = setup_mailbox();
    let server_config = tokio_rustls::rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(
            tokio_rustls::rustls::server::ResolvesServerCertUsingSni::new(),
        ));
    let tls_context = Arc::new(super::tls::TlsContext {
        acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(server_config)),
    });
    let (client, server) = duplex(16 * 1024);
    let server_task = tokio::spawn(process_stream(
        Box::new(server),
        mail_root.to_string_lossy().to_string(),
        Some(tls_context),
        Some(db_path.to_string_lossy().to_string()),
        None,
        false,
        false,
        true,
        Arc::new(SecurityConfig::default()),
        SmtpService::Mta,
        None,
    ));
    let mut reader = BufReader::new(client);
    let mut greeting = String::new();
    reader.read_line(&mut greeting).await.expect("greeting");
    reader
        .get_mut()
        .write_all(b"EHLO localhost\r\nSTARTTLS\r\nNOOP\r\nQUIT\r\n")
        .await
        .expect("commands");
    reader.get_mut().flush().await.expect("flush");
    let ehlo = read_until(&mut reader, "250 ENHANCEDSTATUSCODES").await;
    assert!(ehlo.contains("STARTTLS"));
    let rejection = read_until(&mut reader, "554 5.5.1").await;
    assert!(rejection.contains("did not wait for STARTTLS reply"));
    assert!(
        read_until(&mut reader, "250 2.0.0")
            .await
            .contains("250 2.0.0")
    );
    assert!(
        read_until(&mut reader, "221 2.0.0 Bye")
            .await
            .contains("221 2.0.0 Bye")
    );
    server_task.await.expect("join").expect("server");
    drop(td);
}

#[tokio::test]
async fn starttls_completes_real_handshake_and_requires_fresh_ehlo() {
    use std::io::Cursor;
    use std::time::SystemTime;
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::client::{ServerCertVerified, ServerCertVerifier};
    use tokio_rustls::rustls::{
        Certificate, ClientConfig, Error as TlsError, RootCertStore, ServerName,
    };

    struct PinnedCertificate(Vec<u8>);
    impl ServerCertVerifier for PinnedCertificate {
        fn verify_server_cert(
            &self,
            end_entity: &Certificate,
            _intermediates: &[Certificate],
            _server_name: &ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            _ocsp_response: &[u8],
            _now: SystemTime,
        ) -> Result<ServerCertVerified, TlsError> {
            if end_entity.0 == self.0 {
                Ok(ServerCertVerified::assertion())
            } else {
                Err(TlsError::General(
                    "STARTTLS test received unexpected certificate".to_string(),
                ))
            }
        }
    }

    let (_td, mail_root, db_path) = setup_mailbox();
    let (cert_path, key_path) = rmail_common::test_support::localhost_cert();
    let tls_context = super::tls::load_tls_context(cert_path, key_path).expect("TLS context");
    let certificate_pem = std::fs::read(cert_path).expect("certificate");
    let certificates =
        rustls_pemfile::certs(&mut Cursor::new(certificate_pem)).expect("parse certificate");
    let mut client_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    client_config
        .dangerous()
        .set_certificate_verifier(Arc::new(PinnedCertificate(certificates[0].clone())));

    let (client, server) = duplex(32 * 1024);
    let server_task = tokio::spawn(process_stream(
        Box::new(server),
        mail_root.to_string_lossy().to_string(),
        Some(tls_context),
        Some(db_path.to_string_lossy().to_string()),
        None,
        false,
        false,
        true,
        Arc::new(SecurityConfig::default()),
        SmtpService::Mta,
        None,
    ));
    let mut plaintext = BufReader::new(client);
    let mut greeting = String::new();
    plaintext.read_line(&mut greeting).await.expect("greeting");
    plaintext
        .get_mut()
        .write_all(b"EHLO localhost\r\n")
        .await
        .expect("EHLO");
    plaintext.get_mut().flush().await.expect("flush");
    assert!(
        read_until(&mut plaintext, "250 ENHANCEDSTATUSCODES")
            .await
            .contains("STARTTLS")
    );
    plaintext
        .get_mut()
        .write_all(b"STARTTLS\r\n")
        .await
        .expect("STARTTLS");
    plaintext.get_mut().flush().await.expect("flush");
    let mut ready = String::new();
    plaintext.read_line(&mut ready).await.expect("ready");
    assert_eq!(ready, "220 2.0.0 Ready to start TLS\r\n");

    let connector = TlsConnector::from(Arc::new(client_config));
    let tls_stream = connector
        .connect(
            ServerName::try_from("localhost").expect("server name"),
            plaintext.into_inner(),
        )
        .await
        .expect("TLS handshake");
    let mut encrypted = BufReader::new(tls_stream);
    encrypted
        .get_mut()
        .write_all(b"AUTH PLAIN =\r\nEHLO localhost\r\nQUIT\r\n")
        .await
        .expect("post-TLS commands");
    encrypted.get_mut().flush().await.expect("flush");
    assert!(
        read_until(&mut encrypted, "503 5.5.1")
            .await
            .contains("Send EHLO before AUTH")
    );
    let capabilities = read_until(&mut encrypted, "250 ENHANCEDSTATUSCODES").await;
    assert!(capabilities.contains("AUTH PLAIN LOGIN SCRAM-SHA-256"));
    assert!(!capabilities.contains("STARTTLS"));
    assert!(
        read_until(&mut encrypted, "221 2.0.0 Bye")
            .await
            .contains("221 2.0.0 Bye")
    );
    server_task.await.expect("join").expect("server");
}

#[tokio::test]
async fn auth_plain_and_login_use_shared_bounded_exchange_handler() {
    let plain = run_encrypted_session(
            b"EHLO localhost\r\nAUTH PLAIN AHVzZXJAZXhhbXBsZS50ZXN0AHBhc3N3b3Jk\r\nAUTH PLAIN AHVzZXJAZXhhbXBsZS50ZXN0AHBhc3N3b3Jk\r\nQUIT\r\n"
                .to_vec(),
            16 * 1024,
        )
        .await;
    assert!(
        plain
            .iter()
            .any(|response| response.starts_with("235 2.7.0"))
    );
    assert!(
        plain
            .iter()
            .any(|response| response.starts_with("503 5.5.0 Already authenticated"))
    );

    let login = run_encrypted_session(
        b"EHLO localhost\r\nAUTH LOGIN\r\ndXNlckBleGFtcGxlLnRlc3Q=\r\ncGFzc3dvcmQ=\r\nQUIT\r\n"
            .to_vec(),
        16 * 1024,
    )
    .await;
    assert!(
        login
            .iter()
            .any(|response| response == "334 VXNlcm5hbWU6\r\n")
    );
    assert!(
        login
            .iter()
            .any(|response| response == "334 UGFzc3dvcmQ6\r\n")
    );
    assert!(
        login
            .iter()
            .any(|response| response.starts_with("235 2.7.0"))
    );
}

#[tokio::test]
async fn auth_scram_sha256_verifies_a_real_client_proof() {
    let (_td, mail_root, db_path) = setup_mailbox();
    let (client, server) = duplex(32 * 1024);
    let server_task = tokio::spawn(process_stream(
        Box::new(server),
        mail_root.to_string_lossy().to_string(),
        None,
        Some(db_path.to_string_lossy().to_string()),
        None,
        true,
        false,
        true,
        Arc::new(SecurityConfig::default()),
        SmtpService::Mta,
        None,
    ));
    let mut reader = BufReader::new(client);
    let mut greeting = String::new();
    reader.read_line(&mut greeting).await.expect("greeting");
    reader
        .get_mut()
        .write_all(b"EHLO localhost\r\n")
        .await
        .expect("EHLO");
    reader.get_mut().flush().await.expect("flush");
    assert!(
        read_until(&mut reader, "250 ENHANCEDSTATUSCODES")
            .await
            .contains("AUTH")
    );

    let bare = "n=user@example.test,r=clientnonce";
    let first = BASE64_ENGINE.encode(format!("n,,{bare}"));
    reader
        .get_mut()
        .write_all(format!("AUTH SCRAM-SHA-256 {first}\r\n").as_bytes())
        .await
        .expect("AUTH");
    reader.get_mut().flush().await.expect("flush");
    let mut challenge = String::new();
    reader
        .read_line(&mut challenge)
        .await
        .expect("server first");
    assert!(challenge.starts_with("334 "), "{challenge:?}");
    let server_first = String::from_utf8(
        BASE64_ENGINE
            .decode(challenge.trim().strip_prefix("334 ").unwrap())
            .expect("decode server first"),
    )
    .expect("UTF-8 server first");
    let final_message = scram_client_final("password", bare, &server_first);
    reader
        .get_mut()
        .write_all(format!("{}\r\n", BASE64_ENGINE.encode(final_message)).as_bytes())
        .await
        .expect("client final");
    reader.get_mut().flush().await.expect("flush");
    let mut success = String::new();
    reader.read_line(&mut success).await.expect("AUTH success");
    assert!(success.starts_with("235 2.7.0 "));
    let server_final = success
        .trim()
        .strip_prefix("235 2.7.0 ")
        .expect("server final");
    assert!(
        String::from_utf8(BASE64_ENGINE.decode(server_final).unwrap())
            .unwrap()
            .starts_with("v=")
    );
    reader.get_mut().write_all(b"QUIT\r\n").await.expect("QUIT");
    reader.get_mut().flush().await.expect("flush");
    assert!(
        read_until(&mut reader, "221 2.0.0 Bye")
            .await
            .contains("221 2.0.0 Bye")
    );
    server_task.await.expect("join").expect("server");
}

#[tokio::test]
async fn auth_cancellation_and_invalid_parameters_preserve_command_stream() {
    let responses = run_encrypted_session(
        b"EHLO localhost\r\nAUTH LOGIN extra extra\r\nAUTH LOGIN\r\n*\r\nNOOP\r\nQUIT\r\n".to_vec(),
        16 * 1024,
    )
    .await;
    assert!(
        responses
            .iter()
            .any(|response| response.starts_with("501 5.5.4 Invalid AUTH parameters"))
    );
    assert!(
        responses
            .iter()
            .any(|response| response.starts_with("501 5.7.0 Authentication canceled"))
    );
    assert!(
        responses
            .iter()
            .any(|response| response.starts_with("250 "))
    );
    assert!(
        responses
            .iter()
            .any(|response| response.starts_with("221 "))
    );
}

#[tokio::test]
async fn overlong_auth_continuation_is_drained_before_next_command() {
    let mut input = b"EHLO localhost\r\nAUTH LOGIN\r\n".to_vec();
    input.extend(std::iter::repeat_n(b'A', protocol::MAX_AUTH_LINE_BYTES + 1));
    input.extend_from_slice(b"\r\nNOOP\r\nQUIT\r\n");
    let responses = run_encrypted_session(input, 32 * 1024).await;
    assert!(
        responses
            .iter()
            .any(|response| response.starts_with("500 5.5.2 AUTH response line too long"))
    );
    assert!(
        responses
            .iter()
            .any(|response| response.starts_with("250 "))
    );
    assert!(
        responses
            .iter()
            .any(|response| response.starts_with("221 "))
    );
}

#[tokio::test]
async fn declared_mail_size_over_limit_is_rejected_before_data() {
    let input = format!(
        "EHLO localhost\r\nMAIL FROM:<user@example.test> SIZE={}\r\nQUIT\r\n",
        MAX_MESSAGE_BYTES + 1
    );
    let (responses, _td) = run_session(input.into_bytes(), 16 * 1024).await;
    assert!(responses.iter().any(|r| r.starts_with("552 5.3.4")));
    assert!(responses.iter().any(|r| r.starts_with("221 2.0.0 Bye")));
}
