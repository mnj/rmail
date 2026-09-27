//! IMAP session tests driving `process_stream` over in-memory streams.
//! Shared helpers live here; tests are grouped by area in the submodules.

mod append;
mod auth;
mod autologout;
mod compat;
mod extensions;
mod fetch;
mod mailboxes;
mod metadata;
mod notify;
mod objectid;
mod partial;
mod protocol;
mod rev2;
mod scram;
mod search;
mod sync;

use crate::response::{CapabilityPhase, capability_tokens};
use crate::{process_stream, process_stream_inner, process_stream_with_policy};
use async_compression::tokio::bufread::DeflateDecoder;
use async_compression::tokio::write::DeflateEncoder;
use base64::Engine;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, duplex};
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
async fn read_until_contains<R>(reader: &mut R, needle: &str) -> Vec<String>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    let mut out = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await.expect("read line");
        if line.is_empty() {
            break;
        }
        out.push(line.clone());
        if line.contains(needle) {
            return out;
        }
    }
    out
}
async fn read_until_contains_bounded<R>(reader: &mut R, needle: &str) -> Vec<String>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        read_until_contains(reader, needle),
    )
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for IMAP response containing {needle:?}"))
}
async fn run_scripted_fixture(reader: &mut BufReader<tokio::io::DuplexStream>, fixture: &str) {
    let mut command_response = Vec::new();
    for raw_line in fixture.lines() {
        let line = raw_line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(command) = line.strip_prefix("C: ") {
            command_response.clear();
            reader
                .get_mut()
                .write_all(format!("{}\r\n", command).as_bytes())
                .await
                .expect("write fixture command");
            reader.get_mut().flush().await.expect("flush fixture");
        } else if let Some(expected) = line.strip_prefix("S: ") {
            if !command_response
                .iter()
                .any(|line: &String| line.contains(expected))
            {
                command_response.extend(read_until_contains(reader, expected).await);
            }
            assert!(
                command_response.iter().any(|line| line.contains(expected)),
                "expected fixture response containing {expected:?}, got {command_response:?}"
            );
        } else {
            panic!("invalid fixture line: {line}");
        }
    }
}
async fn run_compatibility_fixture(fixture: &str) {
    let td = tempfile::tempdir().expect("tempdir");
    let mail_root = td.path().join("mail");
    let db_path = td.path().join("config.db");
    rmail_common::db::init_db(&db_path).expect("init db");
    rmail_common::db::add_mailbox(
        &db_path,
        "user@example.test",
        Some("plain:password"),
        None,
        None,
    )
    .expect("add mailbox");
    rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "user",
            b"Date: Sun, 14 Jun 2026 12:00:00 +0000\r\nFrom: alice@example.test\r\nTo: user@example.test\r\nSubject: one\r\nMessage-ID: <one@example.test>\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nfirst body\r\n",
        )
        .expect("deliver first");
    rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "user",
            b"Date: Mon, 15 Jun 2026 12:00:00 +0000\r\nFrom: bob@example.test\r\nTo: user@example.test\r\nSubject: two\r\nMessage-ID: <two@example.test>\r\nReferences: <one@example.test>\r\nContent-Type: multipart/alternative; boundary=\"alt\"\r\n\r\n--alt\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nsecond plain\r\n--alt\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<p>second html</p>\r\n--alt--\r\n",
        )
        .expect("deliver second");

    let (client, server) = duplex(128 * 1024);
    let server_task = tokio::spawn(async move {
        process_stream(
            Box::new(server),
            mail_root.to_string_lossy().to_string(),
            None::<Arc<crate::tls::TlsContext>>,
            Some(db_path.to_string_lossy().to_string()),
            None,
            true,
        )
        .await
    });
    let mut reader = BufReader::new(client);
    let mut greeting = String::new();
    reader.read_line(&mut greeting).await.expect("greeting");
    let mut capability = String::new();
    reader.read_line(&mut capability).await.expect("capability");
    run_scripted_fixture(&mut reader, fixture).await;
    server_task.await.expect("join").expect("server");
}
fn scram_client_final(password: &str, client_first_bare: &str, server_first: &str) -> String {
    scram_client_final_with_binding(password, client_first_bare, server_first, b"n,,", &[])
}
fn scram_client_final_with_binding(
    password: &str,
    client_first_bare: &str,
    server_first: &str,
    gs2_header: &[u8],
    channel_binding_data: &[u8],
) -> String {
    use hmac::Mac;
    use hmac::digest::KeyInit;
    use pbkdf2::pbkdf2;
    use sha2::{Digest, Sha256};

    type HmacSha256 = hmac::Hmac<Sha256>;

    let salt_b64 = crate::parse_scram_attr(server_first, "s=").expect("salt");
    let iterations = crate::parse_scram_attr(server_first, "i=")
        .expect("iterations")
        .parse::<u32>()
        .expect("parse iterations");
    let nonce = crate::parse_scram_attr(server_first, "r=").expect("nonce");
    let salt = crate::BASE64_ENGINE.decode(salt_b64).expect("decode salt");
    let channel_binding = [gs2_header, channel_binding_data].concat();
    let client_final_without_proof = format!(
        "c={},r={}",
        crate::BASE64_ENGINE.encode(channel_binding),
        nonce
    );
    let auth_message = format!(
        "{},{},{}",
        client_first_bare, server_first, client_final_without_proof
    );

    let mut salted_password = [0u8; 32];
    pbkdf2::<HmacSha256>(password.as_bytes(), &salt, iterations, &mut salted_password)
        .expect("derive salted password");
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&salted_password).unwrap();
    mac.update(b"Client Key");
    let client_key = mac.finalize().into_bytes();
    let stored_key = Sha256::digest(client_key);
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&stored_key).unwrap();
    mac.update(auth_message.as_bytes());
    let client_signature = mac.finalize().into_bytes();
    let proof = client_key
        .iter()
        .zip(client_signature.iter())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<_>>();
    format!(
        "{},p={}",
        client_final_without_proof,
        crate::BASE64_ENGINE.encode(proof)
    )
}
