use std::net::SocketAddr;

use crate::{
    auth::{self, PasswordAuthResult},
    parser,
    response::{Response, Status, StatusLine},
};

pub(crate) struct Outcome {
    pub(crate) response: Response,
    pub(crate) authenticated_mailbox: Option<String>,
}

pub(crate) async fn handle(
    tag: &str,
    raw_args: &str,
    db_path: Option<&String>,
    peer: Option<SocketAddr>,
) -> Outcome {
    if let Some(remaining) = peer.and_then(|peer| auth::auth_block_remaining(peer.ip())) {
        return failure(
            tag,
            Status::No,
            format!(
                "Too many failed auth attempts; try again in {}s",
                remaining.as_secs()
            ),
            None,
        );
    }
    let (user, password) = match parser::parse_login_args(raw_args) {
        Ok(credentials) => credentials,
        Err(error) => {
            return failure(
                tag,
                Status::Bad,
                format!("Invalid LOGIN arguments: {error:?}"),
                None,
            );
        }
    };

    println!(
        "IMAP LOGIN attempt peer={peer:?} user={user:?} password_len={}",
        password.len()
    );
    match auth::verify_password(db_path, &user, &password).await {
        PasswordAuthResult::Success(mailbox) => {
            if let Some(peer) = peer {
                auth::reset_auth_failures(peer.ip());
            }
            let address = mailbox.address.to_ascii_lowercase();
            println!("IMAP LOGIN success peer={peer:?} mailbox={address}");
            Outcome {
                response: Response::new().status(StatusLine::tagged(
                    tag,
                    Status::Ok,
                    "LOGIN completed",
                )),
                authenticated_mailbox: Some(address),
            }
        }
        PasswordAuthResult::Rejected => {
            record_failure(peer);
            failure(
                tag,
                Status::No,
                "Authentication failed",
                Some("AUTHENTICATIONFAILED"),
            )
        }
        PasswordAuthResult::Unavailable { mailbox, message } => {
            record_failure(peer);
            eprintln!(
                "IMAP LOGIN verification error peer={peer:?} mailbox={} err={message}",
                mailbox
                    .as_ref()
                    .map(|mailbox| mailbox.address.as_str())
                    .unwrap_or("-")
            );
            failure(tag, Status::No, "Authentication error", Some("UNAVAILABLE"))
        }
    }
}

fn record_failure(peer: Option<SocketAddr>) {
    if let Some(peer) = peer {
        auth::record_auth_failure(peer.ip());
    }
}

fn failure(tag: &str, status: Status, text: impl Into<String>, code: Option<&str>) -> Outcome {
    let mut line = StatusLine::tagged(tag, status, text);
    if let Some(code) = code {
        line = line.with_code(code);
    }
    Outcome {
        response: Response::new().status(line),
        authenticated_mailbox: None,
    }
}
