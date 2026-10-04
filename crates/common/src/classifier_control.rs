//! Control protocol between the admin console and the `rmail_classifier`
//! daemon: one JSON request line, one JSON reply line, over the Unix socket at
//! [`crate::config::Config::classifier_socket`].

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

pub fn socket_path(mail_root: &Path) -> std::path::PathBuf {
    mail_root.join("run").join("classifier.sock")
}

/// Longest accepted request or reply line.
pub const MAX_LINE: usize = 256 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum Request {
    /// Loaded models, account counts and the last poll cycle.
    Status,
    /// Re-read settings from the database and reload models that changed.
    Reload,
    /// Embed `text` with the active embedding model.
    TestEmbed { text: String },
    /// Pick one of `folders` for `text` with the active chat model.
    TestChat { text: String, folders: Vec<String> },
    /// Which of `labels` apply to `text` (and, with `may_propose`, a new
    /// label when none fits), from the fallback model. Webmail's "preview
    /// labels" action.
    Label {
        text: String,
        labels: Vec<LabelSpec>,
        #[serde(default)]
        may_propose: bool,
    },
    /// A short summary of `text` from the fallback model, which must be one
    /// that writes text (not Jev).
    Summarize { text: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LabelSpec {
    pub name: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reply {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub data: serde_json::Value,
}

impl Reply {
    pub fn ok(data: serde_json::Value) -> Self {
        Self {
            ok: true,
            error: None,
            data,
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(message.into()),
            data: serde_json::Value::Null,
        }
    }
}

/// Send one request and wait up to `wait` for the reply.
pub async fn call(socket: &Path, request: &Request, wait: Duration) -> Result<serde_json::Value> {
    let exchange = async {
        let stream = UnixStream::connect(socket).await.with_context(|| {
            format!("classifier daemon is not reachable at {}", socket.display())
        })?;
        let (read, mut write) = stream.into_split();
        let mut line = serde_json::to_vec(request)?;
        line.push(b'\n');
        write.write_all(&line).await?;
        write.shutdown().await?;
        let mut reader = BufReader::new(read.take(MAX_LINE as u64));
        let mut reply = String::new();
        reader.read_line(&mut reply).await?;
        let reply: Reply =
            serde_json::from_str(reply.trim()).context("invalid reply from classifier daemon")?;
        if !reply.ok {
            bail!(
                reply
                    .error
                    .unwrap_or_else(|| "classifier daemon error".to_string())
            );
        }
        Ok(reply.data)
    };
    tokio::time::timeout(wait, exchange)
        .await
        .context("classifier daemon did not answer in time")?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_use_a_command_tag() {
        let encoded = serde_json::to_string(&Request::TestChat {
            text: "hi".into(),
            folders: vec!["A".into()],
        })
        .unwrap();
        assert_eq!(
            encoded,
            r#"{"command":"test_chat","text":"hi","folders":["A"]}"#
        );
        assert_eq!(
            serde_json::from_str::<Request>(r#"{"command":"status"}"#).unwrap(),
            Request::Status
        );
    }
}
