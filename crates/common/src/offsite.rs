//! Copies of backups kept off the machine: S3-compatible storage (AWS S3,
//! Google Cloud Storage through its S3 API, Cloudflare R2, Backblaze B2,
//! MinIO, Garage...), Azure Blob Storage, or a server over SFTP.
//!
//! - S3: requests signed with AWS Signature Version 4; files above one part
//!   go up as a multipart upload; an optional storage class.
//! - Azure: Shared Key or a SAS token; blocks and a block list; an
//!   optional access tier.
//! - SFTP: the system `sftp` client with a key, uploading to a `.partial`
//!   name then renaming, so a half-written file is never taken for a
//!   backup. The server's host key is trusted on first use and checked
//!   after that.
//!
//! Only the backups' own names (`rmail-*.tar.zst`) are listed or deleted.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::BackupUploadConfig;

/// Bytes per S3 part or Azure block (memory held at once while uploading;
/// S3's smallest part is 5 MiB, which tests use).
const PART: usize = if cfg!(test) {
    5 * 1024 * 1024
} else {
    64 * 1024 * 1024
};

type HmacSha256 = Hmac<Sha256>;

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// Whether a name is one of ours.
pub fn is_backup_name(name: &str) -> bool {
    name.starts_with("rmail-")
        && name.ends_with(".tar.zst")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

fn client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(30))
        // No limit on a whole request (a large backup downloads for a long
        // time); a connection that stalls for five minutes fails.
        .read_timeout(Duration::from_secs(5 * 60))
        .user_agent(concat!("rMail-backup/", env!("CARGO_PKG_VERSION")))
        .build()?)
}

async fn check(response: reqwest::Response, what: &str) -> Result<reqwest::Response> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    let detail: String = body.chars().take(400).collect();
    bail!("{what} failed: HTTP {status} {detail}");
}

/// A prefix as a folder: empty, or ending in one `/`.
fn folder(prefix: &str) -> String {
    let prefix = prefix.trim().trim_matches('/');
    if prefix.is_empty() {
        String::new()
    } else {
        format!("{prefix}/")
    }
}

/// Read the next part of a file (up to [`PART`] bytes).
async fn next_part(file: &mut tokio::fs::File) -> Result<Vec<u8>> {
    let mut buffer = vec![0u8; PART];
    let mut filled = 0;
    while filled < PART {
        let read = file.read(&mut buffer[filled..]).await?;
        if read == 0 {
            break;
        }
        filled += read;
    }
    buffer.truncate(filled);
    Ok(buffer)
}

async fn save_body(response: reqwest::Response, out: &Path) -> Result<()> {
    let partial = out.with_extension("partial");
    let mut file = tokio::fs::File::create(&partial).await?;
    let mut response = response;
    while let Some(chunk) = response.chunk().await? {
        file.write_all(&chunk).await?;
    }
    file.sync_all().await?;
    tokio::fs::rename(&partial, out).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// S3

/// RFC 3986 encoding as SigV4 wants it; `/` kept when `path`.
fn aws_encode(text: &str, path: bool) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) || (path && byte == b'/') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

struct S3 {
    endpoint: reqwest::Url,
    region: String,
    bucket: String,
    prefix: String,
    access_key: String,
    secret_key: String,
    storage_class: String,
    path_style: bool,
}

/// A signed request's headers, by SigV4.
struct Signed {
    headers: Vec<(String, String)>,
}

impl S3 {
    /// The URL of `key` (or the bucket, for an empty key), and its host.
    fn url(&self, key: &str, query: &[(String, String)]) -> Result<(reqwest::Url, String)> {
        let mut url = self.endpoint.clone();
        let host = url
            .host_str()
            .context("the S3 endpoint has no host")?
            .to_string();
        let base_path = url.path().trim_end_matches('/').to_string();
        let object = aws_encode(key, true);
        if self.path_style {
            url.set_path(&format!(
                "{base_path}/{}/{object}",
                aws_encode(&self.bucket, false)
            ));
        } else {
            url.set_host(Some(&format!("{}.{host}", self.bucket)))?;
            url.set_path(&format!("{base_path}/{object}"));
        }
        let mut pairs: Vec<String> = query
            .iter()
            .map(|(k, v)| format!("{}={}", aws_encode(k, false), aws_encode(v, false)))
            .collect();
        pairs.sort();
        let joined = pairs.join("&");
        url.set_query(if pairs.is_empty() {
            None
        } else {
            Some(&joined)
        });
        let host = match url.port() {
            Some(port) => format!("{}:{port}", url.host_str().unwrap_or_default()),
            None => url.host_str().unwrap_or_default().to_string(),
        };
        Ok((url, host))
    }

    fn sign(
        &self,
        method: &str,
        url: &reqwest::Url,
        host: &str,
        extra: &[(&str, String)],
        payload_hash: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Signed {
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date = now.format("%Y%m%d").to_string();
        let mut headers: Vec<(String, String)> = vec![
            ("host".into(), host.to_string()),
            ("x-amz-content-sha256".into(), payload_hash.to_string()),
            ("x-amz-date".into(), amz_date.clone()),
        ];
        for (name, value) in extra {
            headers.push((name.to_ascii_lowercase(), value.trim().to_string()));
        }
        headers.sort();
        let canonical_headers: String = headers.iter().map(|(n, v)| format!("{n}:{v}\n")).collect();
        let signed_headers = headers
            .iter()
            .map(|(n, _)| n.as_str())
            .collect::<Vec<_>>()
            .join(";");
        let canonical = format!(
            "{method}\n{}\n{}\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
            url.path(),
            url.query().unwrap_or_default(),
        );
        let scope = format!("{date}/{}/s3/aws4_request", self.region);
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            sha256_hex(canonical.as_bytes())
        );
        let key = hmac(
            &hmac(
                &hmac(
                    &hmac(
                        format!("AWS4{}", self.secret_key).as_bytes(),
                        date.as_bytes(),
                    ),
                    self.region.as_bytes(),
                ),
                b"s3",
            ),
            b"aws4_request",
        );
        let signature = hex(&hmac(&key, to_sign.as_bytes()));
        headers.push((
            "authorization".into(),
            format!(
                "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
                self.access_key
            ),
        ));
        headers.retain(|(n, _)| n != "host");
        Signed { headers }
    }

    async fn send(
        &self,
        http: &reqwest::Client,
        method: reqwest::Method,
        key: &str,
        query: &[(&str, &str)],
        extra: &[(&str, String)],
        body: Vec<u8>,
    ) -> Result<reqwest::Response> {
        let query: Vec<(String, String)> = query
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let (url, host) = self.url(key, &query)?;
        let signed = self.sign(
            method.as_str(),
            &url,
            &host,
            extra,
            &sha256_hex(&body),
            chrono::Utc::now(),
        );
        let mut request = http.request(method, url).body(body);
        for (name, value) in signed.headers {
            request = request.header(name, value);
        }
        Ok(request.send().await?)
    }

    fn class_header(&self) -> Vec<(&'static str, String)> {
        if self.storage_class.trim().is_empty() {
            Vec::new()
        } else {
            vec![("x-amz-storage-class", self.storage_class.trim().to_string())]
        }
    }

    async fn upload(&self, file: &Path, name: &str) -> Result<()> {
        let http = client()?;
        let key = format!("{}{name}", self.prefix);
        let mut source = tokio::fs::File::open(file).await?;
        let first = next_part(&mut source).await?;
        if first.len() < PART {
            let response = self
                .send(
                    &http,
                    reqwest::Method::PUT,
                    &key,
                    &[],
                    &self.class_header(),
                    first,
                )
                .await?;
            check(response, "S3 upload").await?;
            return Ok(());
        }
        // Multipart: started, parts, completed (or aborted on failure).
        let started = self
            .send(
                &http,
                reqwest::Method::POST,
                &key,
                &[("uploads", "")],
                &self.class_header(),
                Vec::new(),
            )
            .await?;
        let text = check(started, "S3 multipart start").await?.text().await?;
        let upload_id = xml_values(&text, "UploadId")
            .into_iter()
            .next()
            .context("no UploadId in the answer")?;
        let result = async {
            let mut etags = Vec::new();
            let mut part = first;
            loop {
                let number = (etags.len() + 1).to_string();
                let response = self
                    .send(
                        &http,
                        reqwest::Method::PUT,
                        &key,
                        &[
                            ("partNumber", number.as_str()),
                            ("uploadId", upload_id.as_str()),
                        ],
                        &[],
                        part,
                    )
                    .await?;
                let response = check(response, "S3 part upload").await?;
                let etag = response
                    .headers()
                    .get("etag")
                    .and_then(|v| v.to_str().ok())
                    .context("a part without an ETag")?
                    .to_string();
                etags.push(etag);
                part = next_part(&mut source).await?;
                if part.is_empty() {
                    break;
                }
            }
            let body: String = etags
                .iter()
                .enumerate()
                .map(|(i, etag)| {
                    format!(
                        "<Part><PartNumber>{}</PartNumber><ETag>{etag}</ETag></Part>",
                        i + 1
                    )
                })
                .collect();
            let body = format!("<CompleteMultipartUpload>{body}</CompleteMultipartUpload>");
            let done = self
                .send(
                    &http,
                    reqwest::Method::POST,
                    &key,
                    &[("uploadId", upload_id.as_str())],
                    &[],
                    body.into_bytes(),
                )
                .await?;
            let text = check(done, "S3 multipart completion").await?.text().await?;
            if text.contains("<Error>") {
                bail!(
                    "S3 multipart completion failed: {}",
                    text.chars().take(400).collect::<String>()
                );
            }
            Ok(())
        }
        .await;
        if result.is_err() {
            let _ = self
                .send(
                    &http,
                    reqwest::Method::DELETE,
                    &key,
                    &[("uploadId", upload_id.as_str())],
                    &[],
                    Vec::new(),
                )
                .await;
        }
        result
    }

    async fn list(&self) -> Result<Vec<String>> {
        let http = client()?;
        let mut names = Vec::new();
        let mut marker = String::new();
        loop {
            let mut query = vec![("prefix", self.prefix.as_str())];
            if !marker.is_empty() {
                query.push(("marker", marker.as_str()));
            }
            let response = self
                .send(&http, reqwest::Method::GET, "", &query, &[], Vec::new())
                .await?;
            let text = check(response, "S3 listing").await?.text().await?;
            let keys = xml_values(&text, "Key");
            for key in &keys {
                if let Some(name) = key.strip_prefix(self.prefix.as_str())
                    && is_backup_name(name)
                {
                    names.push(name.to_string());
                }
            }
            let truncated = xml_values(&text, "IsTruncated")
                .first()
                .is_some_and(|v| v == "true");
            match (truncated, keys.last()) {
                (true, Some(last)) => marker = last.clone(),
                _ => break,
            }
        }
        names.sort();
        Ok(names)
    }

    async fn delete(&self, name: &str) -> Result<()> {
        let http = client()?;
        let response = self
            .send(
                &http,
                reqwest::Method::DELETE,
                &format!("{}{name}", self.prefix),
                &[],
                &[],
                Vec::new(),
            )
            .await?;
        check(response, "S3 delete").await?;
        Ok(())
    }

    async fn download(&self, name: &str, out: &Path) -> Result<()> {
        let http = client()?;
        let response = self
            .send(
                &http,
                reqwest::Method::GET,
                &format!("{}{name}", self.prefix),
                &[],
                &[],
                Vec::new(),
            )
            .await?;
        save_body(check(response, "S3 download").await?, out).await
    }
}

/// The text of every `<tag>` element (entities decoded), in order.
fn xml_values(xml: &str, tag: &str) -> Vec<String> {
    let Ok(document) = roxmltree::Document::parse(xml) else {
        return Vec::new();
    };
    document
        .descendants()
        .filter(|node| node.tag_name().name() == tag)
        .map(|node| node.text().unwrap_or_default().to_string())
        .collect()
}

// ---------------------------------------------------------------------------
// Azure Blob Storage

struct Azure {
    endpoint: reqwest::Url,
    account: String,
    container: String,
    prefix: String,
    key: Option<Vec<u8>>,
    sas: Option<String>,
    tier: String,
}

const AZURE_VERSION: &str = "2021-08-06";

impl Azure {
    fn url(&self, blob: Option<&str>, query: &[(&str, &str)]) -> reqwest::Url {
        let mut url = self.endpoint.clone();
        let base = url.path().trim_end_matches('/').to_string();
        let path = match blob {
            Some(blob) => format!("{base}/{}/{}", self.container, aws_encode(blob, true)),
            None => format!("{base}/{}", self.container),
        };
        url.set_path(&path);
        let mut pairs: Vec<String> = query
            .iter()
            .map(|(k, v)| format!("{}={}", aws_encode(k, false), aws_encode(v, false)))
            .collect();
        if let Some(sas) = &self.sas {
            pairs.push(sas.trim_start_matches('?').to_string());
        }
        let joined = pairs.join("&");
        url.set_query(if pairs.is_empty() {
            None
        } else {
            Some(&joined)
        });
        url
    }

    /// Shared Key authorization (when no SAS token is used).
    fn shared_key(
        &self,
        method: &str,
        url: &reqwest::Url,
        query: &[(&str, &str)],
        headers: &[(String, String)],
        length: usize,
    ) -> Option<String> {
        let key = self.key.as_ref()?;
        let header = |name: &str| {
            headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        let mut ms: Vec<(String, String)> = headers
            .iter()
            .filter(|(n, _)| n.to_ascii_lowercase().starts_with("x-ms-"))
            .map(|(n, v)| (n.to_ascii_lowercase(), v.trim().to_string()))
            .collect();
        ms.sort();
        let canonical_headers: String = ms.iter().map(|(n, v)| format!("{n}:{v}\n")).collect();
        let mut resource = format!("/{}{}", self.account, url.path());
        let mut params: Vec<(String, String)> = query
            .iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v.to_string()))
            .collect();
        params.sort();
        for (name, value) in params {
            resource.push_str(&format!("\n{name}:{value}"));
        }
        let length = if length == 0 {
            String::new()
        } else {
            length.to_string()
        };
        let to_sign = format!(
            "{method}\n\n\n{length}\n\n{}\n\n\n\n\n\n\n{canonical_headers}{resource}",
            header("content-type"),
        );
        Some(format!(
            "SharedKey {}:{}",
            self.account,
            B64.encode(hmac(key, to_sign.as_bytes()))
        ))
    }

    async fn send(
        &self,
        http: &reqwest::Client,
        method: reqwest::Method,
        blob: Option<&str>,
        query: &[(&str, &str)],
        extra: &[(&str, String)],
        body: Vec<u8>,
    ) -> Result<reqwest::Response> {
        let url = self.url(blob, query);
        let mut headers: Vec<(String, String)> = vec![
            (
                "x-ms-date".into(),
                chrono::Utc::now()
                    .format("%a, %d %b %Y %H:%M:%S GMT")
                    .to_string(),
            ),
            ("x-ms-version".into(), AZURE_VERSION.into()),
        ];
        headers.extend(extra.iter().map(|(n, v)| (n.to_string(), v.clone())));
        if let Some(authorization) =
            self.shared_key(method.as_str(), &url, query, &headers, body.len())
        {
            headers.push(("authorization".into(), authorization));
        }
        let mut request = http.request(method, url);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        Ok(request.body(body).send().await?)
    }

    fn tier_header(&self) -> Vec<(&'static str, String)> {
        if self.tier.trim().is_empty() {
            Vec::new()
        } else {
            vec![("x-ms-access-tier", self.tier.trim().to_string())]
        }
    }

    async fn upload(&self, file: &Path, name: &str) -> Result<()> {
        let http = client()?;
        let blob = format!("{}{name}", self.prefix);
        let mut source = tokio::fs::File::open(file).await?;
        let first = next_part(&mut source).await?;
        if first.len() < PART {
            let mut extra = vec![("x-ms-blob-type", "BlockBlob".to_string())];
            extra.extend(self.tier_header());
            let response = self
                .send(&http, reqwest::Method::PUT, Some(&blob), &[], &extra, first)
                .await?;
            check(response, "Azure upload").await?;
            return Ok(());
        }
        let mut ids = Vec::new();
        let mut part = first;
        loop {
            let id = B64.encode(format!("{:08}", ids.len()));
            let response = self
                .send(
                    &http,
                    reqwest::Method::PUT,
                    Some(&blob),
                    &[("comp", "block"), ("blockid", id.as_str())],
                    &[],
                    part,
                )
                .await?;
            check(response, "Azure block upload").await?;
            ids.push(id);
            part = next_part(&mut source).await?;
            if part.is_empty() {
                break;
            }
        }
        let list: String = ids
            .iter()
            .map(|id| format!("<Latest>{id}</Latest>"))
            .collect();
        let body =
            format!("<?xml version=\"1.0\" encoding=\"utf-8\"?><BlockList>{list}</BlockList>");
        let mut extra = vec![("content-type", "application/xml".to_string())];
        extra.extend(self.tier_header());
        let response = self
            .send(
                &http,
                reqwest::Method::PUT,
                Some(&blob),
                &[("comp", "blocklist")],
                &extra,
                body.into_bytes(),
            )
            .await?;
        check(response, "Azure block list").await?;
        Ok(())
    }

    async fn list(&self) -> Result<Vec<String>> {
        let http = client()?;
        let mut names = Vec::new();
        let mut marker = String::new();
        loop {
            let mut query = vec![
                ("restype", "container"),
                ("comp", "list"),
                ("prefix", self.prefix.as_str()),
            ];
            if !marker.is_empty() {
                query.push(("marker", marker.as_str()));
            }
            let response = self
                .send(&http, reqwest::Method::GET, None, &query, &[], Vec::new())
                .await?;
            let text = check(response, "Azure listing").await?.text().await?;
            let text = text.trim_start_matches('\u{feff}');
            for blob in xml_values(text, "Name") {
                if let Some(name) = blob.strip_prefix(self.prefix.as_str())
                    && is_backup_name(name)
                {
                    names.push(name.to_string());
                }
            }
            match xml_values(text, "NextMarker")
                .into_iter()
                .find(|m| !m.is_empty())
            {
                Some(next) => marker = next,
                None => break,
            }
        }
        names.sort();
        Ok(names)
    }

    async fn delete(&self, name: &str) -> Result<()> {
        let http = client()?;
        let blob = format!("{}{name}", self.prefix);
        let response = self
            .send(
                &http,
                reqwest::Method::DELETE,
                Some(&blob),
                &[],
                &[],
                Vec::new(),
            )
            .await?;
        check(response, "Azure delete").await?;
        Ok(())
    }

    async fn download(&self, name: &str, out: &Path) -> Result<()> {
        let http = client()?;
        let blob = format!("{}{name}", self.prefix);
        let response = self
            .send(
                &http,
                reqwest::Method::GET,
                Some(&blob),
                &[],
                &[],
                Vec::new(),
            )
            .await?;
        save_body(check(response, "Azure download").await?, out).await
    }
}

// ---------------------------------------------------------------------------
// SFTP

struct Sftp {
    /// The client program (`sftp`; tests use a stand-in).
    program: PathBuf,
    host: String,
    port: u16,
    user: String,
    key: PathBuf,
    dir: String,
    known_hosts: PathBuf,
}

impl Sftp {
    /// Run `commands` in one batch session; their output.
    async fn batch(&self, commands: &str) -> Result<String> {
        let mut child = tokio::process::Command::new(&self.program)
            .arg("-b")
            .arg("-")
            .arg("-P")
            .arg(self.port.to_string())
            .arg("-i")
            .arg(&self.key)
            .args([
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=accept-new",
                "-o",
                "ConnectTimeout=30",
            ])
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", self.known_hosts.display()))
            .arg(format!("{}@{}", self.user, self.host))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("running sftp (is the OpenSSH client installed?)")?;
        child
            .stdin
            .take()
            .context("no stdin for sftp")?
            .write_all(commands.as_bytes())
            .await?;
        let output =
            tokio::time::timeout(Duration::from_secs(6 * 60 * 60), child.wait_with_output())
                .await
                .context("sftp took over six hours")??;
        if !output.status.success() {
            bail!(
                "sftp failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn remote(&self, name: &str) -> String {
        format!("{}/{name}", self.dir.trim_end_matches('/'))
    }

    async fn upload(&self, file: &Path, name: &str) -> Result<()> {
        let local = quoted(&file.display().to_string())?;
        let remote = quoted(&self.remote(name))?;
        let partial = quoted(&self.remote(&format!("{name}.partial")))?;
        // A leading "-" lets a command fail without ending the batch.
        self.batch(&format!(
            "-mkdir {}\nput {local} {partial}\n-rm {remote}\nrename {partial} {remote}\n",
            quoted(&self.dir)?
        ))
        .await?;
        Ok(())
    }

    async fn list(&self) -> Result<Vec<String>> {
        let out = self
            .batch(&format!("ls -1 {}\n", quoted(&self.dir)?))
            .await?;
        let mut names: Vec<String> = out
            .lines()
            .filter_map(|line| line.trim().rsplit('/').next())
            .filter(|name| is_backup_name(name))
            .map(str::to_string)
            .collect();
        names.sort();
        names.dedup();
        Ok(names)
    }

    async fn delete(&self, name: &str) -> Result<()> {
        self.batch(&format!("rm {}\n", quoted(&self.remote(name))?))
            .await?;
        Ok(())
    }

    async fn download(&self, name: &str, out: &Path) -> Result<()> {
        let partial = out.with_extension("partial");
        self.batch(&format!(
            "get {} {}\n",
            quoted(&self.remote(name))?,
            quoted(&partial.display().to_string())?
        ))
        .await?;
        tokio::fs::rename(&partial, out).await?;
        Ok(())
    }
}

/// A path for an sftp batch command, in double quotes.
fn quoted(path: &str) -> Result<String> {
    if path.is_empty() || path.contains(['"', '\\', '\n', '\r']) {
        bail!("unusable path for sftp: {path:?}");
    }
    Ok(format!("\"{path}\""))
}

// ---------------------------------------------------------------------------
// Targets

/// Where backups are copied.
pub struct Target(Kind);

enum Kind {
    S3(S3),
    Azure(Azure),
    Sftp(Sftp),
}

fn required(value: &str, what: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        bail!("backup upload: set {what}");
    }
    Ok(value.to_string())
}

fn secret(value: &Option<crate::config::SecretString>) -> Option<String> {
    value
        .as_ref()
        .map(|s| s.expose().trim().to_string())
        .filter(|s| !s.is_empty())
}

fn https(text: &str, what: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(text.trim())
        .with_context(|| format!("backup upload: {what} is not a URL"))?;
    let host = url.host_str().unwrap_or_default().trim_matches(['[', ']']);
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    match url.scheme() {
        "https" => Ok(url),
        "http" if loopback => Ok(url),
        _ => bail!("backup upload: {what} must use HTTPS"),
    }
}

/// The configured target, or `None` when uploads are off.
pub fn target(config: &BackupUploadConfig, mail_root: &Path) -> Result<Option<Target>> {
    Ok(Some(Target(match config.target.trim() {
        "" | "none" => return Ok(None),
        "s3" => {
            let endpoint = if config.s3_endpoint.trim().is_empty() {
                format!(
                    "https://s3.{}.amazonaws.com",
                    required(&config.s3_region, "the S3 region")?
                )
            } else {
                config.s3_endpoint.clone()
            };
            Kind::S3(S3 {
                endpoint: https(&endpoint, "the S3 endpoint")?,
                region: if config.s3_region.trim().is_empty() {
                    "us-east-1".into()
                } else {
                    config.s3_region.trim().into()
                },
                bucket: required(&config.s3_bucket, "the S3 bucket")?,
                prefix: folder(&config.s3_prefix),
                access_key: required(&config.s3_access_key_id, "the S3 access key ID")?,
                secret_key: secret(&config.s3_secret_access_key)
                    .context("backup upload: set the S3 secret key")?,
                storage_class: config.s3_storage_class.trim().to_string(),
                path_style: config.s3_path_style,
            })
        }
        "azure" => {
            let account = required(&config.azure_account, "the Azure storage account")?;
            let endpoint = if config.azure_endpoint.trim().is_empty() {
                format!("https://{account}.blob.core.windows.net")
            } else {
                config.azure_endpoint.clone()
            };
            let key = match secret(&config.azure_key) {
                Some(key) => Some(
                    B64.decode(key)
                        .context("backup upload: the Azure key is not base64")?,
                ),
                None => None,
            };
            let sas = secret(&config.azure_sas);
            if key.is_none() && sas.is_none() {
                bail!("backup upload: set the Azure account key or a SAS token");
            }
            Kind::Azure(Azure {
                endpoint: https(&endpoint, "the Azure endpoint")?,
                account,
                container: required(&config.azure_container, "the Azure container")?,
                prefix: folder(&config.azure_prefix),
                // A SAS token is used as given; the key signs otherwise.
                key: if sas.is_some() { None } else { key },
                sas,
                tier: config.azure_tier.trim().to_string(),
            })
        }
        "sftp" => Kind::Sftp(Sftp {
            program: PathBuf::from("sftp"),
            host: ssh_word(
                &required(&config.sftp_host, "the SFTP host")?,
                "the SFTP host",
                b".-:[]",
            )?,
            port: config.sftp_port,
            user: ssh_word(
                &required(&config.sftp_user, "the SFTP user")?,
                "the SFTP user",
                b"._-",
            )?,
            key: PathBuf::from(required(&config.sftp_key_path, "the SFTP key file")?),
            dir: required(&config.sftp_path, "the SFTP directory")?,
            known_hosts: mail_root.join("backup-known-hosts"),
        }),
        other => bail!("backup upload: unknown target {other}"),
    })))
}

/// A host or user name for the `sftp` command line: plain characters, and
/// never starting with `-`, which ssh would take as an option.
fn ssh_word(value: &str, what: &str, extra: &[u8]) -> Result<String> {
    if value.starts_with('-')
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
    {
        bail!("backup upload: {what} has characters it cannot have");
    }
    Ok(value.to_string())
}

/// Settings check on save: a chosen target must be complete.
pub fn validate_config(config: &BackupUploadConfig) -> Result<()> {
    target(config, Path::new(".")).map(|_| ())
}

impl Target {
    pub fn describe(&self) -> String {
        match &self.0 {
            Kind::S3(s3) => format!("s3://{}/{}", s3.bucket, s3.prefix),
            Kind::Azure(azure) => format!(
                "azure://{}/{}/{}",
                azure.account, azure.container, azure.prefix
            ),
            Kind::Sftp(sftp) => format!(
                "sftp://{}@{}:{}{}",
                sftp.user, sftp.host, sftp.port, sftp.dir
            ),
        }
    }

    pub async fn upload(&self, file: &Path) -> Result<String> {
        let name = file
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|n| is_backup_name(n))
            .context("only rmail-*.tar.zst backups are uploaded")?
            .to_string();
        match &self.0 {
            Kind::S3(s3) => s3.upload(file, &name).await?,
            Kind::Azure(azure) => azure.upload(file, &name).await?,
            Kind::Sftp(sftp) => sftp.upload(file, &name).await?,
        }
        Ok(name)
    }

    /// The uploaded backups, oldest first.
    pub async fn list(&self) -> Result<Vec<String>> {
        match &self.0 {
            Kind::S3(s3) => s3.list().await,
            Kind::Azure(azure) => azure.list().await,
            Kind::Sftp(sftp) => sftp.list().await,
        }
    }

    pub async fn delete(&self, name: &str) -> Result<()> {
        if !is_backup_name(name) {
            bail!("not a backup name: {name}");
        }
        match &self.0 {
            Kind::S3(s3) => s3.delete(name).await,
            Kind::Azure(azure) => azure.delete(name).await,
            Kind::Sftp(sftp) => sftp.delete(name).await,
        }
    }

    pub async fn download(&self, name: &str, out: &Path) -> Result<()> {
        if !is_backup_name(name) {
            bail!("not a backup name: {name}");
        }
        match &self.0 {
            Kind::S3(s3) => s3.download(name, out).await,
            Kind::Azure(azure) => azure.download(name, out).await,
            Kind::Sftp(sftp) => sftp.download(name, out).await,
        }
    }

    /// Upload `file`, then delete all but the newest `keep` (0 keeps all);
    /// the names deleted.
    pub async fn upload_and_prune(&self, file: &Path, keep: u32) -> Result<Vec<String>> {
        self.upload(file).await?;
        if keep == 0 {
            return Ok(Vec::new());
        }
        let names = self.list().await?;
        let surplus = names.len().saturating_sub(keep as usize);
        let mut deleted = Vec::new();
        for name in names.into_iter().take(surplus) {
            self.delete(&name).await?;
            deleted.push(name);
        }
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round trip against a live service, configured from the environment
    /// (RMAIL_TEST_UPLOAD_* as the Backup upload settings, e.g. MinIO or
    /// Azurite in a container). Run with --ignored.
    #[tokio::test]
    #[ignore]
    async fn live_round_trip() {
        let env =
            |name: &str| std::env::var(format!("RMAIL_TEST_UPLOAD_{name}")).unwrap_or_default();
        let config = BackupUploadConfig {
            target: env("TARGET"),
            s3_endpoint: env("S3_ENDPOINT"),
            s3_region: env("S3_REGION"),
            s3_bucket: env("S3_BUCKET"),
            s3_prefix: "nightly".into(),
            s3_access_key_id: env("S3_KEY"),
            s3_secret_access_key: Some(crate::config::SecretString(env("S3_SECRET"))),
            s3_path_style: true,
            azure_account: env("AZURE_ACCOUNT"),
            azure_container: env("AZURE_CONTAINER"),
            azure_prefix: "nightly".into(),
            azure_key: Some(crate::config::SecretString(env("AZURE_KEY")))
                .filter(|k| !k.0.is_empty()),
            azure_endpoint: env("AZURE_ENDPOINT"),
            azure_tier: env("AZURE_TIER"),
            ..BackupUploadConfig::default()
        };
        let td = tempfile::tempdir().unwrap();
        let target = target(&config, td.path()).unwrap().expect("a target");
        if let Kind::Azure(azure) = &target.0 {
            // A fresh emulator has no container yet.
            let http = client().unwrap();
            let _ = azure
                .send(
                    &http,
                    reqwest::Method::PUT,
                    None,
                    &[("restype", "container")],
                    &[],
                    Vec::new(),
                )
                .await;
        }
        // One small backup, and one large enough for several parts.
        let small = td.path().join("rmail-20200101-000000.tar.zst");
        std::fs::write(&small, b"small backup").unwrap();
        let large = td.path().join("rmail-20200102-000000.tar.zst");
        let data: Vec<u8> = (0..(PART * 2 + 12_345)).map(|i| (i % 251) as u8).collect();
        std::fs::write(&large, &data).unwrap();
        let newest = td.path().join("rmail-20200103-000000.tar.zst");
        std::fs::write(&newest, b"newest").unwrap();
        target.upload(&small).await.unwrap();
        target.upload(&large).await.unwrap();
        let pruned = target.upload_and_prune(&newest, 2).await.unwrap();
        assert_eq!(pruned, ["rmail-20200101-000000.tar.zst"]);
        assert_eq!(
            target.list().await.unwrap(),
            [
                "rmail-20200102-000000.tar.zst",
                "rmail-20200103-000000.tar.zst"
            ]
        );
        let back = td.path().join("back.tar.zst");
        target
            .download("rmail-20200102-000000.tar.zst", &back)
            .await
            .unwrap();
        assert!(
            std::fs::read(&back).unwrap() == data,
            "the large one comes back intact"
        );
        for name in target.list().await.unwrap() {
            target.delete(&name).await.unwrap();
        }
        assert!(target.list().await.unwrap().is_empty());
    }

    fn s3(endpoint: &str, path_style: bool) -> S3 {
        S3 {
            endpoint: reqwest::Url::parse(endpoint).unwrap(),
            region: "us-east-1".into(),
            bucket: "examplebucket".into(),
            prefix: String::new(),
            access_key: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            storage_class: String::new(),
            path_style,
        }
    }

    /// AWS's documented example (GET Object, "Signature Calculations for
    /// the Authorization Header").
    #[test]
    fn sigv4_matches_the_aws_example() {
        let s3 = s3("https://s3.amazonaws.com", false);
        let (url, host) = s3.url("test.txt", &[]).unwrap();
        assert_eq!(
            (url.as_str(), host.as_str()),
            (
                "https://examplebucket.s3.amazonaws.com/test.txt",
                "examplebucket.s3.amazonaws.com"
            )
        );
        let now = chrono::DateTime::parse_from_rfc3339("2013-05-24T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let signed = s3.sign(
            "GET",
            &url,
            &host,
            &[("Range", "bytes=0-9".into())],
            &sha256_hex(b""),
            now,
        );
        let authorization = &signed
            .headers
            .iter()
            .find(|(n, _)| n == "authorization")
            .unwrap()
            .1;
        assert_eq!(
            authorization,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn path_style_and_queries_are_canonical() {
        let s3 = s3("http://127.0.0.1:9000", true);
        let (url, host) = s3
            .url(
                "rmail/a b.tar.zst",
                &[
                    ("uploadId".into(), "x/y".into()),
                    ("partNumber".into(), "2".into()),
                ],
            )
            .unwrap();
        assert_eq!(host, "127.0.0.1:9000");
        assert_eq!(url.path(), "/examplebucket/rmail/a%20b.tar.zst");
        assert_eq!(url.query(), Some("partNumber=2&uploadId=x%2Fy"));
    }

    #[tokio::test]
    async fn sftp_batches_upload_to_a_partial_name_and_list_ours() {
        let td = tempfile::tempdir().unwrap();
        let log = td.path().join("log");
        // A stand-in sftp: records its arguments and batch, and lists two
        // backups and something else.
        let program = td.path().join("fake-sftp");
        std::fs::write(
            &program,
            format!(
                "#!/bin/sh\necho \"$@\" >> {log}\ncat >> {log}\nprintf '/backups/rmail-20200101-000000.tar.zst\\n/backups/notes.txt\\n/backups/rmail-20200102-000000.tar.zst\\n'\n",
                log = log.display()
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let sftp = Sftp {
            program,
            host: "backup.example.test".into(),
            port: 2222,
            user: "rmail".into(),
            key: PathBuf::from("/opt/rmail/config/backup_ed25519"),
            dir: "/backups".into(),
            known_hosts: td.path().join("known"),
        };
        let file = td.path().join("rmail-20200103-000000.tar.zst");
        std::fs::write(&file, b"x").unwrap();
        sftp.upload(&file, "rmail-20200103-000000.tar.zst")
            .await
            .unwrap();
        assert_eq!(
            sftp.list().await.unwrap(),
            [
                "rmail-20200101-000000.tar.zst",
                "rmail-20200102-000000.tar.zst"
            ]
        );
        let log = std::fs::read_to_string(&log).unwrap();
        assert!(
            log.contains("-P 2222 -i /opt/rmail/config/backup_ed25519")
                && log.contains("BatchMode=yes")
                && log.contains("rmail@backup.example.test"),
            "{log}"
        );
        assert!(
            log.contains("put \"") && log.contains("rmail-20200103-000000.tar.zst.partial\""),
            "{log}"
        );
        assert!(log.contains("rename \"/backups/rmail-20200103-000000.tar.zst.partial\" \"/backups/rmail-20200103-000000.tar.zst\""), "{log}");
    }

    #[test]
    fn targets_need_their_settings_and_names_are_ours() {
        let mut config = BackupUploadConfig {
            target: "s3".into(),
            ..BackupUploadConfig::default()
        };
        assert!(validate_config(&config).is_err());
        config.s3_region = "eu-west-1".into();
        config.s3_bucket = "b".into();
        config.s3_access_key_id = "k".into();
        config.s3_secret_access_key = Some(crate::config::SecretString("s".into()));
        assert!(validate_config(&config).is_ok());
        config.s3_endpoint = "http://storage.example.test".into();
        assert!(
            validate_config(&config).is_err(),
            "plain HTTP only to the loopback"
        );
        assert!(
            validate_config(&BackupUploadConfig::default()).is_ok(),
            "off"
        );
        assert!(is_backup_name("rmail-20261017-031500.tar.zst"));
        assert!(!is_backup_name("../rmail-1.tar.zst") && !is_backup_name("notes.txt"));
        assert!(quoted("a\"b").is_err());
        let sftp = |user: &str, host: &str| BackupUploadConfig {
            target: "sftp".into(),
            sftp_host: host.into(),
            sftp_user: user.into(),
            sftp_key_path: "/k".into(),
            sftp_path: "/b".into(),
            ..BackupUploadConfig::default()
        };
        assert!(validate_config(&sftp("rmail", "backup.example.test")).is_ok());
        assert!(validate_config(&sftp("-oProxyCommand=touch x", "h")).is_err());
        assert!(validate_config(&sftp("rmail", "-oProxyCommand=x")).is_err());
        assert!(validate_config(&sftp("rm ail", "h")).is_err());
        assert_eq!(folder("/rmail/"), "rmail/");
    }
}
