//! Keys for OpenPGP and S/MIME in webmail.
//!
//! Signing, encrypting, decrypting and verifying all happen in the browser;
//! the server never holds a usable private key.
//!
//! - Each user picks where their own keys live: `browser` (in that
//!   browser's storage only) or `server` (here, still locked with the
//!   user's passphrase, so every device they sign in on can use them). The
//!   browser locks a key before it is stored; the server keeps what it is
//!   given and hands it back.
//! - Correspondents' public keys and certificates are kept here for every
//!   device: imported by the user, or picked up from mail they read.
//! - Everything lives in the account's own store, next to its mail index.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{Session, Shared, blocking, internal_error};

const MAX_KEY_BYTES: usize = 256 * 1024;
const MAX_PRIVATE_KEYS: i64 = 20;
const MAX_PUBLIC_KEYS: i64 = 2000;

const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS crypto_settings (
        name TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS crypto_private_keys (
        id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        label TEXT NOT NULL,
        data TEXT NOT NULL,
        created INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS crypto_public_keys (
        id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        address TEXT NOT NULL,
        label TEXT NOT NULL,
        data TEXT NOT NULL,
        created INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_crypto_public_keys_address ON crypto_public_keys(address);
";

pub(crate) fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/crypto", get(overview).put(save_settings))
        .route(
            "/api/crypto/keys/{id}",
            put(save_private_key).delete(delete_private_key),
        )
        .route(
            "/api/crypto/public-keys/{id}",
            put(save_public_key).delete(delete_public_key),
        )
}

fn open(
    state: &Shared,
    session: &Session,
) -> anyhow::Result<rmail_common::sqlite_pool::SqliteConnection> {
    let conn =
        rmail_common::jmap::store::open(&state.mail_root, &session.domain, &session.localpart)?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

fn refused(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

/// Key ids are fingerprints (OpenPGP) or certificate digests (S/MIME).
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[derive(Serialize)]
struct PrivateKey {
    id: String,
    kind: String,
    label: String,
    data: String,
    created: i64,
}

#[derive(Serialize)]
struct PublicKey {
    id: String,
    kind: String,
    address: String,
    label: String,
    data: String,
    created: i64,
}

fn storage(conn: &Connection) -> anyhow::Result<Option<String>> {
    use rusqlite::OptionalExtension;
    Ok(conn
        .query_row(
            "SELECT value FROM crypto_settings WHERE name = 'storage'",
            [],
            |row| row.get(0),
        )
        .optional()?)
}

async fn overview(app: State<Shared>, headers: HeaderMap) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let result = blocking(move || {
        let conn = open(&state, &session)?;
        let mut statement = conn.prepare(
            "SELECT id, kind, label, data, created FROM crypto_private_keys ORDER BY created",
        )?;
        let keys = statement
            .query_map([], |row| {
                Ok(PrivateKey {
                    id: row.get(0)?,
                    kind: row.get(1)?,
                    label: row.get(2)?,
                    data: row.get(3)?,
                    created: row.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut statement = conn.prepare(
            "SELECT id, kind, address, label, data, created FROM crypto_public_keys ORDER BY address, created",
        )?;
        let public_keys = statement
            .query_map([], |row| {
                Ok(PublicKey {
                    id: row.get(0)?,
                    kind: row.get(1)?,
                    address: row.get(2)?,
                    label: row.get(3)?,
                    data: row.get(4)?,
                    created: row.get(5)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(json!({
            "storage": storage(&conn)?,
            "keys": keys,
            "public_keys": public_keys,
        }))
    })
    .await;
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => internal_error(error),
    }
}

#[derive(Deserialize)]
struct Settings {
    storage: String,
}

async fn save_settings(app: State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let Ok(input) = serde_json::from_slice::<Settings>(&body) else {
        return refused(StatusCode::BAD_REQUEST, "invalid json");
    };
    if !matches!(input.storage.as_str(), "browser" | "server") {
        return refused(
            StatusCode::UNPROCESSABLE_ENTITY,
            "storage is browser or server",
        );
    }
    let result = blocking(move || {
        let conn = open(&state, &session)?;
        conn.execute(
            "INSERT INTO crypto_settings (name, value) VALUES ('storage', ?1)
             ON CONFLICT(name) DO UPDATE SET value = excluded.value",
            params![input.storage],
        )?;
        // Keys kept in the browser are not left here.
        if input.storage == "browser" {
            conn.execute("DELETE FROM crypto_private_keys", [])?;
        }
        Ok(())
    })
    .await;
    match result {
        Ok(()) => Json(json!({ "result": "ok" })).into_response(),
        Err(error) => internal_error(error),
    }
}

#[derive(Deserialize)]
struct KeyInput {
    kind: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    address: String,
    data: String,
}

/// Why a key cannot be stored, if it cannot: OpenPGP keys are armored
/// blocks, S/MIME private keys PKCS#12 (base64) and certificates PEM.
fn check_key(input: &KeyInput, private: bool) -> Result<(), &'static str> {
    if input.data.len() > MAX_KEY_BYTES || input.label.chars().count() > 200 {
        return Err("the key is too large");
    }
    let looks_right = match (input.kind.as_str(), private) {
        ("pgp", true) => input.data.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----"),
        ("pgp", false) => input.data.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----"),
        ("smime", true) => {
            !input.data.is_empty()
                && input
                    .data
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"+/=\r\n".contains(&b))
        }
        ("smime", false) => input.data.contains("-----BEGIN CERTIFICATE-----"),
        _ => return Err("kind is pgp or smime"),
    };
    if !looks_right {
        return Err("this is not a key of that kind");
    }
    if !private
        && (input.address.len() > 320
            || !input.address.contains('@')
            || input.address.contains(['\r', '\n', ' ']))
    {
        return Err("a public key needs the address it is for");
    }
    Ok(())
}

async fn save_private_key(
    app: State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    save_key(app.0, headers, id, body, true).await
}

async fn save_public_key(
    app: State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    save_key(app.0, headers, id, body, false).await
}

async fn save_key(
    state: Shared,
    headers: HeaderMap,
    id: String,
    body: Bytes,
    private: bool,
) -> Response {
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let Ok(input) = serde_json::from_slice::<KeyInput>(&body) else {
        return refused(StatusCode::BAD_REQUEST, "invalid json");
    };
    if !valid_id(&id) {
        return refused(StatusCode::UNPROCESSABLE_ENTITY, "not a key id");
    }
    if let Err(message) = check_key(&input, private) {
        return refused(StatusCode::UNPROCESSABLE_ENTITY, message);
    }
    let result = blocking(move || {
        let conn = open(&state, &session)?;
        let now = chrono::Utc::now().timestamp();
        if private {
            if storage(&conn)?.as_deref() != Some("server") {
                return Ok(Err("keys are kept in the browser; choose server storage first"));
            }
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM crypto_private_keys WHERE id != ?1",
                params![id],
                |row| row.get(0),
            )?;
            if count >= MAX_PRIVATE_KEYS {
                return Ok(Err("too many keys"));
            }
            conn.execute(
                "INSERT INTO crypto_private_keys (id, kind, label, data, created) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(id) DO UPDATE SET kind = excluded.kind, label = excluded.label, data = excluded.data",
                params![id, input.kind, input.label.trim(), input.data, now],
            )?;
        } else {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM crypto_public_keys WHERE id != ?1",
                params![id],
                |row| row.get(0),
            )?;
            if count >= MAX_PUBLIC_KEYS {
                return Ok(Err("too many keys"));
            }
            conn.execute(
                "INSERT INTO crypto_public_keys (id, kind, address, label, data, created) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(id) DO UPDATE SET kind = excluded.kind, address = excluded.address,
                     label = excluded.label, data = excluded.data",
                params![
                    id,
                    input.kind,
                    input.address.trim().to_ascii_lowercase(),
                    input.label.trim(),
                    input.data,
                    now
                ],
            )?;
        }
        Ok(Ok(()))
    })
    .await;
    match result {
        Ok(Ok(())) => Json(json!({ "result": "ok" })).into_response(),
        Ok(Err(message)) => refused(StatusCode::CONFLICT, message),
        Err(error) => internal_error(error),
    }
}

async fn delete_private_key(
    app: State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    delete_key(app.0, headers, id, "crypto_private_keys").await
}

async fn delete_public_key(
    app: State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    delete_key(app.0, headers, id, "crypto_public_keys").await
}

async fn delete_key(
    state: Shared,
    headers: HeaderMap,
    id: String,
    table: &'static str,
) -> Response {
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let result = blocking(move || {
        let conn = open(&state, &session)?;
        Ok(conn.execute(&format!("DELETE FROM {table} WHERE id = ?1"), params![id])?)
    })
    .await;
    match result {
        Ok(0) => StatusCode::NOT_FOUND.into_response(),
        Ok(_) => Json(json!({ "result": "ok" })).into_response(),
        Err(error) => internal_error(error),
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{req, route, state};
    use super::super::{SESSION_COOKIE, sign_session};
    use serde_json::{Value, json};

    #[tokio::test]
    async fn keys_are_kept_where_the_user_chose() {
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        rmail_common::imap_state::init_account(&state.mail_root, "example.test", "user").unwrap();
        let cookie = Some(format!(
            "{SESSION_COOKIE}={}",
            sign_session(&state, "user@example.test")
        ));
        let call = |method: &'static str, path: &'static str, body: Value| {
            let (state, cookie) = (state.clone(), cookie.clone());
            async move {
                let response = route(
                    req(method, path, body.to_string().as_bytes(), cookie),
                    &state,
                )
                .await;
                (
                    response.status,
                    serde_json::from_slice::<Value>(&response.body).unwrap_or(Value::Null),
                )
            }
        };
        let private = json!({"kind": "pgp", "label": "Me", "data": "-----BEGIN PGP PRIVATE KEY BLOCK-----\nx\n-----END PGP PRIVATE KEY BLOCK-----"});
        let (status, _) = call("PUT", "/api/crypto/keys/ABCD", private.clone()).await;
        assert_eq!(status, 409, "browser storage is the default");
        assert_eq!(
            call("PUT", "/api/crypto", json!({"storage": "server"}))
                .await
                .0,
            200
        );
        assert_eq!(call("PUT", "/api/crypto/keys/ABCD", private).await.0, 200);
        let wrong = json!({"kind": "pgp", "data": "-----BEGIN PGP PUBLIC KEY BLOCK-----"});
        assert_eq!(call("PUT", "/api/crypto/keys/EF01", wrong).await.0, 422);
        assert_eq!(
            call("PUT", "/api/crypto/keys/bad%20id", json!({})).await.0,
            400
        );
        let public = json!({"kind": "smime", "address": "Ann@X.test", "data": "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----"});
        assert_eq!(
            call("PUT", "/api/crypto/public-keys/c1", public).await.0,
            200
        );
        let (_, overview) = call("GET", "/api/crypto", Value::Null).await;
        assert_eq!(overview["storage"], "server");
        assert_eq!(overview["keys"][0]["id"], "ABCD");
        assert_eq!(overview["public_keys"][0]["address"], "ann@x.test");

        // Moving keys to the browser removes them here.
        assert_eq!(
            call("PUT", "/api/crypto", json!({"storage": "browser"}))
                .await
                .0,
            200
        );
        let (_, overview) = call("GET", "/api/crypto", Value::Null).await;
        assert_eq!(overview["keys"], json!([]));
        assert_eq!(
            call("DELETE", "/api/crypto/public-keys/c1", Value::Null)
                .await
                .0,
            200
        );
        assert_eq!(
            call("DELETE", "/api/crypto/public-keys/c1", Value::Null)
                .await
                .0,
            404
        );
    }
}
