//! HTTP serving shared by the admin console and webmail.
//!
//! Both daemons build an [`axum::Router`] and hand each accepted connection
//! (plain TCP or TLS) to [`serve_connection`], which drives hyper's HTTP/1
//! implementation with keep-alive, a header read timeout and graceful
//! shutdown. [`harden`] adds the request body limit and handling timeout
//! every router needs.

use std::net::SocketAddr;
use std::time::Duration;

use axum::http::StatusCode;
use axum::{Extension, Router};
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

/// Deadline for receiving a request's headers.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);
/// Deadline for reading the body and producing a response.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Remote address of the connection, available to handlers as
/// `Extension<Peer>`.
#[derive(Debug, Clone, Copy)]
pub struct Peer(pub Option<SocketAddr>);

impl Peer {
    pub fn ip(&self) -> Option<std::net::IpAddr> {
        self.0.map(|address| address.ip())
    }
}

/// Reject bodies over `max_body_bytes` (413, checked against
/// Content-Length before reading) and requests that take longer than
/// [`REQUEST_TIMEOUT`] (408).
pub fn harden(router: Router, max_body_bytes: usize) -> Router {
    router
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .layer(RequestBodyLimitLayer::new(max_body_bytes))
}

/// Serve HTTP/1.1 on one connection until the client disconnects or
/// `shutdown` flips to true (in-flight requests then finish first).
pub async fn serve_connection<S>(
    stream: S,
    peer: Option<SocketAddr>,
    router: Router,
    shutdown: Option<watch::Receiver<bool>>,
) -> Result<(), hyper::Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = TowerToHyperService::new(router.layer(Extension(Peer(peer))));
    let connection = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .keep_alive(true)
        // Finish queued requests when the client half-closes its side.
        .half_close(true)
        .title_case_headers(true)
        .serve_connection(TokioIo::new(stream), service);
    tokio::pin!(connection);
    let Some(mut shutdown) = shutdown else {
        return connection.await;
    };
    tokio::select! {
        result = connection.as_mut() => result,
        // Drop the watch guard before awaiting the connection.
        _ = async { shutdown.wait_for(|stop| *stop).await.map(|_| ()) } => {
            connection.as_mut().graceful_shutdown();
            connection.await
        }
    }
}

/// Returns true for socket addresses that only accept connections from the
/// local host.
pub fn is_loopback_bind(addr: &str) -> bool {
    addr.parse::<SocketAddr>()
        .map(|socket| socket.ip().is_loopback())
        .unwrap_or(false)
}

/// Constant-time byte comparison.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::{get, post};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn app() -> Router {
        harden(
            Router::new()
                .route("/", get(|| async { "hello" }))
                .route("/echo", post(|body: axum::body::Bytes| async move { body })),
            16,
        )
    }

    async fn exchange(request: &[u8]) -> String {
        let (mut client, server) = tokio::io::duplex(1 << 16);
        let task = tokio::spawn(serve_connection(server, None, app(), None));
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let _ = task.await;
        String::from_utf8_lossy(&response).into_owned()
    }

    #[tokio::test]
    async fn serves_requests_with_keep_alive() {
        let response =
            exchange(b"GET / HTTP/1.1\r\nHost: h\r\n\r\nGET / HTTP/1.1\r\nHost: h\r\n\r\n").await;
        assert_eq!(response.matches("HTTP/1.1 200 OK").count(), 2, "{response}");
        assert!(response.contains("hello"));
    }

    #[tokio::test]
    async fn rejects_oversized_bodies_before_reading_them() {
        let response =
            exchange(b"POST /echo HTTP/1.1\r\nHost: h\r\nContent-Length: 99999999999\r\n\r\n")
                .await;
        assert!(response.starts_with("HTTP/1.1 413"), "{response}");
    }

    #[tokio::test]
    async fn graceful_shutdown_closes_idle_connections() {
        let (client, server) = tokio::io::duplex(1024);
        let (stop, shutdown) = watch::channel(false);
        let task = tokio::spawn(serve_connection(server, None, app(), Some(shutdown)));
        stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("connection closes on shutdown")
            .unwrap()
            .unwrap();
        drop(client);
    }

    #[test]
    fn loopback_detection() {
        assert!(is_loopback_bind("127.0.0.1:8080"));
        assert!(is_loopback_bind("[::1]:8080"));
        assert!(!is_loopback_bind("0.0.0.0:8080"));
        assert!(!is_loopback_bind("[::]:8080"));
    }
}
