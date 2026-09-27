//! Per-connection tracking: byte counters, SMTP reply capture and the
//! durable tracking hub.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};

#[cfg(test)]
use once_cell::sync::Lazy;
use once_cell::sync::OnceCell;
use rmail_common::metrics;
use rmail_common::tracking::{TrackingEvent, TrackingHub, new_tracking_id};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::AsyncStream;

pub(crate) static TRACKING_HUB: OnceCell<Arc<TrackingHub>> = OnceCell::new();
#[cfg(test)]
pub(crate) static TRACKING_TEST_EVENTS: Lazy<Mutex<Vec<TrackingEvent>>> =
    Lazy::new(|| Mutex::new(Vec::new()));

#[derive(Clone)]
pub(crate) struct ConnectionTrace {
    pub(crate) id: String,
    pub(crate) local_addr: Option<SocketAddr>,
    pub(crate) state: Arc<ReplyTraceState>,
}

#[derive(Default)]
pub(crate) struct ReplyTraceState {
    pub(crate) message_id: Mutex<Option<String>>,
    pub(crate) bytes_in: AtomicU64,
    pub(crate) bytes_out: AtomicU64,
}

impl ConnectionTrace {
    pub(crate) fn new(local_addr: Option<SocketAddr>) -> Self {
        Self {
            id: new_tracking_id("smtp-conn"),
            local_addr,
            state: Arc::new(ReplyTraceState::default()),
        }
    }

    /// Inbound tracking event for this connection with current byte counters.
    pub(crate) fn event(
        &self,
        peer: Option<SocketAddr>,
        message_id: Option<String>,
        kind: &str,
        phase: &str,
    ) -> TrackingEvent {
        let mut event = TrackingEvent::new("smtpd", &self.id, "inbound", kind, phase);
        event.message_id = message_id;
        event.peer_addr = peer.map(|address| address.to_string());
        event.local_addr = self.local_addr.map(|address| address.to_string());
        event.bytes_in = self.state.bytes_in.load(Ordering::Relaxed);
        event.bytes_out = self.state.bytes_out.load(Ordering::Relaxed);
        event
    }

    pub(crate) fn set_message_id(&self, message_id: Option<String>) {
        if let Ok(mut current) = self.state.message_id.lock() {
            *current = message_id;
        }
    }
}

pub(crate) struct ReplyTrackingStream {
    inner: Box<dyn AsyncStream + Send + 'static>,
    trace: ConnectionTrace,
    peer: Option<SocketAddr>,
    enabled: bool,
    reply_line: Vec<u8>,
}

impl ReplyTrackingStream {
    pub(crate) fn new(
        inner: Box<dyn AsyncStream + Send + 'static>,
        trace: ConnectionTrace,
        peer: Option<SocketAddr>,
    ) -> Self {
        Self {
            inner,
            trace,
            peer,
            enabled: true,
            reply_line: Vec::with_capacity(512),
        }
    }

    pub(crate) fn disable(&mut self) {
        self.enabled = false;
    }

    fn record_written(&mut self, bytes: &[u8]) {
        if !self.enabled {
            return;
        }
        self.trace
            .state
            .bytes_out
            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        for byte in bytes {
            self.reply_line.push(*byte);
            if self.reply_line.ends_with(b"\r\n") {
                if self.reply_line.len() >= 5
                    && self.reply_line[..3].iter().all(u8::is_ascii_digit)
                    && matches!(self.reply_line[3], b' ' | b'-')
                {
                    let code = std::str::from_utf8(&self.reply_line[..3])
                        .ok()
                        .and_then(|value| value.parse().ok());
                    let mut event = TrackingEvent::new(
                        "smtpd",
                        &self.trace.id,
                        "inbound",
                        "reply",
                        "smtp_reply",
                    );
                    event.message_id = self
                        .trace
                        .state
                        .message_id
                        .lock()
                        .ok()
                        .and_then(|value| value.clone());
                    event.peer_addr = self.peer.map(|address| address.to_string());
                    event.local_addr = self.trace.local_addr.map(|address| address.to_string());
                    event.detail =
                        Some(String::from_utf8_lossy(&self.reply_line).trim().to_string());
                    event.smtp_code = code;
                    if let Some(code) = code {
                        metrics::inc_smtp_response(metrics::SmtpDirection::Inbound, code);
                    }
                    event.bytes_in = self.trace.state.bytes_in.load(Ordering::Relaxed);
                    event.bytes_out = self.trace.state.bytes_out.load(Ordering::Relaxed);
                    emit_tracking(event);
                }
                self.reply_line.clear();
            } else if self.reply_line.len() > 4096 {
                self.reply_line.clear();
            }
        }
    }
}

impl AsyncRead for ReplyTrackingStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buffer.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buffer);
        if this.enabled && matches!(result, Poll::Ready(Ok(()))) {
            this.trace
                .state
                .bytes_in
                .fetch_add((buffer.filled().len() - before) as u64, Ordering::Relaxed);
        }
        result
    }
}

impl AsyncWrite for ReplyTrackingStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, bytes) {
            Poll::Ready(Ok(written)) => {
                this.record_written(&bytes[..written]);
                Poll::Ready(Ok(written))
            }
            other => other,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

pub(crate) fn emit_tracking(event: TrackingEvent) {
    #[cfg(test)]
    TRACKING_TEST_EVENTS.lock().unwrap().push(event.clone());
    if let Some(hub) = TRACKING_HUB.get() {
        let _ = hub.emit(event);
    }
}
