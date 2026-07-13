use crate::config::TrackingConfig;
use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, SyncSender, TryRecvError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const EVENT_QUEUE_CAPACITY: usize = 8_192;
const MAX_EVENT_DETAIL_BYTES: usize = 2_048;
const MAX_DATAGRAM_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrackingEvent {
    pub timestamp_ms: i64,
    pub service: String,
    pub connection_id: String,
    pub message_id: Option<String>,
    pub direction: String,
    pub kind: String,
    pub phase: String,
    pub peer_addr: Option<String>,
    pub local_addr: Option<String>,
    pub detail: Option<String>,
    pub smtp_code: Option<u16>,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

impl TrackingEvent {
    pub fn new(
        service: impl Into<String>,
        connection_id: impl Into<String>,
        direction: impl Into<String>,
        kind: impl Into<String>,
        phase: impl Into<String>,
    ) -> Self {
        Self {
            timestamp_ms: now_millis(),
            service: service.into(),
            connection_id: connection_id.into(),
            message_id: None,
            direction: direction.into(),
            kind: kind.into(),
            phase: phase.into(),
            peer_addr: None,
            local_addr: None,
            detail: None,
            smtp_code: None,
            bytes_in: 0,
            bytes_out: 0,
        }
    }

    pub fn sanitize(mut self) -> Self {
        if let Some(detail) = self.detail.as_mut() {
            *detail = detail.replace(['\r', '\n', '\0'], " ");
            if detail.len() > MAX_EVENT_DETAIL_BYTES {
                let mut end = MAX_EVENT_DETAIL_BYTES;
                while !detail.is_char_boundary(end) {
                    end -= 1;
                }
                detail.truncate(end);
            }
        }
        self
    }
}

pub fn new_tracking_id(prefix: &str) -> String {
    format!(
        "{prefix}-{:x}-{:x}-{:x}",
        now_millis(),
        std::process::id(),
        rand::random::<u64>()
    )
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}

pub fn tracking_db_path(mail_root: &Path) -> PathBuf {
    mail_root.join("_tracking").join("events.sqlite")
}

#[cfg(unix)]
pub fn service_socket_path(mail_root: &Path, service: &str) -> PathBuf {
    mail_root
        .join("_runtime")
        .join("events")
        .join(format!("{service}.sock"))
}

#[cfg(unix)]
pub fn watcher_directory(mail_root: &Path) -> PathBuf {
    mail_root.join("_runtime").join("watch")
}

pub struct TrackingHub {
    sender: SyncSender<TrackingEvent>,
}

impl TrackingHub {
    #[cfg(unix)]
    pub fn start(mail_root: &Path, service: &str) -> Result<Self> {
        Self::start_with_config(mail_root, service, TrackingConfig::default())
    }

    #[cfg(unix)]
    pub fn start_with_config(
        mail_root: &Path,
        service: &str,
        config: TrackingConfig,
    ) -> Result<Self> {
        use std::os::unix::net::UnixDatagram;

        let db_path = tracking_db_path(mail_root);
        let socket_path = service_socket_path(mail_root, service);
        let watch_dir = watcher_directory(mail_root);
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::create_dir_all(&watch_dir)?;
        let _ = std::fs::remove_file(&socket_path);

        let (sender, receiver) = mpsc::sync_channel(EVENT_QUEUE_CAPACITY);
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name(format!("rmail-events-{service}"))
            .spawn(move || {
                let initialization = (|| -> Result<(Connection, UnixDatagram)> {
                    let connection = open_tracking_db(&db_path)?;
                    let socket = UnixDatagram::bind(&socket_path).with_context(|| {
                        format!("binding event socket {}", socket_path.display())
                    })?;
                    socket.set_nonblocking(true)?;
                    Ok((connection, socket))
                })();
                let (connection, socket) = match initialization {
                    Ok(state) => {
                        let _ = ready_sender.send(Ok(()));
                        state
                    }
                    Err(error) => {
                        let _ = ready_sender.send(Err(error.to_string()));
                        return;
                    }
                };
                run_event_loop(connection, socket, receiver, &watch_dir, config);
                let _ = std::fs::remove_file(socket_path);
            })
            .context("spawning event publisher")?;
        ready_receiver
            .recv()
            .context("waiting for event publisher startup")?
            .map_err(anyhow::Error::msg)?;
        Ok(Self { sender })
    }

    pub fn emit(&self, event: TrackingEvent) -> bool {
        let accepted = self.sender.try_send(event.sanitize()).is_ok();
        if !accepted {
            crate::metrics::inc_tracking_events_dropped();
        }
        accepted
    }
}

#[cfg(unix)]
fn run_event_loop(
    connection: Connection,
    socket: std::os::unix::net::UnixDatagram,
    receiver: mpsc::Receiver<TrackingEvent>,
    watch_dir: &Path,
    config: TrackingConfig,
) {
    let mut subscribers = HashSet::<PathBuf>::new();
    let mut subscribe_buffer = [0_u8; 4096];
    if let Err(error) = prune_tracking_events(&connection, config, true) {
        eprintln!("failed to prune tracking events at startup: {error}");
    }
    let prune_interval = Duration::from_secs(config.prune_interval_seconds.max(60));
    let mut next_prune = std::time::Instant::now() + prune_interval;
    loop {
        loop {
            match socket.recv(&mut subscribe_buffer) {
                Ok(length) => {
                    if let Ok(path) = std::str::from_utf8(&subscribe_buffer[..length]) {
                        let path = PathBuf::from(path);
                        if valid_watcher_path(&path, watch_dir) {
                            subscribers.insert(path.clone());
                            let _ = socket.send_to(b"{\"subscribed\":true}", path);
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }

        let first = match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(event) => Some(event),
            Err(mpsc::RecvTimeoutError::Timeout) => None,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };
        if let Some(event) = first {
            persist_and_publish(&connection, &socket, &mut subscribers, &event);
        }
        loop {
            match receiver.try_recv() {
                Ok(event) => persist_and_publish(&connection, &socket, &mut subscribers, &event),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return,
            }
        }
        if std::time::Instant::now() >= next_prune {
            if let Err(error) = prune_tracking_events(&connection, config, false) {
                eprintln!("failed to prune tracking events: {error}");
            }
            next_prune = std::time::Instant::now() + prune_interval;
        }
    }
}

#[cfg(unix)]
fn valid_watcher_path(path: &Path, watch_dir: &Path) -> bool {
    path.parent() == Some(watch_dir)
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("watch-") && name.ends_with(".sock"))
}

fn open_tracking_db(path: &Path) -> Result<Connection> {
    let connection = Connection::open(path)?;
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         CREATE TABLE IF NOT EXISTS events (
           id INTEGER PRIMARY KEY AUTOINCREMENT,
           timestamp_ms INTEGER NOT NULL,
           service TEXT NOT NULL,
           connection_id TEXT NOT NULL,
           message_id TEXT,
           direction TEXT NOT NULL,
           kind TEXT NOT NULL,
           phase TEXT NOT NULL,
           peer_addr TEXT,
           local_addr TEXT,
           detail TEXT,
           smtp_code INTEGER,
           bytes_in INTEGER NOT NULL,
           bytes_out INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS events_message_id ON events(message_id, id);
         CREATE INDEX IF NOT EXISTS events_connection_id ON events(connection_id, id);
         CREATE INDEX IF NOT EXISTS events_timestamp ON events(timestamp_ms, id);",
    )?;
    Ok(connection)
}

fn prune_tracking_events(
    connection: &Connection,
    config: TrackingConfig,
    startup: bool,
) -> Result<usize> {
    let batch = i64::from(config.prune_batch_size.max(1));
    let passes = if startup { 100 } else { 1 };
    let mut removed = 0;
    for _ in 0..passes {
        let mut pass_removed = 0;
        if config.retention_days != 0 {
            let cutoff = now_millis().saturating_sub(
                i64::from(config.retention_days).saturating_mul(24 * 60 * 60 * 1_000),
            );
            pass_removed += connection.execute(
                "DELETE FROM events WHERE id IN (SELECT id FROM events WHERE timestamp_ms < ?1 ORDER BY id LIMIT ?2)",
                params![cutoff, batch],
            )?;
        }
        if config.max_events != 0 {
            let count: i64 =
                connection.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?;
            let excess = count.saturating_sub(i64::try_from(config.max_events).unwrap_or(i64::MAX));
            if excess > 0 {
                pass_removed += connection.execute(
                    "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY id LIMIT ?1)",
                    [excess.min(batch)],
                )?;
            }
        }
        removed += pass_removed;
        if pass_removed == 0 {
            break;
        }
    }
    Ok(removed)
}

#[cfg(unix)]
fn persist_and_publish(
    connection: &Connection,
    socket: &std::os::unix::net::UnixDatagram,
    subscribers: &mut HashSet<PathBuf>,
    event: &TrackingEvent,
) {
    if let Err(error) = connection.execute(
        "INSERT INTO events(timestamp_ms, service, connection_id, message_id, direction, kind, phase, peer_addr, local_addr, detail, smtp_code, bytes_in, bytes_out)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            event.timestamp_ms,
            event.service,
            event.connection_id,
            event.message_id,
            event.direction,
            event.kind,
            event.phase,
            event.peer_addr,
            event.local_addr,
            event.detail,
            event.smtp_code,
            event.bytes_in as i64,
            event.bytes_out as i64,
        ],
    ) {
        crate::metrics::inc_tracking_events_dropped();
        eprintln!("failed to persist tracking event: {error}");
        return;
    }
    let Ok(serialized) = serde_json::to_vec(event) else {
        return;
    };
    if serialized.len() > MAX_DATAGRAM_BYTES {
        return;
    }
    subscribers.retain(|subscriber| socket.send_to(&serialized, subscriber).is_ok());
}

pub fn recent_events(
    mail_root: &Path,
    limit: usize,
    message_id: Option<&str>,
) -> Result<Vec<TrackingEvent>> {
    let connection = open_tracking_db(&tracking_db_path(mail_root))?;
    let limit = i64::try_from(limit.min(10_000)).unwrap_or(10_000);
    let sql = if message_id.is_some() {
        "SELECT timestamp_ms, service, connection_id, message_id, direction, kind, phase, peer_addr, local_addr, detail, smtp_code, bytes_in, bytes_out
         FROM events WHERE message_id = ?1 ORDER BY id DESC LIMIT ?2"
    } else {
        "SELECT timestamp_ms, service, connection_id, message_id, direction, kind, phase, peer_addr, local_addr, detail, smtp_code, bytes_in, bytes_out
         FROM events ORDER BY id DESC LIMIT ?2"
    };
    let mut statement = connection.prepare(sql)?;
    let mapper = |row: &rusqlite::Row<'_>| {
        Ok(TrackingEvent {
            timestamp_ms: row.get(0)?,
            service: row.get(1)?,
            connection_id: row.get(2)?,
            message_id: row.get(3)?,
            direction: row.get(4)?,
            kind: row.get(5)?,
            phase: row.get(6)?,
            peer_addr: row.get(7)?,
            local_addr: row.get(8)?,
            detail: row.get(9)?,
            smtp_code: row.get(10)?,
            bytes_in: row.get::<_, i64>(11)?.max(0) as u64,
            bytes_out: row.get::<_, i64>(12)?.max(0) as u64,
        })
    };
    let rows = if let Some(message_id) = message_id {
        statement.query_map(params![message_id, limit], mapper)?
    } else {
        statement.query_map(params![rusqlite::types::Null, limit], mapper)?
    };
    let mut events = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    events.reverse();
    Ok(events)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;

    #[test]
    fn events_are_persisted_and_published_over_unix_datagrams() {
        let temporary = tempfile::tempdir().unwrap();
        let hub = TrackingHub::start(temporary.path(), "smtpd").unwrap();
        let watch_dir = watcher_directory(temporary.path());
        let watcher_path = watch_dir.join("watch-test.sock");
        let watcher = UnixDatagram::bind(&watcher_path).unwrap();
        watcher
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        watcher
            .send_to(
                watcher_path.to_string_lossy().as_bytes(),
                service_socket_path(temporary.path(), "smtpd"),
            )
            .unwrap();
        let mut buffer = [0_u8; MAX_DATAGRAM_BYTES];
        let length = watcher.recv(&mut buffer).unwrap();
        assert_eq!(&buffer[..length], b"{\"subscribed\":true}");

        let mut event = TrackingEvent::new("smtpd", "conn-1", "inbound", "command", "mail");
        event.message_id = Some("msg-1".to_string());
        event.peer_addr = Some("192.0.2.1:25".to_string());
        event.detail = Some("MAIL FROM:<sender@example.test>\r\ninjected".to_string());
        event.bytes_in = 42;
        assert!(hub.emit(event.clone()));

        let length = watcher.recv(&mut buffer).unwrap();
        let live: TrackingEvent = serde_json::from_slice(&buffer[..length]).unwrap();
        assert_eq!(live.message_id.as_deref(), Some("msg-1"));
        assert_eq!(
            live.detail.as_deref(),
            Some("MAIL FROM:<sender@example.test>  injected")
        );

        let persisted = recent_events(temporary.path(), 10, Some("msg-1")).unwrap();
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0], live);
    }

    #[test]
    fn event_details_are_utf8_safely_bounded() {
        let mut event = TrackingEvent::new("smtpd", "conn", "inbound", "reply", "data");
        event.detail = Some("€".repeat(MAX_EVENT_DETAIL_BYTES));
        let event = event.sanitize();

        assert!(event.detail.unwrap().len() <= MAX_EVENT_DETAIL_BYTES);
    }

    #[test]
    fn retention_prunes_old_and_excess_events_in_bounded_batches() {
        let temporary = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temporary.path().join("_tracking")).unwrap();
        let connection = open_tracking_db(&tracking_db_path(temporary.path())).unwrap();
        let insert = |timestamp_ms: i64| {
            connection.execute(
                "INSERT INTO events(timestamp_ms, service, connection_id, direction, kind, phase, bytes_in, bytes_out)
                 VALUES(?1, 'smtpd', 'connection', 'inbound', 'reply', 'smtp_reply', 0, 0)",
                [timestamp_ms],
            ).unwrap();
        };
        insert(now_millis() - 3 * 24 * 60 * 60 * 1_000);
        insert(now_millis() - 2 * 24 * 60 * 60 * 1_000);
        insert(now_millis());
        let age_config = TrackingConfig {
            retention_days: 1,
            max_events: 0,
            prune_interval_seconds: 60,
            prune_batch_size: 1,
        };
        assert_eq!(
            prune_tracking_events(&connection, age_config, false).unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM events", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            prune_tracking_events(&connection, age_config, true).unwrap(),
            1
        );

        for _ in 0..5 {
            insert(now_millis());
        }
        let count_config = TrackingConfig {
            retention_days: 0,
            max_events: 2,
            prune_interval_seconds: 60,
            prune_batch_size: 2,
        };
        assert_eq!(
            prune_tracking_events(&connection, count_config, true).unwrap(),
            4
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM events", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
    }
}
