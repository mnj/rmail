use anyhow::{Context, Result};
use chrono::{DateTime, Local};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::{
    DefaultTerminal, Frame,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
};
use rmail_common::tracking::{
    TrackingEvent, recent_events, service_socket_path, watcher_directory,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;
use trust_dns_resolver::TokioAsyncResolver;

const MAX_EVENTS: usize = 10_000;

pub fn run(root: &Path, plain: bool, history: usize) -> Result<()> {
    let mut feed = EventFeed::connect(root)?;
    let mut state = WatchState::new(recent_events(root, history, None)?);
    let dns = ReverseDns::start();
    state.request_dns(&dns);
    if plain {
        return run_plain(&mut feed, &dns, state);
    }

    let mut terminal = ratatui::init();
    let result = run_tui(&mut terminal, &mut feed, &dns, &mut state);
    ratatui::restore();
    result
}

fn run_plain(feed: &mut EventFeed, dns: &ReverseDns, mut state: WatchState) -> Result<()> {
    loop {
        if let Some(event) = feed.receive()? {
            state.add(event.clone());
            state.request_dns(dns);
            state.apply_dns(dns);
            println!(
                "{} {:8} {:9} {:16} {} -> {} {}{}",
                display_time(event.timestamp_ms),
                event.service,
                event.direction,
                event.phase,
                display_endpoint(event.local_addr.as_deref(), &state.hostnames),
                display_endpoint(event.peer_addr.as_deref(), &state.hostnames),
                event.detail.as_deref().unwrap_or(""),
                event
                    .smtp_code
                    .map(|code| format!(" [{code}]"))
                    .unwrap_or_default()
            );
        }
    }
}

fn run_tui(
    terminal: &mut DefaultTerminal,
    feed: &mut EventFeed,
    dns: &ReverseDns,
    state: &mut WatchState,
) -> Result<()> {
    loop {
        while let Some(item) = feed.receive()? {
            state.add(item);
        }
        state.request_dns(dns);
        state.apply_dns(dns);
        terminal.draw(|frame| draw(frame, state))?;
        if event::poll(Duration::from_millis(100))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                KeyCode::Up | KeyCode::Char('k') => state.select_previous(),
                KeyCode::Down | KeyCode::Char('j') => state.select_next(),
                KeyCode::Home => state.selected = 0,
                KeyCode::End => state.selected = state.events.len().saturating_sub(1),
                _ => {}
            }
        }
    }
}

fn draw(frame: &mut Frame<'_>, state: &mut WatchState) {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Percentage(45),
            Constraint::Min(8),
        ])
        .split(frame.area());
    let active = state.active_connections();
    let inbound = active
        .iter()
        .filter(|event| event.direction == "inbound")
        .count();
    let outbound = active.len().saturating_sub(inbound);
    let bytes_in: u64 = active.iter().map(|event| event.bytes_in).sum();
    let bytes_out: u64 = active.iter().map(|event| event.bytes_out).sum();
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                " rMail watch ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "  active {}  inbound {}  outbound {}  rx {}  tx {}",
                active.len(),
                inbound,
                outbound,
                human_bytes(bytes_in),
                human_bytes(bytes_out)
            )),
            Span::styled(
                "    q quit  ↑/↓ inspect",
                Style::default().fg(Color::DarkGray),
            ),
        ]))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        ),
        areas[0],
    );

    let rows = active.into_iter().map(|item| {
        Row::new(vec![
            Cell::from(display_time(item.timestamp_ms)),
            Cell::from(item.direction.clone()),
            Cell::from(display_endpoint(
                item.peer_addr.as_deref(),
                &state.hostnames,
            )),
            Cell::from(item.phase.clone()),
            Cell::from(item.message_id.clone().unwrap_or_default()),
            Cell::from(format!(
                "{} / {}",
                human_bytes(item.bytes_in),
                human_bytes(item.bytes_out)
            )),
        ])
    });
    frame.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(9),
                Constraint::Length(9),
                Constraint::Percentage(30),
                Constraint::Length(16),
                Constraint::Percentage(28),
                Constraint::Length(15),
            ],
        )
        .header(
            Row::new(["updated", "flow", "remote", "phase", "message", "rx / tx"]).style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        )
        .column_spacing(1)
        .block(
            Block::default()
                .title(" active SMTP connections ")
                .borders(Borders::ALL),
        ),
        areas[1],
    );

    let visible = usize::from(areas[2].height.saturating_sub(3));
    let start = state.selected.saturating_sub(visible.saturating_sub(1));
    let rows = state.events.iter().skip(start).take(visible).map(|item| {
        Row::new(vec![
            Cell::from(display_time(item.timestamp_ms)),
            Cell::from(item.service.clone()),
            Cell::from(item.kind.clone()),
            Cell::from(item.phase.clone()),
            Cell::from(
                item.smtp_code
                    .map(|code| code.to_string())
                    .unwrap_or_default(),
            ),
            Cell::from(item.detail.clone().unwrap_or_default()),
        ])
    });
    let mut table_state =
        TableState::default().with_selected(Some(state.selected.saturating_sub(start)));
    frame.render_stateful_widget(
        Table::new(
            rows,
            [
                Constraint::Length(9),
                Constraint::Length(9),
                Constraint::Length(12),
                Constraint::Length(15),
                Constraint::Length(5),
                Constraint::Min(15),
            ],
        )
        .header(
            Row::new(["time", "service", "event", "phase", "code", "detail"]).style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .block(
            Block::default()
                .title(" delivery timeline ")
                .borders(Borders::ALL),
        ),
        areas[2],
        &mut table_state,
    );
}

struct WatchState {
    events: VecDeque<TrackingEvent>,
    selected: usize,
    hostnames: HashMap<IpAddr, Option<String>>,
    dns_pending: HashSet<IpAddr>,
}

impl WatchState {
    fn new(events: Vec<TrackingEvent>) -> Self {
        let selected = events.len().saturating_sub(1);
        Self {
            events: events.into(),
            selected,
            hostnames: HashMap::new(),
            dns_pending: HashSet::new(),
        }
    }

    fn add(&mut self, event: TrackingEvent) {
        if self.events.len() == MAX_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(event);
        self.selected = self.events.len().saturating_sub(1);
    }

    fn active_connections(&self) -> Vec<&TrackingEvent> {
        let mut latest = HashMap::<&str, &TrackingEvent>::new();
        for event in &self.events {
            latest.insert(&event.connection_id, event);
        }
        let mut active: Vec<_> = latest
            .into_values()
            .filter(|event| {
                !matches!(
                    event.phase.as_str(),
                    "disconnected" | "delivered" | "failed"
                )
            })
            .collect();
        active.sort_by_key(|event| std::cmp::Reverse(event.timestamp_ms));
        active
    }

    fn request_dns(&mut self, dns: &ReverseDns) {
        for event in &self.events {
            for address in [&event.peer_addr, &event.local_addr].into_iter().flatten() {
                if let Ok(address) = address.parse::<SocketAddr>() {
                    let ip = address.ip();
                    if !self.hostnames.contains_key(&ip) && self.dns_pending.insert(ip) {
                        dns.request(ip);
                    }
                }
            }
        }
    }

    fn apply_dns(&mut self, dns: &ReverseDns) {
        while let Ok((ip, hostname)) = dns.results.try_recv() {
            self.dns_pending.remove(&ip);
            self.hostnames.insert(ip, hostname);
        }
    }

    fn select_previous(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }
    fn select_next(&mut self) {
        self.selected = (self.selected + 1).min(self.events.len().saturating_sub(1));
    }
}

struct EventFeed {
    socket: UnixDatagram,
    path: PathBuf,
}

impl EventFeed {
    fn connect(root: &Path) -> Result<Self> {
        let directory = watcher_directory(root);
        std::fs::create_dir_all(&directory)?;
        let path = directory.join(format!(
            "watch-{}-{:x}.sock",
            std::process::id(),
            rand::random::<u32>()
        ));
        let socket = UnixDatagram::bind(&path)
            .with_context(|| format!("binding watcher socket {}", path.display()))?;
        socket.set_nonblocking(true)?;
        for service in ["smtpd", "outbound"] {
            let service_path = service_socket_path(root, service);
            if service_path.exists() {
                let _ = socket.send_to(path.to_string_lossy().as_bytes(), service_path);
            }
        }
        Ok(Self { socket, path })
    }

    fn receive(&mut self) -> Result<Option<TrackingEvent>> {
        let mut buffer = [0_u8; 16 * 1024];
        match self.socket.recv(&mut buffer) {
            Ok(length) if buffer[..length].starts_with(b"{\"subscribed\"") => Ok(None),
            Ok(length) => Ok(Some(serde_json::from_slice(&buffer[..length])?)),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}

impl Drop for EventFeed {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

struct ReverseDns {
    requests: mpsc::Sender<IpAddr>,
    results: mpsc::Receiver<(IpAddr, Option<String>)>,
}

impl ReverseDns {
    fn start() -> Self {
        let (request_tx, request_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("DNS runtime");
            runtime.block_on(async move {
                let resolver = TokioAsyncResolver::tokio_from_system_conf().ok();
                while let Ok(ip) = request_rx.recv() {
                    let hostname = if let Some(resolver) = &resolver {
                        tokio::time::timeout(Duration::from_secs(2), resolver.reverse_lookup(ip))
                            .await
                            .ok()
                            .and_then(Result::ok)
                            .and_then(|lookup| {
                                lookup
                                    .iter()
                                    .next()
                                    .map(|name| name.to_utf8().trim_end_matches('.').to_string())
                            })
                    } else {
                        None
                    };
                    let _ = result_tx.send((ip, hostname));
                }
            });
        });
        Self {
            requests: request_tx,
            results: result_rx,
        }
    }
    fn request(&self, ip: IpAddr) {
        let _ = self.requests.send(ip);
    }
}

fn display_endpoint(value: Option<&str>, hostnames: &HashMap<IpAddr, Option<String>>) -> String {
    let Some(value) = value else {
        return "-".into();
    };
    let Ok(address) = value.parse::<SocketAddr>() else {
        return value.into();
    };
    match hostnames.get(&address.ip()).and_then(Option::as_deref) {
        Some(host) => format!("{host} ({address})"),
        None => address.to_string(),
    }
}

fn display_time(timestamp_ms: i64) -> String {
    DateTime::from_timestamp_millis(timestamp_ms)
        .map(|time| time.with_timezone(&Local).format("%H:%M:%S").to_string())
        .unwrap_or_else(|| "--:--:--".into())
}

fn human_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", bytes as f64 / 1024.0 / 1024.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    fn event(connection: &str, phase: &str, timestamp_ms: i64) -> TrackingEvent {
        let mut event = TrackingEvent::new("smtpd", connection, "inbound", "command", phase);
        event.timestamp_ms = timestamp_ms;
        event.peer_addr = Some("192.0.2.8:25".into());
        event.message_id = Some("message-test".into());
        event
    }

    #[test]
    fn terminal_view_renders_active_connections_and_timeline() {
        let mut state = WatchState::new(vec![event("connection-test", "mail", 1_700_000_000_000)]);
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &mut state)).unwrap();
        let rendered = terminal.backend().to_string();
        assert!(rendered.contains("active SMTP connections"));
        assert!(rendered.contains("message-test"));
        assert!(rendered.contains("delivery timeline"));
    }

    #[test]
    fn disconnected_connections_leave_the_active_table() {
        let state = WatchState::new(vec![
            event("one", "mail", 1),
            event("one", "disconnected", 2),
            event("two", "data", 3),
        ]);
        let active = state.active_connections();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].connection_id, "two");
    }

    #[test]
    fn watcher_receives_events_from_both_smtp_services() {
        let temporary = tempfile::tempdir().unwrap();
        let smtpd = rmail_common::tracking::TrackingHub::start(temporary.path(), "smtpd").unwrap();
        let outbound =
            rmail_common::tracking::TrackingHub::start(temporary.path(), "outbound").unwrap();
        let mut feed = EventFeed::connect(temporary.path()).unwrap();
        std::thread::sleep(Duration::from_millis(150));

        smtpd.emit(event("inbound-test", "mail", 1));
        let mut outgoing = event("outbound-test", "rcpt", 2);
        outgoing.service = "outbound".into();
        outgoing.direction = "outbound".into();
        outbound.emit(outgoing);

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut services = HashSet::new();
        while services.len() < 2 && std::time::Instant::now() < deadline {
            if let Some(event) = feed.receive().unwrap() {
                services.insert(event.service);
            } else {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        assert_eq!(services, HashSet::from(["smtpd".into(), "outbound".into()]));
    }
}
