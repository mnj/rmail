use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const HISTOGRAM_BOUNDS_US: [u64; 14] = [
    1_000,
    5_000,
    10_000,
    25_000,
    50_000,
    100_000,
    250_000,
    500_000,
    1_000_000,
    5_000_000,
    30_000_000,
    300_000_000,
    3_600_000_000,
    86_400_000_000,
];

struct Histogram {
    buckets: [AtomicU64; HISTOGRAM_BOUNDS_US.len() + 1],
    count: AtomicU64,
    sum_us: AtomicU64,
}

impl Histogram {
    const fn new() -> Self {
        Self {
            buckets: [const { AtomicU64::new(0) }; HISTOGRAM_BOUNDS_US.len() + 1],
            count: AtomicU64::new(0),
            sum_us: AtomicU64::new(0),
        }
    }

    fn observe(&self, duration: Duration) {
        let micros = duration.as_micros().min(u128::from(u64::MAX)) as u64;
        let index = HISTOGRAM_BOUNDS_US
            .iter()
            .position(|bound| micros <= *bound)
            .unwrap_or(HISTOGRAM_BOUNDS_US.len());
        self.buckets[index].fetch_add(1, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_us.fetch_add(micros, Ordering::Relaxed);
    }

    fn render(&self, output: &mut String, name: &str, help: &str) {
        output.push_str(&format!("# HELP {name} {help}\n# TYPE {name} histogram\n"));
        let mut cumulative = 0;
        for (index, bound) in HISTOGRAM_BOUNDS_US.iter().enumerate() {
            cumulative += self.buckets[index].load(Ordering::Relaxed);
            output.push_str(&format!(
                "{name}_bucket{{le=\"{}\"}} {cumulative}\n",
                *bound as f64 / 1_000_000.0
            ));
        }
        cumulative += self.buckets[HISTOGRAM_BOUNDS_US.len()].load(Ordering::Relaxed);
        output.push_str(&format!("{name}_bucket{{le=\"+Inf\"}} {cumulative}\n"));
        output.push_str(&format!(
            "{name}_sum {}\n{name}_count {}\n",
            self.sum_us.load(Ordering::Relaxed) as f64 / 1_000_000.0,
            self.count.load(Ordering::Relaxed)
        ));
    }
}

static DNS_DURATION: Histogram = Histogram::new();
static TLS_HANDSHAKE_DURATION: Histogram = Histogram::new();
static SCANNER_DURATION: Histogram = Histogram::new();
static QUEUE_DELAY: Histogram = Histogram::new();
static IMAP_COMMAND_DURATION: Histogram = Histogram::new();
static DATABASE_WAIT_DURATION: Histogram = Histogram::new();

pub struct HistogramTimer {
    histogram: &'static Histogram,
    started: std::time::Instant,
}

impl Drop for HistogramTimer {
    fn drop(&mut self) {
        self.histogram.observe(self.started.elapsed());
    }
}

pub fn imap_command_timer() -> HistogramTimer {
    HistogramTimer {
        histogram: &IMAP_COMMAND_DURATION,
        started: std::time::Instant::now(),
    }
}

pub fn observe_dns_duration(duration: Duration) {
    DNS_DURATION.observe(duration);
}
pub fn observe_tls_handshake_duration(duration: Duration) {
    TLS_HANDSHAKE_DURATION.observe(duration);
}
pub fn observe_scanner_duration(duration: Duration) {
    SCANNER_DURATION.observe(duration);
}
pub fn observe_queue_delay(duration: Duration) {
    QUEUE_DELAY.observe(duration);
}
pub fn observe_imap_command_duration(duration: Duration) {
    IMAP_COMMAND_DURATION.observe(duration);
}
pub fn observe_database_wait_duration(duration: Duration) {
    DATABASE_WAIT_DURATION.observe(duration);
}

pub static DELIVERIES_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static DELIVERIES_FAILED_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static DELIVERED_BYTES_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static DELIVERY_LATENCY_US_SUM: AtomicU64 = AtomicU64::new(0);
pub static DELIVERY_LATENCY_US_COUNT: AtomicU64 = AtomicU64::new(0);
pub static CONNECTIONS_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static TLS_HANDSHAKES_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static BYTES_RECEIVED_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static TRACKING_EVENTS_DROPPED_TOTAL: AtomicU64 = AtomicU64::new(0);
// Authentication failures recorded by servers (incremented on each failed auth attempt)
pub static AUTH_FAILURES_TOTAL: AtomicU64 = AtomicU64::new(0);
// Mail auth metrics
pub static DKIM_PASS_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static DKIM_FAIL_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static SPF_PASS_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static SPF_FAIL_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static DMARC_PASS_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static DMARC_QUARANTINE_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static DMARC_REJECT_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static ARC_PASS_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static ARC_FAIL_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static ARC_SEALED_TOTAL: AtomicU64 = AtomicU64::new(0);
static SMTP_MESSAGES_RECEIVED: [AtomicU64; 12] = [const { AtomicU64::new(0) }; 12];
static LMTP_MESSAGES_RECEIVED: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
static SMTP_RESPONSES: [AtomicU64; 1_200] = [const { AtomicU64::new(0) }; 1_200];

#[derive(Clone, Copy)]
pub enum SmtpDirection {
    Inbound,
    Outbound,
}

pub fn inc_smtp_response(direction: SmtpDirection, code: u16) {
    if code >= 600 {
        return;
    }
    let offset = match direction {
        SmtpDirection::Inbound => 0,
        SmtpDirection::Outbound => 600,
    };
    SMTP_RESPONSES[offset + usize::from(code)].fetch_add(1, Ordering::Relaxed);
}

pub fn inc_deliveries() {
    DELIVERIES_TOTAL.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_failed_deliveries() {
    DELIVERIES_FAILED_TOTAL.fetch_add(1, Ordering::Relaxed);
}
pub fn add_delivered_bytes(n: u64) {
    DELIVERED_BYTES_TOTAL.fetch_add(n, Ordering::Relaxed);
}
pub fn observe_delivery_latency_us(us: u64) {
    DELIVERY_LATENCY_US_SUM.fetch_add(us, Ordering::Relaxed);
    DELIVERY_LATENCY_US_COUNT.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_connections() {
    CONNECTIONS_TOTAL.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_tls_handshakes() {
    TLS_HANDSHAKES_TOTAL.fetch_add(1, Ordering::Relaxed);
}
pub fn add_bytes_received(n: u64) {
    BYTES_RECEIVED_TOTAL.fetch_add(n, Ordering::Relaxed);
}
pub fn inc_tracking_events_dropped() {
    TRACKING_EVENTS_DROPPED_TOTAL.fetch_add(1, Ordering::Relaxed);
}
/// Increment the total count of recorded authentication failures. This is a best-effort
/// metric to track brute-force attempts and can be monitored via the web UI.
pub fn inc_auth_failures() {
    AUTH_FAILURES_TOTAL.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_dkim_pass() {
    DKIM_PASS_TOTAL.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_dkim_fail() {
    DKIM_FAIL_TOTAL.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_spf_pass() {
    SPF_PASS_TOTAL.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_spf_fail() {
    SPF_FAIL_TOTAL.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_dmarc_pass() {
    DMARC_PASS_TOTAL.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_dmarc_quarantine() {
    DMARC_QUARANTINE_TOTAL.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_dmarc_reject() {
    DMARC_REJECT_TOTAL.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_arc_pass() {
    ARC_PASS_TOTAL.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_arc_fail() {
    ARC_FAIL_TOTAL.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_arc_sealed() {
    ARC_SEALED_TOTAL.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_smtp_message_received(
    peer: Option<SocketAddr>,
    implicit_tls: bool,
    encrypted: bool,
    extended_smtp: bool,
) {
    let ip_index = usize::from(peer.is_some_and(|address| address.is_ipv6()));
    let transport_index = if implicit_tls {
        2
    } else if encrypted {
        1
    } else {
        0
    };
    let protocol_index = usize::from(extended_smtp);
    SMTP_MESSAGES_RECEIVED[ip_index * 6 + transport_index * 2 + protocol_index]
        .fetch_add(1, Ordering::Relaxed);
}

pub fn inc_lmtp_message_received(peer: Option<SocketAddr>) {
    let ip_index = usize::from(peer.is_some_and(|address| address.is_ipv6()));
    LMTP_MESSAGES_RECEIVED[ip_index].fetch_add(1, Ordering::Relaxed);
}

pub fn gather_prometheus() -> String {
    let mut out = String::new();
    out.push_str("# HELP rmail_deliveries_total Total number of successful deliveries\n");
    out.push_str("# TYPE rmail_deliveries_total counter\n");
    out.push_str(&format!(
        "rmail_deliveries_total {}\n",
        DELIVERIES_TOTAL.load(Ordering::Relaxed)
    ));
    out.push_str("# HELP rmail_deliveries_failed_total Total number of failed deliveries\n");
    out.push_str("# TYPE rmail_deliveries_failed_total counter\n");
    out.push_str(&format!(
        "rmail_deliveries_failed_total {}\n",
        DELIVERIES_FAILED_TOTAL.load(Ordering::Relaxed)
    ));
    out.push_str("# HELP rmail_delivered_bytes_total Total bytes delivered\n");
    out.push_str("# TYPE rmail_delivered_bytes_total counter\n");
    out.push_str(&format!(
        "rmail_delivered_bytes_total {}\n",
        DELIVERED_BYTES_TOTAL.load(Ordering::Relaxed)
    ));
    out.push_str("# HELP rmail_delivery_latency_seconds_avg Average delivery latency in seconds\n");
    out.push_str("# TYPE rmail_delivery_latency_seconds_avg gauge\n");
    let cnt = DELIVERY_LATENCY_US_COUNT.load(Ordering::Relaxed);
    let sum_us = DELIVERY_LATENCY_US_SUM.load(Ordering::Relaxed);
    let avg_secs = if cnt == 0 {
        0.0
    } else {
        (sum_us as f64) / (cnt as f64) / 1_000_000.0
    };
    out.push_str(&format!(
        "rmail_delivery_latency_seconds_avg {}\n",
        avg_secs
    ));
    out.push_str("# HELP rmail_connections_total Total accepted connections\n");
    out.push_str("# TYPE rmail_connections_total counter\n");
    out.push_str(&format!(
        "rmail_connections_total {}\n",
        CONNECTIONS_TOTAL.load(Ordering::Relaxed)
    ));
    out.push_str("# HELP rmail_tls_handshakes_total Total TLS handshakes\n");
    out.push_str("# TYPE rmail_tls_handshakes_total counter\n");
    out.push_str(&format!(
        "rmail_tls_handshakes_total {}\n",
        TLS_HANDSHAKES_TOTAL.load(Ordering::Relaxed)
    ));
    out.push_str("# HELP rmail_bytes_received_total Total bytes received\n");
    out.push_str("# TYPE rmail_bytes_received_total counter\n");
    out.push_str(&format!(
        "rmail_bytes_received_total {}\n",
        BYTES_RECEIVED_TOTAL.load(Ordering::Relaxed)
    ));
    out.push_str("# HELP rmail_tracking_events_dropped_total Tracking events dropped before durable storage\n");
    out.push_str("# TYPE rmail_tracking_events_dropped_total counter\n");
    out.push_str(&format!(
        "rmail_tracking_events_dropped_total {}\n",
        TRACKING_EVENTS_DROPPED_TOTAL.load(Ordering::Relaxed)
    ));
    out.push_str("# HELP rmail_smtp_messages_received_total Accepted SMTP messages by IP version, transport, and greeting protocol\n");
    out.push_str("# TYPE rmail_smtp_messages_received_total counter\n");
    for (ip_index, ip_version) in ["4", "6"].iter().enumerate() {
        for (transport_index, transport) in ["plain", "starttls", "implicit_tls"].iter().enumerate()
        {
            for (protocol_index, protocol) in ["smtp", "esmtp"].iter().enumerate() {
                let value = SMTP_MESSAGES_RECEIVED
                    [ip_index * 6 + transport_index * 2 + protocol_index]
                    .load(Ordering::Relaxed);
                out.push_str(&format!(
                    "rmail_smtp_messages_received_total{{ip_version=\"{ip_version}\",transport=\"{transport}\",protocol=\"{protocol}\"}} {value}\n"
                ));
            }
        }
        out.push_str(&format!(
            "rmail_smtp_messages_received_total{{ip_version=\"{ip_version}\",transport=\"plain\",protocol=\"lmtp\"}} {}\n",
            LMTP_MESSAGES_RECEIVED[ip_index].load(Ordering::Relaxed)
        ));
    }
    out.push_str("# HELP rmail_smtp_responses_total SMTP replies by direction and status code\n");
    out.push_str("# TYPE rmail_smtp_responses_total counter\n");
    for (offset, direction) in [(0, "inbound"), (600, "outbound")] {
        for code in 200..600 {
            let value = SMTP_RESPONSES[offset + code].load(Ordering::Relaxed);
            if value != 0 {
                out.push_str(&format!(
                    "rmail_smtp_responses_total{{direction=\"{direction}\",code=\"{code}\"}} {value}\n"
                ));
            }
        }
    }
    out.push_str("# HELP rmail_auth_failures_total Total authentication failures recorded\n");
    out.push_str("# TYPE rmail_auth_failures_total counter\n");
    out.push_str(&format!(
        "rmail_auth_failures_total {}\n",
        AUTH_FAILURES_TOTAL.load(Ordering::Relaxed)
    ));
    out.push_str("# HELP rmail_dkim_pass_total DKIM verification pass count\n");
    out.push_str("# TYPE rmail_dkim_pass_total counter\n");
    out.push_str(&format!(
        "rmail_dkim_pass_total {}\n",
        DKIM_PASS_TOTAL.load(Ordering::Relaxed)
    ));
    out.push_str("# HELP rmail_dkim_fail_total DKIM verification failure count\n");
    out.push_str("# TYPE rmail_dkim_fail_total counter\n");
    out.push_str(&format!(
        "rmail_dkim_fail_total {}\n",
        DKIM_FAIL_TOTAL.load(Ordering::Relaxed)
    ));
    out.push_str("# HELP rmail_spf_pass_total SPF verification pass count\n");
    out.push_str("# TYPE rmail_spf_pass_total counter\n");
    out.push_str(&format!(
        "rmail_spf_pass_total {}\n",
        SPF_PASS_TOTAL.load(Ordering::Relaxed)
    ));
    out.push_str("# HELP rmail_spf_fail_total SPF verification failure count\n");
    out.push_str("# TYPE rmail_spf_fail_total counter\n");
    out.push_str(&format!(
        "rmail_spf_fail_total {}\n",
        SPF_FAIL_TOTAL.load(Ordering::Relaxed)
    ));
    out.push_str("# HELP rmail_dmarc_pass_total DMARC alignment pass count\n");
    out.push_str("# TYPE rmail_dmarc_pass_total counter\n");
    out.push_str(&format!(
        "rmail_dmarc_pass_total {}\n",
        DMARC_PASS_TOTAL.load(Ordering::Relaxed)
    ));
    out.push_str("# HELP rmail_dmarc_quarantine_total DMARC quarantine count\n");
    out.push_str("# TYPE rmail_dmarc_quarantine_total counter\n");
    out.push_str(&format!(
        "rmail_dmarc_quarantine_total {}\n",
        DMARC_QUARANTINE_TOTAL.load(Ordering::Relaxed)
    ));
    out.push_str("# HELP rmail_dmarc_reject_total DMARC reject count\n");
    out.push_str("# TYPE rmail_dmarc_reject_total counter\n");
    out.push_str(&format!(
        "rmail_dmarc_reject_total {}\n",
        DMARC_REJECT_TOTAL.load(Ordering::Relaxed)
    ));
    out.push_str("# HELP rmail_arc_verifications_total ARC chain verification outcomes\n");
    out.push_str("# TYPE rmail_arc_verifications_total counter\n");
    out.push_str(&format!(
        "rmail_arc_verifications_total{{result=\"pass\"}} {}\n",
        ARC_PASS_TOTAL.load(Ordering::Relaxed)
    ));
    out.push_str(&format!(
        "rmail_arc_verifications_total{{result=\"fail\"}} {}\n",
        ARC_FAIL_TOTAL.load(Ordering::Relaxed)
    ));
    out.push_str("# HELP rmail_arc_sealed_total Forwarded messages given a new ARC set\n");
    out.push_str("# TYPE rmail_arc_sealed_total counter\n");
    out.push_str(&format!(
        "rmail_arc_sealed_total {}\n",
        ARC_SEALED_TOTAL.load(Ordering::Relaxed)
    ));
    DNS_DURATION.render(&mut out, "rmail_dns_duration_seconds", "DNS lookup latency");
    TLS_HANDSHAKE_DURATION.render(
        &mut out,
        "rmail_tls_handshake_duration_seconds",
        "TLS handshake latency",
    );
    SCANNER_DURATION.render(
        &mut out,
        "rmail_scanner_duration_seconds",
        "Message scanner latency",
    );
    QUEUE_DELAY.render(
        &mut out,
        "rmail_queue_delay_seconds",
        "Time from queue creation to delivery attempt",
    );
    IMAP_COMMAND_DURATION.render(
        &mut out,
        "rmail_imap_command_duration_seconds",
        "IMAP command processing latency",
    );
    DATABASE_WAIT_DURATION.render(
        &mut out,
        "rmail_database_wait_duration_seconds",
        "SQLite connection pool acquisition latency",
    );
    out
}

pub fn persist_prometheus_snapshot(mail_root: &Path, component: &str) -> anyhow::Result<()> {
    let path = crate::runtime::prometheus_snapshot_path(mail_root, component);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("prom.tmp");
    std::fs::write(&temporary, gather_prometheus())?;
    std::fs::rename(temporary, path)?;
    Ok(())
}

pub fn spawn_prometheus_snapshot_task(
    mail_root: &Path,
    component: &'static str,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    persist_prometheus_snapshot(mail_root, component)?;
    let mail_root = mail_root.to_path_buf();
    Ok(tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        interval.tick().await;
        loop {
            interval.tick().await;
            let root = mail_root.clone();
            match tokio::task::spawn_blocking(move || persist_prometheus_snapshot(&root, component))
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    eprintln!("metrics snapshot update failed for {component}: {error}");
                }
                Err(error) => {
                    eprintln!("metrics snapshot task failed for {component}: {error}");
                }
            }
        }
    }))
}

pub fn add_component_label(snapshot: &str, component: &str) -> String {
    let mut output = String::with_capacity(snapshot.len() + snapshot.len() / 10);
    for line in snapshot.lines() {
        if line.starts_with('#') || line.is_empty() {
            output.push_str(line);
            output.push('\n');
            continue;
        }
        let Some(space) = line.find(char::is_whitespace) else {
            continue;
        };
        let (metric, value) = line.split_at(space);
        if let Some(open) = metric.find('{') {
            output.push_str(&metric[..=open]);
            output.push_str("component=\"");
            output.push_str(component);
            output.push_str("\",");
            output.push_str(&metric[open + 1..]);
        } else {
            output.push_str(metric);
            output.push_str("{component=\"");
            output.push_str(component);
            output.push_str("\"}");
        }
        output.push_str(value);
        output.push('\n');
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smtp_message_metrics_include_ip_transport_and_protocol_dimensions() {
        inc_smtp_message_received(Some("[2001:db8::1]:25".parse().unwrap()), false, true, true);
        inc_lmtp_message_received(Some("127.0.0.1:24".parse().unwrap()));
        let metrics = gather_prometheus();

        assert!(metrics.contains(
            "rmail_smtp_messages_received_total{ip_version=\"6\",transport=\"starttls\",protocol=\"esmtp\"} 1"
        ));
        assert!(metrics.contains(
            "rmail_smtp_messages_received_total{ip_version=\"4\",transport=\"plain\",protocol=\"smtp\"} 0"
        ));
        assert!(metrics.contains(
            "rmail_smtp_messages_received_total{ip_version=\"4\",transport=\"plain\",protocol=\"lmtp\"} 1"
        ));
    }

    #[test]
    fn histograms_render_cumulative_buckets_sum_and_count() {
        let histogram = Histogram::new();
        histogram.observe(Duration::from_millis(2));
        histogram.observe(Duration::from_secs(2 * 24 * 60 * 60));
        let mut output = String::new();
        histogram.render(&mut output, "test_duration_seconds", "test latency");

        assert!(output.contains("# TYPE test_duration_seconds histogram"));
        assert!(output.contains("test_duration_seconds_bucket{le=\"0.005\"} 1"));
        assert!(output.contains("test_duration_seconds_bucket{le=\"+Inf\"} 2"));
        assert!(output.contains("test_duration_seconds_count 2"));
        assert!(output.contains("test_duration_seconds_sum 172800.002"));
    }

    #[test]
    fn smtp_reply_metrics_are_direction_and_code_bounded() {
        inc_smtp_response(SmtpDirection::Inbound, 250);
        inc_smtp_response(SmtpDirection::Outbound, 451);
        inc_smtp_response(SmtpDirection::Outbound, 999);
        let output = gather_prometheus();

        assert!(
            output.contains("rmail_smtp_responses_total{direction=\"inbound\",code=\"250\"} 1")
        );
        assert!(
            output.contains("rmail_smtp_responses_total{direction=\"outbound\",code=\"451\"} 1")
        );
        assert!(!output.contains("code=\"999\""));
    }

    #[test]
    fn component_labels_are_added_to_plain_and_labeled_samples() {
        let snapshot = "# HELP example test\nexample 1\nexample_bucket{le=\"1\"} 2\n";
        let labeled = add_component_label(snapshot, "imapd");
        assert!(labeled.contains("example{component=\"imapd\"} 1"));
        assert!(labeled.contains("example_bucket{component=\"imapd\",le=\"1\"} 2"));
        assert!(labeled.contains("# HELP example test"));
    }
}
