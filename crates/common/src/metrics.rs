use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

pub static DELIVERIES_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static DELIVERIES_FAILED_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static DELIVERED_BYTES_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static DELIVERY_LATENCY_US_SUM: AtomicU64 = AtomicU64::new(0);
pub static DELIVERY_LATENCY_US_COUNT: AtomicU64 = AtomicU64::new(0);
pub static CONNECTIONS_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static TLS_HANDSHAKES_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static BYTES_RECEIVED_TOTAL: AtomicU64 = AtomicU64::new(0);
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
static SMTP_MESSAGES_RECEIVED: [AtomicU64; 12] = [const { AtomicU64::new(0) }; 12];

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
    out
}

pub fn persist_prometheus_snapshot(mail_root: &Path, component: &str) -> anyhow::Result<()> {
    let path = crate::runtime::prometheus_snapshot_path(mail_root, component);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, gather_prometheus())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{gather_prometheus, inc_smtp_message_received};

    #[test]
    fn smtp_message_metrics_include_ip_transport_and_protocol_dimensions() {
        inc_smtp_message_received(Some("[2001:db8::1]:25".parse().unwrap()), false, true, true);
        let metrics = gather_prometheus();

        assert!(metrics.contains(
            "rmail_smtp_messages_received_total{ip_version=\"6\",transport=\"starttls\",protocol=\"esmtp\"} 1"
        ));
        assert!(metrics.contains(
            "rmail_smtp_messages_received_total{ip_version=\"4\",transport=\"plain\",protocol=\"smtp\"} 0"
        ));
    }
}
