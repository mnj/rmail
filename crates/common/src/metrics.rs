use std::sync::atomic::{AtomicU64, Ordering};

pub static DELIVERIES_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static DELIVERIES_FAILED_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static DELIVERED_BYTES_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static DELIVERY_LATENCY_US_SUM: AtomicU64 = AtomicU64::new(0);
pub static DELIVERY_LATENCY_US_COUNT: AtomicU64 = AtomicU64::new(0);
pub static CONNECTIONS_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static TLS_HANDSHAKES_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static BYTES_RECEIVED_TOTAL: AtomicU64 = AtomicU64::new(0);

pub fn inc_deliveries() { DELIVERIES_TOTAL.fetch_add(1, Ordering::Relaxed); }
pub fn inc_failed_deliveries() { DELIVERIES_FAILED_TOTAL.fetch_add(1, Ordering::Relaxed); }
pub fn add_delivered_bytes(n: u64) { DELIVERED_BYTES_TOTAL.fetch_add(n, Ordering::Relaxed); }
pub fn observe_delivery_latency_us(us: u64) {
    DELIVERY_LATENCY_US_SUM.fetch_add(us, Ordering::Relaxed);
    DELIVERY_LATENCY_US_COUNT.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_connections() { CONNECTIONS_TOTAL.fetch_add(1, Ordering::Relaxed); }
pub fn inc_tls_handshakes() { TLS_HANDSHAKES_TOTAL.fetch_add(1, Ordering::Relaxed); }
pub fn add_bytes_received(n: u64) { BYTES_RECEIVED_TOTAL.fetch_add(n, Ordering::Relaxed); }

pub fn gather_prometheus() -> String {
    let mut out = String::new();
    out.push_str("# HELP rmail_deliveries_total Total number of successful deliveries\n");
    out.push_str("# TYPE rmail_deliveries_total counter\n");
    out.push_str(&format!("rmail_deliveries_total {}\n", DELIVERIES_TOTAL.load(Ordering::Relaxed)));
    out.push_str("# HELP rmail_deliveries_failed_total Total number of failed deliveries\n");
    out.push_str("# TYPE rmail_deliveries_failed_total counter\n");
    out.push_str(&format!("rmail_deliveries_failed_total {}\n", DELIVERIES_FAILED_TOTAL.load(Ordering::Relaxed)));
    out.push_str("# HELP rmail_delivered_bytes_total Total bytes delivered\n");
    out.push_str("# TYPE rmail_delivered_bytes_total counter\n");
    out.push_str(&format!("rmail_delivered_bytes_total {}\n", DELIVERED_BYTES_TOTAL.load(Ordering::Relaxed)));
    out.push_str("# HELP rmail_delivery_latency_seconds_avg Average delivery latency in seconds\n");
    out.push_str("# TYPE rmail_delivery_latency_seconds_avg gauge\n");
    let cnt = DELIVERY_LATENCY_US_COUNT.load(Ordering::Relaxed);
    let sum_us = DELIVERY_LATENCY_US_SUM.load(Ordering::Relaxed);
    let avg_secs = if cnt == 0 { 0.0 } else { (sum_us as f64) / (cnt as f64) / 1_000_000.0 };
    out.push_str(&format!("rmail_delivery_latency_seconds_avg {}\n", avg_secs));
    out.push_str("# HELP rmail_connections_total Total accepted connections\n");
    out.push_str("# TYPE rmail_connections_total counter\n");
    out.push_str(&format!("rmail_connections_total {}\n", CONNECTIONS_TOTAL.load(Ordering::Relaxed)));
    out.push_str("# HELP rmail_tls_handshakes_total Total TLS handshakes\n");
    out.push_str("# TYPE rmail_tls_handshakes_total counter\n");
    out.push_str(&format!("rmail_tls_handshakes_total {}\n", TLS_HANDSHAKES_TOTAL.load(Ordering::Relaxed)));
    out.push_str("# HELP rmail_bytes_received_total Total bytes received\n");
    out.push_str("# TYPE rmail_bytes_received_total counter\n");
    out.push_str(&format!("rmail_bytes_received_total {}\n", BYTES_RECEIVED_TOTAL.load(Ordering::Relaxed)));
    out
}