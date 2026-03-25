//! Prometheus metrics export for the MILNET SSO system.
//!
//! Provides a zero-dependency metrics registry that renders Prometheus
//! text exposition format. Each service embeds this and exposes `/metrics`.
//!
//! Metric types:
//! - **Histogram** for latency (auth, KMS, DB operations)
//! - **Counter** for event counts (auth success/failure, SIEM events)
//! - **Gauge** for current state (active sessions, revocation list size,
//!   circuit breaker state, connection pool)
//!
//! Thread-safe: all operations use atomics or Mutex for interior mutability.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// Counter
// ---------------------------------------------------------------------------

/// A monotonically increasing counter (e.g. request counts).
pub struct Counter {
    name: &'static str,
    help: &'static str,
    values: Mutex<HashMap<Vec<(&'static str, String)>, AtomicU64Wrapper>>,
}

/// Wrapper to allow AtomicU64 in HashMap values.
struct AtomicU64Wrapper(AtomicU64);

impl Counter {
    /// Create a new counter with the given metric name and help text.
    pub fn new(name: &'static str, help: &'static str) -> Self {
        Self {
            name,
            help,
            values: Mutex::new(HashMap::new()),
        }
    }

    /// Increment the counter with the given label set.
    pub fn inc(&self, labels: &[(&'static str, &str)]) {
        self.inc_by(labels, 1);
    }

    /// Increment the counter by a specific amount.
    pub fn inc_by(&self, labels: &[(&'static str, &str)], n: u64) {
        let key: Vec<_> = labels.iter().map(|(k, v)| (*k, v.to_string())).collect();
        let mut map = self.values.lock().unwrap_or_else(|e| e.into_inner());
        map.entry(key)
            .or_insert_with(|| AtomicU64Wrapper(AtomicU64::new(0)))
            .0
            .fetch_add(n, Ordering::Relaxed);
    }

    /// Render in Prometheus text format.
    pub fn render(&self) -> String {
        let map = self.values.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = format!("# HELP {} {}\n# TYPE {} counter\n", self.name, self.help, self.name);
        for (labels, value) in map.iter() {
            let label_str = render_labels(labels);
            let v = value.0.load(Ordering::Relaxed);
            out.push_str(&format!("{}{} {}\n", self.name, label_str, v));
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Gauge
// ---------------------------------------------------------------------------

/// A gauge that can go up and down (e.g. active sessions).
pub struct Gauge {
    name: &'static str,
    help: &'static str,
    values: Mutex<HashMap<Vec<(&'static str, String)>, AtomicI64Wrapper>>,
}

struct AtomicI64Wrapper(AtomicI64);

impl Gauge {
    pub fn new(name: &'static str, help: &'static str) -> Self {
        Self {
            name,
            help,
            values: Mutex::new(HashMap::new()),
        }
    }

    /// Set the gauge to a specific value.
    pub fn set(&self, labels: &[(&'static str, &str)], value: i64) {
        let key: Vec<_> = labels.iter().map(|(k, v)| (*k, v.to_string())).collect();
        let mut map = self.values.lock().unwrap_or_else(|e| e.into_inner());
        map.entry(key)
            .or_insert_with(|| AtomicI64Wrapper(AtomicI64::new(0)))
            .0
            .store(value, Ordering::Relaxed);
    }

    /// Increment the gauge by 1.
    pub fn inc(&self, labels: &[(&'static str, &str)]) {
        let key: Vec<_> = labels.iter().map(|(k, v)| (*k, v.to_string())).collect();
        let mut map = self.values.lock().unwrap_or_else(|e| e.into_inner());
        map.entry(key)
            .or_insert_with(|| AtomicI64Wrapper(AtomicI64::new(0)))
            .0
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement the gauge by 1.
    pub fn dec(&self, labels: &[(&'static str, &str)]) {
        let key: Vec<_> = labels.iter().map(|(k, v)| (*k, v.to_string())).collect();
        let mut map = self.values.lock().unwrap_or_else(|e| e.into_inner());
        map.entry(key)
            .or_insert_with(|| AtomicI64Wrapper(AtomicI64::new(0)))
            .0
            .fetch_sub(1, Ordering::Relaxed);
    }

    pub fn render(&self) -> String {
        let map = self.values.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = format!("# HELP {} {}\n# TYPE {} gauge\n", self.name, self.help, self.name);
        for (labels, value) in map.iter() {
            let label_str = render_labels(labels);
            let v = value.0.load(Ordering::Relaxed);
            out.push_str(&format!("{}{} {}\n", self.name, label_str, v));
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Histogram
// ---------------------------------------------------------------------------

/// A histogram for tracking distributions (e.g. latency).
pub struct Histogram {
    name: &'static str,
    help: &'static str,
    buckets: Vec<f64>,
    /// Per label-set: (bucket_counts, sum, count)
    values: Mutex<HashMap<Vec<(&'static str, String)>, HistogramData>>,
}

struct HistogramData {
    bucket_counts: Vec<AtomicU64>,
    sum: AtomicU64, // stored as f64 bits
    count: AtomicU64,
}

impl Histogram {
    /// Create a histogram with the given name and bucket boundaries.
    pub fn new(name: &'static str, help: &'static str, buckets: Vec<f64>) -> Self {
        Self {
            name,
            help,
            buckets,
            values: Mutex::new(HashMap::new()),
        }
    }

    /// Create a histogram with default latency buckets (suitable for HTTP request latencies).
    pub fn with_default_buckets(name: &'static str, help: &'static str) -> Self {
        Self::new(
            name,
            help,
            vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
        )
    }

    /// Observe a value (e.g. a latency measurement in seconds).
    pub fn observe(&self, labels: &[(&'static str, &str)], value: f64) {
        let key: Vec<_> = labels.iter().map(|(k, v)| (*k, v.to_string())).collect();
        let mut map = self.values.lock().unwrap_or_else(|e| e.into_inner());
        let data = map.entry(key).or_insert_with(|| HistogramData {
            bucket_counts: self.buckets.iter().map(|_| AtomicU64::new(0)).collect(),
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        });

        for (i, bound) in self.buckets.iter().enumerate() {
            if value <= *bound {
                data.bucket_counts[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        // Atomically add to sum using CAS loop on the bit representation
        loop {
            let old_bits = data.sum.load(Ordering::Relaxed);
            let old_val = f64::from_bits(old_bits);
            let new_val = old_val + value;
            if data
                .sum
                .compare_exchange(
                    old_bits,
                    new_val.to_bits(),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                break;
            }
        }
        data.count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn render(&self) -> String {
        let map = self.values.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = format!(
            "# HELP {} {}\n# TYPE {} histogram\n",
            self.name, self.help, self.name
        );
        for (labels, data) in map.iter() {
            let label_str_base = render_labels(labels);
            for (i, bound) in self.buckets.iter().enumerate() {
                let bucket_val = data.bucket_counts[i].load(Ordering::Relaxed);
                let le_label = if labels.is_empty() {
                    format!("{{le=\"{}\"}}", bound)
                } else {
                    // Insert le into existing labels
                    let inner = &label_str_base[1..label_str_base.len() - 1];
                    format!("{{{},le=\"{}\"}}", inner, bound)
                };
                out.push_str(&format!("{}_bucket{} {}\n", self.name, le_label, bucket_val));
            }
            // +Inf bucket
            let total = data.count.load(Ordering::Relaxed);
            let inf_label = if labels.is_empty() {
                "{le=\"+Inf\"}".to_string()
            } else {
                let inner = &label_str_base[1..label_str_base.len() - 1];
                format!("{{{},le=\"+Inf\"}}", inner)
            };
            out.push_str(&format!("{}_bucket{} {}\n", self.name, inf_label, total));
            let sum = f64::from_bits(data.sum.load(Ordering::Relaxed));
            out.push_str(&format!("{}_sum{} {}\n", self.name, label_str_base, sum));
            out.push_str(&format!("{}_count{} {}\n", self.name, label_str_base, total));
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Global metric registry
// ---------------------------------------------------------------------------

/// Global metrics registry. Services call `register_*` at startup and
/// `render_all()` on the `/metrics` endpoint.
pub struct MetricsRegistry {
    renderers: Mutex<Vec<Box<dyn Fn() -> String + Send + Sync>>>,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self {
            renderers: Mutex::new(Vec::new()),
        }
    }

    /// Register a render function that will be called on `/metrics`.
    pub fn register(&self, renderer: impl Fn() -> String + Send + Sync + 'static) {
        let mut renderers = self.renderers.lock().unwrap_or_else(|e| e.into_inner());
        renderers.push(Box::new(renderer));
    }

    /// Render all registered metrics in Prometheus text exposition format.
    pub fn render_all(&self) -> String {
        let renderers = self.renderers.lock().unwrap_or_else(|e| e.into_inner());
        let mut output = String::with_capacity(4096);
        for r in renderers.iter() {
            output.push_str(&r());
        }
        output
    }
}

// ---------------------------------------------------------------------------
// Pre-defined MILNET SSO metrics
// ---------------------------------------------------------------------------

/// Authentication latency histogram (seconds).
pub static AUTH_LATENCY: std::sync::LazyLock<Histogram> = std::sync::LazyLock::new(|| {
    Histogram::new(
        "milnet_auth_latency_seconds",
        "Authentication request latency in seconds",
        vec![0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
    )
});

/// Authentication result counter (success/failure).
pub static AUTH_TOTAL: std::sync::LazyLock<Counter> = std::sync::LazyLock::new(|| {
    Counter::new(
        "milnet_auth_total",
        "Total authentication attempts by result",
    )
});

/// Active sessions gauge.
pub static ACTIVE_SESSIONS: std::sync::LazyLock<Gauge> = std::sync::LazyLock::new(|| {
    Gauge::new("milnet_active_sessions", "Number of active sessions")
});

/// Revocation list size gauge.
pub static REVOCATION_LIST_SIZE: std::sync::LazyLock<Gauge> = std::sync::LazyLock::new(|| {
    Gauge::new(
        "milnet_revocation_list_size",
        "Number of entries in the token revocation list",
    )
});

/// SIEM events counter by severity.
pub static SIEM_EVENTS: std::sync::LazyLock<Counter> = std::sync::LazyLock::new(|| {
    Counter::new(
        "milnet_siem_events_total",
        "Total SIEM events emitted by severity",
    )
});

/// Risk score histogram.
pub static RISK_SCORE: std::sync::LazyLock<Histogram> = std::sync::LazyLock::new(|| {
    Histogram::new(
        "milnet_risk_score",
        "Distribution of risk scores",
        vec![0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
    )
});

/// Active connections gauge (per service).
pub static ACTIVE_CONNECTIONS: std::sync::LazyLock<Gauge> = std::sync::LazyLock::new(|| {
    Gauge::new(
        "milnet_active_connections",
        "Number of active connections per service",
    )
});

/// Circuit breaker state gauge (0=closed, 1=half-open, 2=open).
pub static CIRCUIT_BREAKER_STATE: std::sync::LazyLock<Gauge> = std::sync::LazyLock::new(|| {
    Gauge::new(
        "milnet_circuit_breaker_state",
        "Circuit breaker state: 0=closed, 1=half-open, 2=open",
    )
});

/// Request errors counter by service.
pub static REQUEST_ERRORS: std::sync::LazyLock<Counter> = std::sync::LazyLock::new(|| {
    Counter::new(
        "milnet_request_errors_total",
        "Total request errors by service",
    )
});

/// Ratchet epoch gauge.
pub static RATCHET_EPOCH: std::sync::LazyLock<Gauge> = std::sync::LazyLock::new(|| {
    Gauge::new(
        "milnet_ratchet_current_epoch",
        "Current ratchet epoch number",
    )
});

/// KMS operation latency histogram.
pub static KMS_LATENCY: std::sync::LazyLock<Histogram> = std::sync::LazyLock::new(|| {
    Histogram::new(
        "milnet_kms_operation_seconds",
        "Cloud KMS operation latency in seconds",
        vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
    )
});

/// Database connection pool gauges.
pub static DB_POOL_ACTIVE: std::sync::LazyLock<Gauge> = std::sync::LazyLock::new(|| {
    Gauge::new("milnet_db_pool_active", "Active database connections")
});

pub static DB_POOL_IDLE: std::sync::LazyLock<Gauge> = std::sync::LazyLock::new(|| {
    Gauge::new("milnet_db_pool_idle", "Idle database connections")
});

/// Puzzle difficulty histogram.
pub static PUZZLE_DIFFICULTY: std::sync::LazyLock<Histogram> = std::sync::LazyLock::new(|| {
    Histogram::new(
        "milnet_puzzle_difficulty",
        "Distribution of puzzle difficulty levels",
        vec![1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0],
    )
});

/// Incidents active gauge (by severity).
pub static INCIDENTS_ACTIVE: std::sync::LazyLock<Gauge> = std::sync::LazyLock::new(|| {
    Gauge::new(
        "milnet_incidents_active",
        "Number of active incidents by severity",
    )
});

/// Render all pre-defined MILNET metrics.
pub fn render_all_milnet_metrics() -> String {
    let mut out = String::with_capacity(8192);
    out.push_str(&AUTH_LATENCY.render());
    out.push_str(&AUTH_TOTAL.render());
    out.push_str(&ACTIVE_SESSIONS.render());
    out.push_str(&REVOCATION_LIST_SIZE.render());
    out.push_str(&SIEM_EVENTS.render());
    out.push_str(&RISK_SCORE.render());
    out.push_str(&ACTIVE_CONNECTIONS.render());
    out.push_str(&CIRCUIT_BREAKER_STATE.render());
    out.push_str(&REQUEST_ERRORS.render());
    out.push_str(&RATCHET_EPOCH.render());
    out.push_str(&KMS_LATENCY.render());
    out.push_str(&DB_POOL_ACTIVE.render());
    out.push_str(&DB_POOL_IDLE.render());
    out.push_str(&PUZZLE_DIFFICULTY.render());
    out.push_str(&INCIDENTS_ACTIVE.render());
    out
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn render_labels(labels: &[(&'static str, String)]) -> String {
    if labels.is_empty() {
        return String::new();
    }
    let inner: Vec<String> = labels
        .iter()
        .map(|(k, v)| format!("{}=\"{}\"", k, v))
        .collect();
    format!("{{{}}}", inner.join(","))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter_increment() {
        let c = Counter::new("test_counter", "A test counter");
        c.inc(&[("method", "GET")]);
        c.inc(&[("method", "GET")]);
        c.inc(&[("method", "POST")]);

        let rendered = c.render();
        assert!(rendered.contains("test_counter{method=\"GET\"} 2"));
        assert!(rendered.contains("test_counter{method=\"POST\"} 1"));
    }

    #[test]
    fn test_gauge_set() {
        let g = Gauge::new("test_gauge", "A test gauge");
        g.set(&[("service", "gateway")], 42);

        let rendered = g.render();
        assert!(rendered.contains("test_gauge{service=\"gateway\"} 42"));
    }

    #[test]
    fn test_histogram_observe() {
        let h = Histogram::new("test_hist", "A test histogram", vec![0.1, 0.5, 1.0]);
        h.observe(&[], 0.05);
        h.observe(&[], 0.3);
        h.observe(&[], 0.8);

        let rendered = h.render();
        assert!(rendered.contains("test_hist_bucket{le=\"0.1\"} 1"));
        assert!(rendered.contains("test_hist_bucket{le=\"0.5\"} 2"));
        assert!(rendered.contains("test_hist_bucket{le=\"1\"} 3"));
        assert!(rendered.contains("test_hist_count 3"));
    }
}
