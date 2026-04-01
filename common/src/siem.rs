//! Structured security event emitter for SIEM integration.
//!
//! Emits JSON-formatted security events to stdout (structured logging) that
//! can be consumed by SIEM systems (Splunk, Elastic, etc.) via log forwarding.
//!
//! Also publishes events to an in-process broadcast channel so that SSE
//! consumers (e.g. the admin `/api/admin/siem/stream` endpoint) can receive
//! events in real time.
//!
//! # SIEM Macros for Unwrap/Expect Replacement
//!
//! The `siem_unwrap!` and `siem_expect!` macros replace `.unwrap()` and
//! `.expect()` calls with SIEM-reporting error propagation. Instead of
//! panicking, they emit a CRITICAL SIEM event with file:line context
//! and propagate the error via `?`.
#![forbid(unsafe_code)]

use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex, OnceLock};
use uuid::Uuid;

// ── SIEM Event Categories ──────────────────────────────────────────────────
//
// Machine-readable categories for filtering events in SIEM dashboards.

/// SIEM event category constants for dashboard filtering.
pub mod category {
    /// Unwrap/panic replacement — runtime errors that would have crashed.
    pub const RUNTIME_ERROR: &str = "RUNTIME_ERROR";
    /// Cryptographic operation failures (encrypt, decrypt, sign, verify, KEM).
    pub const CRYPTO_FAILURE: &str = "CRYPTO_FAILURE";
    /// Authentication failures (login, token, OPAQUE, FIDO2).
    pub const AUTH_FAILURE: &str = "AUTH_FAILURE";
    /// Protocol-level violations (malformed messages, invalid state machines).
    pub const PROTOCOL_VIOLATION: &str = "PROTOCOL_VIOLATION";
    /// Quorum/threshold failures (FROST, Shamir, BFT).
    pub const THRESHOLD_VIOLATION: &str = "THRESHOLD_VIOLATION";
    /// Tamper detection / integrity check failures.
    pub const INTEGRITY_VIOLATION: &str = "INTEGRITY_VIOLATION";
    /// Network-level anomalies (connection failures, TLS errors, timeouts).
    pub const NETWORK_ANOMALY: &str = "NETWORK_ANOMALY";
    /// Authorization failures (forbidden, insufficient privilege).
    pub const ACCESS_DENIED: &str = "ACCESS_DENIED";
    /// Key lifecycle events (generation, rotation, destruction, compromise).
    pub const KEY_MANAGEMENT: &str = "KEY_MANAGEMENT";
    /// Compliance check failures (FIPS, STIG, CMMC, FedRAMP).
    pub const COMPLIANCE_ALERT: &str = "COMPLIANCE_ALERT";
}

// ── SIEM Dashboard Panel ───────────────────────────────────────────────────

/// Dashboard panel categories for grouping events in the SIEM UI.
///
/// Each panel corresponds to a logical section of the security operations
/// dashboard, allowing operators to filter and triage events by domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SiemPanel {
    /// Runtime errors (unwrap failures, unexpected states)
    RuntimeErrors,
    /// Cryptographic operation failures
    CryptoFailures,
    /// Authentication failures (login, token, ceremony)
    AuthFailures,
    /// Protocol violations (malformed requests, replay attempts)
    ProtocolViolations,
    /// Threshold/quorum violations
    ThresholdViolations,
    /// Integrity violations (tamper detection, canary)
    IntegrityViolations,
    /// Network anomalies (connection failures, timeouts)
    NetworkAnomalies,
    /// Access denied events
    AccessDenied,
    /// Key management events (rotation, derivation, destruction)
    KeyManagement,
    /// Compliance check results
    ComplianceAlerts,
    /// Signing witness events
    SigningWitness,
    /// Multi-region events
    MultiRegion,
    /// Distributed KMS events
    DistributedKms,
    /// Debug panel — all errors with file:line
    DebugPanel,
}

impl SiemPanel {
    /// Return a stable string identifier for dashboard filtering.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RuntimeErrors => "runtime_errors",
            Self::CryptoFailures => "crypto_failures",
            Self::AuthFailures => "auth_failures",
            Self::ProtocolViolations => "protocol_violations",
            Self::ThresholdViolations => "threshold_violations",
            Self::IntegrityViolations => "integrity_violations",
            Self::NetworkAnomalies => "network_anomalies",
            Self::AccessDenied => "access_denied",
            Self::KeyManagement => "key_management",
            Self::ComplianceAlerts => "compliance_alerts",
            Self::SigningWitness => "signing_witness",
            Self::MultiRegion => "multi_region",
            Self::DistributedKms => "distributed_kms",
            Self::DebugPanel => "debug_panel",
        }
    }

    /// Return all panel variants (useful for dashboard enumeration).
    pub fn all() -> &'static [SiemPanel] {
        &[
            SiemPanel::RuntimeErrors,
            SiemPanel::CryptoFailures,
            SiemPanel::AuthFailures,
            SiemPanel::ProtocolViolations,
            SiemPanel::ThresholdViolations,
            SiemPanel::IntegrityViolations,
            SiemPanel::NetworkAnomalies,
            SiemPanel::AccessDenied,
            SiemPanel::KeyManagement,
            SiemPanel::ComplianceAlerts,
            SiemPanel::SigningWitness,
            SiemPanel::MultiRegion,
            SiemPanel::DistributedKms,
            SiemPanel::DebugPanel,
        ]
    }
}

// ── Severity levels for panel events ───────────────────────────────────────

/// Severity level for SIEM panel events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SiemSeverity {
    Debug = 0,
    Info = 1,
    Warning = 2,
    Error = 3,
    Critical = 4,
    Fatal = 5,
}

// ── Enhanced SIEM event with panel tagging ─────────────────────────────────

/// A panel-tagged SIEM event carrying source location information.
///
/// Every event records the exact `file:line` and module path so that the
/// debug panel can show operators where errors originate.
#[derive(Debug, Clone, Serialize)]
pub struct PanelSiemEvent {
    /// Dashboard panel this event belongs to.
    pub panel: SiemPanel,
    /// Severity of the event.
    pub severity: SiemSeverity,
    /// Human-readable category string (e.g. "authentication", "crypto").
    pub category: String,
    /// Human-readable message describing the event.
    pub message: String,
    /// Source file where the event was emitted (from `file!()`).
    pub source_file: &'static str,
    /// Source line where the event was emitted (from `line!()`).
    pub source_line: u32,
    /// Module path where the event was emitted (from `module_path!()`).
    pub source_module: &'static str,
    /// Node identifier (hostname or configured node ID).
    pub node_id: String,
    /// Unix-epoch seconds when the event was created.
    pub timestamp: i64,
    /// Optional correlation ID for tracing across services.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    /// Optional structured details (arbitrary JSON).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// Return the node ID for SIEM events (cached after first call).
fn node_id() -> &'static str {
    static NODE_ID: OnceLock<String> = OnceLock::new();
    NODE_ID.get_or_init(|| {
        std::env::var("MILNET_NODE_ID").unwrap_or_else(|_| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "unknown".to_string())
        })
    })
}

impl PanelSiemEvent {
    /// Create a new panel SIEM event with automatic timestamp and node ID.
    pub fn new(
        panel: SiemPanel,
        severity: SiemSeverity,
        category: impl Into<String>,
        message: impl Into<String>,
        source_file: &'static str,
        source_line: u32,
        source_module: &'static str,
    ) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        Self {
            panel,
            severity,
            category: category.into(),
            message: message.into(),
            source_file,
            source_line,
            source_module,
            node_id: node_id().to_string(),
            timestamp,
            correlation_id: None,
            details: None,
        }
    }

    /// Set a correlation ID for distributed tracing.
    pub fn with_correlation_id(mut self, id: impl Into<String>) -> Self {
        self.correlation_id = Some(id.into());
        self
    }

    /// Set structured JSON details.
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    /// Emit this panel event: broadcast on the SIEM bus, forward to webhook,
    /// and log via tracing.  Respects per-panel rate limiting.
    pub fn emit(self) {
        // Rate-limit: deduplicate identical events within window
        if !panel_rate_limiter_allow(&self) {
            return;
        }

        let json = serde_json::to_string(&self).unwrap_or_else(|_| "{}".to_string());
        tracing::info!(target: "siem", panel = %self.panel.as_str(), severity = ?self.severity, "{}", json);

        // Bridge to the legacy SiemEvent broadcast bus
        let legacy = SiemEvent {
            timestamp: self.timestamp,
            severity: match self.severity {
                SiemSeverity::Debug => 0,
                SiemSeverity::Info => 2,
                SiemSeverity::Warning => 6,
                SiemSeverity::Error => 7,
                SiemSeverity::Critical => 10,
                SiemSeverity::Fatal => 10,
            },
            event_type: format!("{}:{}", self.panel.as_str(), self.category),
            json: json.clone(),
        };

        broadcast_event(&legacy);
        crate::siem_webhook::queue_global_event(&json);

        // Alert on high-severity events
        if legacy.severity >= 7 {
            process_alert(&legacy);
        }
    }
}

// ── Per-panel rate limiting / deduplication ─────────────────────────────────

/// Deduplication window in seconds.  Events with the same panel + message
/// within this window are suppressed after the first occurrence.
const DEDUP_WINDOW_SECS: i64 = 60;

/// Key for deduplication: (panel, message_hash).
type DedupKey = (SiemPanel, u64);

struct DedupEntry {
    first_seen: i64,
    count: u64,
}

static PANEL_DEDUP: LazyLock<Mutex<HashMap<DedupKey, DedupEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Hash a message string for dedup keying (fast, non-cryptographic FNV-1a).
fn hash_message(msg: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in msg.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Check whether this event should be emitted (true) or suppressed (false).
fn panel_rate_limiter_allow(event: &PanelSiemEvent) -> bool {
    let key: DedupKey = (event.panel, hash_message(&event.message));
    let now = event.timestamp;

    let mut map = match PANEL_DEDUP.lock() {
        Ok(m) => m,
        Err(poisoned) => poisoned.into_inner(),
    };

    // GC expired entries when map grows large (amortised)
    if map.len() > 1000 {
        map.retain(|_, v| now - v.first_seen < DEDUP_WINDOW_SECS);
    }

    match map.get_mut(&key) {
        Some(entry) if now - entry.first_seen < DEDUP_WINDOW_SECS => {
            entry.count += 1;
            false // suppress duplicate
        }
        _ => {
            map.insert(key, DedupEntry { first_seen: now, count: 1 });
            true
        }
    }
}

/// Reset the dedup state (for testing).
#[cfg(test)]
pub fn reset_panel_dedup() {
    let mut map = PANEL_DEDUP.lock().unwrap_or_else(|p| p.into_inner());
    map.clear();
}

// ── siem_event! macro ─────────────────────────────────────────────────────

/// Emit a SIEM event with automatic source location capture.
///
/// # Usage
/// ```ignore
/// siem_event!(SiemPanel::AuthFailures, SiemSeverity::Error, "login failed");
/// siem_event!(SiemPanel::CryptoFailures, SiemSeverity::Critical, "key derive failed", json!({"algo": "AES"}));
/// ```
#[macro_export]
macro_rules! siem_event {
    ($panel:expr, $severity:expr, $msg:expr) => {{
        let event = $crate::siem::PanelSiemEvent::new(
            $panel,
            $severity,
            stringify!($panel),
            $msg,
            file!(),
            line!(),
            module_path!(),
        );
        event.emit();
    }};
    ($panel:expr, $severity:expr, $msg:expr, $details:expr) => {{
        let event = $crate::siem::PanelSiemEvent::new(
            $panel,
            $severity,
            stringify!($panel),
            $msg,
            file!(),
            line!(),
            module_path!(),
        )
        .with_details($details);
        event.emit();
    }};
}

// ── SIEM error reporting helper ────────────────────────────────────────────

/// Emit a SIEM event for a runtime error (unwrap/expect/panic replacement).
///
/// This is the backing function for `siem_unwrap!` and `siem_expect!`.
/// It creates and emits a `SecurityEvent` with full source location context.
pub fn emit_runtime_error(
    siem_category: &'static str,
    context: &str,
    error_detail: &str,
    file: &str,
    line: u32,
    column: u32,
    module: &str,
) {
    let detail = format!(
        "{}:{}: {} — {} [module={}, col={}]",
        file, line, context, error_detail, module, column
    );

    let event = SecurityEvent {
        timestamp: SecurityEvent::now_iso8601(),
        category: siem_category,
        action: "runtime_error",
        severity: Severity::Critical,
        outcome: "failure",
        user_id: None,
        source_ip: None,
        detail: Some(detail),
    };
    event.emit();
}

// ── siem_unwrap! macro ─────────────────────────────────────────────────────

/// Replace `.unwrap()` on `Result<T, E>` with SIEM-reported error propagation.
///
/// On `Err(e)`, emits a CRITICAL SIEM event with file:line:column context,
/// then propagates via `?` (the enclosing function must return `Result`).
///
/// # Usage
/// ```ignore
/// let val = siem_unwrap!(some_result, "decrypting DEK");
/// let val = siem_unwrap!(some_result, "signing JWT", CRYPTO_FAILURE);
/// ```
#[macro_export]
macro_rules! siem_unwrap {
    ($expr:expr, $context:expr) => {
        match $expr {
            Ok(v) => v,
            Err(e) => {
                let err_msg = format!("{}", e);
                $crate::siem::emit_runtime_error(
                    $crate::siem::category::RUNTIME_ERROR,
                    $context,
                    &err_msg,
                    file!(),
                    line!(),
                    column!(),
                    module_path!(),
                );
                // Also emit to panel system for dashboard visibility
                let _panel_evt = $crate::siem::PanelSiemEvent::new(
                    $crate::siem::SiemPanel::DebugPanel,
                    $crate::siem::SiemSeverity::Error,
                    "runtime_error",
                    &format!("{}: {}", $context, err_msg),
                    file!(),
                    line!(),
                    module_path!(),
                );
                _panel_evt.emit();
                return Err(format!("{}:{}: {}: {}", file!(), line!(), $context, e));
            }
        }
    };
    ($expr:expr, $context:expr, $category:ident) => {
        match $expr {
            Ok(v) => v,
            Err(e) => {
                let err_msg = format!("{}", e);
                $crate::siem::emit_runtime_error(
                    $crate::siem::category::$category,
                    $context,
                    &err_msg,
                    file!(),
                    line!(),
                    column!(),
                    module_path!(),
                );
                let _panel_evt = $crate::siem::PanelSiemEvent::new(
                    $crate::siem::SiemPanel::DebugPanel,
                    $crate::siem::SiemSeverity::Error,
                    "runtime_error",
                    &format!("{}: {}", $context, err_msg),
                    file!(),
                    line!(),
                    module_path!(),
                );
                _panel_evt.emit();
                return Err(format!("{}:{}: {}: {}", file!(), line!(), $context, e));
            }
        }
    };
}

/// Replace `.unwrap()` on `Option<T>` with SIEM-reported error propagation.
///
/// On `None`, emits a CRITICAL SIEM event with file:line:column context,
/// then propagates via `?` (the enclosing function must return `Result`).
///
/// # Usage
/// ```ignore
/// let val = siem_expect!(some_option, "loading KEK from keyring");
/// let val = siem_expect!(some_option, "parsing KEM ciphertext", CRYPTO_FAILURE);
/// ```
#[macro_export]
macro_rules! siem_expect {
    ($expr:expr, $context:expr) => {
        match $expr {
            Some(v) => v,
            None => {
                $crate::siem::emit_runtime_error(
                    $crate::siem::category::RUNTIME_ERROR,
                    $context,
                    "None",
                    file!(),
                    line!(),
                    column!(),
                    module_path!(),
                );
                let _panel_evt = $crate::siem::PanelSiemEvent::new(
                    $crate::siem::SiemPanel::DebugPanel,
                    $crate::siem::SiemSeverity::Error,
                    "runtime_error",
                    &format!("{}: value was None", $context),
                    file!(),
                    line!(),
                    module_path!(),
                );
                _panel_evt.emit();
                return Err(format!("{}:{}: {}: None", file!(), line!(), $context));
            }
        }
    };
    ($expr:expr, $context:expr, $category:ident) => {
        match $expr {
            Some(v) => v,
            None => {
                $crate::siem::emit_runtime_error(
                    $crate::siem::category::$category,
                    $context,
                    "None",
                    file!(),
                    line!(),
                    column!(),
                    module_path!(),
                );
                let _panel_evt = $crate::siem::PanelSiemEvent::new(
                    $crate::siem::SiemPanel::DebugPanel,
                    $crate::siem::SiemSeverity::Error,
                    "runtime_error",
                    &format!("{}: value was None", $context),
                    file!(),
                    line!(),
                    module_path!(),
                );
                _panel_evt.emit();
                return Err(format!("{}:{}: {}: None", file!(), line!(), $context));
            }
        }
    };
}

// ── Webhook thread pool limiter ─────────────────────────────────────────────
static ACTIVE_WEBHOOK_THREADS: AtomicUsize = AtomicUsize::new(0);
const MAX_WEBHOOK_THREADS: usize = 8;

/// Counter for dropped webhook events due to thread pool exhaustion.
/// Enables monitoring — if this value is non-zero, critical alerts may
/// have been lost.  Exposed via `/api/health` and SIEM metrics.
static DROPPED_WEBHOOK_EVENTS: AtomicUsize = AtomicUsize::new(0);

/// Returns the number of SIEM webhook events dropped due to thread pool
/// exhaustion since process start.  Non-zero values indicate alert loss.
pub fn dropped_webhook_event_count() -> usize {
    DROPPED_WEBHOOK_EVENTS.load(Ordering::Acquire)
}

// ── Alert file rotation ─────────────────────────────────────────────────────
/// Maximum alert file size before rotation (100 MB).
const MAX_ALERT_FILE_BYTES: u64 = 100 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Global broadcast bus for live SIEM event streaming
// ---------------------------------------------------------------------------

/// A lightweight, cloneable event that flows through the broadcast channel.
#[derive(Debug, Clone, Serialize)]
pub struct SiemEvent {
    /// Unix-epoch seconds when the event was created.
    pub timestamp: i64,
    /// CEF-compatible severity (0-10).
    pub severity: u8,
    /// Machine-readable event type (e.g. `"tamper_detected"`).
    pub event_type: String,
    /// Full JSON representation of the underlying `SecurityEvent`.
    pub json: String,
}

/// Global broadcast sender.  Capacity of 1000 means slow consumers that fall
/// more than 1000 events behind will see `RecvError::Lagged`.
static SIEM_BUS: LazyLock<tokio::sync::broadcast::Sender<SiemEvent>> = LazyLock::new(|| {
    let (tx, _rx) = tokio::sync::broadcast::channel(1000);
    tx
});

/// Publish a `SiemEvent` to all current subscribers.
/// Silently drops the event if there are no active receivers.
pub fn broadcast_event(event: &SiemEvent) {
    let _ = SIEM_BUS.send(event.clone());
}

/// Obtain a new receiver handle for the global SIEM event bus.
pub fn subscribe() -> tokio::sync::broadcast::Receiver<SiemEvent> {
    SIEM_BUS.subscribe()
}

// ---------------------------------------------------------------------------
// Webhook / file-based alerting for critical events
// ---------------------------------------------------------------------------

/// Webhook URL for forwarding high-severity events.  Loaded once from
/// `MILNET_ALERT_WEBHOOK_URL` on first access.
static ALERT_WEBHOOK_URL: OnceLock<Option<String>> = OnceLock::new();

/// Directory for the file-based alert sink.
const ALERT_DIR: &str = "/var/lib/milnet/alerts";
const CRITICAL_ALERT_FILE: &str = "/var/lib/milnet/alerts/critical.jsonl";

/// Return the configured webhook URL (if any).
fn alert_webhook_url() -> &'static Option<String> {
    ALERT_WEBHOOK_URL.get_or_init(|| {
        std::env::var("MILNET_ALERT_WEBHOOK_URL").ok().filter(|u| !u.is_empty())
    })
}

/// Persist a critical/high event to the file-based alert sink.
/// Public so that super admin access logging can use it directly.
pub fn persist_critical_alert(json: &str) {
    persist_alert_to_file(json);
}

/// Internal implementation of file-based alert persistence.
fn persist_alert_to_file(json: &str) {
    if let Err(e) = std::fs::create_dir_all(ALERT_DIR) {
        tracing::warn!("failed to create alert directory {}: {}", ALERT_DIR, e);
        return;
    }

    // Rotate alert file if it exceeds the size limit
    if let Ok(meta) = std::fs::metadata(CRITICAL_ALERT_FILE) {
        if meta.len() >= MAX_ALERT_FILE_BYTES {
            let rotate_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let rotated = format!("{}.{}", CRITICAL_ALERT_FILE, rotate_ts);
            let _ = std::fs::rename(CRITICAL_ALERT_FILE, &rotated);
            tracing::warn!(target: "siem", "Alert file rotated due to size limit");
        }
    }

    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(CRITICAL_ALERT_FILE)
    {
        Ok(mut f) => {
            use std::io::Write;
            if let Err(e) = writeln!(f, "{}", json) {
                tracing::warn!("failed to write alert to {}: {}", CRITICAL_ALERT_FILE, e);
            }
        }
        Err(e) => {
            tracing::warn!("failed to open alert file {}: {}", CRITICAL_ALERT_FILE, e);
        }
    }
}

/// Send a webhook alert for a high-severity SIEM event.
///
/// Uses a minimal HTTP/1.1 POST over `std::net::TcpStream` so we do not
/// require an external HTTP client crate.  The call is best-effort: failures
/// are logged but never propagated.
fn send_webhook_alert(event: &SiemEvent) {
    let url_str = match alert_webhook_url() {
        Some(u) => u.clone(),
        None => return,
    };

    // FIX 3: Refuse non-HTTPS URLs in production
    if crate::sealed_keys::is_production() && !url_str.starts_with("https://") {
        tracing::error!(
            target: "siem",
            "REFUSED: SIEM webhook URL must use HTTPS in production: {}",
            url_str
        );
        return;
    }

    let body = match serde_json::to_string(event) {
        Ok(b) => b,
        Err(_) => return,
    };

    // Thread pool limiter — refuse to spawn if at capacity.
    // Instead of silently dropping, increment a counter and persist the
    // event to the file-based alert sink so it is never fully lost.
    if ACTIVE_WEBHOOK_THREADS.load(Ordering::Acquire) >= MAX_WEBHOOK_THREADS {
        let dropped = DROPPED_WEBHOOK_EVENTS.fetch_add(1, Ordering::Release) + 1;
        tracing::error!(
            target: "siem",
            dropped_total = dropped,
            "SIEM webhook thread pool exhausted — event persisted to file but webhook delivery skipped"
        );
        // Persist to file sink as fallback so the event is not lost entirely.
        persist_alert_to_file(&body);
        return;
    }
    ACTIVE_WEBHOOK_THREADS.fetch_add(1, Ordering::Release);

    // Spawn a blocking task so we don't block the async runtime.
    let _ = std::thread::Builder::new()
        .name("siem-webhook".into())
        .spawn(move || {
            send_webhook_blocking(&url_str, &body);
            ACTIVE_WEBHOOK_THREADS.fetch_sub(1, Ordering::Release);
        });
}

/// Blocking HTTP POST helper with mandatory TLS for https:// URLs.
fn send_webhook_blocking(url: &str, body: &str) {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    let is_https = url.starts_with("https://");
    let without_scheme = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);

    let (host_port, path) = match without_scheme.find('/') {
        Some(i) => (&without_scheme[..i], &without_scheme[i..]),
        None => (without_scheme, "/"),
    };

    // Extract hostname (without port) for TLS SNI
    let hostname = if let Some(colon) = host_port.find(':') {
        &host_port[..colon]
    } else {
        host_port
    };

    let default_port = if is_https { 443 } else { 80 };
    let host_port_owned = if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{}:{}", host_port, default_port)
    };

    let tcp_stream = match TcpStream::connect_timeout(
        &host_port_owned.parse().unwrap_or_else(|_| {
            std::net::SocketAddr::from(([127, 0, 0, 1], default_port))
        }),
        Duration::from_secs(5),
    ) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("webhook connect failed: {}", e);
            return;
        }
    };

    let _ = tcp_stream.set_write_timeout(Some(Duration::from_secs(5)));
    let _ = tcp_stream.set_read_timeout(Some(Duration::from_secs(5)));

    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path, host_port, body.len(), body
    );

    if is_https {
        // Use rustls for TLS — mandatory for HTTPS webhooks
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let tls_config = std::sync::Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        );
        let server_name = match rustls::pki_types::ServerName::try_from(hostname.to_string()) {
            Ok(sn) => sn,
            Err(e) => {
                tracing::warn!("webhook invalid hostname for TLS: {}: {}", hostname, e);
                return;
            }
        };
        let tls_conn = match rustls::ClientConnection::new(tls_config, server_name) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("webhook TLS handshake init failed: {}", e);
                return;
            }
        };
        let mut tls_stream = rustls::StreamOwned::new(tls_conn, tcp_stream);
        if let Err(e) = tls_stream.write_all(request.as_bytes()) {
            tracing::warn!("webhook TLS write failed: {}", e);
            return;
        }
        let mut buf = [0u8; 512];
        let _ = tls_stream.read(&mut buf);
    } else {
        // Plain HTTP — only allowed in non-production mode (checked by caller)
        let mut stream = tcp_stream;
        if let Err(e) = stream.write_all(request.as_bytes()) {
            tracing::warn!("webhook write failed: {}", e);
            return;
        }
        let mut buf = [0u8; 512];
        let _ = stream.read(&mut buf);
    }
}

/// Process alerting for a SIEM event: persist to file and optionally forward
/// via webhook.  Called for events with severity >= HIGH (7).
fn process_alert(event: &SiemEvent) {
    // Always persist to file-based sink as a fallback
    persist_alert_to_file(&event.json);

    // Forward via webhook if configured
    if alert_webhook_url().is_some() {
        send_webhook_alert(event);
    }
}

/// Security event severity levels (CEF-compatible, 0-10 scale).
#[derive(Debug, Clone, Copy, Serialize)]
pub enum Severity {
    Low = 1,
    Info = 2,
    Medium = 4,
    Notice = 5,
    Warning = 6,
    High = 7,
    Elevated = 8,
    Critical = 10,
}

/// Structured security event for SIEM consumption.
#[derive(Debug, Serialize)]
pub struct SecurityEvent {
    /// ISO 8601 timestamp
    pub timestamp: String,
    /// Event category
    pub category: &'static str,
    /// Event action
    pub action: &'static str,
    /// Severity level
    pub severity: Severity,
    /// Outcome: success or failure
    pub outcome: &'static str,
    /// User ID (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<Uuid>,
    /// Source IP (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    /// Additional details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl SecurityEvent {
    pub(crate) fn now_iso8601() -> String {
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let secs = d.as_secs();
        // Simple UTC timestamp (good enough; proper chrono formatting in production)
        format!("{}Z", secs)
    }

    /// Emit an authentication success event.
    pub fn auth_success(user_id: Uuid, source_ip: Option<String>) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "authentication",
            action: "login",
            severity: Severity::Low,
            outcome: "success",
            user_id: Some(user_id),
            source_ip,
            detail: None,
        };
        event.emit();
    }

    /// Emit an authentication failure event.
    pub fn auth_failure(user_id: Option<Uuid>, source_ip: Option<String>, reason: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "authentication",
            action: "login",
            severity: Severity::Medium,
            outcome: "failure",
            user_id,
            source_ip,
            detail: Some(reason.to_string()),
        };
        event.emit();
    }

    /// Emit an account lockout event.
    pub fn account_lockout(user_id: Uuid) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "authentication",
            action: "lockout",
            severity: Severity::High,
            outcome: "failure",
            user_id: Some(user_id),
            source_ip: None,
            detail: Some("account locked due to excessive failed attempts".into()),
        };
        event.emit();
    }

    /// Emit a duress detection event.
    pub fn duress_detected(user_id: Uuid) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "authentication",
            action: "duress",
            severity: Severity::Critical,
            outcome: "failure",
            user_id: Some(user_id),
            source_ip: None,
            detail: Some("duress PIN activated — possible coercion".into()),
        };
        event.emit();
    }

    /// Emit a privilege escalation attempt event.
    pub fn privilege_escalation(user_id: Uuid, action_level: u8) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "authorization",
            action: "privilege_escalation",
            severity: Severity::High,
            outcome: "attempt",
            user_id: Some(user_id),
            source_ip: None,
            detail: Some(format!("action level {} attempted", action_level)),
        };
        event.emit();
    }

    /// Emit a key rotation event.
    pub fn key_rotation(detail: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "key_management",
            action: "rotation",
            severity: Severity::Medium,
            outcome: "success",
            user_id: None,
            source_ip: None,
            detail: Some(detail.to_string()),
        };
        event.emit();
    }

    /// Emit a tamper detection event.
    pub fn tamper_detected(detail: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "integrity",
            action: "tamper_detected",
            severity: Severity::Critical,
            outcome: "failure",
            user_id: None,
            source_ip: None,
            detail: Some(detail.to_string()),
        };
        event.emit();
    }

    /// Emit a session created event.
    pub fn session_created(user_id: &str, source_ip: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "session",
            action: "session_created",
            severity: Severity::Info,
            outcome: "success",
            user_id: Uuid::parse_str(user_id).ok(),
            source_ip: Some(source_ip.to_string()),
            detail: None,
        };
        event.emit();
    }

    /// Emit a session expired event.
    pub fn session_expired(user_id: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "session",
            action: "session_expired",
            severity: Severity::Info,
            outcome: "success",
            user_id: Uuid::parse_str(user_id).ok(),
            source_ip: None,
            detail: None,
        };
        event.emit();
    }

    /// Emit a session revoked event.
    pub fn session_revoked(user_id: &str, reason: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "session",
            action: "session_revoked",
            severity: Severity::Medium,
            outcome: "success",
            user_id: Uuid::parse_str(user_id).ok(),
            source_ip: None,
            detail: Some(reason.to_string()),
        };
        event.emit();
    }

    /// Emit a token revoked event.
    pub fn token_revoked(token_id: &str, reason: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "session",
            action: "token_revoked",
            severity: Severity::Notice,
            outcome: "success",
            user_id: None,
            source_ip: None,
            detail: Some(format!("token={} reason={}", token_id, reason)),
        };
        event.emit();
    }

    /// Emit a circuit breaker opened event.
    pub fn circuit_breaker_opened(service: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "availability",
            action: "circuit_breaker_opened",
            severity: Severity::Warning,
            outcome: "failure",
            user_id: None,
            source_ip: None,
            detail: Some(format!("service={}", service)),
        };
        event.emit();
    }

    /// Emit a circuit breaker closed event.
    pub fn circuit_breaker_closed(service: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "availability",
            action: "circuit_breaker_closed",
            severity: Severity::Info,
            outcome: "success",
            user_id: None,
            source_ip: None,
            detail: Some(format!("service={}", service)),
        };
        event.emit();
    }

    /// Emit a circuit breaker failure count saturation event.
    ///
    /// Indicates sustained service failure — the u32 failure counter reached
    /// `u32::MAX`. This may indicate an attack or total downstream service loss.
    pub fn circuit_breaker_saturated(service: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "availability",
            action: "circuit_breaker_saturated",
            severity: Severity::Critical,
            outcome: "failure",
            user_id: None,
            source_ip: None,
            detail: Some(format!(
                "service={} failure_count=SATURATED(u32::MAX)",
                service
            )),
        };
        event.emit();
    }

    /// Emit a rate limit exceeded event.
    pub fn rate_limit_exceeded(source_ip: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "access_control",
            action: "rate_limit_exceeded",
            severity: Severity::Notice,
            outcome: "failure",
            user_id: None,
            source_ip: Some(source_ip.to_string()),
            detail: None,
        };
        event.emit();
    }

    /// Emit a certificate validation failure event.
    pub fn certificate_validation_failed(peer: &str, reason: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "authentication",
            action: "certificate_validation_failed",
            severity: Severity::Elevated,
            outcome: "failure",
            user_id: None,
            source_ip: Some(peer.to_string()),
            detail: Some(reason.to_string()),
        };
        event.emit();
    }

    /// Emit a DPoP proof missing event.
    pub fn dpop_missing(source_ip: Option<String>) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "authentication",
            action: "dpop_missing",
            severity: Severity::Medium,
            outcome: "failure",
            user_id: None,
            source_ip,
            detail: Some("DPoP proof not provided for token-bound request".into()),
        };
        event.emit();
    }

    /// Emit a capacity warning event for maps/lists approaching limits.
    pub fn capacity_warning(source_module: &str, current: usize, max: usize) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "availability",
            action: "capacity_warning",
            severity: Severity::Warning,
            outcome: "failure",
            user_id: None,
            source_ip: None,
            detail: Some(format!(
                "module={} current={} max={} pct={}%",
                source_module, current, max,
                current * 100 / max.max(1)
            )),
        };
        event.emit();
    }

    /// Emit an invalid ceremony approval signature event.
    pub fn ceremony_approval_invalid(user_id: Option<Uuid>, detail: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "authorization",
            action: "ceremony_approval_invalid",
            severity: Severity::High,
            outcome: "failure",
            user_id,
            source_ip: None,
            detail: Some(detail.to_string()),
        };
        event.emit();
    }

    /// Emit a CAC/PIV authentication success event.
    pub fn cac_auth_success(card_serial: &str, clearance_level: u8) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "authentication",
            action: "cac_auth_success",
            severity: Severity::Low,
            outcome: "success",
            user_id: None,
            source_ip: None,
            detail: Some(format!(
                "CAC authentication succeeded: serial={} clearance={}",
                card_serial, clearance_level
            )),
        };
        event.emit();
    }

    /// Emit a CAC/PIV authentication failure event.
    pub fn cac_auth_failure(reason: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "authentication",
            action: "cac_auth_failure",
            severity: Severity::High,
            outcome: "failure",
            user_id: None,
            source_ip: None,
            detail: Some(format!("CAC authentication failed: reason={}", reason)),
        };
        event.emit();
    }

    /// Emit a CAC/PIV PIN locked event (too many failed PIN attempts).
    pub fn cac_pin_locked(card_serial: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "authentication",
            action: "cac_pin_locked",
            severity: Severity::High,
            outcome: "failure",
            user_id: None,
            source_ip: None,
            detail: Some(format!("CAC PIN locked for card: serial={}", card_serial)),
        };
        event.emit();
    }

    /// Emit a configuration error level change blocked event (production protection).
    pub fn developer_mode_blocked() {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "configuration",
            action: "developer_mode_blocked",
            severity: Severity::Critical,
            outcome: "failure",
            user_id: None,
            source_ip: None,
            detail: Some("runtime error_level configuration change blocked".into()),
        };
        event.emit();
    }

    /// Emit a FIPS mode toggle blocked event (production protection).
    pub fn fips_mode_blocked() {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "configuration",
            action: "fips_mode_blocked",
            severity: Severity::Critical,
            outcome: "failure",
            user_id: None,
            source_ip: None,
            detail: Some("runtime FIPS mode disable blocked in production".into()),
        };
        event.emit();
    }

    /// Emit an admin data access event (read operations).
    /// SECURITY: Logs all admin read operations to detect silent data exfiltration.
    pub fn admin_data_access(detail: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "access",
            action: "admin_data_access",
            severity: Severity::Info,
            outcome: "success",
            user_id: None,
            source_ip: None,
            detail: Some(detail.to_string()),
        };
        event.emit();
    }

    /// Emit a cryptographic failure event.
    pub fn crypto_failure(detail: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "crypto",
            action: "crypto_failure",
            severity: Severity::Critical,
            outcome: "failure",
            user_id: None,
            source_ip: None,
            detail: Some(detail.to_string()),
        };
        event.emit();
    }

    /// Emit an entropy quality check failure event.
    pub fn entropy_quality_failure(detail: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "integrity",
            action: "entropy_quality_failure",
            severity: Severity::Critical,
            outcome: "failure",
            user_id: None,
            source_ip: None,
            detail: Some(detail.to_string()),
        };
        event.emit();
    }

    /// Emit a TLS required violation event (non-TLS in production).
    pub fn tls_required_violation(source_ip: Option<String>) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "access_control",
            action: "tls_required_violation",
            severity: Severity::High,
            outcome: "failure",
            user_id: None,
            source_ip,
            detail: Some("non-TLS connection attempted in production environment".into()),
        };
        event.emit();
    }

    /// Emit a ratchet heartbeat failure event (service unreachable).
    pub fn ratchet_heartbeat_failure(detail: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "availability",
            action: "ratchet_heartbeat_failure",
            severity: Severity::Critical,
            outcome: "failure",
            user_id: None,
            source_ip: None,
            detail: Some(detail.to_string()),
        };
        event.emit();
    }

    /// Emit a key rotation overdue event (reminder — operator action needed).
    pub fn key_rotation_overdue(detail: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "key_management",
            action: "key_rotation_overdue",
            severity: Severity::High,
            outcome: "failure",
            user_id: None,
            source_ip: None,
            detail: Some(detail.to_string()),
        };
        event.emit();
    }

    /// Emit a mutex poisoning recovery event.
    pub fn database_operation_failed(detail: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "database",
            action: "database_operation_failed",
            severity: Severity::Critical,
            outcome: "failure",
            user_id: None,
            source_ip: None,
            detail: Some(detail.to_string()),
        };
        event.emit();
    }

    pub fn mutex_poisoning(detail: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "integrity",
            action: "mutex_poisoning",
            severity: Severity::Elevated,
            outcome: "failure",
            user_id: None,
            source_ip: None,
            detail: Some(detail.to_string()),
        };
        event.emit();
    }

    /// Serialize this event to structured JSON suitable for SIEM ingestion.
    ///
    /// Output format:
    /// ```json
    /// {
    ///   "event_type": "login",
    ///   "timestamp": "1711234567Z",
    ///   "severity": "MEDIUM",
    ///   "source_module": "authentication",
    ///   "details": { "action": "login", "outcome": "failure", ... }
    /// }
    /// ```
    pub fn to_json(&self) -> String {
        let severity_label = match self.severity {
            Severity::Critical => "CRITICAL",
            Severity::Elevated | Severity::High => "HIGH",
            Severity::Warning | Severity::Medium => "MEDIUM",
            Severity::Notice | Severity::Low => "LOW",
            Severity::Info => "INFO",
        };

        let details = serde_json::json!({
            "action": self.action,
            "outcome": self.outcome,
            "user_id": self.user_id,
            "source_ip": self.source_ip,
            "detail": self.detail,
        });

        let envelope = serde_json::json!({
            "event_type": self.action,
            "timestamp": self.timestamp,
            "severity": severity_label,
            "source_module": self.category,
            "details": details,
        });

        serde_json::to_string(&envelope).unwrap_or_else(|_| "{}".to_string())
    }

    /// Emit this event via structured logging (JSON to tracing) and broadcast
    /// it to the live SIEM event bus for SSE consumers.
    pub(crate) fn emit(&self) {
        let json = self.to_json();
        tracing::info!(target: "siem", "{}", json);

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let siem_event = SiemEvent {
            timestamp,
            severity: self.severity as u8,
            event_type: self.action.to_string(),
            json,
        };

        broadcast_event(&siem_event);

        // Queue to external SIEM webhook if one has been initialised.
        crate::siem_webhook::queue_global_event(&siem_event.json);

        // Alert on high-severity events (severity >= 7 = HIGH)
        if siem_event.severity >= 7 {
            process_alert(&siem_event);
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── SiemPanel serialization ────────────────────────────────────────────

    #[test]
    fn test_siem_panel_serializes_all_variants() {
        let panels = SiemPanel::all();
        let expected = [
            "runtime_errors",
            "crypto_failures",
            "auth_failures",
            "protocol_violations",
            "threshold_violations",
            "integrity_violations",
            "network_anomalies",
            "access_denied",
            "key_management",
            "compliance_alerts",
            "signing_witness",
            "multi_region",
            "distributed_kms",
            "debug_panel",
        ];
        assert_eq!(panels.len(), expected.len(), "panel count mismatch");
        for (panel, expect) in panels.iter().zip(expected.iter()) {
            let json = serde_json::to_string(panel).unwrap();
            assert_eq!(json, format!("\"{}\"", expect), "panel {:?} serialized wrong", panel);
            assert_eq!(panel.as_str(), *expect);
        }
    }

    #[test]
    fn test_all_panel_variants_are_distinct() {
        let panels = SiemPanel::all();
        let mut seen = std::collections::HashSet::new();
        for p in panels {
            assert!(seen.insert(p), "duplicate panel: {:?}", p);
        }
        assert_eq!(seen.len(), 14);
    }

    // ── SiemSeverity serialization ─────────────────────────────────────────

    #[test]
    fn test_siem_severity_serializes() {
        assert_eq!(serde_json::to_string(&SiemSeverity::Debug).unwrap(), "\"DEBUG\"");
        assert_eq!(serde_json::to_string(&SiemSeverity::Info).unwrap(), "\"INFO\"");
        assert_eq!(serde_json::to_string(&SiemSeverity::Warning).unwrap(), "\"WARNING\"");
        assert_eq!(serde_json::to_string(&SiemSeverity::Error).unwrap(), "\"ERROR\"");
        assert_eq!(serde_json::to_string(&SiemSeverity::Critical).unwrap(), "\"CRITICAL\"");
        assert_eq!(serde_json::to_string(&SiemSeverity::Fatal).unwrap(), "\"FATAL\"");
    }

    #[test]
    fn test_siem_severity_ordering() {
        assert!(SiemSeverity::Debug < SiemSeverity::Info);
        assert!(SiemSeverity::Info < SiemSeverity::Warning);
        assert!(SiemSeverity::Warning < SiemSeverity::Error);
        assert!(SiemSeverity::Error < SiemSeverity::Critical);
        assert!(SiemSeverity::Critical < SiemSeverity::Fatal);
    }

    // ── siem_event! macro captures file:line ───────────────────────────────

    #[test]
    fn test_siem_event_macro_captures_source_location() {
        reset_panel_dedup();

        // Construct event manually with same mechanism as the macro
        let event = PanelSiemEvent::new(
            SiemPanel::AuthFailures,
            SiemSeverity::Error,
            "SiemPanel::AuthFailures",
            "test login failed",
            file!(),
            line!(),
            module_path!(),
        );

        assert_eq!(event.panel, SiemPanel::AuthFailures);
        assert_eq!(event.severity, SiemSeverity::Error);
        assert!(event.source_file.contains("siem.rs"), "file should contain siem.rs, got {}", event.source_file);
        assert!(event.source_line > 0, "line should be non-zero");
        assert!(event.source_module.contains("siem"), "module should contain siem, got {}", event.source_module);
        assert_eq!(event.message, "test login failed");
    }

    #[test]
    fn test_siem_event_macro_with_details() {
        reset_panel_dedup();

        let event = PanelSiemEvent::new(
            SiemPanel::CryptoFailures,
            SiemSeverity::Critical,
            "SiemPanel::CryptoFailures",
            "key derive failed",
            file!(),
            line!(),
            module_path!(),
        )
        .with_details(serde_json::json!({"algo": "AES-256-GCM"}));

        assert_eq!(event.panel, SiemPanel::CryptoFailures);
        let details = event.details.unwrap();
        assert_eq!(details["algo"], "AES-256-GCM");
    }

    // ── PanelSiemEvent serialization includes all fields ───────────────────

    #[test]
    fn test_panel_siem_event_serialization() {
        let event = PanelSiemEvent {
            panel: SiemPanel::NetworkAnomalies,
            severity: SiemSeverity::Warning,
            category: "network".to_string(),
            message: "connection timeout".to_string(),
            source_file: "src/net.rs",
            source_line: 42,
            source_module: "common::net",
            node_id: "node-1".to_string(),
            timestamp: 1700000000,
            correlation_id: Some("corr-abc".to_string()),
            details: Some(serde_json::json!({"peer": "10.0.0.1"})),
        };

        let json: serde_json::Value = serde_json::to_value(&event).unwrap();
        assert_eq!(json["panel"], "network_anomalies");
        assert_eq!(json["severity"], "WARNING");
        assert_eq!(json["source_file"], "src/net.rs");
        assert_eq!(json["source_line"], 42);
        assert_eq!(json["source_module"], "common::net");
        assert_eq!(json["node_id"], "node-1");
        assert_eq!(json["correlation_id"], "corr-abc");
        assert_eq!(json["details"]["peer"], "10.0.0.1");
    }

    // ── siem_unwrap on Ok returns value ────────────────────────────────────

    #[test]
    fn test_siem_unwrap_ok_returns_value() {
        reset_panel_dedup();

        fn inner() -> Result<i32, String> {
            let val: Result<i32, String> = Ok(42);
            let v = siem_unwrap!(val, "test unwrap");
            Ok(v)
        }
        assert_eq!(inner().unwrap(), 42);
    }

    // ── siem_unwrap on Err emits event ─────────────────────────────────────

    #[test]
    fn test_siem_unwrap_err_emits_event_and_returns_err() {
        reset_panel_dedup();

        fn inner() -> Result<i32, String> {
            let val: Result<i32, &str> = Err("bad key");
            let _v = siem_unwrap!(val, "decrypting DEK");
            Ok(0)
        }
        let result = inner();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("decrypting DEK"), "error should contain context, got: {}", err);
        assert!(err.contains("bad key"), "error should contain original error, got: {}", err);
        // file:line is embedded in the error string
        assert!(err.contains("siem.rs:"), "error should contain file:line, got: {}", err);
    }

    // ── siem_expect on Some returns value ──────────────────────────────────

    #[test]
    fn test_siem_expect_some_returns_value() {
        reset_panel_dedup();

        fn inner() -> Result<i32, String> {
            let val: Option<i32> = Some(99);
            let v = siem_expect!(val, "loading config");
            Ok(v)
        }
        assert_eq!(inner().unwrap(), 99);
    }

    // ── siem_expect on None emits event ────────────────────────────────────

    #[test]
    fn test_siem_expect_none_emits_event_and_returns_err() {
        reset_panel_dedup();

        fn inner() -> Result<i32, String> {
            let val: Option<i32> = None;
            let _v = siem_expect!(val, "loading KEK");
            Ok(0)
        }
        let result = inner();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("loading KEK"), "error should contain context, got: {}", err);
        assert!(err.contains("None"), "error should contain None, got: {}", err);
    }

    // ── Event batching deduplicates within window ──────────────────────────

    #[test]
    fn test_event_batching_deduplicates_within_window() {
        reset_panel_dedup();

        // First event should be allowed
        let e1 = PanelSiemEvent::new(
            SiemPanel::RuntimeErrors,
            SiemSeverity::Error,
            "test",
            "same message",
            file!(),
            line!(),
            module_path!(),
        );
        assert!(panel_rate_limiter_allow(&e1), "first event should pass");

        // Second identical event within window should be suppressed
        let e2 = PanelSiemEvent::new(
            SiemPanel::RuntimeErrors,
            SiemSeverity::Error,
            "test",
            "same message",
            file!(),
            line!(),
            module_path!(),
        );
        assert!(!panel_rate_limiter_allow(&e2), "duplicate event should be suppressed");

        // Different message should pass
        let e3 = PanelSiemEvent::new(
            SiemPanel::RuntimeErrors,
            SiemSeverity::Error,
            "test",
            "different message",
            file!(),
            line!(),
            module_path!(),
        );
        assert!(panel_rate_limiter_allow(&e3), "different message should pass");

        // Different panel with same message should pass
        let e4 = PanelSiemEvent::new(
            SiemPanel::CryptoFailures,
            SiemSeverity::Error,
            "test",
            "same message",
            file!(),
            line!(),
            module_path!(),
        );
        assert!(panel_rate_limiter_allow(&e4), "different panel should pass");
    }

    #[test]
    fn test_event_batching_allows_after_window_expires() {
        reset_panel_dedup();

        let mut e1 = PanelSiemEvent::new(
            SiemPanel::DebugPanel,
            SiemSeverity::Error,
            "test",
            "expiry test msg",
            file!(),
            line!(),
            module_path!(),
        );
        // Set timestamp in the past beyond the dedup window
        e1.timestamp = 1000;
        assert!(panel_rate_limiter_allow(&e1), "first event should pass");

        // Second event with timestamp beyond window
        let mut e2 = PanelSiemEvent::new(
            SiemPanel::DebugPanel,
            SiemSeverity::Error,
            "test",
            "expiry test msg",
            file!(),
            line!(),
            module_path!(),
        );
        e2.timestamp = 1000 + DEDUP_WINDOW_SECS + 1;
        assert!(panel_rate_limiter_allow(&e2), "event after window should pass");
    }

    // ── PanelSiemEvent with_correlation_id ─────────────────────────────────

    #[test]
    fn test_panel_event_correlation_id() {
        let event = PanelSiemEvent::new(
            SiemPanel::MultiRegion,
            SiemSeverity::Info,
            "multi_region",
            "region sync",
            file!(),
            line!(),
            module_path!(),
        )
        .with_correlation_id("req-12345");

        assert_eq!(event.correlation_id.as_deref(), Some("req-12345"));
    }

    // ── hash_message produces different hashes ─────────────────────────────

    #[test]
    fn test_hash_message_distinct() {
        let h1 = hash_message("alpha");
        let h2 = hash_message("beta");
        let h3 = hash_message("alpha");
        assert_ne!(h1, h2);
        assert_eq!(h1, h3);
    }
}
