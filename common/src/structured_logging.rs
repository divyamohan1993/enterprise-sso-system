//! Structured JSON logging compatible with Google Cloud Logging.
//!
//! Provides a logging layer that emits JSON-structured log entries with:
//! - Cloud Logging severity mapping
//! - Distributed tracing: trace_id and span_id fields
//! - Service metadata (name, version, instance)
//! - Request correlation via `x-request-id`
//!
//! Output format matches the Cloud Logging
//! [structured logging](https://cloud.google.com/logging/docs/structured-logging)
//! specification so that Fluent Bit or the GKE logging agent can parse entries
//! without additional transformation.
#![forbid(unsafe_code)]

use serde::Serialize;
use std::sync::OnceLock;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Global service metadata, set once at startup.
static SERVICE_META: OnceLock<ServiceMeta> = OnceLock::new();

/// Metadata about the running service instance.
#[derive(Debug, Clone, Serialize)]
pub struct ServiceMeta {
    /// Service name (e.g. "gateway", "orchestrator").
    pub service_name: String,
    /// Semantic version of the service binary.
    pub service_version: String,
    /// Instance ID (pod name or unique ID).
    pub instance_id: String,
    /// GCP project ID.
    pub project_id: String,
}

/// Initialize the structured logging subsystem. Must be called once at startup
/// before any log entries are emitted.
pub fn init(meta: ServiceMeta) {
    let _ = SERVICE_META.set(meta);
}

/// Get a reference to the service metadata (returns a default if not initialized).
fn meta() -> &'static ServiceMeta {
    SERVICE_META.get_or_init(|| ServiceMeta {
        service_name: "unknown".into(),
        service_version: "0.0.0".into(),
        instance_id: "unknown".into(),
        project_id: "lmsforshantithakur".into(),
    })
}

// ---------------------------------------------------------------------------
// Cloud Logging severity levels
// ---------------------------------------------------------------------------

/// Severity levels matching Cloud Logging's `severity` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Default,
    Debug,
    Info,
    Notice,
    Warning,
    Error,
    Critical,
    Alert,
    Emergency,
}

impl Severity {
    /// Map from the MILNET SIEM severity string to Cloud Logging severity.
    pub fn from_milnet(s: &str) -> Self {
        match s {
            "CRITICAL" => Severity::Critical,
            "HIGH" => Severity::Error,
            "MEDIUM" => Severity::Warning,
            "LOW" => Severity::Info,
            "INFO" => Severity::Debug,
            _ => Severity::Default,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Severity::Default => "DEFAULT",
            Severity::Debug => "DEBUG",
            Severity::Info => "INFO",
            Severity::Notice => "NOTICE",
            Severity::Warning => "WARNING",
            Severity::Error => "ERROR",
            Severity::Critical => "CRITICAL",
            Severity::Alert => "ALERT",
            Severity::Emergency => "EMERGENCY",
        };
        write!(f, "{}", s)
    }
}

// ---------------------------------------------------------------------------
// Trace context
// ---------------------------------------------------------------------------

/// Distributed tracing context extracted from incoming requests or generated
/// at the service boundary.
#[derive(Debug, Clone, Serialize)]
pub struct TraceContext {
    /// Full trace resource name for Cloud Trace:
    /// `projects/{project}/traces/{trace_id}`
    #[serde(rename = "logging.googleapis.com/trace")]
    pub trace: String,
    /// Span ID within the trace (hex string).
    #[serde(rename = "logging.googleapis.com/spanId")]
    pub span_id: String,
    /// Whether this span was sampled.
    #[serde(rename = "logging.googleapis.com/trace_sampled")]
    pub trace_sampled: bool,
}

impl TraceContext {
    /// Create a new trace context from raw IDs.
    pub fn new(trace_id: &str, span_id: &str, sampled: bool) -> Self {
        let m = meta();
        Self {
            trace: format!("projects/{}/traces/{}", m.project_id, trace_id),
            span_id: span_id.to_string(),
            trace_sampled: sampled,
        }
    }

    /// Generate a brand-new trace context (for request entry points).
    pub fn generate() -> Self {
        let trace_id = Uuid::new_v4().to_string().replace('-', "");
        let span_bytes: [u8; 8] = {
            let mut buf = [0u8; 8];
            getrandom::getrandom(&mut buf).unwrap_or_default();
            buf
        };
        let span_id = hex::encode(span_bytes);
        Self::new(&trace_id, &span_id, true)
    }

    /// Parse from the `x-cloud-trace-context` header.
    /// Format: `TRACE_ID/SPAN_ID;o=TRACE_TRUE`
    pub fn from_header(header: &str) -> Option<Self> {
        let parts: Vec<&str> = header.split('/').collect();
        if parts.len() < 2 {
            return None;
        }
        let trace_id = parts[0];
        let span_and_flags: Vec<&str> = parts[1].split(';').collect();
        let span_id = span_and_flags[0];
        let sampled = span_and_flags
            .get(1)
            .map(|f| f.contains("o=1"))
            .unwrap_or(false);
        Some(Self::new(trace_id, span_id, sampled))
    }
}

// ---------------------------------------------------------------------------
// Structured log entry
// ---------------------------------------------------------------------------

/// A structured log entry compatible with Cloud Logging's JSON format.
#[derive(Debug, Serialize)]
pub struct LogEntry {
    /// Cloud Logging severity level.
    pub severity: Severity,
    /// Human-readable log message.
    pub message: String,
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// Trace context for distributed tracing.
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_context: Option<TraceContext>,
    /// Service metadata.
    #[serde(rename = "serviceContext")]
    pub service_context: ServiceContext,
    /// Request-specific fields.
    #[serde(rename = "httpRequest")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_request: Option<HttpRequestContext>,
    /// Arbitrary structured payload (the "jsonPayload" for SIEM events).
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
    /// Labels for filtering in Cloud Logging.
    #[serde(rename = "logging.googleapis.com/labels")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<std::collections::HashMap<String, String>>,
}

/// Service context attached to every log entry.
#[derive(Debug, Serialize)]
pub struct ServiceContext {
    pub service: String,
    pub version: String,
    #[serde(rename = "instanceId")]
    pub instance_id: String,
}

/// HTTP request context for request-scoped log entries.
#[derive(Debug, Serialize)]
pub struct HttpRequestContext {
    #[serde(rename = "requestMethod")]
    pub method: String,
    #[serde(rename = "requestUrl")]
    pub url: String,
    #[serde(rename = "remoteIp")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_ip: Option<String>,
    #[serde(rename = "latency")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency: Option<String>,
    #[serde(rename = "status")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
}

impl LogEntry {
    /// Create a new log entry with the current timestamp and service metadata.
    pub fn new(severity: Severity, message: impl Into<String>) -> Self {
        let m = meta();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let secs = now.as_secs();
        let nanos = now.subsec_nanos();

        Self {
            severity,
            message: message.into(),
            timestamp: format!("{}.{:09}Z", secs, nanos),
            trace_context: None,
            service_context: ServiceContext {
                service: m.service_name.clone(),
                version: m.service_version.clone(),
                instance_id: m.instance_id.clone(),
            },
            http_request: None,
            payload: None,
            labels: None,
        }
    }

    /// Attach trace context.
    pub fn with_trace(mut self, ctx: TraceContext) -> Self {
        self.trace_context = Some(ctx);
        self
    }

    /// Attach HTTP request context.
    /// PRIVACY: The `remote_ip` field is pseudonymized before storage to prevent
    /// raw IP addresses from appearing in log output. Uses HMAC-SHA512 keyed by
    /// the master KEK when available, otherwise falls back to SHA-512 hash
    /// truncated to 8 bytes for KEK-independent unlinkability.
    pub fn with_http(mut self, mut req: HttpRequestContext) -> Self {
        if let Some(ref ip) = req.remote_ip {
            req.remote_ip = Some(pseudonymize_ip(ip));
        }
        self.http_request = Some(req);
        self
    }

    /// Attach an arbitrary JSON payload (for SIEM event forwarding).
    pub fn with_payload(mut self, payload: serde_json::Value) -> Self {
        self.payload = Some(payload);
        self
    }

    /// Add a label key-value pair.
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels
            .get_or_insert_with(std::collections::HashMap::new)
            .insert(key.into(), value.into());
        self
    }

    /// Emit this entry to stdout as a single JSON line.
    /// If `MILNET_SYSLOG_ENDPOINT` is set, also sends via UDP to the remote
    /// syslog endpoint as a secondary log sink surviving local compromise.
    pub fn emit(&self) {
        if let Ok(json) = serde_json::to_string(self) {
            // Use println! to ensure atomicity of the line write
            println!("{}", json);

            // Send to remote syslog if configured
            if let Some(endpoint) = syslog_endpoint() {
                send_to_syslog(endpoint, &json);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Remote syslog support
// ---------------------------------------------------------------------------

/// Cached syslog endpoint from `MILNET_SYSLOG_ENDPOINT` env var.
static SYSLOG_ENDPOINT: OnceLock<Option<String>> = OnceLock::new();

/// Get the remote syslog endpoint, if configured.
fn syslog_endpoint() -> Option<&'static str> {
    SYSLOG_ENDPOINT
        .get_or_init(|| {
            std::env::var("MILNET_SYSLOG_ENDPOINT")
                .ok()
                .filter(|s| !s.is_empty())
        })
        .as_deref()
}

/// Send a log line to the remote syslog endpoint via TCP+TLS (preferred) or UDP (dev/test only).
///
/// SECURITY: UDP syslog transmits log lines in plaintext, observable by network
/// attackers. In production (MILNET_PRODUCTION=1), UDP syslog is refused entirely.
/// In military mode (MILNET_MILITARY_DEPLOYMENT=1), configuring UDP syslog is fatal.
/// TCP+TLS is used when `MILNET_SYSLOG_TLS=1` is set.
fn send_to_syslog(endpoint: &str, json_line: &str) {
    use std::net::UdpSocket;

    // Check if TLS syslog is enabled (preferred for military deployment)
    static USE_TLS: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let use_tls = *USE_TLS.get_or_init(|| {
        std::env::var("MILNET_SYSLOG_TLS").as_deref() == Ok("1")
    });

    if use_tls {
        send_to_syslog_tls(endpoint, json_line);
        return;
    }

    // SECURITY: In production, refuse plaintext UDP syslog.
    static IS_PRODUCTION: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let is_production = *IS_PRODUCTION.get_or_init(|| {
        std::env::var("MILNET_PRODUCTION").as_deref() == Ok("1")
    });

    static IS_MILITARY: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let is_military = *IS_MILITARY.get_or_init(|| {
        std::env::var("MILNET_MILITARY_DEPLOYMENT").as_deref() == Ok("1")
    });

    if is_military {
        // Military mode: UDP syslog configuration is a fatal misconfiguration
        eprintln!(
            "FATAL: UDP syslog configured in military deployment. \
             Set MILNET_SYSLOG_TLS=1 or remove MILNET_SYSLOG_ENDPOINT."
        );
        std::process::exit(1);
    }

    if is_production {
        // Production mode: refuse UDP, log SIEM:CRITICAL
        tracing::error!(
            "SIEM:CRITICAL: UDP syslog refused in production mode. \
             Set MILNET_SYSLOG_TLS=1 for secure log shipping."
        );
        return;
    }

    // Dev/test only: plaintext UDP syslog
    thread_local! {
        static UDP_SOCKET: Option<UdpSocket> = {
            UdpSocket::bind("0.0.0.0:0").ok().map(|s| {
                let _ = s.set_nonblocking(true);
                s
            })
        };
    }

    UDP_SOCKET.with(|sock| {
        if let Some(ref s) = sock {
            let _ = s.send_to(json_line.as_bytes(), endpoint);
        }
    });
}

/// Send a log line over TCP+TLS syslog (RFC 5425 framing: octet-counted).
///
/// SECURITY: TLS syslog requires a full rustls + tokio-rustls integration
/// which is not yet implemented in the common crate. This function logs
/// SIEM:CRITICAL and refuses to silently drop log lines. Deployers must
/// use MILNET_SIEM_WEBHOOK for secure log shipping until TLS syslog is
/// implemented.
fn send_to_syslog_tls(endpoint: &str, _json_line: &str) {
    // Log at most once to avoid flooding
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        tracing::error!(
            endpoint = endpoint,
            "SIEM:CRITICAL: TLS syslog transport not yet implemented. \
             Log lines to syslog endpoint are being DROPPED. \
             Use MILNET_SIEM_WEBHOOK for secure log shipping instead."
        );
    }
}

// ---------------------------------------------------------------------------
// IP pseudonymization for log output
// ---------------------------------------------------------------------------

/// Pseudonymize an IP address for log output.
/// Tries HMAC-SHA512 keyed by master KEK (via `log_pseudonym::pseudonym_ip`).
/// If the KEK is unavailable (e.g. during early startup), falls back to a
/// plain SHA-512 hash truncated to 8 bytes, providing unlinkability without
/// requiring the KEK.
fn pseudonymize_ip(ip: &str) -> String {
    // Try KEK-backed pseudonymization (production path)
    let result = std::panic::catch_unwind(|| {
        crate::log_pseudonym::pseudonym_ip(ip)
    });
    if let Ok(pseudonym) = result {
        return pseudonym;
    }
    // Fallback: SHA-512 hash when KEK is not available (early startup / tests)
    use sha2::{Sha512, Digest};
    let mut hasher = Sha512::new();
    hasher.update(b"MILNET-LOG-IP-PSEUDO:");
    hasher.update(ip.as_bytes());
    let hash = hasher.finalize();
    format!("ip-{}", hex::encode(&hash[..8]))
}

// ---------------------------------------------------------------------------
// Convenience functions
// ---------------------------------------------------------------------------

/// Emit a debug-level structured log entry.
pub fn debug(message: impl Into<String>) {
    LogEntry::new(Severity::Debug, message).emit();
}

/// Emit an info-level structured log entry.
pub fn info(message: impl Into<String>) {
    LogEntry::new(Severity::Info, message).emit();
}

/// Emit a warning-level structured log entry.
pub fn warning(message: impl Into<String>) {
    LogEntry::new(Severity::Warning, message).emit();
}

/// Emit an error-level structured log entry.
pub fn error(message: impl Into<String>) {
    LogEntry::new(Severity::Error, message).emit();
}

/// Emit a critical-level structured log entry.
pub fn critical(message: impl Into<String>) {
    LogEntry::new(Severity::Critical, message).emit();
}

/// Emit a structured SIEM event as a Cloud Logging entry with the appropriate
/// severity and payload, including optional trace context.
pub fn siem_event(
    severity_label: &str,
    event_json: serde_json::Value,
    trace: Option<TraceContext>,
) {
    let severity = Severity::from_milnet(severity_label);
    let mut entry = LogEntry::new(severity, format!("SIEM: {}", severity_label))
        .with_payload(event_json)
        .with_label("log_type", "siem_event");
    if let Some(t) = trace {
        entry = entry.with_trace(t);
    }
    entry.emit();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_entry_serializes() {
        let entry = LogEntry::new(Severity::Warning, "test message")
            .with_label("test_key", "test_value");

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"severity\":\"WARNING\""));
        assert!(json.contains("\"message\":\"test message\""));
        assert!(json.contains("\"test_key\":\"test_value\""));
    }

    #[test]
    fn test_trace_context_from_header() {
        let ctx = TraceContext::from_header(
            "105445aa7843bc8bf206b120001000/1;o=1",
        )
        .unwrap();
        assert!(ctx.trace.contains("105445aa7843bc8bf206b120001000"));
        assert_eq!(ctx.span_id, "1");
        assert!(ctx.trace_sampled);
    }

    #[test]
    fn test_severity_mapping() {
        assert_eq!(Severity::from_milnet("CRITICAL"), Severity::Critical);
        assert_eq!(Severity::from_milnet("HIGH"), Severity::Error);
        assert_eq!(Severity::from_milnet("MEDIUM"), Severity::Warning);
        assert_eq!(Severity::from_milnet("LOW"), Severity::Info);
        assert_eq!(Severity::from_milnet("INFO"), Severity::Debug);
        assert_eq!(Severity::from_milnet("unknown"), Severity::Default);
    }
}
