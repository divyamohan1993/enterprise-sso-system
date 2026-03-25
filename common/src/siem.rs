//! Structured security event emitter for SIEM integration.
//!
//! Emits JSON-formatted security events to stdout (structured logging) that
//! can be consumed by SIEM systems (Splunk, Elastic, etc.) via log forwarding.
//!
//! Also publishes events to an in-process broadcast channel so that SSE
//! consumers (e.g. the admin `/api/admin/siem/stream` endpoint) can receive
//! events in real time.
#![forbid(unsafe_code)]

use serde::Serialize;
use std::sync::{LazyLock, OnceLock};
use uuid::Uuid;

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
fn persist_alert_to_file(json: &str) {
    if let Err(e) = std::fs::create_dir_all(ALERT_DIR) {
        tracing::warn!("failed to create alert directory {}: {}", ALERT_DIR, e);
        return;
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

    // Minimal URL parsing: expect "http://host:port/path" or "https://..."
    let body = match serde_json::to_string(event) {
        Ok(b) => b,
        Err(_) => return,
    };

    // Spawn a blocking task so we don't block the async runtime.
    let _ = std::thread::Builder::new()
        .name("siem-webhook".into())
        .spawn(move || {
            send_webhook_blocking(&url_str, &body);
        });
}

/// Blocking HTTP POST helper.
fn send_webhook_blocking(url: &str, body: &str) {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    // Very minimal URL parsing
    let without_scheme = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);

    let (host_port, path) = match without_scheme.find('/') {
        Some(i) => (&without_scheme[..i], &without_scheme[i..]),
        None => (without_scheme, "/"),
    };

    let host_port_owned = if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{}:80", host_port)
    };

    let stream = match TcpStream::connect_timeout(
        &host_port_owned.parse().unwrap_or_else(|_| {
            std::net::SocketAddr::from(([127, 0, 0, 1], 80))
        }),
        Duration::from_secs(5),
    ) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("webhook connect failed: {}", e);
            return;
        }
    };

    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));

    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path, host_port, body.len(), body
    );

    let mut stream = stream;
    if let Err(e) = stream.write_all(request.as_bytes()) {
        tracing::warn!("webhook write failed: {}", e);
        return;
    }

    // Read (and discard) the response to complete the TCP exchange.
    let mut buf = [0u8; 512];
    let _ = stream.read(&mut buf);
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
    fn now_iso8601() -> String {
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

    /// Emit a developer mode toggle blocked event (production protection).
    pub fn developer_mode_blocked() {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "configuration",
            action: "developer_mode_blocked",
            severity: Severity::Critical,
            outcome: "failure",
            user_id: None,
            source_ip: None,
            detail: Some("runtime developer mode toggle blocked in production".into()),
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
    fn emit(&self) {
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

        // Alert on high-severity events (severity >= 7 = HIGH)
        if siem_event.severity >= 7 {
            process_alert(&siem_event);
        }
    }
}
