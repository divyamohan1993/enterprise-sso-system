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
use std::sync::LazyLock;
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

    /// Emit this event via structured logging (JSON to tracing) and broadcast
    /// it to the live SIEM event bus for SSE consumers.
    fn emit(&self) {
        if let Ok(json) = serde_json::to_string(self) {
            tracing::info!(target: "siem", "{}", json);

            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            broadcast_event(&SiemEvent {
                timestamp,
                severity: self.severity as u8,
                event_type: self.action.to_string(),
                json,
            });
        }
    }
}
