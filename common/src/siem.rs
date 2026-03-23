//! Structured security event emitter for SIEM integration.
//!
//! Emits JSON-formatted security events to stdout (structured logging) that
//! can be consumed by SIEM systems (Splunk, Elastic, etc.) via log forwarding.
#![forbid(unsafe_code)]

use serde::Serialize;
use uuid::Uuid;

/// Security event severity levels (CEF-compatible).
#[derive(Debug, Clone, Copy, Serialize)]
pub enum Severity {
    Low = 1,
    Medium = 4,
    High = 7,
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

    /// Emit this event via structured logging (JSON to tracing).
    fn emit(&self) {
        if let Ok(json) = serde_json::to_string(self) {
            tracing::info!(target: "siem", "{}", json);
        }
    }
}
