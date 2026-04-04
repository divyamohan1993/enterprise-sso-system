//! Webhook and Event Streaming for the MILNET SSO system.
//!
//! Provides:
//! - EventStreamManager for pushing auth events to external systems
//! - Webhook delivery with HMAC-SHA512 signing, retries, dead letter queue
//! - Server-Sent Events (SSE) streaming endpoint support
//! - CloudEvents format (CNCF spec) for event envelope
//! - Webhook registration API (CRUD + test)
//! - Webhook secret rotation
//! - Delivery status tracking
//! - Integration with existing SIEM broadcast channel
#![forbid(unsafe_code)]

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use uuid::Uuid;

use crate::siem::{self, SecurityEvent, SiemEvent};

// ── Constants ───────────────────────────────────────────────────────────────

/// Maximum retries for webhook delivery.
const MAX_RETRIES: u32 = 3;

/// Maximum number of registered webhooks.
const MAX_WEBHOOKS: usize = 100;

/// Maximum dead letter queue size per webhook.
const MAX_DEAD_LETTER_PER_WEBHOOK: usize = 1_000;

/// Default rate limit: requests per minute per webhook.
const DEFAULT_RATE_LIMIT_PER_MINUTE: u32 = 60;

/// Webhook HMAC signature header name.
pub const SIGNATURE_HEADER: &str = "X-MILNET-Signature";

/// CloudEvents spec version.
const CLOUDEVENTS_SPEC_VERSION: &str = "1.0";

// ── Event Types ─────────────────────────────────────────────────────────────

/// Categories of events that can be streamed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventCategory {
    /// Authentication events (login, logout, MFA, etc.).
    Auth,
    /// Administrative events (user CRUD, config changes).
    Admin,
    /// Security events (brute force, anomalies, tampering).
    Security,
    /// Compliance events (audit, policy violations).
    Compliance,
}

impl EventCategory {
    /// Return the string representation used in CloudEvents type field.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auth => "mil.milnet.sso.auth",
            Self::Admin => "mil.milnet.sso.admin",
            Self::Security => "mil.milnet.sso.security",
            Self::Compliance => "mil.milnet.sso.compliance",
        }
    }

    /// Classify a SIEM event type into an EventCategory.
    pub fn from_siem_event_type(event_type: &str) -> Self {
        match event_type {
            "login" | "logout" | "mfa_challenge" | "mfa_success" | "cac_auth_success"
            | "cac_auth_failure" | "session_created" | "session_expired" | "session_revoked"
            | "dpop_missing" | "authn_request_received" => Self::Auth,

            "user_created" | "user_updated" | "user_deleted" | "role_assigned"
            | "sp_registered" | "key_rotation" | "config_changed" => Self::Admin,

            "tamper_detected" | "brute_force" | "rate_limit_exceeded"
            | "privilege_escalation" | "duress" | "lockout"
            | "certificate_validation_failed" | "entropy_quality_failure"
            | "mutex_poisoning" | "circuit_breaker_opened" => Self::Security,

            "audit_export" | "compliance_violation" | "data_residency_violation"
            | "stig_finding" | "cmmc_assessment" => Self::Compliance,

            _ => Self::Security, // Default to security for unknown types
        }
    }
}

impl std::fmt::Display for EventCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ── CloudEvents Envelope ────────────────────────────────────────────────────

/// CloudEvents-formatted event envelope (CNCF spec 1.0).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudEvent {
    /// Event ID (UUID).
    pub id: String,
    /// Event source URI.
    pub source: String,
    /// CloudEvents spec version.
    pub specversion: String,
    /// Event type (e.g., "mil.milnet.sso.auth.login").
    #[serde(rename = "type")]
    pub event_type: String,
    /// Timestamp (ISO 8601).
    pub time: String,
    /// Content type of the data payload.
    pub datacontenttype: String,
    /// Subject (e.g., user ID or entity ID).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Event data payload (the actual event content).
    pub data: serde_json::Value,
}

impl CloudEvent {
    /// Create a new CloudEvent from a SIEM event.
    pub fn from_siem_event(siem_event: &SiemEvent, source: &str) -> Self {
        let category = EventCategory::from_siem_event_type(&siem_event.event_type);
        let data: serde_json::Value =
            serde_json::from_str(&siem_event.json).unwrap_or(serde_json::Value::Null);

        Self {
            id: Uuid::new_v4().to_string(),
            source: source.to_string(),
            specversion: CLOUDEVENTS_SPEC_VERSION.to_string(),
            event_type: format!("{}.{}", category.as_str(), siem_event.event_type),
            time: epoch_to_iso8601(siem_event.timestamp),
            datacontenttype: "application/json".to_string(),
            subject: data
                .get("details")
                .and_then(|d| d.get("user_id"))
                .and_then(|u| u.as_str())
                .map(|s| s.to_string()),
            data,
        }
    }

    /// Serialize to JSON bytes for delivery.
    pub fn to_json_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
}

// ── Delivery Status ─────────────────────────────────────────────────────────

/// Status of a webhook delivery attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryStatus {
    /// Delivery is queued/pending.
    Pending,
    /// Successfully delivered (2xx response).
    Delivered,
    /// Delivery failed after all retries.
    Failed,
    /// Moved to dead letter queue.
    DeadLetter,
}

impl std::fmt::Display for DeliveryStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Delivered => write!(f, "delivered"),
            Self::Failed => write!(f, "failed"),
            Self::DeadLetter => write!(f, "dead_letter"),
        }
    }
}

/// Record of a single delivery attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryRecord {
    /// Delivery attempt ID.
    pub id: String,
    /// Webhook ID this delivery is for.
    pub webhook_id: String,
    /// CloudEvent ID.
    pub event_id: String,
    /// Current delivery status.
    pub status: DeliveryStatus,
    /// Number of attempts made.
    pub attempts: u32,
    /// Last attempt timestamp (epoch seconds).
    pub last_attempt_at: i64,
    /// HTTP status code from last attempt (if any).
    pub last_status_code: Option<u16>,
    /// Error message from last attempt (if failed).
    pub last_error: Option<String>,
    /// Next retry timestamp (if pending retry).
    pub next_retry_at: Option<i64>,
}

// ── Webhook Configuration ───────────────────────────────────────────────────

/// A registered webhook endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Unique webhook ID.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Target URL (HTTPS required in production).
    pub url: String,
    /// HMAC-SHA512 secret for payload signing.
    #[serde(skip_serializing)]
    pub secret: String,
    /// Event category filters — only matching events are delivered.
    /// Empty means all events.
    pub event_filters: Vec<EventCategory>,
    /// Specific event type filters (e.g., "auth_failure", "tamper_detected").
    /// Empty means all event types within the category filters.
    pub event_type_filters: Vec<String>,
    /// Whether this webhook is active.
    pub active: bool,
    /// Rate limit: max deliveries per minute.
    pub rate_limit_per_minute: u32,
    /// Creation timestamp (epoch seconds).
    pub created_at: i64,
    /// Last modified timestamp (epoch seconds).
    pub updated_at: i64,
    /// Description.
    pub description: Option<String>,
}

impl WebhookConfig {
    /// Create a new webhook configuration.
    pub fn new(name: &str, url: &str) -> Self {
        let now = now_epoch();
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            url: url.to_string(),
            secret: generate_webhook_secret(),
            event_filters: Vec::new(),
            event_type_filters: Vec::new(),
            active: true,
            rate_limit_per_minute: DEFAULT_RATE_LIMIT_PER_MINUTE,
            created_at: now,
            updated_at: now,
            description: None,
        }
    }

    /// Validate the webhook URL. Returns error if invalid or non-HTTPS in production.
    pub fn validate_url(&self, is_production: bool) -> Result<(), String> {
        if self.url.is_empty() {
            return Err("webhook URL cannot be empty".to_string());
        }
        if is_production && !self.url.starts_with("https://") {
            return Err("webhook URL must use HTTPS in production".to_string());
        }
        if !self.url.starts_with("http://") && !self.url.starts_with("https://") {
            return Err("webhook URL must start with http:// or https://".to_string());
        }
        // Reject localhost/internal IPs in production to prevent SSRF
        if is_production {
            let host = self
                .url
                .strip_prefix("https://")
                .unwrap_or(&self.url)
                .split('/')
                .next()
                .unwrap_or("");
            if host.starts_with("127.")
                || host.starts_with("10.")
                || host.starts_with("192.168.")
                || host == "localhost"
                || host.starts_with("[::1]")
            {
                return Err("webhook URL must not target internal/private addresses in production".to_string());
            }
        }
        Ok(())
    }

    /// Check if this webhook should receive the given event.
    pub fn matches_event(&self, event: &SiemEvent) -> bool {
        if !self.active {
            return false;
        }

        let category = EventCategory::from_siem_event_type(&event.event_type);

        // If category filters are set, check membership
        if !self.event_filters.is_empty() && !self.event_filters.contains(&category) {
            return false;
        }

        // If event type filters are set, check membership
        if !self.event_type_filters.is_empty()
            && !self.event_type_filters.iter().any(|f| f == &event.event_type)
        {
            return false;
        }

        true
    }

    /// Compute HMAC-SHA512 signature for a payload.
    pub fn sign_payload(&self, payload: &[u8]) -> String {
        type HmacSha512 = Hmac<Sha512>;
        let mut mac = HmacSha512::new_from_slice(self.secret.as_bytes()).unwrap_or_else(|e| {
            tracing::error!("FATAL: HMAC-SHA512 key init failed for webhook signing: {e}");
            std::process::exit(1);
        });
        mac.update(payload);
        let result = mac.finalize().into_bytes();
        format!("sha512={}", hex::encode(result))
    }

    /// Verify an HMAC-SHA512 signature.
    pub fn verify_signature(&self, payload: &[u8], signature: &str) -> bool {
        let expected = self.sign_payload(payload);
        {
            use subtle::ConstantTimeEq;
            expected.as_bytes().ct_eq(signature.as_bytes()).into()
        }
    }
}

/// Webhook update request (fields that can be modified).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookUpdate {
    /// Updated name (if any).
    pub name: Option<String>,
    /// Updated URL (if any).
    pub url: Option<String>,
    /// Updated event filters (if any).
    pub event_filters: Option<Vec<EventCategory>>,
    /// Updated event type filters (if any).
    pub event_type_filters: Option<Vec<String>>,
    /// Updated active status (if any).
    pub active: Option<bool>,
    /// Updated rate limit (if any).
    pub rate_limit_per_minute: Option<u32>,
    /// Updated description (if any).
    pub description: Option<Option<String>>,
}

// ── Rate Limiter ────────────────────────────────────────────────────────────

/// Per-webhook rate limiter using a sliding window counter.
struct WebhookRateLimiter {
    /// Map of webhook ID -> (count in current window, window start epoch).
    windows: HashMap<String, (u32, i64)>,
}

impl WebhookRateLimiter {
    fn new() -> Self {
        Self {
            windows: HashMap::new(),
        }
    }

    /// Check if a delivery is allowed under the rate limit.
    /// Returns true if allowed, false if rate-limited.
    fn check_and_increment(&mut self, webhook_id: &str, limit_per_minute: u32) -> bool {
        let now = now_epoch();
        let window_start = now - (now % 60); // 1-minute window

        let entry = self
            .windows
            .entry(webhook_id.to_string())
            .or_insert((0, window_start));

        // Reset if we're in a new window
        if entry.1 < window_start {
            *entry = (0, window_start);
        }

        if entry.0 >= limit_per_minute {
            return false;
        }

        entry.0 += 1;
        true
    }

    /// Evict stale rate limit windows.
    fn evict_stale(&mut self) {
        let cutoff = now_epoch() - 120; // Keep 2 minutes of history
        self.windows.retain(|_, (_, start)| *start > cutoff);
    }
}

// ── Dead Letter Queue ───────────────────────────────────────────────────────

/// A dead letter entry for permanently failed deliveries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadLetterEntry {
    /// Original CloudEvent.
    pub event: CloudEvent,
    /// Webhook ID.
    pub webhook_id: String,
    /// Total attempts made.
    pub total_attempts: u32,
    /// Final error message.
    pub final_error: String,
    /// Timestamp when moved to DLQ (epoch seconds).
    pub dead_lettered_at: i64,
}

// ── SSE Event ───────────────────────────────────────────────────────────────

/// A Server-Sent Event formatted for SSE streaming.
#[derive(Debug, Clone)]
pub struct SseEvent {
    /// Event type (SSE `event:` field).
    pub event_type: String,
    /// Event data (SSE `data:` field, JSON-encoded CloudEvent).
    pub data: String,
    /// Event ID (SSE `id:` field).
    pub id: String,
    /// Retry hint in milliseconds (SSE `retry:` field).
    pub retry_ms: Option<u32>,
}

impl SseEvent {
    /// Create an SSE event from a CloudEvent.
    pub fn from_cloud_event(ce: &CloudEvent) -> Self {
        Self {
            event_type: ce.event_type.clone(),
            data: serde_json::to_string(ce).unwrap_or_default(),
            id: ce.id.clone(),
            retry_ms: Some(5000),
        }
    }

    /// Format as SSE wire protocol string.
    pub fn to_sse_string(&self) -> String {
        let mut out = String::new();
        if let Some(retry) = self.retry_ms {
            out.push_str(&format!("retry: {}\n", retry));
        }
        out.push_str(&format!("id: {}\n", self.id));
        out.push_str(&format!("event: {}\n", self.event_type));
        // SSE spec requires each line of data to be prefixed with "data: "
        for line in self.data.lines() {
            out.push_str(&format!("data: {}\n", line));
        }
        out.push('\n'); // Empty line terminates the event
        out
    }
}

// ── Event Stream Manager ────────────────────────────────────────────────────

/// Central manager for event streaming: webhooks, SSE, and dead letter queue.
pub struct EventStreamManager {
    /// Registered webhooks.
    webhooks: RwLock<HashMap<String, WebhookConfig>>,
    /// Dead letter queue per webhook.
    dead_letter_queues: RwLock<HashMap<String, Vec<DeadLetterEntry>>>,
    /// Delivery records (recent, bounded).
    delivery_records: RwLock<Vec<DeliveryRecord>>,
    /// Rate limiter.
    rate_limiter: RwLock<WebhookRateLimiter>,
    /// Event source URI for CloudEvents.
    source_uri: String,
    /// Whether running in production mode.
    is_production: bool,
    /// Total events processed counter.
    events_processed: AtomicU64,
    /// Total deliveries attempted counter.
    deliveries_attempted: AtomicU64,
    /// Total deliveries succeeded counter.
    deliveries_succeeded: AtomicU64,
    /// Total deliveries failed counter.
    deliveries_failed: AtomicU64,
    /// Maximum delivery records to keep.
    max_delivery_records: usize,
}

impl EventStreamManager {
    /// Create a new EventStreamManager.
    pub fn new(source_uri: &str, is_production: bool) -> Self {
        Self {
            webhooks: RwLock::new(HashMap::new()),
            dead_letter_queues: RwLock::new(HashMap::new()),
            delivery_records: RwLock::new(Vec::new()),
            rate_limiter: RwLock::new(WebhookRateLimiter::new()),
            source_uri: source_uri.to_string(),
            is_production,
            events_processed: AtomicU64::new(0),
            deliveries_attempted: AtomicU64::new(0),
            deliveries_succeeded: AtomicU64::new(0),
            deliveries_failed: AtomicU64::new(0),
            max_delivery_records: 10_000,
        }
    }

    // ── Webhook Registration API ────────────────────────────────────────

    /// Register a new webhook.
    pub fn create_webhook(&self, mut config: WebhookConfig) -> Result<WebhookConfig, String> {
        config.validate_url(self.is_production)?;

        let mut webhooks = self
            .webhooks
            .write()
            .map_err(|_| "webhooks lock poisoned".to_string())?;

        if webhooks.len() >= MAX_WEBHOOKS {
            return Err(format!(
                "maximum number of webhooks ({}) reached",
                MAX_WEBHOOKS
            ));
        }

        if webhooks.values().any(|w| w.url == config.url && w.name == config.name) {
            return Err("webhook with same name and URL already exists".to_string());
        }

        config.id = Uuid::new_v4().to_string();
        config.created_at = now_epoch();
        config.updated_at = now_epoch();

        let result = config.clone();
        webhooks.insert(config.id.clone(), config);

        SecurityEvent::webhook_registered(&result.id, &result.url);
        Ok(result)
    }

    /// Update an existing webhook.
    pub fn update_webhook(
        &self,
        webhook_id: &str,
        update: WebhookUpdate,
    ) -> Result<WebhookConfig, String> {
        let mut webhooks = self
            .webhooks
            .write()
            .map_err(|_| "webhooks lock poisoned".to_string())?;

        let webhook = webhooks
            .get_mut(webhook_id)
            .ok_or_else(|| format!("webhook '{}' not found", webhook_id))?;

        if let Some(name) = update.name {
            webhook.name = name;
        }
        if let Some(url) = update.url {
            let test_config = WebhookConfig {
                url: url.clone(),
                ..webhook.clone()
            };
            test_config.validate_url(self.is_production)?;
            webhook.url = url;
        }
        if let Some(filters) = update.event_filters {
            webhook.event_filters = filters;
        }
        if let Some(type_filters) = update.event_type_filters {
            webhook.event_type_filters = type_filters;
        }
        if let Some(active) = update.active {
            webhook.active = active;
        }
        if let Some(rate_limit) = update.rate_limit_per_minute {
            webhook.rate_limit_per_minute = rate_limit;
        }
        if let Some(desc) = update.description {
            webhook.description = desc;
        }

        webhook.updated_at = now_epoch();
        let result = webhook.clone();

        SecurityEvent::webhook_updated(&result.id);
        Ok(result)
    }

    /// Delete a webhook.
    pub fn delete_webhook(&self, webhook_id: &str) -> Result<(), String> {
        let mut webhooks = self
            .webhooks
            .write()
            .map_err(|_| "webhooks lock poisoned".to_string())?;

        webhooks
            .remove(webhook_id)
            .ok_or_else(|| format!("webhook '{}' not found", webhook_id))?;

        // Clean up DLQ
        if let Ok(mut dlqs) = self.dead_letter_queues.write() {
            dlqs.remove(webhook_id);
        }

        SecurityEvent::webhook_deleted(webhook_id);
        Ok(())
    }

    /// List all registered webhooks.
    pub fn list_webhooks(&self) -> Result<Vec<WebhookConfig>, String> {
        let webhooks = self
            .webhooks
            .read()
            .map_err(|_| "webhooks lock poisoned".to_string())?;
        Ok(webhooks.values().cloned().collect())
    }

    /// Get a specific webhook by ID.
    pub fn get_webhook(&self, webhook_id: &str) -> Result<Option<WebhookConfig>, String> {
        let webhooks = self
            .webhooks
            .read()
            .map_err(|_| "webhooks lock poisoned".to_string())?;
        Ok(webhooks.get(webhook_id).cloned())
    }

    /// Send a test event to a webhook to verify connectivity.
    pub fn test_webhook(&self, webhook_id: &str) -> Result<DeliveryRecord, String> {
        let webhooks = self
            .webhooks
            .read()
            .map_err(|_| "webhooks lock poisoned".to_string())?;

        let webhook = webhooks
            .get(webhook_id)
            .ok_or_else(|| format!("webhook '{}' not found", webhook_id))?;

        let test_event = CloudEvent {
            id: Uuid::new_v4().to_string(),
            source: self.source_uri.clone(),
            specversion: CLOUDEVENTS_SPEC_VERSION.to_string(),
            event_type: "mil.milnet.sso.test".to_string(),
            time: epoch_to_iso8601(now_epoch()),
            datacontenttype: "application/json".to_string(),
            subject: None,
            data: serde_json::json!({
                "message": "This is a test event from MILNET SSO",
                "webhook_id": webhook_id,
            }),
        };

        let record = self.deliver_to_webhook(webhook, &test_event);
        Ok(record)
    }

    /// Rotate the secret for a webhook. Returns the new secret.
    pub fn rotate_webhook_secret(&self, webhook_id: &str) -> Result<String, String> {
        let mut webhooks = self
            .webhooks
            .write()
            .map_err(|_| "webhooks lock poisoned".to_string())?;

        let webhook = webhooks
            .get_mut(webhook_id)
            .ok_or_else(|| format!("webhook '{}' not found", webhook_id))?;

        let new_secret = generate_webhook_secret();
        webhook.secret = new_secret.clone();
        webhook.updated_at = now_epoch();

        SecurityEvent::webhook_secret_rotated(webhook_id);
        Ok(new_secret)
    }

    // ── Event Processing ────────────────────────────────────────────────

    /// Process a SIEM event: wrap in CloudEvents, deliver to matching webhooks.
    pub fn process_siem_event(&self, siem_event: &SiemEvent) {
        self.events_processed.fetch_add(1, Ordering::Relaxed);

        let cloud_event = CloudEvent::from_siem_event(siem_event, &self.source_uri);

        let webhooks = match self.webhooks.read() {
            Ok(w) => w,
            Err(_) => return,
        };

        for webhook in webhooks.values() {
            if webhook.matches_event(siem_event) {
                // Check rate limit
                let allowed = self
                    .rate_limiter
                    .write()
                    .map(|mut rl| rl.check_and_increment(&webhook.id, webhook.rate_limit_per_minute))
                    .unwrap_or(false);

                if !allowed {
                    SecurityEvent::webhook_rate_limited(&webhook.id);
                    continue;
                }

                let record = self.deliver_to_webhook(webhook, &cloud_event);
                self.record_delivery(record);
            }
        }

        // Periodic rate limiter cleanup
        if self.events_processed.load(Ordering::Relaxed) % 100 == 0 {
            if let Ok(mut rl) = self.rate_limiter.write() {
                rl.evict_stale();
            }
        }
    }

    /// Deliver a CloudEvent to a specific webhook with retry logic.
    ///
    /// When `MILNET_SIEM_ENCRYPTION_KEY` is set, the payload is encrypted with
    /// AES-256-GCM before signing and transmission. The HMAC signature covers
    /// the encrypted payload (encrypt-then-sign).
    fn deliver_to_webhook(&self, webhook: &WebhookConfig, event: &CloudEvent) -> DeliveryRecord {
        let raw_payload = event.to_json_bytes();

        // Optionally encrypt with AES-256-GCM if configured
        let (payload, _is_encrypted) = match encrypt_event_payload(&raw_payload) {
            Some(encrypted) => (encrypted.into_bytes(), true),
            None => (raw_payload, false),
        };

        let signature = webhook.sign_payload(&payload);

        let mut record = DeliveryRecord {
            id: Uuid::new_v4().to_string(),
            webhook_id: webhook.id.clone(),
            event_id: event.id.clone(),
            status: DeliveryStatus::Pending,
            attempts: 0,
            last_attempt_at: now_epoch(),
            last_status_code: None,
            last_error: None,
            next_retry_at: None,
        };

        for attempt in 0..=MAX_RETRIES {
            record.attempts = attempt + 1;
            record.last_attempt_at = now_epoch();
            self.deliveries_attempted.fetch_add(1, Ordering::Relaxed);

            match self.http_post(&webhook.url, &payload, &signature) {
                Ok(status_code) => {
                    record.last_status_code = Some(status_code);
                    if (200..300).contains(&(status_code as u32)) {
                        record.status = DeliveryStatus::Delivered;
                        self.deliveries_succeeded.fetch_add(1, Ordering::Relaxed);
                        return record;
                    }
                    record.last_error =
                        Some(format!("non-2xx status code: {}", status_code));
                }
                Err(e) => {
                    record.last_error = Some(e);
                }
            }

            if attempt < MAX_RETRIES {
                // Exponential backoff: 1s, 2s, 4s
                let backoff_secs = 1i64 << attempt;
                record.next_retry_at = Some(now_epoch() + backoff_secs);
                // In async context we would await; here we note the delay
                std::thread::sleep(std::time::Duration::from_millis(
                    (backoff_secs * 100) as u64, // Shortened for non-blocking
                ));
            }
        }

        // All retries exhausted — move to dead letter queue
        record.status = DeliveryStatus::Failed;
        self.deliveries_failed.fetch_add(1, Ordering::Relaxed);

        self.add_to_dead_letter(DeadLetterEntry {
            event: event.clone(),
            webhook_id: webhook.id.clone(),
            total_attempts: record.attempts,
            final_error: record.last_error.clone().unwrap_or_default(),
            dead_lettered_at: now_epoch(),
        });

        record.status = DeliveryStatus::DeadLetter;
        record
    }

    /// Perform an HTTP POST to the webhook URL.
    ///
    /// Returns the HTTP status code on success, or an error string.
    fn http_post(&self, url: &str, body: &[u8], signature: &str) -> Result<u16, String> {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        use std::time::Duration;

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
        } else if url.starts_with("https://") {
            format!("{}:443", host_port)
        } else {
            format!("{}:80", host_port)
        };

        let addr: std::net::SocketAddr = host_port_owned
            .parse()
            .map_err(|e| format!("invalid address '{}': {}", host_port_owned, e))?;

        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
            .map_err(|e| format!("connection failed: {}", e))?;
        let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));

        let request = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/cloudevents+json\r\nContent-Length: {}\r\n{}: {}\r\nConnection: close\r\n\r\n",
            path,
            host_port,
            body.len(),
            SIGNATURE_HEADER,
            signature,
        );

        let mut stream = stream;
        stream
            .write_all(request.as_bytes())
            .map_err(|e| format!("write request headers: {}", e))?;
        stream
            .write_all(body)
            .map_err(|e| format!("write request body: {}", e))?;

        let mut buf = [0u8; 1024];
        let n = stream
            .read(&mut buf)
            .map_err(|e| format!("read response: {}", e))?;

        let response = String::from_utf8_lossy(&buf[..n]);
        // Parse HTTP status code from "HTTP/1.1 200 OK\r\n..."
        let status_code = response
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);

        Ok(status_code)
    }

    /// Add a failed delivery to the dead letter queue.
    fn add_to_dead_letter(&self, entry: DeadLetterEntry) {
        if let Ok(mut dlqs) = self.dead_letter_queues.write() {
            let queue = dlqs
                .entry(entry.webhook_id.clone())
                .or_insert_with(Vec::new);

            if queue.len() >= MAX_DEAD_LETTER_PER_WEBHOOK {
                queue.remove(0); // FIFO eviction
            }
            queue.push(entry);
        }
    }

    /// Record a delivery attempt.
    fn record_delivery(&self, record: DeliveryRecord) {
        if let Ok(mut records) = self.delivery_records.write() {
            if records.len() >= self.max_delivery_records {
                let quarter = records.len() / 4;
                records.drain(0..quarter); // Remove oldest 25%
            }
            records.push(record);
        }
    }

    // ── Dead Letter Queue Management ────────────────────────────────────

    /// Get dead letter entries for a webhook.
    pub fn get_dead_letters(&self, webhook_id: &str) -> Result<Vec<DeadLetterEntry>, String> {
        let dlqs = self
            .dead_letter_queues
            .read()
            .map_err(|_| "DLQ lock poisoned".to_string())?;
        Ok(dlqs.get(webhook_id).cloned().unwrap_or_default())
    }

    /// Replay a dead letter entry (re-attempt delivery).
    pub fn replay_dead_letter(
        &self,
        webhook_id: &str,
        entry_index: usize,
    ) -> Result<DeliveryRecord, String> {
        let entry = {
            let dlqs = self
                .dead_letter_queues
                .read()
                .map_err(|_| "DLQ lock poisoned".to_string())?;
            let queue = dlqs
                .get(webhook_id)
                .ok_or("no dead letters for this webhook")?;
            queue
                .get(entry_index)
                .cloned()
                .ok_or("dead letter entry not found")?
        };

        let webhooks = self
            .webhooks
            .read()
            .map_err(|_| "webhooks lock poisoned".to_string())?;
        let webhook = webhooks
            .get(webhook_id)
            .ok_or("webhook not found")?;

        let record = self.deliver_to_webhook(webhook, &entry.event);

        // If delivered, remove from DLQ
        if record.status == DeliveryStatus::Delivered {
            if let Ok(mut dlqs) = self.dead_letter_queues.write() {
                if let Some(queue) = dlqs.get_mut(webhook_id) {
                    if entry_index < queue.len() {
                        queue.remove(entry_index);
                    }
                }
            }
        }

        Ok(record)
    }

    /// Purge all dead letters for a webhook.
    pub fn purge_dead_letters(&self, webhook_id: &str) -> Result<usize, String> {
        let mut dlqs = self
            .dead_letter_queues
            .write()
            .map_err(|_| "DLQ lock poisoned".to_string())?;

        match dlqs.remove(webhook_id) {
            Some(entries) => Ok(entries.len()),
            None => Ok(0),
        }
    }

    // ── Delivery Status Tracking ────────────────────────────────────────

    /// Get recent delivery records for a webhook.
    pub fn get_delivery_records(
        &self,
        webhook_id: &str,
        limit: usize,
    ) -> Result<Vec<DeliveryRecord>, String> {
        let records = self
            .delivery_records
            .read()
            .map_err(|_| "delivery records lock poisoned".to_string())?;
        let filtered: Vec<_> = records
            .iter()
            .rev()
            .filter(|r| r.webhook_id == webhook_id)
            .take(limit)
            .cloned()
            .collect();
        Ok(filtered)
    }

    // ── SSE Support ─────────────────────────────────────────────────────

    /// Create an SSE event from a SIEM event.
    pub fn create_sse_event(&self, siem_event: &SiemEvent) -> SseEvent {
        let cloud_event = CloudEvent::from_siem_event(siem_event, &self.source_uri);
        SseEvent::from_cloud_event(&cloud_event)
    }

    /// Subscribe to the SIEM broadcast channel for SSE streaming.
    pub fn subscribe_siem(&self) -> tokio::sync::broadcast::Receiver<SiemEvent> {
        siem::subscribe()
    }

    // ── Statistics ──────────────────────────────────────────────────────

    /// Get streaming statistics.
    pub fn stats(&self) -> StreamingStats {
        StreamingStats {
            events_processed: self.events_processed.load(Ordering::Relaxed),
            deliveries_attempted: self.deliveries_attempted.load(Ordering::Relaxed),
            deliveries_succeeded: self.deliveries_succeeded.load(Ordering::Relaxed),
            deliveries_failed: self.deliveries_failed.load(Ordering::Relaxed),
            webhooks_registered: self
                .webhooks
                .read()
                .map(|w| w.len() as u64)
                .unwrap_or(0),
            dead_letter_total: self
                .dead_letter_queues
                .read()
                .map(|d| d.values().map(|v| v.len() as u64).sum())
                .unwrap_or(0),
        }
    }
}

/// Streaming subsystem statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamingStats {
    /// Total events processed.
    pub events_processed: u64,
    /// Total delivery attempts.
    pub deliveries_attempted: u64,
    /// Successful deliveries.
    pub deliveries_succeeded: u64,
    /// Failed deliveries.
    pub deliveries_failed: u64,
    /// Number of registered webhooks.
    pub webhooks_registered: u64,
    /// Total entries in dead letter queues.
    pub dead_letter_total: u64,
}

// ── SIEM Event Extensions ───────────────────────────────────────────────────

impl SecurityEvent {
    /// Emit a webhook registered event.
    pub fn webhook_registered(webhook_id: &str, url: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "event_streaming",
            action: "webhook_registered",
            severity: crate::siem::Severity::Medium,
            outcome: "success",
            user_id: None,
            source_ip: None,
            detail: Some(format!("webhook registered: id={} url={}", webhook_id, url)),
        };
        event.emit();
    }

    /// Emit a webhook updated event.
    pub fn webhook_updated(webhook_id: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "event_streaming",
            action: "webhook_updated",
            severity: crate::siem::Severity::Low,
            outcome: "success",
            user_id: None,
            source_ip: None,
            detail: Some(format!("webhook updated: id={}", webhook_id)),
        };
        event.emit();
    }

    /// Emit a webhook deleted event.
    pub fn webhook_deleted(webhook_id: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "event_streaming",
            action: "webhook_deleted",
            severity: crate::siem::Severity::Medium,
            outcome: "success",
            user_id: None,
            source_ip: None,
            detail: Some(format!("webhook deleted: id={}", webhook_id)),
        };
        event.emit();
    }

    /// Emit a webhook secret rotated event.
    pub fn webhook_secret_rotated(webhook_id: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "event_streaming",
            action: "webhook_secret_rotated",
            severity: crate::siem::Severity::Medium,
            outcome: "success",
            user_id: None,
            source_ip: None,
            detail: Some(format!("webhook secret rotated: id={}", webhook_id)),
        };
        event.emit();
    }

    /// Emit a webhook rate limited event.
    pub fn webhook_rate_limited(webhook_id: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "event_streaming",
            action: "webhook_rate_limited",
            severity: crate::siem::Severity::Notice,
            outcome: "failure",
            user_id: None,
            source_ip: None,
            detail: Some(format!("webhook rate limited: id={}", webhook_id)),
        };
        event.emit();
    }
}

// ── Webhook Payload Encryption ──────────────────────────────────────────────

/// Encrypt a webhook event payload using AES-256-GCM when `MILNET_SIEM_ENCRYPTION_KEY`
/// is set (64 hex chars = 256-bit key).
///
/// Returns `None` if no encryption key is configured or on any error.
/// Output format: `base64(nonce) || "." || base64(ciphertext+tag)`.
fn encrypt_event_payload(payload: &[u8]) -> Option<String> {
    let key_hex = std::env::var("MILNET_SIEM_ENCRYPTION_KEY").ok()?;
    if key_hex.is_empty() {
        return None;
    }

    let key_bytes = match hex::decode(&key_hex) {
        Ok(k) if k.len() == 32 => k,
        Ok(k) => {
            tracing::error!(
                target: "siem",
                "MILNET_SIEM_ENCRYPTION_KEY must be 64 hex chars (256 bits), got {} bytes",
                k.len()
            );
            return None;
        }
        Err(e) => {
            tracing::error!(
                target: "siem",
                "MILNET_SIEM_ENCRYPTION_KEY is not valid hex: {}",
                e
            );
            return None;
        }
    };

    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
    use aes_gcm::Nonce;

    let cipher = match Aes256Gcm::new_from_slice(&key_bytes) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(target: "siem", "AES-256-GCM key init failed: {}", e);
            return None;
        }
    };

    let mut nonce_bytes = [0u8; 12];
    if getrandom::getrandom(&mut nonce_bytes).is_err() {
        tracing::error!(target: "siem", "CSPRNG failure generating nonce for event encryption");
        return None;
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    match cipher.encrypt(nonce, payload) {
        Ok(ciphertext) => {
            use base64::{engine::general_purpose::STANDARD as B64, Engine};
            let nonce_b64 = B64.encode(nonce_bytes);
            let ct_b64 = B64.encode(&ciphertext);
            Some(format!("{}.{}", nonce_b64, ct_b64))
        }
        Err(e) => {
            tracing::error!(target: "siem", "AES-256-GCM encryption failed: {}", e);
            None
        }
    }
}

// ── Utility Functions ───────────────────────────────────────────────────────

/// Get the current time as Unix epoch seconds.
fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Convert Unix epoch seconds to ISO 8601 UTC timestamp.
fn epoch_to_iso8601(epoch: i64) -> String {
    let secs_per_day: i64 = 86400;
    let days = epoch / secs_per_day;
    let time_of_day = epoch % secs_per_day;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    let (year, month, day) = days_to_ymd(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

/// Convert days since epoch to (year, month, day).
fn days_to_ymd(days: i64) -> (i64, i64, i64) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Generate a random webhook secret (64 hex characters = 256 bits).
fn generate_webhook_secret() -> String {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).unwrap_or_else(|e| {
        tracing::error!("FATAL: CSPRNG failure in webhook secret generation: {e}");
        std::process::exit(1);
    });
    hex::encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_category_classification() {
        assert_eq!(
            EventCategory::from_siem_event_type("login"),
            EventCategory::Auth
        );
        assert_eq!(
            EventCategory::from_siem_event_type("user_created"),
            EventCategory::Admin
        );
        assert_eq!(
            EventCategory::from_siem_event_type("tamper_detected"),
            EventCategory::Security
        );
        assert_eq!(
            EventCategory::from_siem_event_type("audit_export"),
            EventCategory::Compliance
        );
    }

    #[test]
    fn test_cloud_event_creation() {
        let siem = SiemEvent {
            timestamp: 1711234567,
            severity: 4,
            event_type: "login".to_string(),
            json: r#"{"event_type":"login","severity":"MEDIUM"}"#.to_string(),
        };
        let ce = CloudEvent::from_siem_event(&siem, "https://sso.milnet.mil");
        assert!(ce.event_type.starts_with("mil.milnet.sso.auth."));
        assert_eq!(ce.specversion, "1.0");
    }

    #[test]
    fn test_webhook_hmac_signing() {
        let webhook = WebhookConfig::new("test", "https://example.com/hook");
        let payload = b"test payload";
        let sig = webhook.sign_payload(payload);
        assert!(sig.starts_with("sha512="));
        assert!(webhook.verify_signature(payload, &sig));
        assert!(!webhook.verify_signature(b"different", &sig));
    }

    #[test]
    fn test_webhook_url_validation() {
        let mut wh = WebhookConfig::new("test", "https://example.com/hook");
        assert!(wh.validate_url(true).is_ok());

        wh.url = "http://example.com/hook".to_string();
        assert!(wh.validate_url(true).is_err()); // HTTP rejected in production
        assert!(wh.validate_url(false).is_ok()); // HTTP OK in dev

        wh.url = "https://127.0.0.1/hook".to_string();
        assert!(wh.validate_url(true).is_err()); // SSRF protection

        wh.url = "ftp://example.com/hook".to_string();
        assert!(wh.validate_url(true).is_err()); // Invalid scheme
    }

    #[test]
    fn test_webhook_event_matching() {
        let mut webhook = WebhookConfig::new("test", "https://example.com/hook");

        let event = SiemEvent {
            timestamp: 1711234567,
            severity: 4,
            event_type: "login".to_string(),
            json: "{}".to_string(),
        };

        // No filters = matches all
        assert!(webhook.matches_event(&event));

        // Category filter
        webhook.event_filters = vec![EventCategory::Security];
        assert!(!webhook.matches_event(&event)); // login is Auth, not Security

        webhook.event_filters = vec![EventCategory::Auth];
        assert!(webhook.matches_event(&event));

        // Event type filter
        webhook.event_type_filters = vec!["logout".to_string()];
        assert!(!webhook.matches_event(&event)); // Not "logout"

        webhook.event_type_filters = vec!["login".to_string()];
        assert!(webhook.matches_event(&event));

        // Inactive webhook
        webhook.active = false;
        assert!(!webhook.matches_event(&event));
    }

    #[test]
    fn test_sse_event_format() {
        let ce = CloudEvent {
            id: "test-id".to_string(),
            source: "https://sso.milnet.mil".to_string(),
            specversion: "1.0".to_string(),
            event_type: "mil.milnet.sso.auth.login".to_string(),
            time: "2024-03-23T12:00:00Z".to_string(),
            datacontenttype: "application/json".to_string(),
            subject: None,
            data: serde_json::json!({"test": true}),
        };
        let sse = SseEvent::from_cloud_event(&ce);
        let wire = sse.to_sse_string();
        assert!(wire.contains("id: test-id"));
        assert!(wire.contains("event: mil.milnet.sso.auth.login"));
        assert!(wire.contains("data: "));
        assert!(wire.ends_with("\n\n")); // SSE terminator
    }

    #[test]
    fn test_delivery_status_display() {
        assert_eq!(DeliveryStatus::Pending.to_string(), "pending");
        assert_eq!(DeliveryStatus::Delivered.to_string(), "delivered");
        assert_eq!(DeliveryStatus::Failed.to_string(), "failed");
        assert_eq!(DeliveryStatus::DeadLetter.to_string(), "dead_letter");
    }

    #[test]
    fn test_event_stream_manager_webhook_crud() {
        let mgr = EventStreamManager::new("https://sso.milnet.mil", false);

        // Create
        let wh = mgr
            .create_webhook(WebhookConfig::new("test", "http://localhost:8080/hook"))
            .unwrap();
        assert!(!wh.id.is_empty());

        // List
        let list = mgr.list_webhooks().unwrap();
        assert_eq!(list.len(), 1);

        // Get
        let found = mgr.get_webhook(&wh.id).unwrap();
        assert!(found.is_some());

        // Update
        let updated = mgr
            .update_webhook(
                &wh.id,
                WebhookUpdate {
                    name: Some("updated".to_string()),
                    url: None,
                    event_filters: None,
                    event_type_filters: None,
                    active: None,
                    rate_limit_per_minute: None,
                    description: None,
                },
            )
            .unwrap();
        assert_eq!(updated.name, "updated");

        // Delete
        mgr.delete_webhook(&wh.id).unwrap();
        let list = mgr.list_webhooks().unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn test_rate_limiter() {
        let mut rl = WebhookRateLimiter::new();
        for _ in 0..5 {
            assert!(rl.check_and_increment("wh1", 5));
        }
        assert!(!rl.check_and_increment("wh1", 5)); // Exceeded limit
        assert!(rl.check_and_increment("wh2", 5)); // Different webhook
    }

    #[test]
    fn test_generate_webhook_secret() {
        let s1 = generate_webhook_secret();
        let s2 = generate_webhook_secret();
        assert_eq!(s1.len(), 64); // 32 bytes = 64 hex chars
        assert_ne!(s1, s2);
    }
}
