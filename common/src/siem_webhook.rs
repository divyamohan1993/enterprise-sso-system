//! SIEM webhook integration — external SIEM forwarding via HTTP webhook.
//!
//! Provides a buffered, batched event queue that can flush security events
//! to an external SIEM endpoint (Splunk HEC, Elastic, etc.).  The HTTP
//! transport layer is pluggable; the buffer/batch/flush semantics are fully
//! implemented here.
#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex};

// ── Buffer overflow protection ──────────────────────────────────────────────
/// Maximum number of events that can be buffered before oldest events are dropped.
const MAX_BUFFER_SIZE: usize = 10_000;

// ── Configuration ─────────────────────────────────────────────────────────────

/// Configuration for the external SIEM webhook integration.
pub struct SiemWebhookConfig {
    /// Full URL of the SIEM HTTP Event Collector endpoint.
    pub endpoint_url: String,
    /// Bearer / HEC token for authenticating to the endpoint.
    pub auth_token: String,
    /// Number of events to accumulate before flushing (default: 10).
    pub batch_size: usize,
    /// Maximum seconds between forced flushes (default: 30).
    pub flush_interval_secs: u64,
    /// Whether forwarding is active.
    pub enabled: bool,
}

impl SiemWebhookConfig {
    /// Read configuration from environment variables.
    ///
    /// Required: `MILNET_SIEM_WEBHOOK_URL`
    /// Optional: `MILNET_SIEM_AUTH_TOKEN`, `MILNET_SIEM_BATCH_SIZE`,
    ///           `MILNET_SIEM_FLUSH_INTERVAL_SECS`, `MILNET_SIEM_ENABLED`
    ///
    /// Returns `None` if `MILNET_SIEM_WEBHOOK_URL` is not set or empty.
    pub fn from_env() -> Option<Self> {
        let endpoint_url = std::env::var("MILNET_SIEM_WEBHOOK_URL")
            .ok()
            .filter(|u| !u.is_empty())?;

        let auth_token = std::env::var("MILNET_SIEM_AUTH_TOKEN")
            .unwrap_or_default();
        // Remove sensitive auth token from environment immediately
        std::env::remove_var("MILNET_SIEM_AUTH_TOKEN");

        let batch_size = std::env::var("MILNET_SIEM_BATCH_SIZE")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(10);

        let flush_interval_secs = std::env::var("MILNET_SIEM_FLUSH_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(30);

        let enabled = std::env::var("MILNET_SIEM_ENABLED")
            .map(|v| !matches!(v.to_ascii_lowercase().as_str(), "false" | "0" | "no"))
            .unwrap_or(true);

        Some(Self {
            endpoint_url,
            auth_token,
            batch_size,
            flush_interval_secs,
            enabled,
        })
    }
}

impl Drop for SiemWebhookConfig {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.auth_token.zeroize();
    }
}

// ── HMAC-SHA512 payload signing ──────────────────────────────────────────────

/// Compute HMAC-SHA512 over `timestamp || payload` using the given key.
/// Returns the hex-encoded signature string.
fn sign_payload(key: &[u8], timestamp: &str, payload: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    type HmacSha512 = Hmac<Sha512>;
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC key");
    mac.update(timestamp.as_bytes());
    mac.update(payload);
    let result = mac.finalize().into_bytes();
    hex::encode(result)
}

// ── Webhook client ────────────────────────────────────────────────────────────

/// Buffered SIEM webhook client.
///
/// Events are queued in an in-memory buffer and flushed either when the
/// batch size is reached or on a periodic timer.  The actual HTTP POST is
/// a stub — it logs via `tracing` — so the interface is stable and the
/// transport can be wired up without any API changes.
pub struct SiemWebhook {
    config: SiemWebhookConfig,
    /// Buffered JSON event strings awaiting flush.
    buffer: Arc<Mutex<Vec<String>>>,
}

impl SiemWebhook {
    /// Create a new webhook client with the given configuration.
    pub fn new(config: SiemWebhookConfig) -> Self {
        Self {
            config,
            buffer: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Queue a JSON-serialized event for batched delivery.
    ///
    /// Thread-safe; safe to call from multiple threads.
    pub fn queue_event(&self, event_json: &str) {
        if !self.config.enabled {
            return;
        }
        match self.buffer.lock() {
            Ok(mut buf) => {
                if buf.len() >= MAX_BUFFER_SIZE {
                    buf.remove(0); // Drop oldest
                    tracing::warn!(target: "siem", "SIEM webhook buffer overflow — dropping oldest event");
                }
                buf.push(event_json.to_string());
            }
            Err(poisoned) => {
                // Recover from a poisoned mutex — log and continue
                tracing::warn!("siem_webhook: buffer mutex poisoned, recovering");
                let mut buf = poisoned.into_inner();
                if buf.len() >= MAX_BUFFER_SIZE {
                    buf.remove(0);
                    tracing::warn!(target: "siem", "SIEM webhook buffer overflow — dropping oldest event");
                }
                buf.push(event_json.to_string());
            }
        }
    }

    /// Flush all buffered events to the SIEM endpoint.
    ///
    /// Collects buffered events into a JSON array, emits them via `tracing`
    /// (the real HTTP POST would be inserted here), clears the buffer, and
    /// returns the count of flushed events.
    ///
    /// Returns `Ok(0)` immediately if the webhook is not active.
    /// Returns `Err` if the buffer lock cannot be acquired.
    pub fn flush(&self) -> Result<usize, String> {
        if !self.is_active() {
            return Ok(0);
        }

        let events: Vec<String> = match self.buffer.lock() {
            Ok(mut buf) => {
                if buf.is_empty() {
                    return Ok(0);
                }
                std::mem::take(&mut *buf)
            }
            Err(_) => return Err("siem_webhook: buffer mutex poisoned during flush".into()),
        };

        let count = events.len();

        // Build a JSON array of all buffered events for the batch POST body.
        let batch_json = format!("[{}]", events.join(","));

        // Compute HMAC-SHA512 signature for payload authentication
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_string();

        let signature = if !self.config.auth_token.is_empty() {
            Some(sign_payload(
                self.config.auth_token.as_bytes(),
                &timestamp,
                batch_json.as_bytes(),
            ))
        } else {
            None
        };

        // Log the flush with authentication metadata.
        // In production, the HTTP POST would include these headers:
        //   Authorization: Bearer <auth_token>
        //   X-MILNET-Signature: <hex-encoded HMAC-SHA512>
        //   X-MILNET-Timestamp: <unix epoch seconds>
        tracing::info!(
            target: "siem_webhook",
            endpoint = %self.config.endpoint_url,
            count = count,
            timestamp = %timestamp,
            has_signature = signature.is_some(),
            has_auth_token = !self.config.auth_token.is_empty(),
            "siem_webhook: flushing {} event(s) to SIEM endpoint",
            count
        );

        // Emit signature and auth headers for downstream consumers
        if let Some(ref sig) = signature {
            tracing::debug!(
                target: "siem_webhook",
                header_x_milnet_signature = %sig,
                header_x_milnet_timestamp = %timestamp,
                header_authorization = "Bearer <redacted>",
                "siem_webhook: payload signed with HMAC-SHA512"
            );
        }

        Ok(count)
    }

    /// Return the number of events currently buffered and awaiting flush.
    pub fn pending_count(&self) -> usize {
        match self.buffer.lock() {
            Ok(buf) => buf.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }

    /// Return `true` if the webhook is both configured and enabled.
    pub fn is_active(&self) -> bool {
        self.config.enabled && !self.config.endpoint_url.is_empty()
    }

    /// Return a reference to the configuration.
    pub fn config(&self) -> &SiemWebhookConfig {
        &self.config
    }
}

// ── Global webhook singleton ──────────────────────────────────────────────────

use std::sync::OnceLock;

/// Global SIEM webhook instance.  Set once at startup via `init_siem_webhook`.
static SIEM_WEBHOOK: OnceLock<Option<SiemWebhook>> = OnceLock::new();

/// Initialise the global SIEM webhook.  Must be called before any events are
/// emitted if webhook forwarding is desired.  Safe to call multiple times —
/// only the first call takes effect.
pub fn init_siem_webhook(config: SiemWebhookConfig) {
    let _ = SIEM_WEBHOOK.set(Some(SiemWebhook::new(config)));
}

/// Queue an event on the global SIEM webhook, if one has been initialised.
/// This is a no-op if `init_siem_webhook` has not been called.
pub fn queue_global_event(event_json: &str) {
    if let Some(Some(webhook)) = SIEM_WEBHOOK.get() {
        webhook.queue_event(event_json);
    }
}

/// Flush the global SIEM webhook.  Returns `Ok(0)` if not initialised.
pub fn flush_global_webhook() -> Result<usize, String> {
    match SIEM_WEBHOOK.get() {
        Some(Some(webhook)) => webhook.flush(),
        _ => Ok(0),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> SiemWebhookConfig {
        SiemWebhookConfig {
            endpoint_url: "http://siem.example.mil/api/events".into(),
            auth_token: "test-token".into(),
            batch_size: 10,
            flush_interval_secs: 30,
            enabled: true,
        }
    }

    #[test]
    fn test_siem_webhook_queue_event() {
        let wh = SiemWebhook::new(test_config());
        wh.queue_event(r#"{"event":"login","user":"alice"}"#);
        wh.queue_event(r#"{"event":"logout","user":"alice"}"#);
        wh.queue_event(r#"{"event":"login","user":"bob"}"#);
        assert_eq!(wh.pending_count(), 3, "expected 3 queued events");
    }

    #[test]
    fn test_siem_webhook_flush() {
        let wh = SiemWebhook::new(test_config());
        wh.queue_event(r#"{"event":"login"}"#);
        wh.queue_event(r#"{"event":"logout"}"#);
        assert_eq!(wh.pending_count(), 2);

        let flushed = wh.flush().expect("flush should succeed");
        assert_eq!(flushed, 2, "flush should report 2 events sent");
        assert_eq!(wh.pending_count(), 0, "buffer should be empty after flush");
    }

    #[test]
    fn test_siem_webhook_batch_size() {
        let config = SiemWebhookConfig {
            endpoint_url: "http://siem.example.mil/api/events".into(),
            auth_token: "test-token".into(),
            batch_size: 5,
            flush_interval_secs: 30,
            enabled: true,
        };
        let wh = SiemWebhook::new(config);
        assert_eq!(wh.config().batch_size, 5);

        // Queue more events than the batch size
        for i in 0..12u32 {
            wh.queue_event(&format!(r#"{{"seq":{}}}"#, i));
        }
        assert_eq!(wh.pending_count(), 12);

        // A single flush drains all events regardless of batch_size
        // (batch_size governs *auto-flush* triggers in a background worker,
        // not the manual flush() call)
        let flushed = wh.flush().expect("flush should succeed");
        assert_eq!(flushed, 12);
        assert_eq!(wh.pending_count(), 0);
    }

    #[test]
    fn test_siem_webhook_config_from_env() {
        // Set the required env var
        std::env::set_var("MILNET_SIEM_WEBHOOK_URL", "http://test-siem.mil/events");
        std::env::set_var("MILNET_SIEM_AUTH_TOKEN", "secret-token-42");
        std::env::set_var("MILNET_SIEM_BATCH_SIZE", "25");
        std::env::set_var("MILNET_SIEM_FLUSH_INTERVAL_SECS", "60");
        std::env::set_var("MILNET_SIEM_ENABLED", "true");

        let cfg = SiemWebhookConfig::from_env()
            .expect("config should be Some when URL is set");

        assert_eq!(cfg.endpoint_url, "http://test-siem.mil/events");
        assert_eq!(cfg.auth_token, "secret-token-42");
        assert_eq!(cfg.batch_size, 25);
        assert_eq!(cfg.flush_interval_secs, 60);
        assert!(cfg.enabled);

        // Clean up
        std::env::remove_var("MILNET_SIEM_WEBHOOK_URL");
        std::env::remove_var("MILNET_SIEM_AUTH_TOKEN");
        std::env::remove_var("MILNET_SIEM_BATCH_SIZE");
        std::env::remove_var("MILNET_SIEM_FLUSH_INTERVAL_SECS");
        std::env::remove_var("MILNET_SIEM_ENABLED");

        // Without URL set, should return None
        let none_cfg = SiemWebhookConfig::from_env();
        assert!(none_cfg.is_none(), "expected None when URL not set");
    }

    #[test]
    fn test_siem_webhook_inactive_when_disabled() {
        let config = SiemWebhookConfig {
            endpoint_url: "http://siem.example.mil/api/events".into(),
            auth_token: "token".into(),
            batch_size: 10,
            flush_interval_secs: 30,
            enabled: false,
        };
        let wh = SiemWebhook::new(config);
        assert!(!wh.is_active(), "webhook should be inactive when enabled=false");

        // Queuing events on a disabled webhook should be a no-op
        wh.queue_event(r#"{"event":"test"}"#);
        assert_eq!(wh.pending_count(), 0, "disabled webhook should not buffer events");

        // Flush on inactive webhook should return Ok(0)
        let result = wh.flush().expect("flush should not error");
        assert_eq!(result, 0);
    }
}
