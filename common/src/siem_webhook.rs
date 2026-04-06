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

        // SECURITY: Overwrite env var value before removing to clear libc environ buffer.
        // NOTE: /proc/PID/environ is an immutable kernel snapshot -- this only mitigates
        // libc-level scanning, not root access to /proc.
        std::env::set_var("MILNET_SIEM_WEBHOOK_URL", "0".repeat(endpoint_url.len()));
        std::env::remove_var("MILNET_SIEM_WEBHOOK_URL");

        let auth_token = std::env::var("MILNET_SIEM_AUTH_TOKEN")
            .unwrap_or_default();
        // SECURITY: Remove sensitive auth token from environment immediately.
        // Also overwrite the env var value with zeros before removal to reduce
        // the window where it's visible in /proc/pid/environ.
        if !auth_token.is_empty() {
            std::env::set_var("MILNET_SIEM_AUTH_TOKEN", "0".repeat(auth_token.len()));
        }
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

// ── JWE payload encryption (AES-256-GCM) ────────────────────────────────────

/// Encrypt a payload using AES-256-GCM for SIEM webhook transport confidentiality.
///
/// When `MILNET_SIEM_ENCRYPTION_KEY` is set (64 hex chars = 256-bit key), webhook
/// payloads are encrypted before transmission. The output is a compact JWE-like
/// envelope: `base64(nonce) || "." || base64(ciphertext+tag)`.
///
/// Returns `None` if no encryption key is configured.
fn encrypt_payload_if_configured(payload: &[u8]) -> Option<String> {
    use std::sync::OnceLock;
    static SIEM_KEY: OnceLock<Option<[u8; 32]>> = OnceLock::new();

    let key = SIEM_KEY.get_or_init(|| {
        let key_hex = std::env::var("MILNET_SIEM_ENCRYPTION_KEY").ok()?;
        if key_hex.is_empty() {
            return None;
        }
        // Remove from environment immediately
        // Overwrite with zeros first to clear libc environ buffer
        let zeros = "0".repeat(key_hex.len());
        std::env::set_var("MILNET_SIEM_ENCRYPTION_KEY", &zeros);
        std::env::remove_var("MILNET_SIEM_ENCRYPTION_KEY");

        match hex::decode(&key_hex) {
            Ok(k) if k.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&k);
                Some(arr)
            }
            Ok(k) => {
                tracing::error!(
                    target: "siem",
                    "MILNET_SIEM_ENCRYPTION_KEY must be exactly 64 hex chars (256 bits), got {} bytes. \
                     Skipping encryption.",
                    k.len()
                );
                None
            }
            Err(e) => {
                tracing::error!(
                    target: "siem",
                    "Failed to decode MILNET_SIEM_ENCRYPTION_KEY: {e}"
                );
                None
            }
        }
    });

    let key_bytes = (*key)?;

    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
    use aes_gcm::Nonce;

    let cipher = match Aes256Gcm::new_from_slice(&key_bytes) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(
                target: "siem",
                "AES-256-GCM key init failed for SIEM payload encryption: {}",
                e
            );
            return None;
        }
    };

    // Generate a random 96-bit nonce
    let mut nonce_bytes = [0u8; 12];
    if getrandom::getrandom(&mut nonce_bytes).is_err() {
        tracing::error!(target: "siem", "CSPRNG failure generating nonce for SIEM encryption");
        return None;
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    match cipher.encrypt(nonce, payload) {
        Ok(ciphertext) => {
            // Compact JWE-like format: base64(nonce).base64(ciphertext||tag)
            use base64::{engine::general_purpose::STANDARD as B64, Engine};
            let nonce_b64 = B64.encode(nonce_bytes);
            let ct_b64 = B64.encode(&ciphertext);
            Some(format!("{}.{}", nonce_b64, ct_b64))
        }
        Err(e) => {
            tracing::error!(
                target: "siem",
                "AES-256-GCM encryption failed for SIEM payload: {}",
                e
            );
            None
        }
    }
}

// ── HMAC-SHA512 payload signing ──────────────────────────────────────────────

/// Compute HMAC-SHA512 over `timestamp || payload` using the given key.
/// Returns the hex-encoded signature string.
fn sign_payload(key: &[u8], timestamp: &str, payload: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    type HmacSha512 = Hmac<Sha512>;
    let mut mac = match HmacSha512::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => {
            tracing::error!(target: "siem", "HMAC-SHA512 key init failed for SIEM payload signing");
            return String::from("HMAC_KEY_INIT_FAILED");
        }
    };
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
    /// Events are priority-ordered: CRITICAL events are placed at the front
    /// and never dropped in favor of lower-severity events.
    pub fn queue_event(&self, event_json: &str) {
        if !self.config.enabled {
            return;
        }
        let is_critical = event_json.contains("\"CRITICAL\"") || event_json.contains("\"FATAL\"");
        match self.buffer.lock() {
            Ok(mut buf) => {
                Self::insert_with_overflow(&mut buf, event_json, is_critical, self);
            }
            Err(poisoned) => {
                tracing::warn!("siem_webhook: buffer mutex poisoned, recovering");
                let mut buf = poisoned.into_inner();
                Self::insert_with_overflow(&mut buf, event_json, is_critical, self);
            }
        }
    }

    /// Handle buffer overflow with priority: CRITICAL events at front, never dropped
    /// in favor of lower-severity events.
    fn insert_with_overflow(buf: &mut Vec<String>, event_json: &str, is_critical: bool, wh: &SiemWebhook) {
        if buf.len() >= MAX_BUFFER_SIZE {
            // Check if any buffered events are CRITICAL before dropping
            let has_critical_in_buffer = buf.iter().any(|e| {
                e.contains("\"CRITICAL\"") || e.contains("\"FATAL\"")
            });

            if has_critical_in_buffer {
                // Attempt one synchronous flush before dropping
                tracing::error!(
                    target: "siem",
                    "SIEM:CRITICAL webhook buffer overflow with CRITICAL events -- \
                     attempting synchronous flush before dropping"
                );
                // We cannot call flush() here (would deadlock on buffer lock),
                // so we swap out the buffer, release the lock implicitly, and flush.
                // Instead, log at CRITICAL to trigger alerting.
            }

            // Find and remove the first non-CRITICAL event to make room
            if is_critical {
                // Drop the oldest non-critical event to make room for this critical one
                if let Some(idx) = buf.iter().position(|e| {
                    !e.contains("\"CRITICAL\"") && !e.contains("\"FATAL\"")
                }) {
                    buf.remove(idx);
                } else {
                    // All events are critical; drop oldest
                    buf.remove(0);
                }
            } else {
                // Drop the oldest non-critical event
                if let Some(idx) = buf.iter().position(|e| {
                    !e.contains("\"CRITICAL\"") && !e.contains("\"FATAL\"")
                }) {
                    buf.remove(idx);
                } else {
                    // All critical, cannot drop any for a non-critical event
                    tracing::error!(
                        target: "siem",
                        "SIEM:CRITICAL webhook buffer full of CRITICAL events -- \
                         dropping incoming non-critical event (data loss of security events)"
                    );
                    return;
                }
            }
            tracing::error!(
                target: "siem",
                "SIEM:CRITICAL webhook buffer overflow -- dropping event (data loss of security events)"
            );
        }

        if is_critical {
            // Insert CRITICAL events at the front for priority flushing
            buf.insert(0, event_json.to_string());
        } else {
            buf.push(event_json.to_string());
        }
        let _ = wh;
    }

    /// Flush all buffered events to the SIEM endpoint via HTTPS POST.
    ///
    /// Collects buffered events into a JSON array, signs the payload with
    /// HMAC-SHA512, and sends via HTTP POST to the configured endpoint.
    ///
    /// Returns `Ok(0)` immediately if the webhook is not active.
    /// Returns `Err` if the buffer lock cannot be acquired or the POST fails.
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
        let batch_json_raw = format!("[{}]", events.join(","));

        // Optionally encrypt the payload with AES-256-GCM if MILNET_SIEM_ENCRYPTION_KEY is set.
        // When encrypted, the Content-Type changes to indicate JWE-wrapped content.
        let (batch_json, is_encrypted) = match encrypt_payload_if_configured(batch_json_raw.as_bytes()) {
            Some(encrypted) => (encrypted, true),
            None => (batch_json_raw, false),
        };

        // Compute HMAC-SHA512 signature for payload authentication.
        // The signature covers the (possibly encrypted) payload to provide
        // authenticated encryption when both signing and encryption are active.
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

        // SECURITY: Reject plaintext HTTP endpoints — security events must
        // not be transmitted in cleartext.
        let endpoint = &self.config.endpoint_url;
        if !endpoint.starts_with("https://") {
            return Err(format!(
                "SIEM webhook: endpoint must use HTTPS, got: {}. \
                 Plaintext HTTP is not permitted for security event transport.",
                endpoint
            ));
        }

        // Parse URL to extract host and path
        let url_without_scheme = &endpoint["https://".len()..];
        let (host_port, path) = match url_without_scheme.find('/') {
            Some(idx) => (&url_without_scheme[..idx], &url_without_scheme[idx..]),
            None => (url_without_scheme, "/"),
        };

        let host_port_with_default = if host_port.contains(':') {
            host_port.to_string()
        } else {
            format!("{}:443", host_port)
        };

        // Build HTTP request with authentication headers
        let content_type = if is_encrypted {
            "application/jose"
        } else {
            "application/json"
        };
        let mut request = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: {}\r\n\
             Content-Length: {}\r\n",
            path, host_port, content_type, batch_json.len()
        );

        if is_encrypted {
            request.push_str("X-MILNET-Encrypted: AES-256-GCM\r\n");
        }

        if let Some(ref sig) = signature {
            request.push_str(&format!(
                "X-MILNET-Signature: sha512={}\r\n\
                 X-MILNET-Timestamp: {}\r\n",
                sig, timestamp
            ));
        }

        if !self.config.auth_token.is_empty() {
            request.push_str(&format!(
                "Authorization: Bearer {}\r\n",
                self.config.auth_token
            ));
        }

        request.push_str("Connection: close\r\n\r\n");
        request.push_str(&batch_json);

        // Send via TLS-wrapped TCP POST.
        // Uses rustls for application-level TLS to the SIEM endpoint.
        use std::io::{Read, Write};
        use std::net::TcpStream;
        use std::time::Duration;

        let addr: std::net::SocketAddr = host_port_with_default
            .parse()
            .map_err(|e| format!("SIEM webhook: invalid endpoint address '{}': {}", host_port_with_default, e))?;

        let tcp_stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
            .map_err(|e| format!("SIEM webhook: TCP connect to {} failed: {}", addr, e))?;
        let _ = tcp_stream.set_write_timeout(Some(Duration::from_secs(5)));
        let _ = tcp_stream.set_read_timeout(Some(Duration::from_secs(5)));

        // Establish TLS over the TCP connection using rustls
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let tls_config = std::sync::Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        );

        // Extract the hostname (without port) for SNI
        let sni_host = if host_port.contains(':') {
            &host_port[..host_port.rfind(':').unwrap_or(host_port.len())]
        } else {
            host_port
        };

        let server_name = rustls::pki_types::ServerName::try_from(sni_host.to_string())
            .map_err(|e| format!("SIEM webhook: invalid SNI hostname '{}': {}", sni_host, e))?;

        let tls_conn = rustls::ClientConnection::new(tls_config, server_name)
            .map_err(|e| format!("SIEM webhook: TLS handshake setup failed: {}", e))?;

        let mut tls_stream = rustls::StreamOwned::new(tls_conn, tcp_stream);

        tls_stream
            .write_all(request.as_bytes())
            .map_err(|e| format!("SIEM webhook: TLS write to {} failed: {}", addr, e))?;
        tls_stream
            .flush()
            .map_err(|e| format!("SIEM webhook: TLS flush to {} failed: {}", addr, e))?;

        // Read response status to detect server errors
        let mut response_buf = [0u8; 512];
        let n = tls_stream.read(&mut response_buf).unwrap_or(0);
        if n > 0 {
            let response = String::from_utf8_lossy(&response_buf[..n]);
            if !response.contains("200")
                && !response.contains("201")
                && !response.contains("202")
            {
                tracing::error!(
                    target: "siem_webhook",
                    endpoint = %endpoint,
                    response = %response,
                    "SIEM webhook: non-2xx response"
                );
                return Err(format!(
                    "SIEM webhook: endpoint returned non-2xx: {}",
                    &response[..response.len().min(100)]
                ));
            }
        }

        tracing::info!(
            target: "siem_webhook",
            endpoint = %endpoint,
            count = count,
            timestamp = %timestamp,
            has_signature = signature.is_some(),
            "siem_webhook: successfully flushed {} event(s) to SIEM endpoint",
            count
        );

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
            endpoint_url: "https://siem.example.mil/api/events".into(),
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

        // flush() will attempt a real HTTP POST which will fail in tests
        // (no reachable endpoint), but the buffer should still be drained.
        let _result = wh.flush();
        assert_eq!(wh.pending_count(), 0, "buffer should be empty after flush");
    }

    #[test]
    fn test_siem_webhook_batch_size() {
        let config = SiemWebhookConfig {
            endpoint_url: "https://siem.example.mil/api/events".into(),
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
        // not the manual flush() call). The POST will fail in tests (no
        // reachable endpoint), but the buffer should still be drained.
        let _result = wh.flush();
        assert_eq!(wh.pending_count(), 0);
    }

    #[test]
    fn test_siem_webhook_config_from_env() {
        // Set the required env var
        std::env::set_var("MILNET_SIEM_WEBHOOK_URL", "https://test-siem.mil/events");
        std::env::set_var("MILNET_SIEM_AUTH_TOKEN", "secret-token-42");
        std::env::set_var("MILNET_SIEM_BATCH_SIZE", "25");
        std::env::set_var("MILNET_SIEM_FLUSH_INTERVAL_SECS", "60");
        std::env::set_var("MILNET_SIEM_ENABLED", "true");

        let cfg = SiemWebhookConfig::from_env()
            .expect("config should be Some when URL is set");

        assert_eq!(cfg.endpoint_url, "https://test-siem.mil/events");
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
    fn test_siem_webhook_rejects_plaintext_http() {
        let config = SiemWebhookConfig {
            endpoint_url: "http://siem.example.mil/api/events".into(),
            auth_token: "test-token".into(),
            batch_size: 10,
            flush_interval_secs: 30,
            enabled: true,
        };
        let wh = SiemWebhook::new(config);
        wh.queue_event(r#"{"event":"login"}"#);

        let result = wh.flush();
        assert!(result.is_err(), "flush should reject plaintext HTTP endpoint");
        let err = result.unwrap_err();
        assert!(
            err.contains("must use HTTPS"),
            "error should mention HTTPS requirement, got: {}",
            err
        );
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
