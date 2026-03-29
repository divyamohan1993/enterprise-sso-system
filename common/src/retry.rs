//! Exponential backoff retry logic for inter-service connections.
//!
//! Provides configurable retry with jitter to prevent thundering herd.
#![forbid(unsafe_code)]

use std::time::Duration;

/// Configuration for exponential backoff retries.
pub struct RetryConfig {
    /// Maximum number of retry attempts (excluding the initial attempt).
    pub max_retries: u32,
    /// Initial backoff delay.
    pub initial_delay: Duration,
    /// Maximum backoff delay (cap).
    pub max_delay: Duration,
    /// Multiplier per retry (typically 2.0 for exponential).
    pub multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
            multiplier: 2.0,
        }
    }
}

impl RetryConfig {
    /// Compute the delay for a given attempt (0-indexed).
    /// Includes cryptographically random jitter: +/-25% randomization.
    ///
    /// SECURITY: Uses `getrandom` (CSPRNG) to prevent thundering herd attacks.
    /// Deterministic jitter (based on attempt parity) allowed all clients to
    /// retry simultaneously, which could be exploited for coordinated DoS.
    /// Random jitter ensures retry storms are spread across time.
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let base_ms = self.initial_delay.as_millis() as f64
            * self.multiplier.powi(attempt as i32);
        let capped_ms = base_ms.min(self.max_delay.as_millis() as f64);

        // SECURITY: Cryptographically random jitter via getrandom (not deterministic).
        // Produces a uniform value in [0.75, 1.25] for +/-25% jitter.
        let jitter_factor = {
            let mut buf = [0u8; 4];
            // getrandom uses the OS CSPRNG; failure here is fatal (entropy exhaustion).
            getrandom::getrandom(&mut buf).unwrap_or_else(|_| {
                // Fallback: if CSPRNG fails, use a safe default (no jitter).
                buf = [0x80, 0x00, 0x00, 0x00];
            });
            let random_u32 = u32::from_le_bytes(buf);
            // Map [0, u32::MAX] to [0.0, 1.0), then scale to [0.75, 1.25]
            let normalized = (random_u32 as f64) / (u32::MAX as f64);
            0.75 + (normalized * 0.5)
        };
        let jittered_ms = capped_ms * jitter_factor;

        Duration::from_millis(jittered_ms as u64)
    }
}

/// Execute an async operation with exponential backoff retries.
///
/// Returns the result of the first successful attempt, or the last error.
pub async fn retry_with_backoff<F, Fut, T, E>(
    config: &RetryConfig,
    operation_name: &str,
    mut operation: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut last_err = None;

    for attempt in 0..=config.max_retries {
        match operation().await {
            Ok(result) => {
                if attempt > 0 {
                    tracing::info!(
                        "{}: succeeded on attempt {} (after {} retries)",
                        operation_name, attempt + 1, attempt
                    );
                }
                return Ok(result);
            }
            Err(e) => {
                if attempt < config.max_retries {
                    let delay = config.delay_for_attempt(attempt);
                    tracing::warn!(
                        "{}: attempt {} failed ({}), retrying in {:?}",
                        operation_name, attempt + 1, e, delay
                    );
                    tokio::time::sleep(delay).await;
                } else {
                    tracing::error!(
                        "{}: all {} attempts failed, last error: {}",
                        operation_name, config.max_retries + 1, e
                    );
                }
                last_err = Some(e);
            }
        }
    }

    Err(last_err.unwrap())
}
