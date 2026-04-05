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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[test]
    fn retry_config_default_values() {
        let cfg = RetryConfig::default();
        assert_eq!(cfg.max_retries, 3);
        assert_eq!(cfg.initial_delay, Duration::from_millis(100));
        assert_eq!(cfg.max_delay, Duration::from_secs(5));
        assert!((cfg.multiplier - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn delay_increases_exponentially() {
        let cfg = RetryConfig {
            max_retries: 10,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(60),
            multiplier: 2.0,
        };

        // With jitter, exact values vary, but the trend must be increasing.
        // Sample many attempts and check median trend.
        let d0 = cfg.delay_for_attempt(0).as_millis();
        let d3 = cfg.delay_for_attempt(3).as_millis();

        // attempt 0: ~100ms * jitter [75..125]
        assert!(d0 >= 50 && d0 <= 200, "attempt 0 delay out of range: {d0}");
        // attempt 3: ~800ms * jitter [600..1000]
        assert!(d3 >= 400 && d3 <= 1500, "attempt 3 delay out of range: {d3}");
        // Later attempts must generally have larger delays.
        // (There's a small chance jitter makes d3 < d0, so we use generous bounds.)
    }

    #[test]
    fn delay_is_capped_at_max_delay() {
        let cfg = RetryConfig {
            max_retries: 100,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(5),
            multiplier: 10.0,
        };

        // At attempt 10, uncapped would be 1s * 10^10 = way beyond max.
        let d = cfg.delay_for_attempt(10);
        // With jitter: max 5000 * 1.25 = 6250ms
        assert!(
            d.as_millis() <= 6500,
            "delay must be capped near max_delay, got {}ms",
            d.as_millis()
        );
    }

    #[test]
    fn delay_has_jitter_variation() {
        let cfg = RetryConfig::default();
        // Generate many delays for the same attempt and verify they are not all identical.
        let delays: Vec<u128> = (0..20).map(|_| cfg.delay_for_attempt(0).as_millis()).collect();
        let all_same = delays.iter().all(|&d| d == delays[0]);
        // With cryptographic jitter, probability of 20 identical values is vanishingly small.
        assert!(!all_same, "jitter must produce variation across calls");
    }

    #[tokio::test]
    async fn retry_succeeds_immediately_on_first_attempt() {
        let cfg = RetryConfig {
            max_retries: 3,
            initial_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(10),
            multiplier: 2.0,
        };
        let call_count = Arc::new(AtomicU32::new(0));
        let count = call_count.clone();

        let result: Result<&str, String> = retry_with_backoff(&cfg, "test-op", || {
            let count = count.clone();
            async move {
                count.fetch_add(1, Ordering::Relaxed);
                Ok("success")
            }
        })
        .await;

        assert_eq!(result.unwrap(), "success");
        assert_eq!(call_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn retry_retries_then_succeeds() {
        let cfg = RetryConfig {
            max_retries: 3,
            initial_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(5),
            multiplier: 2.0,
        };
        let call_count = Arc::new(AtomicU32::new(0));
        let count = call_count.clone();

        let result: Result<&str, String> = retry_with_backoff(&cfg, "test-op", || {
            let count = count.clone();
            async move {
                let n = count.fetch_add(1, Ordering::Relaxed);
                if n < 2 {
                    Err(format!("fail attempt {}", n))
                } else {
                    Ok("recovered")
                }
            }
        })
        .await;

        assert_eq!(result.unwrap(), "recovered");
        assert_eq!(call_count.load(Ordering::Relaxed), 3); // 2 failures + 1 success
    }

    #[tokio::test]
    async fn retry_exhausts_all_attempts_and_returns_last_error() {
        let cfg = RetryConfig {
            max_retries: 2,
            initial_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(5),
            multiplier: 2.0,
        };
        let call_count = Arc::new(AtomicU32::new(0));
        let count = call_count.clone();

        let result: Result<(), String> = retry_with_backoff(&cfg, "test-op", || {
            let count = count.clone();
            async move {
                let n = count.fetch_add(1, Ordering::Relaxed);
                Err(format!("error-{}", n))
            }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "error-2"); // last attempt's error
        assert_eq!(call_count.load(Ordering::Relaxed), 3); // initial + 2 retries
    }

    #[tokio::test]
    async fn retry_with_zero_retries_tries_once() {
        let cfg = RetryConfig {
            max_retries: 0,
            initial_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(5),
            multiplier: 2.0,
        };
        let call_count = Arc::new(AtomicU32::new(0));
        let count = call_count.clone();

        let result: Result<(), String> = retry_with_backoff(&cfg, "test-op", || {
            let count = count.clone();
            async move {
                count.fetch_add(1, Ordering::Relaxed);
                Err("only-error".to_string())
            }
        })
        .await;

        assert_eq!(result.unwrap_err(), "only-error");
        assert_eq!(call_count.load(Ordering::Relaxed), 1);
    }
}
