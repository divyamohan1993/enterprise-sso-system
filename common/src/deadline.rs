//! Deadline propagation for request processing pipelines.
//!
//! SECURITY: In a military-grade SSO system, unbounded request processing
//! enables resource exhaustion attacks (slowloris, computational DoS).
//! The `RequestDeadline` ensures that every internal call checks remaining
//! time before starting work. If the deadline is exceeded, the call returns
//! immediately -- no work is started that cannot finish in time.
//!
//! This implements a hierarchical timeout model:
//! - Entry point sets a deadline (e.g., 5 seconds from now)
//! - Each internal call checks remaining time before proceeding
//! - Sub-calls inherit the parent deadline (propagation)
//! - Uses `std::time::Instant` for monotonic, non-adjustable timing
#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

/// Error returned when a request deadline has been exceeded.
#[derive(Debug, Clone)]
pub struct DeadlineExceeded {
    /// The operation that detected the deadline was exceeded.
    pub operation: String,
    /// How long ago the deadline expired.
    pub exceeded_by: Duration,
}

impl std::fmt::Display for DeadlineExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "deadline exceeded in '{}' (expired {:?} ago)",
            self.operation, self.exceeded_by
        )
    }
}

impl std::error::Error for DeadlineExceeded {}

/// A propagatable request deadline.
///
/// Created at the entry point (e.g., gateway) and passed through all internal
/// calls. Each service checks `remaining()` before starting expensive work.
#[derive(Debug, Clone, Copy)]
pub struct RequestDeadline {
    /// Monotonic instant when the deadline expires.
    expires_at: Instant,
}

impl RequestDeadline {
    /// Create a new deadline that expires `timeout` from now.
    ///
    /// Typical values: 5s for authentication, 10s for admin operations,
    /// 30s for key ceremonies.
    pub fn new(timeout: Duration) -> Self {
        Self {
            expires_at: Instant::now() + timeout,
        }
    }

    /// Create a deadline from a specific expiration instant.
    pub fn from_instant(expires_at: Instant) -> Self {
        Self { expires_at }
    }

    /// Check if the deadline has been exceeded.
    pub fn is_exceeded(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Get the remaining time before the deadline expires.
    /// Returns `Duration::ZERO` if the deadline has already passed.
    pub fn remaining(&self) -> Duration {
        self.expires_at.saturating_duration_since(Instant::now())
    }

    /// Check the deadline before starting an operation.
    ///
    /// Returns `Ok(remaining)` if there is still time, or
    /// `Err(DeadlineExceeded)` if the deadline has passed.
    ///
    /// Usage:
    /// ```ignore
    /// let remaining = deadline.check("database_query")?;
    /// // Only proceed if enough time remains for the operation.
    /// ```
    pub fn check(&self, operation: &str) -> Result<Duration, DeadlineExceeded> {
        let now = Instant::now();
        if now >= self.expires_at {
            Err(DeadlineExceeded {
                operation: operation.to_string(),
                exceeded_by: now - self.expires_at,
            })
        } else {
            Ok(self.expires_at - now)
        }
    }

    /// Check the deadline and ensure at least `min_remaining` time is left.
    ///
    /// This prevents starting work that is known to take longer than the
    /// remaining budget. For example, if a FROST signing ceremony takes ~500ms,
    /// don't start it with only 100ms remaining.
    pub fn check_with_budget(
        &self,
        operation: &str,
        min_remaining: Duration,
    ) -> Result<Duration, DeadlineExceeded> {
        let remaining = self.check(operation)?;
        if remaining < min_remaining {
            Err(DeadlineExceeded {
                operation: operation.to_string(),
                exceeded_by: min_remaining - remaining,
            })
        } else {
            Ok(remaining)
        }
    }

    /// Create a sub-deadline that is the tighter of this deadline and the
    /// given timeout.
    ///
    /// This ensures sub-operations never exceed the parent deadline, even if
    /// they specify a longer timeout.
    pub fn sub_deadline(&self, timeout: Duration) -> Self {
        let sub_expires = Instant::now() + timeout;
        Self {
            expires_at: self.expires_at.min(sub_expires),
        }
    }

    /// Get the absolute expiration instant (for passing to tokio::time::timeout_at).
    pub fn expires_at(&self) -> Instant {
        self.expires_at
    }
}

/// Default request deadlines for different operation types.
/// SECURITY: These values are tuned for military-grade latency requirements.
pub mod defaults {
    use std::time::Duration;

    /// Authentication request deadline (gateway -> orchestrator -> opaque -> tss).
    pub const AUTH_DEADLINE: Duration = Duration::from_secs(5);

    /// Admin API operation deadline.
    pub const ADMIN_DEADLINE: Duration = Duration::from_secs(10);

    /// Key ceremony deadline (DKG, threshold signing).
    pub const CEREMONY_DEADLINE: Duration = Duration::from_secs(30);

    /// Health check deadline.
    pub const HEALTH_DEADLINE: Duration = Duration::from_secs(2);

    /// Internal inter-service RPC deadline.
    pub const RPC_DEADLINE: Duration = Duration::from_secs(3);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deadline_not_exceeded_initially() {
        let d = RequestDeadline::new(Duration::from_secs(5));
        assert!(!d.is_exceeded());
        assert!(d.remaining() > Duration::ZERO);
    }

    #[test]
    fn deadline_check_succeeds_within_time() {
        let d = RequestDeadline::new(Duration::from_secs(5));
        let remaining = d.check("test_op").unwrap();
        assert!(remaining > Duration::ZERO);
    }

    #[test]
    fn deadline_exceeded_after_expiry() {
        let d = RequestDeadline::new(Duration::from_nanos(1));
        std::thread::sleep(Duration::from_millis(1));
        assert!(d.is_exceeded());
        assert!(d.check("test_op").is_err());
    }

    #[test]
    fn deadline_check_with_budget() {
        let d = RequestDeadline::new(Duration::from_secs(1));
        // Budget of 500ms should succeed with 1s remaining.
        assert!(d.check_with_budget("signing", Duration::from_millis(500)).is_ok());
        // Budget of 5s should fail with only 1s remaining.
        assert!(d.check_with_budget("ceremony", Duration::from_secs(5)).is_err());
    }

    #[test]
    fn sub_deadline_takes_tighter_bound() {
        let parent = RequestDeadline::new(Duration::from_secs(10));
        let sub = parent.sub_deadline(Duration::from_secs(2));
        // Sub-deadline should expire in ~2s, not 10s.
        assert!(sub.remaining() < Duration::from_secs(3));
    }

    #[test]
    fn sub_deadline_respects_parent() {
        let parent = RequestDeadline::new(Duration::from_secs(1));
        let sub = parent.sub_deadline(Duration::from_secs(60));
        // Sub-deadline should not exceed parent (1s), even though 60s was requested.
        assert!(sub.remaining() < Duration::from_secs(2));
    }
}
