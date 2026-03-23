//! Circuit breaker pattern — prevents cascade failures between services.
#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Circuit breaker states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,   // Normal operation
    Open,     // Failing, reject requests immediately
    HalfOpen, // Testing if service recovered
}

/// A thread-safe circuit breaker that tracks failures and prevents cascade.
pub struct CircuitBreaker {
    failure_count: AtomicU32,
    last_failure_epoch_ms: AtomicU64,
    threshold: u32,
    reset_timeout_ms: u64,
    start: Instant,
    /// Service name for SIEM event reporting.
    service_name: String,
}

impl CircuitBreaker {
    /// Create a new circuit breaker.
    /// - `threshold`: number of consecutive failures before opening
    /// - `reset_timeout`: how long to wait before trying again
    pub fn new(threshold: u32, reset_timeout: Duration) -> Self {
        Self::with_name("unknown", threshold, reset_timeout)
    }

    /// Create a new circuit breaker with a service name for SIEM reporting.
    pub fn with_name(service_name: &str, threshold: u32, reset_timeout: Duration) -> Self {
        Self {
            failure_count: AtomicU32::new(0),
            last_failure_epoch_ms: AtomicU64::new(0),
            threshold,
            reset_timeout_ms: reset_timeout.as_millis() as u64,
            start: Instant::now(),
            service_name: service_name.to_string(),
        }
    }

    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// Get current circuit state.
    pub fn state(&self) -> CircuitState {
        let failures = self.failure_count.load(Ordering::Relaxed);
        if failures < self.threshold {
            return CircuitState::Closed;
        }
        let last = self.last_failure_epoch_ms.load(Ordering::Relaxed);
        let elapsed = self.now_ms().saturating_sub(last);
        if elapsed >= self.reset_timeout_ms {
            CircuitState::HalfOpen
        } else {
            CircuitState::Open
        }
    }

    /// Check if a request should be allowed through.
    pub fn allow_request(&self) -> bool {
        matches!(self.state(), CircuitState::Closed | CircuitState::HalfOpen)
    }

    /// Record a successful call — resets the failure counter.
    pub fn record_success(&self) {
        let was_open = self.failure_count.load(Ordering::Relaxed) >= self.threshold;
        self.failure_count.store(0, Ordering::Relaxed);
        if was_open {
            crate::siem::SecurityEvent::circuit_breaker_closed(&self.service_name);
        }
    }

    /// Record a failed call.
    pub fn record_failure(&self) {
        let prev = self.failure_count.fetch_add(1, Ordering::Relaxed);
        self.last_failure_epoch_ms.store(self.now_ms(), Ordering::Relaxed);
        // Emit SIEM event when we cross the threshold into Open state
        if prev + 1 == self.threshold {
            crate::siem::SecurityEvent::circuit_breaker_opened(&self.service_name);
        }
    }
}
