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
///
/// Includes exponential backoff on HalfOpen probes: each consecutive probe
/// failure doubles the wait before the next attempt (capped at 5 minutes).
/// Without this, an attacker can keep auth in a permanent ~99.9% failure
/// state by ensuring each HalfOpen probe fails.
pub struct CircuitBreaker {
    failure_count: AtomicU32,
    last_failure_epoch_ms: AtomicU64,
    /// Number of consecutive HalfOpen probe failures — drives backoff.
    consecutive_open_cycles: AtomicU32,
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
            consecutive_open_cycles: AtomicU32::new(0),
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
    ///
    /// Uses exponential backoff for HalfOpen transitions: each consecutive
    /// probe failure doubles the wait before the next HalfOpen window.
    /// Capped at 5 minutes (300_000 ms) to prevent indefinite lockout.
    pub fn state(&self) -> CircuitState {
        let failures = self.failure_count.load(Ordering::Acquire);
        if failures < self.threshold {
            return CircuitState::Closed;
        }
        let last = self.last_failure_epoch_ms.load(Ordering::Acquire);
        let elapsed = self.now_ms().saturating_sub(last);

        // Exponential backoff: base_timeout * 2^consecutive_open_cycles
        // Capped at 5 minutes to prevent indefinite lockout.
        let cycles = self.consecutive_open_cycles.load(Ordering::Acquire);
        let backoff_factor = 1u64.checked_shl(cycles.min(10)).unwrap_or(1024);
        let effective_timeout = (self.reset_timeout_ms.saturating_mul(backoff_factor))
            .min(300_000); // Cap at 5 minutes

        if elapsed >= effective_timeout {
            CircuitState::HalfOpen
        } else {
            CircuitState::Open
        }
    }

    /// Check if a request should be allowed through.
    pub fn allow_request(&self) -> bool {
        matches!(self.state(), CircuitState::Closed | CircuitState::HalfOpen)
    }

    /// Record a successful call — resets the failure counter and backoff.
    pub fn record_success(&self) {
        let was_open = self.failure_count.load(Ordering::Acquire) >= self.threshold;
        self.failure_count.store(0, Ordering::Release);
        self.consecutive_open_cycles.store(0, Ordering::Release);
        if was_open {
            crate::siem::SecurityEvent::circuit_breaker_closed(&self.service_name);
        }
    }

    /// Record a failed call.
    ///
    /// Uses saturating addition to prevent u32 wraparound. When the counter
    /// reaches `u32::MAX` it stays there and emits a SIEM saturation event.
    pub fn record_failure(&self) {
        // Saturating increment via compare-and-swap loop to prevent wraparound.
        let prev = loop {
            let current = self.failure_count.load(Ordering::Acquire);
            if current == u32::MAX {
                // Already saturated — nothing to do
                return;
            }
            let new = current.saturating_add(1);
            match self.failure_count.compare_exchange_weak(
                current,
                new,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(prev) => break prev,
                Err(_) => continue, // CAS failed, retry
            }
        };

        self.last_failure_epoch_ms.store(self.now_ms(), Ordering::Release);

        // If we were already in Open/HalfOpen state, increment the backoff
        // cycle counter so the next HalfOpen window takes longer to arrive.
        if prev >= self.threshold {
            let _ = self.consecutive_open_cycles.fetch_add(1, Ordering::Release);
        }

        // Emit SIEM event when we cross the threshold into Open state
        if prev + 1 == self.threshold {
            crate::siem::SecurityEvent::circuit_breaker_opened(&self.service_name);
        }

        // Emit SIEM event when failure count saturates at u32::MAX
        if prev + 1 == u32::MAX {
            tracing::error!(
                service = %self.service_name,
                "circuit breaker failure count SATURATED at u32::MAX — \
                 sustained failure, possible attack or total service loss"
            );
            crate::siem::SecurityEvent::circuit_breaker_saturated(&self.service_name);
        }
    }
}
