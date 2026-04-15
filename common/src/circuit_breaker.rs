//! Circuit breaker pattern -- prevents cascade failures between services.
//!
//! # RES-CB status
//!
//! The fix-spec for RES-CB asked for a `tower::Layer` wrapper so the breaker
//! can be spliced into tonic/tower client stacks. The current MILNET service
//! graph does **not** use tower for downstream calls: orchestrator reaches
//! OPAQUE/TSS via `TlsShardTransport` (SHARD-over-mTLS, request/response
//! objects, not a `tower::Service`), and gateway reaches orchestrator via the
//! same transport. Wrapping a non-tower transport in a `tower::Layer` would
//! be cargo-cult — the layer would have nothing to poll_ready on, and every
//! call site would still have to bridge by hand.
//!
//! Instead we expose two ergonomics on top of the existing
//! [`CircuitBreaker::allow_request`] / [`CircuitBreaker::record_success`] /
//! [`CircuitBreaker::record_failure`] primitives:
//!
//! - [`CircuitOpenError`]: a typed error so call sites can propagate the
//!   "fail fast, circuit is open" state without reaching for strings.
//! - [`CircuitBreaker::guard`]: an RAII helper returning [`CircuitGuard`]
//!   that records failure on drop unless [`CircuitGuard::succeed`] is called.
//!   This makes the call/record pattern miss-proof in the presence of early
//!   returns and `?` propagation.
//!
//! A real `tower::Layer` will be added alongside the tonic migration tracked
//! in CAT-H-followup. Until that migration lands, adding a Layer here would
//! not reduce miscalls.
#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
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
///
/// Single-flight probing: when the circuit transitions to HalfOpen, only ONE
/// request is allowed to probe the recovering service. All other concurrent
/// requests see the circuit as Open.
pub struct CircuitBreaker {
    failure_count: AtomicU32,
    last_failure_epoch_ms: AtomicU64,
    /// Number of consecutive HalfOpen probe failures -- drives backoff.
    consecutive_open_cycles: AtomicU32,
    threshold: u32,
    reset_timeout_ms: u64,
    start: Instant,
    /// Service name for SIEM event reporting.
    service_name: String,
    /// Single-flight probe guard: true when a HalfOpen probe is in progress.
    /// Only one request at a time may probe the recovering service.
    probe_in_flight: AtomicBool,
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
            probe_in_flight: AtomicBool::new(false),
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
        let effective_timeout =
            (self.reset_timeout_ms.saturating_mul(backoff_factor)).min(300_000); // Cap at 5 minutes

        if elapsed >= effective_timeout {
            CircuitState::HalfOpen
        } else {
            CircuitState::Open
        }
    }

    /// Check if a request should be allowed through.
    ///
    /// When the circuit is HalfOpen, only one request at a time is allowed to
    /// probe the recovering service (single-flight). All other concurrent
    /// requests see the circuit as Open and are rejected.
    pub fn allow_request(&self) -> bool {
        match self.state() {
            CircuitState::Closed => true,
            CircuitState::HalfOpen => {
                // CAS: only the first caller flips false -> true and becomes the probe.
                self.probe_in_flight
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            }
            CircuitState::Open => false,
        }
    }

    /// Record a successful call -- resets the failure counter, backoff, and probe flag.
    pub fn record_success(&self) {
        let was_open = self.failure_count.load(Ordering::Acquire) >= self.threshold;
        self.failure_count.store(0, Ordering::Release);
        self.consecutive_open_cycles.store(0, Ordering::Release);
        // Release the probe lock so future HalfOpen transitions can probe again.
        self.probe_in_flight.store(false, Ordering::Release);
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
                // Already saturated -- nothing to do
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

        self.last_failure_epoch_ms
            .store(self.now_ms(), Ordering::Release);

        // If we were already in Open/HalfOpen state, increment the backoff
        // cycle counter and release the single-flight probe lock.
        if prev >= self.threshold {
            let _ = self
                .consecutive_open_cycles
                .fetch_add(1, Ordering::Release);
            self.probe_in_flight.store(false, Ordering::Release);
        }

        // Emit SIEM event when we cross the threshold into Open state
        if prev + 1 == self.threshold {
            crate::siem::SecurityEvent::circuit_breaker_opened(&self.service_name);
        }

        // Emit SIEM event when failure count saturates at u32::MAX
        if prev + 1 == u32::MAX {
            tracing::error!(
                service = %self.service_name,
                "circuit breaker failure count SATURATED at u32::MAX -- \
                 sustained failure, possible attack or total service loss"
            );
            crate::siem::SecurityEvent::circuit_breaker_saturated(&self.service_name);
        }
    }

    /// Acquire an RAII guard around a call. Returns
    /// `Err(CircuitOpenError)` if the breaker is open (fail-fast), or an
    /// [`Ok(CircuitGuard)`] otherwise. The guard records failure on
    /// drop by default; call [`CircuitGuard::succeed`] to flip that to
    /// a success record.
    ///
    /// Typical use:
    ///
    /// ```ignore
    /// let guard = breaker.guard()?; // fail fast if open
    /// let result = downstream_call().await?;
    /// guard.succeed();
    /// Ok(result)
    /// ```
    ///
    /// On early return via `?`, `guard` is dropped without `succeed()`
    /// being called, so the failure is recorded automatically.
    pub fn guard(&self) -> Result<CircuitGuard<'_>, CircuitOpenError> {
        if self.allow_request() {
            Ok(CircuitGuard {
                breaker: self,
                succeeded: false,
            })
        } else {
            Err(CircuitOpenError {
                service: self.service_name.clone(),
            })
        }
    }
}

/// Fail-fast error returned by [`CircuitBreaker::guard`] when the
/// breaker is in the `Open` state (or `HalfOpen` with a probe already
/// in flight).
///
/// Callers MUST propagate this without retrying. Retrying an open
/// circuit defeats the purpose of the breaker — the whole point is to
/// stop hammering a failing dependency until the backoff elapses.
#[derive(Debug, Clone)]
pub struct CircuitOpenError {
    pub service: String,
}

impl std::fmt::Display for CircuitOpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} service circuit breaker is open -- service unavailable",
            self.service.to_uppercase()
        )
    }
}

impl std::error::Error for CircuitOpenError {}

/// RAII guard returned by [`CircuitBreaker::guard`].
///
/// Records failure on drop unless [`CircuitGuard::succeed`] is called,
/// guaranteeing that every `allow_request()` pairs with either
/// `record_success()` or `record_failure()` exactly once — even in the
/// presence of `?` propagation or panics.
#[must_use = "CircuitGuard records failure on drop unless succeed() is called"]
pub struct CircuitGuard<'a> {
    breaker: &'a CircuitBreaker,
    succeeded: bool,
}

impl<'a> CircuitGuard<'a> {
    /// Mark this call as successful. The guard will NOT record a
    /// failure on drop after this.
    pub fn succeed(mut self) {
        self.breaker.record_success();
        self.succeeded = true;
    }
}

impl<'a> Drop for CircuitGuard<'a> {
    fn drop(&mut self) {
        if !self.succeeded {
            self.breaker.record_failure();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_records_failure_on_drop_when_not_succeeded() {
        let cb = CircuitBreaker::new(2, Duration::from_secs(60));
        {
            let _g = cb.guard().expect("closed circuit");
            // drop without succeed()
        }
        {
            let _g = cb.guard().expect("still closed after 1 failure");
            // drop without succeed() again — this trips the breaker
        }
        assert!(cb.guard().is_err(), "breaker should be open after 2 failures");
    }

    #[test]
    fn guard_records_success_when_succeed_called() {
        let cb = CircuitBreaker::new(2, Duration::from_secs(60));
        let g = cb.guard().expect("closed");
        g.succeed();
        // Record a failure now; counter should be at 1, still closed.
        let _f = cb.guard().expect("still closed");
        drop(_f); // failure recorded
        let _g2 = cb.guard().expect("still closed at 1/2");
    }

    #[test]
    fn guard_returns_circuit_open_error_when_open() {
        let cb = CircuitBreaker::new(1, Duration::from_secs(60));
        cb.record_failure();
        match cb.guard() {
            Err(e) => assert!(e.to_string().contains("circuit breaker is open")),
            Ok(_) => panic!("expected CircuitOpenError"),
        };
    }
}
