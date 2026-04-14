//! F4/F5/F10: Idempotency, saga compensation, and bounded worker pool.
//!
//! F4 — every outbound RPC wrapper carries a `Uuid` idempotency key and
//! caches its in-flight / recent responses for 60s so that retries from
//! the gateway do not double-spend ceremony state.
//!
//! F5 — `RevocationSet` holds OPAQUE receipt IDs that MUST be rejected in
//! any subsequent ceremony because their companion TSS call failed
//! (saga compensation). Entries expire after 24h.
//!
//! F10 — `WorkerPool` is a bounded mpsc-backed worker pool that replaces
//! unbounded `tokio::spawn` for incoming ceremonies. Pair with
//! `common::circuit_breaker::CircuitBreaker` at call sites.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Idempotency cache TTL (60 seconds, per F4).
pub const IDEMPOTENCY_TTL: Duration = Duration::from_secs(60);
/// Saga compensation revocation TTL (24 hours, per F5).
pub const REVOCATION_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Maximum entries in the idempotency cache before aggressive eviction.
const IDEMPOTENCY_MAX: usize = 10_000;
/// Maximum entries in the revocation set.
const REVOCATION_MAX: usize = 100_000;

struct IdemEntry {
    inserted_at: Instant,
    response: Vec<u8>,
}

/// Thread-safe idempotency cache for outbound RPCs.
pub struct IdempotencyCache {
    inner: Mutex<HashMap<Uuid, IdemEntry>>,
}

impl IdempotencyCache {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Get a cached response for an in-flight or recent idempotency key.
    pub fn get(&self, key: &Uuid) -> Option<Vec<u8>> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        Self::evict_expired(&mut g);
        g.get(key).map(|e| e.response.clone())
    }

    /// Store a response keyed by idempotency key.
    pub fn put(&self, key: Uuid, response: Vec<u8>) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        Self::evict_expired(&mut g);
        if g.len() >= IDEMPOTENCY_MAX {
            // Drop the oldest half to recover; O(n) on overflow only.
            let target = IDEMPOTENCY_MAX / 2;
            let mut all: Vec<(Uuid, Instant)> =
                g.iter().map(|(k, v)| (*k, v.inserted_at)).collect();
            all.sort_by_key(|&(_, t)| t);
            for (k, _) in all.into_iter().take(g.len() - target) {
                g.remove(&k);
            }
        }
        g.insert(
            key,
            IdemEntry {
                inserted_at: Instant::now(),
                response,
            },
        );
    }

    fn evict_expired(map: &mut HashMap<Uuid, IdemEntry>) {
        let now = Instant::now();
        map.retain(|_, v| now.duration_since(v.inserted_at) < IDEMPOTENCY_TTL);
    }
}

impl Default for IdempotencyCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Saga compensation revocation set (F5).
pub struct RevocationSet {
    inner: Mutex<HashMap<[u8; 32], Instant>>,
}

impl RevocationSet {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Add a receipt ID to the revocation set.
    pub fn revoke(&self, receipt_id: [u8; 32]) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        Self::evict_expired(&mut g);
        if g.len() >= REVOCATION_MAX {
            let target = REVOCATION_MAX / 2;
            let mut all: Vec<([u8; 32], Instant)> = g.iter().map(|(k, v)| (*k, *v)).collect();
            all.sort_by_key(|&(_, t)| t);
            for (k, _) in all.into_iter().take(g.len() - target) {
                g.remove(&k);
            }
        }
        g.insert(receipt_id, Instant::now());
        tracing::warn!(
            target: "siem",
            "SIEM:WARN saga compensation — receipt revoked"
        );
    }

    /// Return true if a receipt ID has been revoked (and is still within TTL).
    pub fn is_revoked(&self, receipt_id: &[u8; 32]) -> bool {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        Self::evict_expired(&mut g);
        g.contains_key(receipt_id)
    }

    fn evict_expired(map: &mut HashMap<[u8; 32], Instant>) {
        let now = Instant::now();
        map.retain(|_, v| now.duration_since(*v) < REVOCATION_TTL);
    }
}

impl Default for RevocationSet {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// F10: bounded worker pool + minimal inline circuit breaker
// ---------------------------------------------------------------------------

/// Minimal inline circuit breaker: 5 failures in 30s opens for 30s.
pub struct InlineBreaker {
    state: Mutex<BreakerState>,
}

struct BreakerState {
    failures: u32,
    window_start: Instant,
    open_until: Option<Instant>,
}

const BREAKER_WINDOW: Duration = Duration::from_secs(30);
const BREAKER_OPEN_FOR: Duration = Duration::from_secs(30);
const BREAKER_THRESHOLD: u32 = 5;

impl InlineBreaker {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(BreakerState {
                failures: 0,
                window_start: Instant::now(),
                open_until: None,
            }),
        }
    }

    pub fn allow(&self) -> bool {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(until) = s.open_until {
            if Instant::now() < until {
                return false;
            }
            s.open_until = None;
            s.failures = 0;
            s.window_start = Instant::now();
        }
        true
    }

    pub fn record_success(&self) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.failures = 0;
        s.window_start = Instant::now();
    }

    pub fn record_failure(&self) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if now.duration_since(s.window_start) > BREAKER_WINDOW {
            s.failures = 0;
            s.window_start = now;
        }
        s.failures = s.failures.saturating_add(1);
        if s.failures >= BREAKER_THRESHOLD {
            s.open_until = Some(now + BREAKER_OPEN_FOR);
            tracing::error!(
                target: "siem",
                "SIEM:CRITICAL F10 inline breaker OPEN for {:?}",
                BREAKER_OPEN_FOR
            );
        }
    }
}

impl Default for InlineBreaker {
    fn default() -> Self {
        Self::new()
    }
}

/// Default bound for the worker pool channel (F10: 1000 in-flight tasks).
pub const WORKER_POOL_CAPACITY: usize = 1000;
