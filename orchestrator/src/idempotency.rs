//! F4/F5/F10: Idempotency, saga compensation, and bounded worker pool.
//!
//! F4 — every outbound RPC wrapper carries an idempotency key and
//! caches its in-flight / recent responses for 60s so that retries from
//! the gateway do not double-spend ceremony state.
//!
//! SECURITY: the idempotency key MUST NOT be a raw gateway-supplied
//! `correlation_id`. Correlation IDs flow through gateway logs, HTTP
//! headers and distributed traces and are not secrets; keying the cache
//! (which stores the FULL signed token) on a guessable UUID is a token
//! replay primitive. The key is therefore a 32-byte value derived from
//! credential-bound material — see `IdempotencyKey::derive`.
//!
//! F5 — `RevocationSet` holds OPAQUE receipt IDs that MUST be rejected in
//! any subsequent ceremony because their companion TSS call failed
//! (saga compensation). Entries expire after 24h.
//!
//! F10 — `WorkerPool` is a bounded mpsc-backed worker pool that replaces
//! unbounded `tokio::spawn` for incoming ceremonies. Pair with
//! `common::circuit_breaker::CircuitBreaker` at call sites.

use sha2::{Digest, Sha512};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Idempotency cache TTL (60 seconds, per F4).
pub const IDEMPOTENCY_TTL: Duration = Duration::from_secs(60);

/// Secret, credential-bound idempotency key.
///
/// A retry from the gateway only legitimately repeats the SAME request:
/// same user, same password, same DPoP key, same correlation_id. The key
/// is `SHA-512(domain || correlation_id || username || password || dpop_key_hash)`
/// truncated to 32 bytes, so a party who only observes/guesses the
/// non-secret `correlation_id` cannot reconstruct it and therefore cannot
/// retrieve another caller's cached token. The password is a confidential
/// input that the attacker does not have, which binds the cache entry to
/// the authenticated caller.
///
/// The stored value is a one-way SHA-512 digest, not the raw password, so
/// it is not itself a recoverable secret; it is still treated as sensitive
/// and never logged in full (see the `Debug` impl).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdempotencyKey([u8; 32]);

impl IdempotencyKey {
    const DOMAIN: &'static [u8] = b"milnet.orchestrator.idempotency.v2";

    /// Derive the cache key from the request's credential-bound material.
    pub fn derive(
        correlation_id: &Uuid,
        username: &str,
        password: &[u8],
        dpop_key_hash: &[u8; 64],
    ) -> Self {
        let mut h = Sha512::new();
        h.update(Self::DOMAIN);
        h.update(correlation_id.as_bytes());
        // Length-prefix variable-length fields so distinct inputs cannot
        // collide via boundary ambiguity.
        h.update((username.len() as u64).to_be_bytes());
        h.update(username.as_bytes());
        h.update((password.len() as u64).to_be_bytes());
        h.update(password);
        h.update(dpop_key_hash);
        let digest = h.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&digest[..32]);
        Self(key)
    }
}

impl std::fmt::Debug for IdempotencyKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the full key — it is credential-derived material.
        write!(f, "IdempotencyKey({:02x}{:02x}…)", self.0[0], self.0[1])
    }
}
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
///
/// Keyed on a credential-bound [`IdempotencyKey`] — never on a raw,
/// gateway-supplied correlation_id — so a cached token can only be
/// retrieved by a caller that can reproduce the original credentials.
pub struct IdempotencyCache {
    inner: Mutex<HashMap<IdempotencyKey, IdemEntry>>,
}

impl IdempotencyCache {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Get a cached response for an in-flight or recent idempotency key.
    pub fn get(&self, key: &IdempotencyKey) -> Option<Vec<u8>> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        Self::evict_expired(&mut g);
        g.get(key).map(|e| e.response.clone())
    }

    /// Store a response keyed by idempotency key.
    pub fn put(&self, key: IdempotencyKey, response: Vec<u8>) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        Self::evict_expired(&mut g);
        if g.len() >= IDEMPOTENCY_MAX {
            // Drop the oldest half to recover; O(n) on overflow only.
            let target = IDEMPOTENCY_MAX / 2;
            let mut all: Vec<(IdempotencyKey, Instant)> =
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

    fn evict_expired(map: &mut HashMap<IdempotencyKey, IdemEntry>) {
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
