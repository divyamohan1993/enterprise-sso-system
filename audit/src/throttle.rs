//! D10: idempotency dedup + per-tenant throttle for audit submissions.
//!
//! Two independent admission-control layers run in front of `propose_entry`:
//!
//! 1. **Idempotency dedup** — a `(event_id, signature)` pair that has already
//!    been committed within the last 24 h is silently accepted without creating
//!    a duplicate BFT entry. The dedup set is bounded by an mpsc-fed eviction
//!    task that runs every minute and drops any entry older than the TTL.
//!
//! 2. **Per-tenant token bucket** — 100 submissions per second per tenant,
//!    with a 100-token burst capacity. Exceeding the bucket is fail-closed
//!    (the request is rejected, the event is logged to SIEM at `Warning`).
//!
//! Both layers are thread-safe via `tokio::sync::Mutex` wrapped in an `Arc`
//! so a single instance can be cloned into per-connection tasks.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use uuid::Uuid;

/// TTL for the dedup set — 24 hours.
const DEDUP_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Per-tenant token bucket refill rate (tokens per second).
const TOKEN_RATE_PER_SEC: f64 = 100.0;

/// Per-tenant token bucket max burst capacity.
const TOKEN_BURST: f64 = 100.0;

/// A single dedup entry — the committed `(event_id, signature)` pair and
/// the instant it was inserted.
#[derive(Clone)]
struct DedupRecord {
    key: DedupKey,
    inserted_at: Instant,
}

type DedupKey = [u8; 32];

/// Compute a 32-byte dedup key from `event_id || signature`.
fn dedup_key(event_id: Uuid, signature: &[u8]) -> DedupKey {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(event_id.as_bytes());
    h.update(signature);
    let out = h.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(&out);
    k
}

/// Per-tenant token bucket.
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

impl Bucket {
    fn new() -> Self {
        Self {
            tokens: TOKEN_BURST,
            last_refill: Instant::now(),
        }
    }

    /// Refill the bucket based on elapsed wall-clock time, then try to take
    /// a single token. Returns `true` on success, `false` on bucket-empty.
    fn try_take(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * TOKEN_RATE_PER_SEC).min(TOKEN_BURST);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Shared admission controller.
#[derive(Clone)]
pub struct AdmissionControl {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    /// FIFO order for O(1) TTL eviction. `HashMap` for O(1) membership test.
    dedup_order: VecDeque<DedupRecord>,
    dedup_set: HashMap<DedupKey, Instant>,
    buckets: HashMap<Uuid, Bucket>,
}

/// Outcome of an admission check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionDecision {
    /// Request is fresh — proceed to BFT propose.
    Accept,
    /// Request is a replay of a recent (event_id, signature) — succeed idempotently.
    DuplicateIgnored,
    /// Per-tenant throttle exceeded — fail closed.
    ThrottleExceeded,
}

impl AdmissionControl {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                dedup_order: VecDeque::new(),
                dedup_set: HashMap::new(),
                buckets: HashMap::new(),
            })),
        }
    }

    /// Check admission for a single audit submission.
    ///
    /// Order: dedup check first (replays are free), then per-tenant throttle.
    /// On `Accept`, the caller MUST then commit to the BFT log and call
    /// `record_commit(event_id, signature)` so subsequent replays hit dedup.
    pub async fn check(
        &self,
        tenant_id: Uuid,
        idempotency_event_id: Option<Uuid>,
        idempotency_signature: &[u8],
    ) -> AdmissionDecision {
        let mut inner = self.inner.lock().await;

        // Dedup: only applies when both event_id and signature are supplied.
        if let Some(eid) = idempotency_event_id {
            if !idempotency_signature.is_empty() {
                let key = dedup_key(eid, idempotency_signature);
                if inner.dedup_set.contains_key(&key) {
                    common::siem::SecurityEvent {
                        timestamp: common::siem::SecurityEvent::now_iso8601(),
                        category: "audit_ingest",
                        action: "idempotent_replay",
                        severity: common::siem::Severity::Info,
                        outcome: "success",
                        user_id: None,
                        source_ip: None,
                        detail: Some(format!(
                            "audit replay within dedup window: event_id={}", eid
                        )),
                    }
                    .emit();
                    return AdmissionDecision::DuplicateIgnored;
                }
            }
        }

        // Per-tenant token bucket.
        let bucket = inner.buckets.entry(tenant_id).or_insert_with(Bucket::new);
        if !bucket.try_take() {
            common::siem::SecurityEvent {
                timestamp: common::siem::SecurityEvent::now_iso8601(),
                category: "audit_ingest",
                action: "throttle_exceeded",
                severity: common::siem::Severity::Warning,
                outcome: "failure",
                user_id: None,
                source_ip: None,
                detail: Some(format!(
                    "per-tenant throttle exceeded: tenant_id={} (limit {}/s, burst {})",
                    tenant_id, TOKEN_RATE_PER_SEC, TOKEN_BURST
                )),
            }
            .emit();
            return AdmissionDecision::ThrottleExceeded;
        }

        AdmissionDecision::Accept
    }

    /// Record a successful commit into the dedup set.
    pub async fn record_commit(
        &self,
        idempotency_event_id: Option<Uuid>,
        idempotency_signature: &[u8],
    ) {
        let Some(eid) = idempotency_event_id else { return };
        if idempotency_signature.is_empty() {
            return;
        }
        let key = dedup_key(eid, idempotency_signature);
        let mut inner = self.inner.lock().await;
        let now = Instant::now();
        inner.dedup_set.insert(key, now);
        inner.dedup_order.push_back(DedupRecord { key, inserted_at: now });
    }

    /// Evict expired dedup entries. Called periodically from the background
    /// task spawned by `spawn_eviction_task`.
    pub async fn evict_expired(&self) {
        let mut inner = self.inner.lock().await;
        let now = Instant::now();
        while let Some(front) = inner.dedup_order.front() {
            if now.duration_since(front.inserted_at) < DEDUP_TTL {
                break;
            }
            let front = inner.dedup_order.pop_front().expect("front peeked above");
            // Only remove from the set if the map entry still matches this record
            // (guards against a shadow-insert, which never currently happens but
            // keeps the invariant explicit).
            if let Some(ts) = inner.dedup_set.get(&front.key) {
                if *ts == front.inserted_at {
                    inner.dedup_set.remove(&front.key);
                }
            }
        }
    }

    /// Spawn a periodic eviction task (every 60 s) that drops entries older
    /// than `DEDUP_TTL` from the dedup set.
    pub fn spawn_eviction_task(&self) {
        let this = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                this.evict_expired().await;
            }
        });
    }
}

impl Default for AdmissionControl {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dedup_allows_first_blocks_replay() {
        let ac = AdmissionControl::new();
        let t = Uuid::new_v4();
        let eid = Uuid::new_v4();
        let sig = vec![1u8, 2, 3];
        assert_eq!(ac.check(t, Some(eid), &sig).await, AdmissionDecision::Accept);
        ac.record_commit(Some(eid), &sig).await;
        assert_eq!(
            ac.check(t, Some(eid), &sig).await,
            AdmissionDecision::DuplicateIgnored
        );
    }

    #[tokio::test]
    async fn throttle_rejects_after_burst() {
        let ac = AdmissionControl::new();
        let t = Uuid::new_v4();
        for _ in 0..(TOKEN_BURST as usize) {
            assert_eq!(ac.check(t, None, &[]).await, AdmissionDecision::Accept);
        }
        assert_eq!(
            ac.check(t, None, &[]).await,
            AdmissionDecision::ThrottleExceeded
        );
    }
}
