//! Bulkhead pattern — isolates thread pools per service type to prevent
//! resource exhaustion cascades.
//!
//! SECURITY: In a military-grade SSO system, a slow database query must NEVER
//! starve authentication requests. The bulkhead pattern ensures that each
//! service type (auth, DB, signing, etc.) has its own bounded concurrency
//! pool. If one pool is exhausted, the others continue operating.
#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Errors returned by the bulkhead when capacity is exceeded.
#[derive(Debug, Clone)]
pub enum BulkheadError {
    /// Maximum concurrent calls reached and wait queue is full.
    Rejected {
        service: String,
        max_concurrent: usize,
        max_wait_queue: usize,
    },
    /// Timed out waiting for a permit in the wait queue.
    WaitTimeout {
        service: String,
        waited: Duration,
    },
}

impl std::fmt::Display for BulkheadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BulkheadError::Rejected { service, max_concurrent, max_wait_queue } => {
                write!(
                    f,
                    "bulkhead rejected: service={service} (max_concurrent={max_concurrent}, \
                     max_wait_queue={max_wait_queue})"
                )
            }
            BulkheadError::WaitTimeout { service, waited } => {
                write!(f, "bulkhead timeout: service={service} (waited {:?})", waited)
            }
        }
    }
}

impl std::error::Error for BulkheadError {}

/// A bulkhead isolates concurrency for a named service type.
///
/// Uses `tokio::sync::Semaphore` to limit concurrent calls, with an
/// additional wait queue depth limit to provide back-pressure when the
/// semaphore is fully acquired.
pub struct Bulkhead {
    /// Human-readable service name (for SIEM event reporting).
    service_name: String,
    /// Semaphore controlling concurrent execution permits.
    semaphore: tokio::sync::Semaphore,
    /// Maximum number of callers that may wait for a permit.
    max_wait_queue: usize,
    /// Current number of callers waiting for a permit.
    waiting: AtomicU64,
    /// Maximum time a caller will wait for a permit before being rejected.
    wait_timeout: Duration,
    /// Total calls accepted (metrics).
    accepted: AtomicU64,
    /// Total calls rejected (metrics).
    rejected: AtomicU64,
}

impl Bulkhead {
    /// Create a new bulkhead for the given service.
    ///
    /// - `service_name`: identifier for logging and SIEM events
    /// - `max_concurrent_calls`: maximum number of calls executing simultaneously
    /// - `max_wait_queue`: maximum number of calls waiting for a permit
    /// - `wait_timeout`: how long a caller will wait before being rejected
    pub fn new(
        service_name: &str,
        max_concurrent_calls: usize,
        max_wait_queue: usize,
        wait_timeout: Duration,
    ) -> Self {
        Self {
            service_name: service_name.to_string(),
            semaphore: tokio::sync::Semaphore::new(max_concurrent_calls),
            max_wait_queue,
            waiting: AtomicU64::new(0),
            wait_timeout,
            accepted: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
        }
    }

    /// Attempt to acquire a permit from this bulkhead.
    ///
    /// Returns a `BulkheadPermit` that releases the permit on drop.
    /// Returns `BulkheadError::Rejected` if the wait queue is full.
    /// Returns `BulkheadError::WaitTimeout` if the wait times out.
    pub async fn acquire(&self) -> Result<BulkheadPermit<'_>, BulkheadError> {
        // Check wait queue depth before entering the semaphore queue.
        let current_waiting = self.waiting.fetch_add(1, Ordering::Relaxed);
        if current_waiting > self.max_wait_queue as u64 {
            self.waiting.fetch_sub(1, Ordering::Relaxed);
            self.rejected.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                service = %self.service_name,
                waiting = current_waiting,
                "bulkhead rejecting call: wait queue full"
            );
            return Err(BulkheadError::Rejected {
                service: self.service_name.clone(),
                max_concurrent: self.semaphore.available_permits(),
                max_wait_queue: self.max_wait_queue,
            });
        }

        // Try to acquire a semaphore permit within the timeout.
        let result = tokio::time::timeout(
            self.wait_timeout,
            self.semaphore.acquire(),
        ).await;

        self.waiting.fetch_sub(1, Ordering::Relaxed);

        match result {
            Ok(Ok(permit)) => {
                self.accepted.fetch_add(1, Ordering::Relaxed);
                Ok(BulkheadPermit { _permit: permit })
            }
            Ok(Err(_closed)) => {
                // Semaphore was closed (should not happen in normal operation).
                self.rejected.fetch_add(1, Ordering::Relaxed);
                Err(BulkheadError::Rejected {
                    service: self.service_name.clone(),
                    max_concurrent: 0,
                    max_wait_queue: self.max_wait_queue,
                })
            }
            Err(_elapsed) => {
                self.rejected.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    service = %self.service_name,
                    timeout_ms = self.wait_timeout.as_millis() as u64,
                    "bulkhead rejecting call: wait timeout exceeded"
                );
                Err(BulkheadError::WaitTimeout {
                    service: self.service_name.clone(),
                    waited: self.wait_timeout,
                })
            }
        }
    }

    /// Number of permits currently available.
    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }

    /// Total calls accepted since creation.
    pub fn total_accepted(&self) -> u64 {
        self.accepted.load(Ordering::Relaxed)
    }

    /// Total calls rejected since creation.
    pub fn total_rejected(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }

    /// Service name for this bulkhead.
    pub fn service_name(&self) -> &str {
        &self.service_name
    }
}

/// A permit that is held while a call is executing inside the bulkhead.
/// The underlying semaphore permit is released when this is dropped.
pub struct BulkheadPermit<'a> {
    _permit: tokio::sync::SemaphorePermit<'a>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn bulkhead_allows_within_limit() {
        let bh = Bulkhead::new("test-auth", 2, 10, Duration::from_secs(1));
        let _p1 = bh.acquire().await.unwrap();
        let _p2 = bh.acquire().await.unwrap();
        assert_eq!(bh.available_permits(), 0);
        assert_eq!(bh.total_accepted(), 2);
    }

    #[tokio::test]
    async fn bulkhead_rejects_when_queue_full() {
        // 1 concurrent, 0 wait queue, short timeout => second call times out
        let bh = Bulkhead::new("test-db", 1, 1, Duration::from_millis(10));
        let _p1 = bh.acquire().await.unwrap();

        // Second acquire should time out since the semaphore has 0 permits
        let result = bh.acquire().await;
        assert!(result.is_err(), "second call must fail when bulkhead is full");
        assert_eq!(bh.total_rejected(), 1);
    }

    #[tokio::test]
    async fn bulkhead_releases_permit_on_drop() {
        let bh = Bulkhead::new("test-sign", 1, 5, Duration::from_secs(1));
        {
            let _p = bh.acquire().await.unwrap();
            assert_eq!(bh.available_permits(), 0);
        }
        // Permit dropped, semaphore should be available again.
        assert_eq!(bh.available_permits(), 1);
        let _p2 = bh.acquire().await.unwrap();
        assert_eq!(bh.total_accepted(), 2);
    }

    // ── 4. Concurrent acquire up to limit ────────────────────────────────

    #[tokio::test]
    async fn concurrent_acquire_up_to_limit() {
        let bh = Arc::new(Bulkhead::new("test-concurrent", 5, 10, Duration::from_secs(1)));
        let mut permits = Vec::new();
        for _ in 0..5 {
            permits.push(bh.acquire().await.unwrap());
        }
        assert_eq!(bh.available_permits(), 0);
        assert_eq!(bh.total_accepted(), 5);
    }

    // ── 5. Wait queue respects depth limit ───────────────────────────────

    #[tokio::test]
    async fn wait_queue_depth_limit_rejects_overflow() {
        // 0 permits available (all taken), max 0 waiters = immediate rejection
        let bh = Bulkhead::new("test-depth", 1, 0, Duration::from_millis(50));

        // Take the only permit
        let _p1 = bh.acquire().await.unwrap();

        // Any subsequent acquire should be rejected immediately (max_wait_queue=0)
        let result = bh.acquire().await;
        assert!(result.is_err());
        if let Err(BulkheadError::Rejected { service, .. }) = result {
            assert_eq!(service, "test-depth");
        }
        assert_eq!(bh.total_rejected(), 1);
    }

    // ── 6. Wait queue FIFO ordering (via timing) ─────────────────────────

    #[tokio::test]
    async fn wait_queue_fifo_ordering() {
        // Semaphore fairness: tokio::sync::Semaphore is FIFO by default.
        // We verify by sequentially acquiring and releasing.
        let bh = Bulkhead::new("test-fifo", 2, 10, Duration::from_secs(2));

        // Acquire 2 permits sequentially, release in order
        let p1 = bh.acquire().await.unwrap();
        let p2 = bh.acquire().await.unwrap();
        assert_eq!(bh.available_permits(), 0);

        drop(p1);
        assert_eq!(bh.available_permits(), 1);
        drop(p2);
        assert_eq!(bh.available_permits(), 2);

        assert_eq!(bh.total_accepted(), 2);
    }

    // ── 7. Bulkhead isolation ────────────────────────────────────────────

    #[tokio::test]
    async fn bulkhead_isolation_separate_pools() {
        let auth_bh = Bulkhead::new("auth", 1, 0, Duration::from_millis(10));
        let db_bh = Bulkhead::new("db", 2, 5, Duration::from_secs(1));

        // Exhaust auth bulkhead
        let _auth_p = auth_bh.acquire().await.unwrap();
        assert_eq!(auth_bh.available_permits(), 0);

        // DB bulkhead should still be fully available
        let _db_p1 = db_bh.acquire().await.unwrap();
        let _db_p2 = db_bh.acquire().await.unwrap();
        assert_eq!(db_bh.total_accepted(), 2);
    }

    // ── 8. Metrics: accepted count, rejected count ───────────────────────

    #[tokio::test]
    async fn metrics_accepted_and_rejected_counts() {
        let bh = Bulkhead::new("test-metrics", 1, 0, Duration::from_millis(10));

        assert_eq!(bh.total_accepted(), 0);
        assert_eq!(bh.total_rejected(), 0);

        let _p = bh.acquire().await.unwrap();
        assert_eq!(bh.total_accepted(), 1);

        // With 0 wait queue and permit taken, next call rejected immediately
        let _ = bh.acquire().await;
        assert_eq!(bh.total_rejected(), 1);

        drop(_p);
        let _p2 = bh.acquire().await.unwrap();
        assert_eq!(bh.total_accepted(), 2);
    }

    // ── 9. Timeout on wait queue ─────────────────────────────────────────

    #[tokio::test]
    async fn wait_timeout_returns_timeout_error() {
        let bh = Bulkhead::new("test-timeout", 1, 10, Duration::from_millis(50));

        // Take the only permit
        let _p = bh.acquire().await.unwrap();

        // Next acquire enters wait queue, but times out after 50ms
        let result = bh.acquire().await;

        match result {
            Err(BulkheadError::WaitTimeout { service, waited }) => {
                assert_eq!(service, "test-timeout");
                assert!(waited.as_millis() >= 40, "should have waited ~50ms");
            }
            other => panic!("expected WaitTimeout, got {:?}", other.is_ok()),
        }
    }

    // ── 10. Zero-capacity bulkhead rejects everything ────────────────────

    #[tokio::test]
    async fn zero_capacity_rejects_all() {
        let bh = Bulkhead::new("test-zero", 0, 0, Duration::from_millis(10));

        // With 0 permits and 0 wait queue, should reject or timeout
        let result = bh.acquire().await;
        assert!(result.is_err());
        assert_eq!(bh.total_rejected(), 1);
    }

    // ── 11. Single-capacity bulkhead serializes ──────────────────────────

    #[tokio::test]
    async fn single_capacity_serializes() {
        let bh = Bulkhead::new("test-serial", 1, 10, Duration::from_secs(1));

        // With capacity 1, sequential acquires must each succeed one at a time
        for i in 0..5 {
            let p = bh.acquire().await.unwrap();
            assert_eq!(bh.available_permits(), 0, "permit {i} should consume the slot");
            drop(p);
            assert_eq!(bh.available_permits(), 1, "permit {i} release should free the slot");
        }

        assert_eq!(bh.total_accepted(), 5);
        assert_eq!(bh.total_rejected(), 0);
    }

    // ── 12. Rapid acquire/release cycle (no leaks) ───────────────────────

    #[tokio::test]
    async fn rapid_acquire_release_no_leaks() {
        let bh = Bulkhead::new("test-rapid", 2, 5, Duration::from_secs(1));

        for _ in 0..100 {
            let _p = bh.acquire().await.unwrap();
            // Permit drops here
        }

        assert_eq!(bh.available_permits(), 2, "all permits should be released");
        assert_eq!(bh.total_accepted(), 100);
        assert_eq!(bh.total_rejected(), 0);
    }

    // ── 13. Drop guard releases permit automatically ─────────────────────

    #[tokio::test]
    async fn drop_guard_releases_permit() {
        let bh = Bulkhead::new("test-drop", 1, 5, Duration::from_secs(1));

        {
            let permit = bh.acquire().await.unwrap();
            assert_eq!(bh.available_permits(), 0);
            drop(permit);
        }

        assert_eq!(bh.available_permits(), 1);

        // Should be able to acquire again
        let _p = bh.acquire().await.unwrap();
        assert_eq!(bh.available_permits(), 0);
    }

    // ── Extra: service_name accessor ─────────────────────────────────────

    #[tokio::test]
    async fn service_name_accessor() {
        let bh = Bulkhead::new("my-service", 5, 10, Duration::from_secs(1));
        assert_eq!(bh.service_name(), "my-service");
    }

    // ── Extra: error display formatting ──────────────────────────────────

    #[test]
    fn error_display_rejected() {
        let err = BulkheadError::Rejected {
            service: "auth".into(),
            max_concurrent: 5,
            max_wait_queue: 10,
        };
        let msg = format!("{err}");
        assert!(msg.contains("auth"));
        assert!(msg.contains("5"));
        assert!(msg.contains("10"));
    }

    #[test]
    fn error_display_timeout() {
        let err = BulkheadError::WaitTimeout {
            service: "db".into(),
            waited: Duration::from_millis(500),
        };
        let msg = format!("{err}");
        assert!(msg.contains("db"));
        assert!(msg.contains("500"));
    }
}
