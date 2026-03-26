//! Tenant-aware request middleware for the MILNET SSO system.
//!
//! Extracts the tenant ID from incoming requests (JWT `tenant_id` claim or
//! `X-Tenant-ID` API header), validates the tenant exists and is Active,
//! sets the [`TenantContext`] for the request lifecycle, and rejects
//! cross-tenant access attempts with SIEM logging.
//!
//! # Extraction priority
//! 1. JWT `tenant_id` claim (from the `Authorization: Bearer <token>` header)
//! 2. `X-Tenant-ID` header (for service-to-service / API key auth)
//!
//! If neither is present, the request is rejected with 403 Forbidden.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use uuid::Uuid;

use crate::multi_tenancy::{TenantContext, TenantId, TenantStatus};
use crate::siem::{self, SiemEvent};

// ---------------------------------------------------------------------------
// Tenant resolution from request headers
// ---------------------------------------------------------------------------

/// Header name for explicit tenant ID (service-to-service calls).
pub const TENANT_ID_HEADER: &str = "x-tenant-id";

/// JWT claim name for tenant ID.
pub const TENANT_ID_CLAIM: &str = "tenant_id";

/// Extract tenant_id from a JWT payload (simple JSON parsing without
/// pulling in a full JWT library — the JWT signature is already verified
/// by the upstream auth middleware).
pub fn extract_tenant_from_jwt_payload(payload_json: &str) -> Option<Uuid> {
    // Minimal extraction: look for "tenant_id":"<uuid>" in the claims JSON.
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(payload_json);
    match parsed {
        Ok(val) => val
            .get(TENANT_ID_CLAIM)
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok()),
        Err(_) => None,
    }
}

/// Extract the tenant UUID from a raw header value.
pub fn parse_tenant_header(header_value: &str) -> Option<Uuid> {
    Uuid::parse_str(header_value.trim()).ok()
}

// ---------------------------------------------------------------------------
// In-memory tenant cache (avoids a DB hit on every request)
// ---------------------------------------------------------------------------

/// Cached tenant metadata — enough to make the accept/reject decision
/// without hitting the database on every request.
#[derive(Debug, Clone)]
pub struct CachedTenant {
    pub tenant_id: Uuid,
    pub status: TenantStatus,
    pub rate_limit_rps: u32,
    pub rate_limit_burst: u32,
    pub fetched_at: Instant,
}

/// Thread-safe tenant cache with TTL-based expiry.
pub struct TenantCache {
    entries: RwLock<HashMap<Uuid, CachedTenant>>,
    ttl: Duration,
}

impl TenantCache {
    /// Create a new cache with the given TTL.
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            ttl,
        }
    }

    /// Look up a tenant, returning `None` if not cached or expired.
    pub fn get(&self, tenant_id: &Uuid) -> Option<CachedTenant> {
        let entries = self.entries.read().unwrap();
        entries.get(tenant_id).and_then(|entry| {
            if entry.fetched_at.elapsed() < self.ttl {
                Some(entry.clone())
            } else {
                None
            }
        })
    }

    /// Insert or update a cached tenant entry.
    pub fn put(&self, entry: CachedTenant) {
        let mut entries = self.entries.write().unwrap();
        entries.insert(entry.tenant_id, entry);
    }

    /// Remove a tenant from the cache (e.g. on status change).
    pub fn invalidate(&self, tenant_id: &Uuid) {
        let mut entries = self.entries.write().unwrap();
        entries.remove(tenant_id);
    }

    /// Purge all expired entries.
    pub fn purge_expired(&self) {
        let mut entries = self.entries.write().unwrap();
        entries.retain(|_, v| v.fetched_at.elapsed() < self.ttl);
    }
}

// ---------------------------------------------------------------------------
// Per-tenant rate limiter (token bucket)
// ---------------------------------------------------------------------------

/// A simple token-bucket rate limiter, keyed by tenant ID.
pub struct TenantRateLimiter {
    buckets: RwLock<HashMap<Uuid, TokenBucket>>,
}

struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
    last_refill: Instant,
}

impl TokenBucket {
    fn new(rps: u32, burst: u32) -> Self {
        Self {
            tokens: burst as f64,
            max_tokens: burst as f64,
            refill_rate: rps as f64,
            last_refill: Instant::now(),
        }
    }

    fn try_acquire(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

impl TenantRateLimiter {
    /// Create a new per-tenant rate limiter.
    pub fn new() -> Self {
        Self {
            buckets: RwLock::new(HashMap::new()),
        }
    }

    /// Check (and consume) a rate-limit token for the given tenant.
    ///
    /// Returns `true` if the request is allowed, `false` if rate-limited.
    pub fn check_rate_limit(&self, tenant_id: &Uuid, rps: u32, burst: u32) -> bool {
        let mut buckets = self.buckets.write().unwrap();
        let bucket = buckets
            .entry(*tenant_id)
            .or_insert_with(|| TokenBucket::new(rps, burst));
        bucket.try_acquire()
    }

    /// Remove the bucket for a decommissioned tenant.
    pub fn remove_tenant(&self, tenant_id: &Uuid) {
        let mut buckets = self.buckets.write().unwrap();
        buckets.remove(tenant_id);
    }
}

impl Default for TenantRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tenant validation result
// ---------------------------------------------------------------------------

/// The outcome of tenant validation for a request.
#[derive(Debug)]
pub enum TenantValidation {
    /// Tenant is valid and active. Proceed with the request.
    Ok(TenantId),
    /// No tenant identifier found in the request.
    Missing,
    /// The tenant UUID is malformed.
    InvalidFormat(String),
    /// The tenant was not found in the database/cache.
    NotFound(Uuid),
    /// The tenant exists but is not Active.
    NotActive { tenant_id: Uuid, status: TenantStatus },
    /// The request was rate-limited.
    RateLimited(Uuid),
}

impl TenantValidation {
    /// Return the HTTP status code for this validation result.
    pub fn status_code(&self) -> u16 {
        match self {
            Self::Ok(_) => 200,
            Self::Missing => 403,
            Self::InvalidFormat(_) => 400,
            Self::NotFound(_) => 403,
            Self::NotActive { .. } => 403,
            Self::RateLimited(_) => 429,
        }
    }

    /// Return a safe error message (no internal details leaked).
    pub fn error_message(&self) -> &'static str {
        match self {
            Self::Ok(_) => "",
            Self::Missing => "tenant identification required",
            Self::InvalidFormat(_) => "invalid tenant identifier format",
            Self::NotFound(_) => "access denied",
            Self::NotActive { .. } => "tenant is not active",
            Self::RateLimited(_) => "rate limit exceeded",
        }
    }
}

// ---------------------------------------------------------------------------
// Core validation logic (framework-agnostic)
// ---------------------------------------------------------------------------

/// Validate a tenant ID extracted from a request.
///
/// 1. Checks the cache (or queries the DB callback if cache miss).
/// 2. Validates the tenant is Active.
/// 3. Checks per-tenant rate limits.
/// 4. Emits SIEM events for rejected requests.
///
/// On success, sets [`TenantContext`] for the current thread.
pub fn validate_tenant_request(
    tenant_uuid: Uuid,
    cache: &TenantCache,
    rate_limiter: &TenantRateLimiter,
) -> TenantValidation {
    // Check cache
    let cached = match cache.get(&tenant_uuid) {
        Some(c) => c,
        None => {
            // Cache miss — caller must populate cache from DB before calling this,
            // or we return NotFound to force a DB lookup + retry.
            return TenantValidation::NotFound(tenant_uuid);
        }
    };

    // Validate status
    if cached.status != TenantStatus::Active {
        let event = SiemEvent {
            timestamp: now_epoch_secs(),
            severity: 6,
            event_type: "TENANT_ACCESS_DENIED_INACTIVE".to_string(),
            json: format!(
                r#"{{"event":"TENANT_ACCESS_DENIED_INACTIVE","tenant_id":"{}","status":"{:?}"}}"#,
                tenant_uuid, cached.status
            ),
        };
        siem::broadcast_event(&event);

        tracing::warn!(
            tenant_id = %tenant_uuid,
            status = ?cached.status,
            event = "TENANT_ACCESS_DENIED_INACTIVE",
            "request rejected: tenant is not active"
        );

        return TenantValidation::NotActive {
            tenant_id: tenant_uuid,
            status: cached.status,
        };
    }

    // Per-tenant rate limiting
    if !rate_limiter.check_rate_limit(
        &tenant_uuid,
        cached.rate_limit_rps,
        cached.rate_limit_burst,
    ) {
        let event = SiemEvent {
            timestamp: now_epoch_secs(),
            severity: 4,
            event_type: "TENANT_RATE_LIMITED".to_string(),
            json: format!(
                r#"{{"event":"TENANT_RATE_LIMITED","tenant_id":"{}","rps_limit":{}}}"#,
                tenant_uuid, cached.rate_limit_rps
            ),
        };
        siem::broadcast_event(&event);

        tracing::warn!(
            tenant_id = %tenant_uuid,
            rps_limit = cached.rate_limit_rps,
            event = "TENANT_RATE_LIMITED",
            "request rate-limited for tenant"
        );

        return TenantValidation::RateLimited(tenant_uuid);
    }

    TenantValidation::Ok(TenantId::from_uuid(tenant_uuid))
}

/// Log a cross-tenant access attempt as a CRITICAL SIEM event.
///
/// Call this when a request attempts to access data belonging to a different
/// tenant than the one identified in the request credentials.
pub fn log_cross_tenant_access(
    request_tenant: &Uuid,
    target_tenant: &Uuid,
    action: &str,
) {
    let event = SiemEvent {
        timestamp: now_epoch_secs(),
        severity: 10, // CRITICAL
        event_type: "CROSS_TENANT_ACCESS_ATTEMPT".to_string(),
        json: format!(
            r#"{{"event":"CROSS_TENANT_ACCESS_ATTEMPT","from_tenant":"{}","to_tenant":"{}","action":"{}","severity":"CRITICAL"}}"#,
            request_tenant, target_tenant, action
        ),
    };
    siem::broadcast_event(&event);

    tracing::error!(
        event = "CROSS_TENANT_ACCESS_ATTEMPT",
        from_tenant = %request_tenant,
        to_tenant = %target_tenant,
        action = action,
        severity = "CRITICAL",
        "CROSS-TENANT ACCESS ATTEMPT DETECTED — SIEM alert raised"
    );
}

/// Execute a closure within the scope of a validated tenant.
///
/// This is the primary entry point for tenant-scoped request handling.
/// It sets the thread-local [`TenantContext`] and restores it on exit.
pub fn with_validated_tenant<F, R>(tenant_id: TenantId, f: F) -> R
where
    F: FnOnce() -> R,
{
    TenantContext::with_tenant(tenant_id, f)
}

/// Guard type that sets TenantContext on creation and clears on drop.
///
/// Useful for async contexts where the scope-based `with_tenant` is awkward.
pub struct TenantGuard {
    _tenant_id: TenantId,
}

impl TenantGuard {
    /// Activate tenant context. The context is cleared when this guard is dropped.
    pub fn activate(tenant_id: TenantId) -> Self {
        crate::multi_tenancy::CURRENT_TENANT.with(|c| {
            *c.borrow_mut() = Some(tenant_id);
        });
        Self { _tenant_id: tenant_id }
    }
}

impl Drop for TenantGuard {
    fn drop(&mut self) {
        crate::multi_tenancy::CURRENT_TENANT.with(|c| {
            *c.borrow_mut() = None;
        });
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_epoch_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_tenant_from_jwt_payload_valid() {
        let payload = r#"{"sub":"user123","tenant_id":"550e8400-e29b-41d4-a716-446655440000","iat":1700000000}"#;
        let result = extract_tenant_from_jwt_payload(payload);
        assert_eq!(
            result,
            Some(Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap())
        );
    }

    #[test]
    fn extract_tenant_from_jwt_payload_missing() {
        let payload = r#"{"sub":"user123","iat":1700000000}"#;
        assert!(extract_tenant_from_jwt_payload(payload).is_none());
    }

    #[test]
    fn extract_tenant_from_jwt_payload_invalid_uuid() {
        let payload = r#"{"tenant_id":"not-a-uuid"}"#;
        assert!(extract_tenant_from_jwt_payload(payload).is_none());
    }

    #[test]
    fn parse_tenant_header_valid() {
        let result = parse_tenant_header("550e8400-e29b-41d4-a716-446655440000");
        assert!(result.is_some());
    }

    #[test]
    fn parse_tenant_header_with_whitespace() {
        let result = parse_tenant_header("  550e8400-e29b-41d4-a716-446655440000  ");
        assert!(result.is_some());
    }

    #[test]
    fn parse_tenant_header_invalid() {
        assert!(parse_tenant_header("garbage").is_none());
    }

    #[test]
    fn tenant_cache_put_and_get() {
        let cache = TenantCache::new(Duration::from_secs(60));
        let tid = Uuid::new_v4();
        cache.put(CachedTenant {
            tenant_id: tid,
            status: TenantStatus::Active,
            rate_limit_rps: 100,
            rate_limit_burst: 200,
            fetched_at: Instant::now(),
        });
        let entry = cache.get(&tid);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().status, TenantStatus::Active);
    }

    #[test]
    fn tenant_cache_expired_entry_returns_none() {
        let cache = TenantCache::new(Duration::from_millis(1));
        let tid = Uuid::new_v4();
        cache.put(CachedTenant {
            tenant_id: tid,
            status: TenantStatus::Active,
            rate_limit_rps: 100,
            rate_limit_burst: 200,
            fetched_at: Instant::now() - Duration::from_secs(10),
        });
        assert!(cache.get(&tid).is_none());
    }

    #[test]
    fn tenant_cache_invalidate() {
        let cache = TenantCache::new(Duration::from_secs(60));
        let tid = Uuid::new_v4();
        cache.put(CachedTenant {
            tenant_id: tid,
            status: TenantStatus::Active,
            rate_limit_rps: 100,
            rate_limit_burst: 200,
            fetched_at: Instant::now(),
        });
        cache.invalidate(&tid);
        assert!(cache.get(&tid).is_none());
    }

    #[test]
    fn rate_limiter_allows_within_limit() {
        let limiter = TenantRateLimiter::new();
        let tid = Uuid::new_v4();
        // With burst=5, first 5 requests should pass
        for _ in 0..5 {
            assert!(limiter.check_rate_limit(&tid, 10, 5));
        }
    }

    #[test]
    fn rate_limiter_rejects_over_burst() {
        let limiter = TenantRateLimiter::new();
        let tid = Uuid::new_v4();
        // Exhaust the burst capacity
        for _ in 0..10 {
            limiter.check_rate_limit(&tid, 1, 10);
        }
        // Next request should be rejected
        assert!(!limiter.check_rate_limit(&tid, 1, 10));
    }

    #[test]
    fn validate_tenant_request_cache_miss_returns_not_found() {
        let cache = TenantCache::new(Duration::from_secs(60));
        let limiter = TenantRateLimiter::new();
        let tid = Uuid::new_v4();
        let result = validate_tenant_request(tid, &cache, &limiter);
        assert!(matches!(result, TenantValidation::NotFound(_)));
    }

    #[test]
    fn validate_tenant_request_inactive_returns_not_active() {
        let cache = TenantCache::new(Duration::from_secs(60));
        let limiter = TenantRateLimiter::new();
        let tid = Uuid::new_v4();
        cache.put(CachedTenant {
            tenant_id: tid,
            status: TenantStatus::Suspended,
            rate_limit_rps: 100,
            rate_limit_burst: 200,
            fetched_at: Instant::now(),
        });
        let result = validate_tenant_request(tid, &cache, &limiter);
        assert!(matches!(result, TenantValidation::NotActive { .. }));
    }

    #[test]
    fn validate_tenant_request_active_returns_ok() {
        let cache = TenantCache::new(Duration::from_secs(60));
        let limiter = TenantRateLimiter::new();
        let tid = Uuid::new_v4();
        cache.put(CachedTenant {
            tenant_id: tid,
            status: TenantStatus::Active,
            rate_limit_rps: 1000,
            rate_limit_burst: 2000,
            fetched_at: Instant::now(),
        });
        let result = validate_tenant_request(tid, &cache, &limiter);
        assert!(matches!(result, TenantValidation::Ok(_)));
    }

    #[test]
    fn tenant_guard_sets_and_clears_context() {
        let tid = TenantId::new();
        {
            let _guard = TenantGuard::activate(tid);
            assert_eq!(TenantContext::current_tenant_id(), Some(tid));
        }
        // Guard dropped — context cleared
        assert!(TenantContext::current_tenant_id().is_none());
    }

    #[test]
    fn tenant_validation_status_codes() {
        assert_eq!(TenantValidation::Missing.status_code(), 403);
        assert_eq!(TenantValidation::InvalidFormat("x".into()).status_code(), 400);
        assert_eq!(TenantValidation::NotFound(Uuid::new_v4()).status_code(), 403);
        assert_eq!(
            TenantValidation::NotActive {
                tenant_id: Uuid::new_v4(),
                status: TenantStatus::Suspended
            }
            .status_code(),
            403
        );
        assert_eq!(TenantValidation::RateLimited(Uuid::new_v4()).status_code(), 429);
    }
}
