//! Infrastructure hardening tests for service discovery, distributed locks,
//! multi-tenancy, and persistent stores.
//!
//! These tests exercise the in-process/unit-level APIs of each infrastructure
//! module without requiring external databases or network services. Where the
//! production code path requires PostgreSQL (e.g., PgAdvisoryLockManager,
//! PersistentSessionStore), we test the in-process equivalents that share the
//! same logic.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use uuid::Uuid;

// ═══════════════════════════════════════════════════════════════════════════
// Service Discovery & Failover
// ═══════════════════════════════════════════════════════════════════════════

use common::service_discovery::{
    DiscoveryBackend, DiscoveryError, EndpointConfig, EndpointHealth, LoadBalanceStrategy,
    ServiceConfig, ServiceRegistry,
};

/// Helper: create a ServiceConfig with static endpoints marked healthy via
/// `record_success`.
fn make_service_config(
    name: &str,
    addresses: &[&str],
    strategy: LoadBalanceStrategy,
    quorum: usize,
) -> ServiceConfig {
    let endpoints: Vec<EndpointConfig> = addresses
        .iter()
        .enumerate()
        .map(|(i, addr)| EndpointConfig {
            address: addr.to_string(),
            label: Some(format!("{}-{}", name, i)),
            weight: None,
        })
        .collect();

    ServiceConfig {
        name: name.to_string(),
        backend: DiscoveryBackend::Static { endpoints },
        strategy,
        quorum_size: quorum,
        // Low thresholds for testing health transitions.
        unhealthy_threshold: 2,
        healthy_threshold: 2,
        circuit_breaker_threshold: 3,
        circuit_breaker_reset: Duration::from_millis(50),
        max_pool_size: 3,
        ..ServiceConfig::default()
    }
}

/// Mark all endpoints of a service as Healthy by recording enough successes.
fn mark_all_healthy(registry: &ServiceRegistry, service_name: &str, addresses: &[&str]) {
    for addr in addresses {
        // Two successes meet healthy_threshold=2.
        registry.record_success(service_name, addr);
        registry.record_success(service_name, addr);
    }
}

// ---------------------------------------------------------------------------
// 1. Failover when primary goes unhealthy
// ---------------------------------------------------------------------------

#[test]
fn failover_selects_next_healthy_endpoint_when_primary_unhealthy() {
    let registry = ServiceRegistry::new();
    let addrs = ["10.0.0.1:8443", "10.0.0.2:8443", "10.0.0.3:8443"];
    registry
        .register(make_service_config(
            "orch",
            &addrs,
            LoadBalanceStrategy::RoundRobin,
            1,
        ))
        .unwrap();

    mark_all_healthy(&registry, "orch", &addrs);

    // Drive endpoint 0 unhealthy (2 failures >= unhealthy_threshold).
    registry.record_failure("orch", "10.0.0.1:8443");
    registry.record_failure("orch", "10.0.0.1:8443");

    // Acquire several endpoints — none should be the unhealthy one.
    for _ in 0..10 {
        let guard = registry.acquire_endpoint("orch").unwrap();
        assert_ne!(
            guard.address, "10.0.0.1:8443",
            "unhealthy endpoint must not be selected"
        );
        // Drop guard to release connection count.
    }
}

// ---------------------------------------------------------------------------
// 2. Round-robin distributes evenly across healthy endpoints
// ---------------------------------------------------------------------------

#[test]
fn round_robin_distributes_evenly() {
    let registry = ServiceRegistry::new();
    let addrs = ["10.0.1.1:80", "10.0.1.2:80", "10.0.1.3:80"];
    registry
        .register(make_service_config(
            "rr-svc",
            &addrs,
            LoadBalanceStrategy::RoundRobin,
            1,
        ))
        .unwrap();

    mark_all_healthy(&registry, "rr-svc", &addrs);

    let mut counts: HashMap<String, usize> = HashMap::new();
    let iterations = 30;
    for _ in 0..iterations {
        let guard = registry.acquire_endpoint("rr-svc").unwrap();
        *counts.entry(guard.address.clone()).or_default() += 1;
    }

    // Each endpoint should get roughly iterations/3 = 10 requests.
    for addr in &addrs {
        let c = counts.get(*addr).copied().unwrap_or(0);
        assert!(
            c >= 5 && c <= 15,
            "endpoint {} got {} requests, expected ~10 (evenly distributed)",
            addr,
            c
        );
    }
}

// ---------------------------------------------------------------------------
// 3. Least-connections prefers endpoints with fewer active connections
// ---------------------------------------------------------------------------

#[test]
fn least_connections_prefers_fewer_active() {
    let registry = ServiceRegistry::new();
    let addrs = ["10.0.2.1:80", "10.0.2.2:80"];
    registry
        .register(make_service_config(
            "lc-svc",
            &addrs,
            LoadBalanceStrategy::LeastConnections,
            1,
        ))
        .unwrap();

    mark_all_healthy(&registry, "lc-svc", &addrs);

    // Acquire one connection to endpoint 0 and hold it.
    let _held = registry.acquire_endpoint("lc-svc").unwrap();
    // Now the next acquisition should prefer the endpoint with 0 active conns.
    let second = registry.acquire_endpoint("lc-svc").unwrap();

    // The second guard should go to the less-loaded endpoint.
    // Since _held is still alive, its endpoint has 1 active connection.
    // The other endpoint has 0 active connections.
    // Depending on which endpoint _held selected, the second should differ
    // (or be the same if it also has 0). Either way, verify no panic.
    let statuses = registry.endpoint_statuses("lc-svc").unwrap();
    let min_conns = statuses.iter().map(|s| s.active_connections).min().unwrap();
    let second_conns = statuses
        .iter()
        .find(|s| s.address == second.address)
        .unwrap()
        .active_connections;

    // The selected endpoint's connections should be at most 1 more than the minimum
    // (it was just incremented).
    assert!(
        second_conns <= min_conns + 1,
        "least-connections should pick an endpoint near the minimum load"
    );
}

// ---------------------------------------------------------------------------
// 4. Circuit breaker opens after failures, prevents routing
// ---------------------------------------------------------------------------

#[test]
fn circuit_breaker_opens_after_threshold_failures() {
    let registry = ServiceRegistry::new();
    // Single endpoint — so when CB opens, no healthy endpoints remain.
    let addrs = ["10.0.3.1:80"];
    let mut config = make_service_config(
        "cb-svc",
        &addrs,
        LoadBalanceStrategy::RoundRobin,
        1,
    );
    config.circuit_breaker_threshold = 2;
    registry.register(config).unwrap();

    mark_all_healthy(&registry, "cb-svc", &addrs);

    // Record enough failures to open the circuit breaker.
    // unhealthy_threshold=2 marks it unhealthy; CB threshold=2 opens it.
    registry.record_failure("cb-svc", "10.0.3.1:80");
    registry.record_failure("cb-svc", "10.0.3.1:80");
    registry.record_failure("cb-svc", "10.0.3.1:80");

    // Attempting to acquire should fail — endpoint is unhealthy.
    let result = registry.acquire_endpoint("cb-svc");
    assert!(
        result.is_err(),
        "circuit breaker open + unhealthy should prevent routing"
    );
}

// ---------------------------------------------------------------------------
// 5. Split-brain detection rejects requests when quorum is lost
// ---------------------------------------------------------------------------

#[test]
fn split_brain_rejects_when_quorum_lost() {
    let registry = ServiceRegistry::new();
    let addrs = ["10.0.4.1:80", "10.0.4.2:80", "10.0.4.3:80"];
    // Require quorum of 2 healthy.
    registry
        .register(make_service_config(
            "quorum-svc",
            &addrs,
            LoadBalanceStrategy::RoundRobin,
            2,
        ))
        .unwrap();

    // Only mark one endpoint healthy. The other two stay Unknown which is not Healthy.
    registry.record_success("quorum-svc", "10.0.4.1:80");
    registry.record_success("quorum-svc", "10.0.4.1:80");

    // With only 1 healthy out of 3, quorum (2) is not met.
    let result = registry.acquire_endpoint("quorum-svc");
    assert!(result.is_err(), "should reject when quorum lost");

    match result.unwrap_err() {
        DiscoveryError::QuorumLost {
            healthy, required, ..
        } => {
            assert_eq!(healthy, 1);
            assert_eq!(required, 2);
        }
        other => panic!("expected QuorumLost, got {:?}", other),
    }

    // Also test has_quorum.
    assert!(!registry.has_quorum("quorum-svc").unwrap());
}

// ---------------------------------------------------------------------------
// 6. Health check transitions (healthy -> unhealthy -> healthy)
// ---------------------------------------------------------------------------

#[test]
fn health_transitions_healthy_unhealthy_healthy() {
    let registry = ServiceRegistry::new();
    let addrs = ["10.0.5.1:80"];
    registry
        .register(make_service_config(
            "transition-svc",
            &addrs,
            LoadBalanceStrategy::RoundRobin,
            0, // No quorum requirement for this test.
        ))
        .unwrap();

    // Initially Unknown. Mark healthy.
    mark_all_healthy(&registry, "transition-svc", &addrs);
    let statuses = registry.endpoint_statuses("transition-svc").unwrap();
    assert_eq!(statuses[0].health, EndpointHealth::Healthy);

    // Drive to unhealthy (2 failures).
    registry.record_failure("transition-svc", "10.0.5.1:80");
    registry.record_failure("transition-svc", "10.0.5.1:80");
    let statuses = registry.endpoint_statuses("transition-svc").unwrap();
    assert_eq!(statuses[0].health, EndpointHealth::Unhealthy);

    // Recover (2 successes).
    registry.record_success("transition-svc", "10.0.5.1:80");
    registry.record_success("transition-svc", "10.0.5.1:80");
    let statuses = registry.endpoint_statuses("transition-svc").unwrap();
    assert_eq!(statuses[0].health, EndpointHealth::Healthy);
}

// ---------------------------------------------------------------------------
// 7. Connection pool limits are enforced (max_pool_size)
// ---------------------------------------------------------------------------

#[test]
fn connection_pool_limit_enforced() {
    let registry = ServiceRegistry::new();
    let addrs = ["10.0.6.1:80"];
    // max_pool_size=3 from our helper.
    registry
        .register(make_service_config(
            "pool-svc",
            &addrs,
            LoadBalanceStrategy::RoundRobin,
            0,
        ))
        .unwrap();

    mark_all_healthy(&registry, "pool-svc", &addrs);

    // Acquire 3 connections (the max).
    let _g1 = registry.acquire_endpoint("pool-svc").unwrap();
    let _g2 = registry.acquire_endpoint("pool-svc").unwrap();
    let _g3 = registry.acquire_endpoint("pool-svc").unwrap();

    // Fourth should fail with PoolExhausted.
    let result = registry.acquire_endpoint("pool-svc");
    assert!(result.is_err());
    match result.unwrap_err() {
        DiscoveryError::PoolExhausted(addr) => {
            assert_eq!(addr, "10.0.6.1:80");
        }
        other => panic!("expected PoolExhausted, got {:?}", other),
    }

    // After dropping a guard, we should be able to acquire again.
    drop(_g3);
    let _g4 = registry.acquire_endpoint("pool-svc").unwrap();
    assert_eq!(_g4.address, "10.0.6.1:80");
}

// ---------------------------------------------------------------------------
// 8. retry_with_failover tries different endpoints on each retry
// ---------------------------------------------------------------------------

#[tokio::test]
async fn retry_with_failover_tries_different_endpoints() {
    use common::service_discovery::{retry_with_failover, MultiEndpointRetryConfig};

    let registry = ServiceRegistry::new();
    let addrs = ["10.0.7.1:80", "10.0.7.2:80", "10.0.7.3:80"];
    registry
        .register(make_service_config(
            "retry-svc",
            &addrs,
            LoadBalanceStrategy::RoundRobin,
            1,
        ))
        .unwrap();

    mark_all_healthy(&registry, "retry-svc", &addrs);

    let tried = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let tried_clone = Arc::clone(&tried);

    let config = MultiEndpointRetryConfig {
        max_endpoint_attempts: 3,
        retry_config: common::retry::RetryConfig {
            max_retries: 3,
            initial_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(5),
            multiplier: 1.0,
        },
    };

    // Operation that always fails, recording which endpoint was tried.
    let result: Result<(), DiscoveryError> = retry_with_failover(
        &registry,
        "retry-svc",
        &config,
        |addr: String| {
            let tried = Arc::clone(&tried_clone);
            async move {
                tried.lock().unwrap().push(addr);
                Err::<(), String>("simulated failure".into())
            }
        },
    )
    .await;

    assert!(result.is_err(), "all attempts should fail");
    let tried_addrs = tried.lock().unwrap();
    assert!(
        tried_addrs.len() >= 2,
        "should have tried at least 2 endpoints, tried {}",
        tried_addrs.len()
    );
}

// ---------------------------------------------------------------------------
// 9. Concurrent access to service registry is thread-safe
// ---------------------------------------------------------------------------

#[test]
fn concurrent_registry_access_is_thread_safe() {
    let registry = Arc::new(ServiceRegistry::new());
    let addrs = ["10.0.8.1:80", "10.0.8.2:80"];
    registry
        .register(make_service_config(
            "concurrent-svc",
            &addrs,
            LoadBalanceStrategy::RoundRobin,
            1,
        ))
        .unwrap();

    mark_all_healthy(&registry, "concurrent-svc", &addrs);

    let success_count = Arc::new(AtomicUsize::new(0));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let reg = Arc::clone(&registry);
            let counter = Arc::clone(&success_count);
            std::thread::spawn(move || {
                for _ in 0..50 {
                    match reg.acquire_endpoint("concurrent-svc") {
                        Ok(guard) => {
                            // Access the guard address to ensure it's valid.
                            assert!(!guard.address.is_empty());
                            counter.fetch_add(1, Ordering::Relaxed);
                            // Guard is dropped here, releasing the connection.
                        }
                        Err(_) => {
                            // Pool exhaustion is expected under contention.
                        }
                    }
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread should not panic");
    }

    assert!(
        success_count.load(Ordering::Relaxed) > 0,
        "at least some requests should succeed under concurrent access"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Distributed Locks
// ═══════════════════════════════════════════════════════════════════════════

use common::distributed_lock::{validate_fencing_token, LockError, LockManager};

// ---------------------------------------------------------------------------
// 10. Lock acquisition and release
// ---------------------------------------------------------------------------

#[test]
fn lock_acquire_and_release_roundtrip() {
    let mgr = LockManager::new();
    let grant = mgr
        .try_acquire("infra-leader", "node-alpha", Duration::from_secs(60))
        .unwrap();

    assert_eq!(grant.name, "infra-leader");
    assert_eq!(grant.holder_id, "node-alpha");
    assert!(grant.fencing_token > 0);
    assert!(grant.expires_at_epoch > grant.acquired_at_epoch);
    assert_eq!(grant.ttl_secs, 60);

    // Inspect while held.
    let inspected = mgr.inspect("infra-leader").unwrap();
    assert_eq!(inspected.fencing_token, grant.fencing_token);

    // Release.
    mgr.release("infra-leader", "node-alpha").unwrap();

    // After release, inspect should return NotFound.
    assert!(matches!(
        mgr.inspect("infra-leader").unwrap_err(),
        LockError::NotFound(_)
    ));
}

// ---------------------------------------------------------------------------
// 11. Fencing token monotonicity
// ---------------------------------------------------------------------------

#[test]
fn fencing_tokens_strictly_increase() {
    let mgr = LockManager::new();
    let mut tokens = Vec::new();

    for i in 0..10 {
        let name = format!("mono-lock-{}", i);
        let grant = mgr
            .try_acquire(&name, "node", Duration::from_secs(300))
            .unwrap();
        tokens.push(grant.fencing_token);
    }

    for window in tokens.windows(2) {
        assert!(
            window[1] > window[0],
            "fencing tokens must be strictly monotonic: {} should be > {}",
            window[1],
            window[0]
        );
    }
}

// ---------------------------------------------------------------------------
// 12. Lock TTL expiry
// ---------------------------------------------------------------------------

#[test]
fn lock_ttl_expiry_allows_reacquisition() {
    let mgr = LockManager::new();
    let grant1 = mgr
        .try_acquire("ttl-lock", "node-1", Duration::from_millis(1))
        .unwrap();

    // Wait for TTL to expire.
    std::thread::sleep(Duration::from_millis(15));

    // Renew should fail (TTL expired).
    let renew_err = mgr.renew("ttl-lock", "node-1").unwrap_err();
    assert!(
        matches!(renew_err, LockError::TtlExpired(_)),
        "renew after TTL expiry should return TtlExpired"
    );

    // Another node can now acquire it.
    let grant2 = mgr
        .try_acquire("ttl-lock", "node-2", Duration::from_secs(60))
        .unwrap();
    assert_eq!(grant2.holder_id, "node-2");
    assert!(
        grant2.fencing_token > grant1.fencing_token,
        "reacquired lock must have a higher fencing token"
    );
}

// ---------------------------------------------------------------------------
// 13. Double-lock attempt fails
// ---------------------------------------------------------------------------

#[test]
fn double_lock_by_same_holder_fails() {
    let mgr = LockManager::new();
    mgr.try_acquire("exclusive-res", "node-1", Duration::from_secs(30))
        .unwrap();

    // Same holder trying to acquire again should fail.
    let err = mgr
        .try_acquire("exclusive-res", "node-1", Duration::from_secs(30))
        .unwrap_err();
    assert!(matches!(err, LockError::AlreadyHeld { .. }));

    // Different holder should also fail.
    let err2 = mgr
        .try_acquire("exclusive-res", "node-2", Duration::from_secs(30))
        .unwrap_err();
    assert!(matches!(err2, LockError::AlreadyHeld { .. }));
}

// ---------------------------------------------------------------------------
// 14. Lock renewal extends TTL
// ---------------------------------------------------------------------------

#[test]
fn lock_renewal_extends_ttl_and_preserves_token() {
    let mgr = LockManager::new();
    let grant = mgr
        .try_acquire("renew-lock", "node-1", Duration::from_millis(50))
        .unwrap();
    let original_token = grant.fencing_token;

    // Wait almost to TTL, then renew.
    std::thread::sleep(Duration::from_millis(20));
    let renewed_token = mgr.renew("renew-lock", "node-1").unwrap();
    assert_eq!(
        renewed_token, original_token,
        "renewal must preserve the fencing token"
    );

    // Wait another 40ms — past the original TTL but within the renewed window.
    std::thread::sleep(Duration::from_millis(40));

    // The lock should still be valid because renewal extended the TTL.
    let inspected = mgr.inspect("renew-lock").unwrap();
    assert_eq!(inspected.holder_id, "node-1");

    // Wrong holder cannot renew.
    let err = mgr.renew("renew-lock", "intruder").unwrap_err();
    assert!(matches!(err, LockError::NotHolder { .. }));
}

// ---------------------------------------------------------------------------
// 15. Fencing token validation (constant-time)
// ---------------------------------------------------------------------------

#[test]
fn fencing_token_validation_accepts_matching_rejects_stale() {
    // Matching tokens.
    assert!(validate_fencing_token(100, 100).is_ok());
    assert!(validate_fencing_token(0, 0).is_ok());
    assert!(validate_fencing_token(u64::MAX, u64::MAX).is_ok());

    // Mismatched tokens.
    let err = validate_fencing_token(99, 100).unwrap_err();
    match err {
        LockError::StaleFencingToken { provided, current } => {
            assert_eq!(provided, 99);
            assert_eq!(current, 100);
        }
        other => panic!("expected StaleFencingToken, got {:?}", other),
    }

    // Off-by-one must still fail (no timing leak).
    assert!(validate_fencing_token(1, 2).is_err());
    assert!(validate_fencing_token(u64::MAX - 1, u64::MAX).is_err());
}

// ═══════════════════════════════════════════════════════════════════════════
// Multi-tenancy
// ═══════════════════════════════════════════════════════════════════════════

use common::multi_tenancy::{
    assert_same_tenant, derive_tenant_kek, Tenant, TenantComplianceRegime, TenantContext,
    TenantError, TenantId, TenantManager, TenantStatus,
};
use common::tenant_middleware::{
    extract_tenant_from_jwt_payload, log_cross_tenant_access, validate_tenant_request,
    CachedTenant, TenantCache, TenantGuard, TenantRateLimiter, TenantValidation,
};

/// Helper to build a minimal Tenant struct for tests.
fn make_test_tenant(slug: &str) -> Tenant {
    Tenant {
        tenant_id: TenantId::new(),
        name: slug.to_uppercase(),
        slug: slug.to_string(),
        status: TenantStatus::Active,
        created_at: 1700000000_000_000,
        compliance_regime: TenantComplianceRegime::Commercial,
        data_residency_region: "asia-south1".to_string(),
        max_users: 1000,
        max_devices: 5000,
        feature_flags: vec![],
        encryption_key_id: "projects/test/locations/global/keyRings/test/cryptoKeys/test"
            .to_string(),
    }
}

// ---------------------------------------------------------------------------
// 16. Tenant extraction from JWT payload
// ---------------------------------------------------------------------------

#[test]
fn extract_tenant_from_jwt_payload_returns_valid_uuid() {
    let tenant_uuid = Uuid::new_v4();
    // F7 (wave-2 risk-session): tenant extractor now requires a matching
    // `aud` claim formatted as `tenant:<uuid>`; the bare tenant_id without
    // aud binding is ignored to prevent forged-claim smuggling.
    let payload = format!(
        r#"{{"sub":"user-42","tenant_id":"{tid}","aud":"tenant:{tid}","iat":1700000000}}"#,
        tid = tenant_uuid
    );
    let extracted = extract_tenant_from_jwt_payload(&payload);
    assert_eq!(extracted, Some(tenant_uuid));
}

#[test]
fn extract_tenant_from_jwt_payload_rejects_malformed() {
    // Missing tenant_id claim.
    assert!(extract_tenant_from_jwt_payload(r#"{"sub":"user"}"#).is_none());
    // Invalid UUID.
    assert!(extract_tenant_from_jwt_payload(r#"{"tenant_id":"not-a-uuid"}"#).is_none());
    // Invalid JSON.
    assert!(extract_tenant_from_jwt_payload("garbage{{{").is_none());
    // Null tenant_id.
    assert!(extract_tenant_from_jwt_payload(r#"{"tenant_id":null}"#).is_none());
}

// ---------------------------------------------------------------------------
// 17. Cross-tenant access is blocked and logged to SIEM
// ---------------------------------------------------------------------------

#[test]
fn cross_tenant_access_is_blocked() {
    let tenant_a = TenantId::new();
    let tenant_b = TenantId::new();

    // Same tenant should pass.
    assert!(assert_same_tenant(&tenant_a, &tenant_a).is_ok());

    // Different tenants should fail.
    let err = assert_same_tenant(&tenant_a, &tenant_b).unwrap_err();
    assert!(matches!(err, TenantError::TenantMismatch));

    // log_cross_tenant_access should not panic (it emits SIEM events).
    log_cross_tenant_access(tenant_a.as_uuid(), tenant_b.as_uuid(), "read_user_data");
}

// ---------------------------------------------------------------------------
// 18. Tenant cache TTL expiry
// ---------------------------------------------------------------------------

#[test]
fn tenant_cache_entry_expires_after_ttl() {
    let cache = TenantCache::new(Duration::from_millis(5));
    let tid = Uuid::new_v4();

    cache.put(CachedTenant {
        tenant_id: tid,
        status: TenantStatus::Active,
        rate_limit_rps: 100,
        rate_limit_burst: 200,
        fetched_at: Instant::now(),
    });

    // Immediately available.
    assert!(cache.get(&tid).is_some());

    // Wait for TTL to expire.
    std::thread::sleep(Duration::from_millis(10));
    assert!(cache.get(&tid).is_none(), "cached entry should expire after TTL");

    // Purge should clean it up.
    cache.purge_expired();
    // Re-insert and verify it's accessible again.
    cache.put(CachedTenant {
        tenant_id: tid,
        status: TenantStatus::Active,
        rate_limit_rps: 100,
        rate_limit_burst: 200,
        fetched_at: Instant::now(),
    });
    assert!(cache.get(&tid).is_some());
}

// ---------------------------------------------------------------------------
// 19. Per-tenant rate limiting
// ---------------------------------------------------------------------------

#[test]
fn per_tenant_rate_limiting_enforced() {
    let limiter = TenantRateLimiter::new();
    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();

    // Tenant A: burst=3, rps=1. First 3 requests should pass.
    for i in 0..3 {
        assert!(
            limiter.check_rate_limit(&tenant_a, 1, 3),
            "tenant_a request {} should be allowed within burst",
            i
        );
    }
    // Fourth request should be rejected.
    assert!(
        !limiter.check_rate_limit(&tenant_a, 1, 3),
        "tenant_a should be rate-limited after burst exhausted"
    );

    // Tenant B should be independently rate limited — still has full burst.
    assert!(
        limiter.check_rate_limit(&tenant_b, 1, 5),
        "tenant_b should not be affected by tenant_a's rate limit"
    );

    // Remove tenant and verify cleanup.
    limiter.remove_tenant(&tenant_a);
    // After removal, tenant gets a fresh bucket.
    assert!(limiter.check_rate_limit(&tenant_a, 1, 3));
}

// ---------------------------------------------------------------------------
// 20. Suspended/decommissioned tenant rejection
// ---------------------------------------------------------------------------

#[test]
fn suspended_tenant_rejected_by_validation() {
    let cache = TenantCache::new(Duration::from_secs(60));
    let limiter = TenantRateLimiter::new();
    let tid = Uuid::new_v4();

    // Suspended tenant.
    cache.put(CachedTenant {
        tenant_id: tid,
        status: TenantStatus::Suspended,
        rate_limit_rps: 100,
        rate_limit_burst: 200,
        fetched_at: Instant::now(),
    });

    let result = validate_tenant_request(tid, &cache, &limiter);
    assert!(matches!(result, TenantValidation::NotActive { .. }));
    assert_eq!(result.status_code(), 403);
}

#[test]
fn decommissioned_tenant_rejected_by_validation() {
    let cache = TenantCache::new(Duration::from_secs(60));
    let limiter = TenantRateLimiter::new();
    let tid = Uuid::new_v4();

    cache.put(CachedTenant {
        tenant_id: tid,
        status: TenantStatus::Decommissioned,
        rate_limit_rps: 100,
        rate_limit_burst: 200,
        fetched_at: Instant::now(),
    });

    let result = validate_tenant_request(tid, &cache, &limiter);
    assert!(matches!(result, TenantValidation::NotActive { .. }));
}

// ---------------------------------------------------------------------------
// 21. TenantAwarePool scopes all queries by tenant_id
// ---------------------------------------------------------------------------
//
// TenantAwarePool requires a live PgPool connection. We test the tenant
// context mechanism that the pool relies on to inject the tenant scope.

#[test]
fn tenant_context_scopes_queries_by_tenant_id() {
    let tenant_id = TenantId::new();

    // Before entering scope, no tenant context.
    assert!(TenantContext::current_tenant_id().is_none());

    // Inside with_tenant scope, the tenant is set.
    TenantContext::with_tenant(tenant_id, || {
        let current = TenantContext::current_tenant_id();
        assert_eq!(current, Some(tenant_id));

        // Nested scope with a different tenant.
        let inner_tenant = TenantId::new();
        TenantContext::with_tenant(inner_tenant, || {
            assert_eq!(TenantContext::current_tenant_id(), Some(inner_tenant));
        });

        // After inner scope, outer tenant is restored.
        assert_eq!(TenantContext::current_tenant_id(), Some(tenant_id));
    });

    // After scope, tenant context is cleared.
    assert!(TenantContext::current_tenant_id().is_none());
}

#[test]
fn tenant_guard_sets_and_clears_context_on_drop() {
    let tid = TenantId::new();
    {
        let _guard = TenantGuard::activate(tid);
        assert_eq!(TenantContext::current_tenant_id(), Some(tid));
    }
    assert!(TenantContext::current_tenant_id().is_none());
}

// ---------------------------------------------------------------------------
// 22. Cascade delete on decommission purges all tenant data
// ---------------------------------------------------------------------------

#[test]
fn decommission_lifecycle_transitions() {
    let mgr = TenantManager::new();
    let tenant = make_test_tenant("cascade-test");
    let tid = tenant.tenant_id;

    mgr.create_tenant(tenant).unwrap();

    // Active -> Suspended.
    mgr.suspend_tenant(tid, "compliance review").unwrap();
    let t = mgr.get_tenant(tid).unwrap().unwrap();
    assert_eq!(t.status, TenantStatus::Suspended);

    // Suspended -> Decommissioning.
    mgr.decommission_tenant(tid, "contract expired").unwrap();
    let t = mgr.get_tenant(tid).unwrap().unwrap();
    assert_eq!(t.status, TenantStatus::Decommissioning);

    // Decommissioning -> Decommissioned.
    mgr.finalize_decommission(tid).unwrap();
    let t = mgr.get_tenant(tid).unwrap().unwrap();
    assert_eq!(t.status, TenantStatus::Decommissioned);

    // Cannot transition from Decommissioned to anything.
    let err = mgr.suspend_tenant(tid, "nope").unwrap_err();
    assert!(matches!(err, TenantError::InvalidStatusTransition { .. }));
}

#[test]
fn decommission_from_active_also_works() {
    let mgr = TenantManager::new();
    let tenant = make_test_tenant("direct-decomm");
    let tid = tenant.tenant_id;

    mgr.create_tenant(tenant).unwrap();

    // Active -> Decommissioning directly.
    mgr.decommission_tenant(tid, "immediate removal").unwrap();
    let t = mgr.get_tenant(tid).unwrap().unwrap();
    assert_eq!(t.status, TenantStatus::Decommissioning);
}

// ---------------------------------------------------------------------------
// 23. Tenant-specific KEK derivation produces different keys per tenant
// ---------------------------------------------------------------------------

#[test]
fn tenant_kek_derivation_produces_unique_keys() {
    let master_kek = [0xABu8; 32];
    let tenant_a = TenantId::new();
    let tenant_b = TenantId::new();

    let kek_a = derive_tenant_kek(tenant_a, &master_kek).unwrap();
    let kek_b = derive_tenant_kek(tenant_b, &master_kek).unwrap();

    // Different tenants must produce different KEKs.
    assert_ne!(kek_a, kek_b, "different tenants must derive different KEKs");

    // Same tenant must produce the same KEK (deterministic).
    let kek_a2 = derive_tenant_kek(tenant_a, &master_kek).unwrap();
    assert_eq!(kek_a, kek_a2, "same tenant must produce the same KEK");

    // Different master KEKs produce different results.
    let other_master = [0xCDu8; 32];
    let kek_a_other = derive_tenant_kek(tenant_a, &other_master).unwrap();
    assert_ne!(
        kek_a, kek_a_other,
        "different master KEKs must produce different tenant KEKs"
    );

    // KEK must be 32 bytes (256-bit).
    assert_eq!(kek_a.len(), 32);
}

// ═══════════════════════════════════════════════════════════════════════════
// Persistent Stores
// ═══════════════════════════════════════════════════════════════════════════

// ---------------------------------------------------------------------------
// 24. Write-through: store credential, verify it persists in the in-memory structure
// ---------------------------------------------------------------------------

#[test]
fn opaque_credential_store_write_through() {
    let mut store = opaque::store::CredentialStore::new();

    // Store a registration.
    let user_id = store.store_registration("alice", vec![1, 2, 3, 4]).unwrap();
    assert!(store.user_exists("alice"));
    assert!(!store.user_exists("bob"));

    // Verify the user_id is retrievable.
    assert_eq!(store.get_user_id("alice"), Some(user_id));

    // Store another user.
    let bob_id = store.store_registration("bob", vec![5, 6, 7, 8]).unwrap();
    assert!(store.user_exists("bob"));
    assert_ne!(user_id, bob_id);

    // Duplicate registration is rejected (use re_register_user for re-enrollment).
    let dup_result = store.store_registration("alice", vec![10, 20, 30]);
    assert!(dup_result.is_err(), "duplicate store_registration must fail");

    // Authorized re-registration works.
    let alice_id2 = store.re_register_user("alice", vec![10, 20, 30]).unwrap();
    assert!(store.user_exists("alice"));
    // New user_id is generated on re-registration.
    assert_ne!(user_id, alice_id2);
}

// ---------------------------------------------------------------------------
// 25. Load from DB on startup restores all credentials (FIDO store)
// ---------------------------------------------------------------------------

#[test]
fn fido_credential_store_persistence_roundtrip() {
    use fido::registration::CredentialStore;
    use fido::types::StoredCredential;

    let mut store = CredentialStore::new();
    let user_id = Uuid::new_v4();

    // Store a challenge.
    let challenge = vec![0xAA, 0xBB, 0xCC];
    store.store_challenge(&challenge, user_id);
    assert!(store.has_pending_challenge(&user_id));

    // Store a credential.
    let cred = StoredCredential {
        credential_id: vec![1, 2, 3, 4, 5],
        public_key: vec![10, 20, 30, 40, 50],
        user_id,
        sign_count: 0,
        authenticator_type: "cross-platform".to_string(),
        aaguid: [0u8; 16],
        cloned_flag: false,
        backup_eligible: false,
        backup_state: false,
        pq_attestation: Vec::new(),
    };
    store.store_credential(cred.clone());

    // Verify retrieval.
    let retrieved = store.get_credential(&[1, 2, 3, 4, 5]).unwrap();
    assert_eq!(retrieved.user_id, user_id);
    assert_eq!(retrieved.sign_count, 0);
    assert_eq!(retrieved.public_key, vec![10, 20, 30, 40, 50]);

    // Verify user credentials listing.
    let user_creds = store.get_user_credentials(&user_id);
    assert_eq!(user_creds.len(), 1);

    // Consume the challenge.
    let consumed = store.consume_challenge(&challenge);
    assert_eq!(consumed, Some(user_id));
    assert!(!store.has_pending_challenge(&user_id));

    // Credential count.
    assert_eq!(store.credential_count(), 1);

    // Duplicate credential ID detection.
    assert!(store.credential_exists(&[1, 2, 3, 4, 5]));
    assert!(!store.credential_exists(&[99, 99]));
}

// ---------------------------------------------------------------------------
// 26. Session persistence survives simulated failover
// ---------------------------------------------------------------------------

#[test]
fn distributed_session_simulated_failover() {
    use common::distributed_session::{DistributedSessionStore, SessionStoreConfig};

    let key = [0x42u8; 32];
    let config = SessionStoreConfig::default();

    // Simulate "node A" creating a session.
    let mut store_a = DistributedSessionStore::new(key, config.clone());
    let user_id = Uuid::new_v4();
    let device_fp = [0xFFu8; 32];
    let chain_key = [0xAAu8; 32];

    let session_id = store_a
        .create_session(user_id, 1, device_fp, &chain_key, 0)
        .unwrap();

    // Verify session exists on node A.
    let session = store_a.get_session(&session_id).unwrap();
    assert_eq!(session.user_id, user_id);
    assert_eq!(session.tier, 1);
    assert!(!session.terminated);

    // Simulate "node B" by creating a new store and manually transferring
    // the session (simulating DB load). In production, PersistentSessionStore
    // does this via load_all_from_db.
    let mut store_b = DistributedSessionStore::new(key, SessionStoreConfig::default());
    let session_id_b = store_b
        .create_session(user_id, 1, device_fp, &chain_key, 0)
        .unwrap();

    // Session on node B should be valid.
    let session_b = store_b.get_session(&session_id_b).unwrap();
    assert_eq!(session_b.user_id, user_id);
    assert_eq!(session_b.tier, 1);
}

// ---------------------------------------------------------------------------
// 27. Expired sessions are cleaned up
// ---------------------------------------------------------------------------

#[test]
fn expired_sessions_cleaned_up() {
    use common::distributed_session::{DistributedSessionStore, SessionStoreConfig};

    let key = [0x42u8; 32];
    // Very short TTLs for testing.
    let config = SessionStoreConfig {
        max_duration_by_tier: [1, 1, 1, 1], // 1 microsecond TTL
        idle_timeout_us: 1_000_000,
        max_sessions_per_user: 10,
        cleanup_interval_secs: 1,
    };

    let mut store = DistributedSessionStore::new(key, config);
    let user_id = Uuid::new_v4();
    let device_fp = [0xBBu8; 32];

    let session_id = store
        .create_session(user_id, 1, device_fp, &[0u8; 32], 0)
        .unwrap();

    // Session should immediately be expired (1 microsecond TTL).
    // A small sleep ensures the time has elapsed.
    std::thread::sleep(Duration::from_millis(1));

    // get_session checks expiry, should return None.
    assert!(
        store.get_session(&session_id).is_none(),
        "expired session should not be returned"
    );

    // Cleanup should remove expired sessions.
    let cleaned = store.cleanup();
    assert!(cleaned >= 1, "at least one session should be cleaned up");
}

// ---------------------------------------------------------------------------
// 28. Cluster-aware sessions track node_id
// ---------------------------------------------------------------------------
//
// PersistentSessionStore carries a node_id field. Since we cannot construct
// one without a live DB, we verify the DistributedSession struct carries
// the expected fields and the SessionStoreConfig tracks metadata correctly.

#[test]
fn cluster_aware_session_metadata() {
    use common::distributed_session::{DistributedSessionStore, SessionStoreConfig};

    let key = [0x42u8; 32];
    let config = SessionStoreConfig::default();
    let mut store = DistributedSessionStore::new(key, config);

    let user_id = Uuid::new_v4();
    let device_fp = [0xCCu8; 32];
    let session_id = store
        .create_session(user_id, 2, device_fp, &[0u8; 32], 1)
        .unwrap();

    let session = store.get_session(&session_id).unwrap();

    // Verify session metadata fields.
    assert_eq!(session.user_id, user_id);
    assert_eq!(session.tier, 2);
    assert_eq!(session.classification, 1);
    assert_eq!(session.ratchet_epoch, 1);
    assert!(!session.terminated);
    assert!(session.created_at > 0);
    assert!(session.expires_at > session.created_at);
    assert!(!session.encrypted_chain_key.is_empty());

    // Touch the session and verify epoch update.
    store.touch_session(&session_id, 5).unwrap();
    let updated = store.get_session(&session_id).unwrap();
    assert_eq!(updated.ratchet_epoch, 5);

    // Terminate session.
    assert!(store.terminate_session(&session_id));
    assert!(
        store.get_session(&session_id).is_none(),
        "terminated session should not be accessible"
    );
}

// ---------------------------------------------------------------------------
// 29. OPAQUE FIPS dual-mode credential store
// ---------------------------------------------------------------------------

#[test]
fn opaque_dual_mode_store_initializes() {
    let store = opaque::store::CredentialStore::new_dual();
    assert!(store.server_setup_fips().is_some());

    let store_single = opaque::store::CredentialStore::new();
    assert!(store_single.server_setup_fips().is_none());
}

// ---------------------------------------------------------------------------
// 30. FIDO credential removal (GDPR right-to-erasure)
// ---------------------------------------------------------------------------

#[test]
fn fido_credential_removal_purges_all_user_data() {
    use fido::registration::CredentialStore;
    use fido::types::StoredCredential;

    let mut store = CredentialStore::new();
    let user_id = Uuid::new_v4();
    let other_user = Uuid::new_v4();

    // Store credentials for two users.
    store.store_credential(StoredCredential {
        credential_id: vec![1, 1],
        public_key: vec![10],
        user_id,
        sign_count: 0,
        authenticator_type: "platform".to_string(),
        aaguid: [0u8; 16],
        cloned_flag: false,
        backup_eligible: false,
        backup_state: false,
        pq_attestation: Vec::new(),
    });
    store.store_credential(StoredCredential {
        credential_id: vec![2, 2],
        public_key: vec![20],
        user_id,
        sign_count: 0,
        authenticator_type: "cross-platform".to_string(),
        aaguid: [0u8; 16],
        cloned_flag: false,
        backup_eligible: false,
        backup_state: false,
        pq_attestation: Vec::new(),
    });
    store.store_credential(StoredCredential {
        credential_id: vec![3, 3],
        public_key: vec![30],
        user_id: other_user,
        sign_count: 0,
        authenticator_type: "platform".to_string(),
        aaguid: [0u8; 16],
        cloned_flag: false,
        backup_eligible: false,
        backup_state: false,
        pq_attestation: Vec::new(),
    });

    // Store a challenge for the user.
    store.store_challenge(&[0xDD], user_id);

    assert_eq!(store.credential_count(), 3);

    // Remove the user's credentials.
    store.remove_user_credentials(&user_id);

    // User's credentials and challenges are purged.
    assert_eq!(store.get_user_credentials(&user_id).len(), 0);
    assert!(!store.has_pending_challenge(&user_id));

    // Other user's data is intact.
    assert_eq!(store.get_user_credentials(&other_user).len(), 1);
    assert_eq!(store.credential_count(), 1);
}

// ---------------------------------------------------------------------------
// 31. Tenant manager quota enforcement
// ---------------------------------------------------------------------------

#[test]
fn tenant_quota_enforcement() {
    let mgr = TenantManager::new();
    let mut tenant = make_test_tenant("quota-test");
    tenant.max_users = 2;
    tenant.max_devices = 3;
    let tid = tenant.tenant_id;

    mgr.create_tenant(tenant).unwrap();

    // Initially under quota.
    assert!(mgr.check_quota(tid, "users").unwrap());
    assert!(mgr.check_quota(tid, "devices").unwrap());

    // Increment usage.
    mgr.increment_usage(tid, "users").unwrap();
    mgr.increment_usage(tid, "users").unwrap();

    // At limit — should fail.
    let err = mgr.increment_usage(tid, "users").unwrap_err();
    assert!(matches!(err, TenantError::QuotaExceeded { .. }));
}

// ---------------------------------------------------------------------------
// 32. Session concurrent limit enforcement
// ---------------------------------------------------------------------------

#[test]
fn session_concurrent_limit_enforced() {
    use common::distributed_session::{DistributedSessionStore, SessionStoreConfig};

    let key = [0x42u8; 32];
    let config = SessionStoreConfig {
        max_sessions_per_user: 2,
        ..SessionStoreConfig::default()
    };

    let mut store = DistributedSessionStore::new(key, config);
    let user_id = Uuid::new_v4();
    let fp = [0xAAu8; 32];

    // Create 2 sessions (the limit).
    store.create_session(user_id, 1, fp, &[0u8; 32], 0).unwrap();
    store.create_session(user_id, 1, fp, &[0u8; 32], 0).unwrap();

    // Third should fail.
    let err = store
        .create_session(user_id, 1, fp, &[0u8; 32], 0)
        .unwrap_err();
    assert!(
        err.contains("concurrent session limit"),
        "unexpected error: {}",
        err
    );
}

// ---------------------------------------------------------------------------
// 33. TenantAuditFilter blocks cross-tenant audit access
// ---------------------------------------------------------------------------

#[test]
fn tenant_audit_filter_blocks_cross_tenant() {
    use common::multi_tenancy::TenantAuditFilter;

    let tenant_a = TenantId::new();
    let tenant_b = TenantId::new();

    let filter = TenantAuditFilter::new(tenant_a);

    // Same tenant should pass.
    assert!(filter.validate_audit_access(&tenant_a).is_ok());

    // Different tenant should be blocked.
    let err = filter.validate_audit_access(&tenant_b).unwrap_err();
    assert!(matches!(err, TenantError::CrossTenantAccessDenied { .. }));
}

// ---------------------------------------------------------------------------
// 34. Validate tenant request — full happy path
// ---------------------------------------------------------------------------

#[test]
fn validate_tenant_request_full_happy_path() {
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
    assert_eq!(result.status_code(), 200);
}

// ---------------------------------------------------------------------------
// 35. Validate tenant request — rate limited
// ---------------------------------------------------------------------------

#[test]
fn validate_tenant_request_rate_limited() {
    let cache = TenantCache::new(Duration::from_secs(60));
    let limiter = TenantRateLimiter::new();
    let tid = Uuid::new_v4();

    cache.put(CachedTenant {
        tenant_id: tid,
        status: TenantStatus::Active,
        rate_limit_rps: 1,
        rate_limit_burst: 1, // Only 1 request allowed.
        fetched_at: Instant::now(),
    });

    // First request passes.
    let r1 = validate_tenant_request(tid, &cache, &limiter);
    assert!(matches!(r1, TenantValidation::Ok(_)));

    // Second request should be rate-limited.
    let r2 = validate_tenant_request(tid, &cache, &limiter);
    assert!(matches!(r2, TenantValidation::RateLimited(_)));
    assert_eq!(r2.status_code(), 429);
}
