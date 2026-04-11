//! Multi-tenant isolation end-to-end tests.
//!
//! Verifies that tenants cannot access each other's data, tokens,
//! sessions, and audit logs. Tests the cryptographic isolation boundary
//! enforced by TenantContext and constant-time TenantId comparison.

use common::multi_tenancy::{
    assert_same_tenant, derive_tenant_kek, Tenant, TenantAuditFilter, TenantComplianceRegime,
    TenantContext, TenantError, TenantId, TenantManager, TenantStatus,
};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helper: create a test tenant
// ---------------------------------------------------------------------------

fn make_tenant(name: &str, slug: &str) -> Tenant {
    Tenant {
        tenant_id: TenantId::new(),
        name: name.to_string(),
        slug: slug.to_string(),
        status: TenantStatus::Active,
        created_at: 1700000000_000_000,
        compliance_regime: TenantComplianceRegime::UsDod,
        data_residency_region: "us-central1".to_string(),
        max_users: 1000,
        max_devices: 5000,
        feature_flags: Vec::new(),
        encryption_key_id: "projects/milnet/locations/global/keyRings/kr/cryptoKeys/k".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Two tenants cannot access each other's data
// ---------------------------------------------------------------------------

#[test]
fn test_cross_tenant_id_mismatch_detected() {
    let tenant_a = TenantId::new();
    let tenant_b = TenantId::new();
    let result = assert_same_tenant(&tenant_a, &tenant_b);
    assert!(
        result.is_err(),
        "different tenant IDs must be detected as mismatch"
    );
    match result.unwrap_err() {
        TenantError::TenantMismatch => {}
        other => panic!("expected TenantMismatch, got: {:?}", other),
    }
}

#[test]
fn test_same_tenant_id_matches() {
    let tenant_a = TenantId::new();
    let result = assert_same_tenant(&tenant_a, &tenant_a);
    assert!(result.is_ok(), "same tenant ID must match");
}

#[test]
fn test_tenant_id_constant_time_comparison() {
    // Verify that PartialEq is implemented (using ct_eq internally).
    let id1 = TenantId::from_uuid(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap());
    let id2 = TenantId::from_uuid(Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap());
    let id1_clone = TenantId::from_uuid(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap());

    assert_ne!(id1, id2);
    assert_eq!(id1, id1_clone);
}

// ---------------------------------------------------------------------------
// Cross-tenant token rejection (KEK isolation)
// ---------------------------------------------------------------------------

#[test]
fn test_cross_tenant_kek_isolation() {
    let master_kek = [0x42u8; 32];
    let tenant_a = TenantId::new();
    let tenant_b = TenantId::new();

    let kek_a = derive_tenant_kek(tenant_a, &master_kek).unwrap();
    let kek_b = derive_tenant_kek(tenant_b, &master_kek).unwrap();

    assert_ne!(
        kek_a, kek_b,
        "different tenants must derive different KEKs"
    );

    // Same tenant always derives the same KEK (deterministic).
    let kek_a2 = derive_tenant_kek(tenant_a, &master_kek).unwrap();
    assert_eq!(kek_a, kek_a2, "same tenant must derive same KEK");
}

#[test]
fn test_different_master_kek_different_tenant_kek() {
    let master_kek1 = [0x01u8; 32];
    let master_kek2 = [0x02u8; 32];
    let tenant = TenantId::new();

    let kek1 = derive_tenant_kek(tenant, &master_kek1).unwrap();
    let kek2 = derive_tenant_kek(tenant, &master_kek2).unwrap();
    assert_ne!(
        kek1, kek2,
        "different master KEKs must produce different tenant KEKs"
    );
}

// ---------------------------------------------------------------------------
// Tenant-scoped session isolation via TenantContext
// ---------------------------------------------------------------------------

#[test]
fn test_tenant_context_scoping() {
    let tenant_a = TenantId::new();
    let tenant_b = TenantId::new();

    // Outside any tenant context.
    assert!(TenantContext::current_tenant_id().is_none());
    assert!(TenantContext::require_tenant().is_err());

    // Inside tenant A's context.
    TenantContext::with_tenant(tenant_a, || {
        let current = TenantContext::current_tenant_id().unwrap();
        assert_eq!(current, tenant_a);

        // Nested: inside tenant B's context.
        TenantContext::with_tenant(tenant_b, || {
            let current = TenantContext::current_tenant_id().unwrap();
            assert_eq!(current, tenant_b);
            assert_ne!(current, tenant_a);
        });

        // After nested context, should restore to tenant A.
        let current = TenantContext::current_tenant_id().unwrap();
        assert_eq!(current, tenant_a);
    });

    // After all contexts, should be None.
    assert!(TenantContext::current_tenant_id().is_none());
}

#[test]
fn test_tenant_context_isolation_between_operations() {
    let tenant_a = TenantId::new();
    let tenant_b = TenantId::new();

    let result_a = TenantContext::with_tenant(tenant_a, || {
        TenantContext::current_tenant_id().unwrap()
    });

    let result_b = TenantContext::with_tenant(tenant_b, || {
        TenantContext::current_tenant_id().unwrap()
    });

    assert_eq!(result_a, tenant_a);
    assert_eq!(result_b, tenant_b);
    assert_ne!(result_a, result_b);
}

// ---------------------------------------------------------------------------
// Tenant-scoped audit log isolation
// ---------------------------------------------------------------------------

#[test]
fn test_tenant_audit_filter_blocks_cross_tenant_access() {
    let tenant_a = TenantId::new();
    let tenant_b = TenantId::new();

    let filter = TenantAuditFilter::new(tenant_a);

    // Same tenant should be allowed.
    assert!(filter.validate_audit_access(&tenant_a).is_ok());

    // Different tenant must be denied.
    let result = filter.validate_audit_access(&tenant_b);
    assert!(result.is_err(), "cross-tenant audit access must be denied");
    match result.unwrap_err() {
        TenantError::CrossTenantAccessDenied { from, to } => {
            assert_eq!(from, tenant_a);
            assert_eq!(to, tenant_b);
        }
        other => panic!("expected CrossTenantAccessDenied, got: {:?}", other),
    }
}

#[test]
fn test_audit_filter_returns_correct_tenant_id() {
    let tenant = TenantId::new();
    let filter = TenantAuditFilter::new(tenant);
    assert_eq!(*filter.tenant_id(), tenant);
}

// ---------------------------------------------------------------------------
// TenantManager isolation
// ---------------------------------------------------------------------------

#[test]
fn test_tenant_manager_create_and_isolate() {
    let manager = TenantManager::new();

    let tenant_a = make_tenant("Alpha Division", "alpha-div");
    let tenant_b = make_tenant("Bravo Division", "bravo-div");

    let id_a = tenant_a.tenant_id;
    let id_b = tenant_b.tenant_id;

    manager.create_tenant(tenant_a).unwrap();
    manager.create_tenant(tenant_b).unwrap();

    // Each tenant can be retrieved independently.
    let a = manager.get_tenant(id_a).unwrap().unwrap();
    let b = manager.get_tenant(id_b).unwrap().unwrap();

    assert_eq!(a.name, "Alpha Division");
    assert_eq!(b.name, "Bravo Division");
    assert_ne!(a.tenant_id, b.tenant_id);
}

#[test]
fn test_tenant_manager_duplicate_slug_rejected() {
    let manager = TenantManager::new();

    let tenant1 = make_tenant("First", "same-slug");
    let tenant2 = make_tenant("Second", "same-slug");

    manager.create_tenant(tenant1).unwrap();
    let result = manager.create_tenant(tenant2);
    assert!(result.is_err(), "duplicate slug must be rejected");
    match result.unwrap_err() {
        TenantError::DuplicateSlug(slug) => {
            assert_eq!(slug, "same-slug");
        }
        other => panic!("expected DuplicateSlug, got: {:?}", other),
    }
}

#[test]
fn test_tenant_manager_invalid_slug_rejected() {
    let manager = TenantManager::new();

    let bad_slugs = vec![
        "",                    // empty
        "UPPER-CASE",          // uppercase
        "has spaces",          // spaces
        "has_underscore",      // underscores
        "has.dot",             // dots
        "has/slash",           // slashes
        "drop;table",          // SQL injection in slug
    ];

    for slug in bad_slugs {
        let tenant = make_tenant("Test", slug);
        let result = manager.create_tenant(tenant);
        assert!(
            result.is_err(),
            "slug '{}' should be rejected as invalid",
            slug
        );
    }
}

// ---------------------------------------------------------------------------
// Tenant lifecycle isolation
// ---------------------------------------------------------------------------

#[test]
fn test_suspended_tenant_isolation() {
    let manager = TenantManager::new();
    let tenant = make_tenant("Suspended Corp", "suspended-corp");
    let id = tenant.tenant_id;
    manager.create_tenant(tenant).unwrap();

    // Suspend the tenant.
    manager.suspend_tenant(id, "security incident").unwrap();

    let t = manager.get_tenant(id).unwrap().unwrap();
    assert_eq!(t.status, TenantStatus::Suspended);
    assert!(!t.is_active());
}

#[test]
fn test_decommissioned_tenant_cannot_reactivate() {
    let manager = TenantManager::new();
    let tenant = make_tenant("Old Corp", "old-corp");
    let id = tenant.tenant_id;
    manager.create_tenant(tenant).unwrap();

    manager.suspend_tenant(id, "sunset").unwrap();
    manager.decommission_tenant(id, "data purge").unwrap();
    manager.finalize_decommission(id).unwrap();

    let t = manager.get_tenant(id).unwrap().unwrap();
    assert_eq!(t.status, TenantStatus::Decommissioned);

    // Cannot reactivate a decommissioned tenant.
    let result = manager.reactivate_tenant(id);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Quota isolation between tenants
// ---------------------------------------------------------------------------

#[test]
fn test_quota_isolation() {
    let manager = TenantManager::new();

    let mut tenant_a = make_tenant("Small Corp", "small-corp");
    tenant_a.max_users = 10;
    let id_a = tenant_a.tenant_id;

    let mut tenant_b = make_tenant("Big Corp", "big-corp");
    tenant_b.max_users = 1_000_000;
    let id_b = tenant_b.tenant_id;

    manager.create_tenant(tenant_a).unwrap();
    manager.create_tenant(tenant_b).unwrap();

    // Tenant A's quota is independent of Tenant B's.
    assert!(manager.check_quota(id_a, "users").unwrap());
    assert!(manager.check_quota(id_b, "users").unwrap());

    // Updating one tenant's quota doesn't affect the other.
    manager.update_quota(id_a, 5, 10).unwrap();
    let a = manager.get_tenant(id_a).unwrap().unwrap();
    let b = manager.get_tenant(id_b).unwrap().unwrap();
    assert_eq!(a.max_users, 5);
    assert_eq!(b.max_users, 1_000_000);
}

// ---------------------------------------------------------------------------
// Concurrent multi-tenant operations
// ---------------------------------------------------------------------------

#[test]
fn test_concurrent_tenant_operations() {
    use std::sync::Arc;

    let manager = Arc::new(TenantManager::new());
    let mut handles = Vec::new();

    for i in 0..10 {
        let mgr = manager.clone();
        handles.push(std::thread::spawn(move || {
            let tenant = Tenant {
                tenant_id: TenantId::new(),
                name: format!("Tenant {}", i),
                slug: format!("tenant-{}", i),
                status: TenantStatus::Active,
                created_at: 1700000000_000_000,
                compliance_regime: TenantComplianceRegime::Commercial,
                data_residency_region: "us-central1".to_string(),
                max_users: 100,
                max_devices: 500,
                feature_flags: Vec::new(),
                encryption_key_id: "key".to_string(),
            };
            let id = tenant.tenant_id;
            mgr.create_tenant(tenant).unwrap();
            let t = mgr.get_tenant(id).unwrap().unwrap();
            assert_eq!(t.name, format!("Tenant {}", i));
        }));
    }

    for h in handles {
        h.join().expect("thread panicked during concurrent tenant ops");
    }

    let all = manager.list_tenants().unwrap();
    assert_eq!(all.len(), 10, "all 10 tenants should be created");
}
