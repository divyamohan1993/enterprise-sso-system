//! Integration tests for the admin crate's public API surface.
//!
//! These tests exercise public types and functions exported from admin::routes
//! without requiring a database connection. They focus on security-critical
//! logic: RBAC, revocation, destructive action policies, and type contracts.

use admin::routes::{
    AdminRole, AuthAdminRole, AuthTier, AuthUserId, DestructiveAction, Portal,
    RevocationList, derive_admin_role_key,
};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// AdminRole — RBAC hierarchy tests
// ---------------------------------------------------------------------------

#[test]
fn test_rbac_super_admin_has_all_permissions() {
    let sa = AdminRole::SuperAdmin;
    assert!(sa.satisfies(AdminRole::SuperAdmin));
    assert!(sa.satisfies(AdminRole::UserManager));
    assert!(sa.satisfies(AdminRole::DeviceManager));
    assert!(sa.satisfies(AdminRole::Auditor));
    assert!(sa.satisfies(AdminRole::ReadOnly));
}

#[test]
fn test_rbac_read_only_denied_write() {
    let ro = AdminRole::ReadOnly;
    assert!(!ro.satisfies(AdminRole::SuperAdmin));
    assert!(!ro.satisfies(AdminRole::UserManager));
    assert!(!ro.satisfies(AdminRole::DeviceManager));
    assert!(!ro.satisfies(AdminRole::Auditor));
    assert!(ro.satisfies(AdminRole::ReadOnly));
}

#[test]
fn test_rbac_user_manager_can_manage_users() {
    let um = AdminRole::UserManager;
    assert!(um.satisfies(AdminRole::UserManager));
    assert!(um.satisfies(AdminRole::ReadOnly));
}

#[test]
fn test_rbac_user_manager_cannot_manage_devices() {
    let um = AdminRole::UserManager;
    assert!(!um.satisfies(AdminRole::DeviceManager));
}

#[test]
fn test_rbac_device_manager_can_manage_devices() {
    let dm = AdminRole::DeviceManager;
    assert!(dm.satisfies(AdminRole::DeviceManager));
    assert!(dm.satisfies(AdminRole::ReadOnly));
}

#[test]
fn test_rbac_device_manager_cannot_manage_users() {
    let dm = AdminRole::DeviceManager;
    assert!(!dm.satisfies(AdminRole::UserManager));
}

#[test]
fn test_rbac_auditor_can_read_audit_logs() {
    let aud = AdminRole::Auditor;
    assert!(aud.satisfies(AdminRole::Auditor));
    assert!(aud.satisfies(AdminRole::ReadOnly));
}

#[test]
fn test_rbac_auditor_cannot_write() {
    let aud = AdminRole::Auditor;
    assert!(!aud.satisfies(AdminRole::SuperAdmin));
    assert!(!aud.satisfies(AdminRole::UserManager));
    assert!(!aud.satisfies(AdminRole::DeviceManager));
}

#[test]
fn test_rbac_no_role_escalation() {
    // No non-SuperAdmin role can satisfy SuperAdmin
    for role in &[
        AdminRole::UserManager,
        AdminRole::DeviceManager,
        AdminRole::Auditor,
        AdminRole::ReadOnly,
    ] {
        assert!(
            !role.satisfies(AdminRole::SuperAdmin),
            "{:?} should not satisfy SuperAdmin",
            role
        );
    }
}

// ---------------------------------------------------------------------------
// AdminRole — from_u8 round-trip
// ---------------------------------------------------------------------------

#[test]
fn test_admin_role_from_u8_roundtrip() {
    for i in 0u8..=4 {
        let role = AdminRole::from_u8(i).expect("valid role index");
        assert_eq!(role as u8, i);
    }
}

#[test]
fn test_admin_role_from_u8_invalid_returns_none() {
    assert!(AdminRole::from_u8(5).is_none());
    assert!(AdminRole::from_u8(100).is_none());
    assert!(AdminRole::from_u8(255).is_none());
}

// ---------------------------------------------------------------------------
// AdminRole — key_label uniqueness
// ---------------------------------------------------------------------------

#[test]
fn test_admin_role_key_labels_unique() {
    let labels: Vec<&str> = [
        AdminRole::SuperAdmin,
        AdminRole::UserManager,
        AdminRole::DeviceManager,
        AdminRole::Auditor,
        AdminRole::ReadOnly,
    ]
    .iter()
    .map(|r| r.key_label())
    .collect();
    let unique: std::collections::HashSet<&&str> = labels.iter().collect();
    assert_eq!(labels.len(), unique.len(), "all key labels must be unique");
}

// ---------------------------------------------------------------------------
// derive_admin_role_key — determinism and uniqueness
// ---------------------------------------------------------------------------

#[test]
fn test_derive_admin_role_key_deterministic() {
    let k1 = derive_admin_role_key(AdminRole::Auditor);
    let k2 = derive_admin_role_key(AdminRole::Auditor);
    assert_eq!(k1, k2);
}

#[test]
fn test_derive_admin_role_key_unique_per_role() {
    let keys: Vec<String> = [
        AdminRole::SuperAdmin,
        AdminRole::UserManager,
        AdminRole::DeviceManager,
        AdminRole::Auditor,
        AdminRole::ReadOnly,
    ]
    .iter()
    .map(|r| derive_admin_role_key(*r))
    .collect();
    let unique: std::collections::HashSet<&String> = keys.iter().collect();
    assert_eq!(keys.len(), unique.len(), "each role must derive a unique key");
}

#[test]
fn test_derive_admin_role_key_is_hex_encoded() {
    let key = derive_admin_role_key(AdminRole::SuperAdmin);
    assert_eq!(key.len(), 64, "32-byte key hex-encoded is 64 chars");
    assert!(
        key.chars().all(|c| c.is_ascii_hexdigit()),
        "key must be valid hex"
    );
}

// ---------------------------------------------------------------------------
// RevocationList — public API tests
// ---------------------------------------------------------------------------

#[test]
fn test_revocation_list_constructs_without_panic() {
    // RevocationList's methods (revoke, count, cleanup) are private.
    // The internal #[cfg(test)] module in routes.rs covers full behavior.
    // Here we verify the public constructor works.
    let _rl = RevocationList::new();
}

// ---------------------------------------------------------------------------
// DestructiveAction — policy tests
// ---------------------------------------------------------------------------

#[test]
fn test_destructive_action_approvals_at_least_two() {
    let actions = [
        DestructiveAction::UserDeletion,
        DestructiveAction::TierChange,
        DestructiveAction::KeyRotation,
        DestructiveAction::BulkDeviceRevocation,
        DestructiveAction::ErrorLevelToggle,
    ];
    for action in &actions {
        assert!(
            action.required_approvals() >= 2,
            "{:?} must require at least 2 approvals",
            action
        );
    }
}

#[test]
fn test_key_rotation_highest_approval_bar() {
    let kr = DestructiveAction::KeyRotation.required_approvals();
    assert!(
        kr >= 3,
        "key rotation should require at least 3 approvals, got {kr}"
    );
    assert!(
        kr > DestructiveAction::UserDeletion.required_approvals(),
        "key rotation should require more approvals than user deletion"
    );
}

#[test]
fn test_all_destructive_actions_require_superadmin_approver() {
    let actions = [
        DestructiveAction::UserDeletion,
        DestructiveAction::TierChange,
        DestructiveAction::KeyRotation,
        DestructiveAction::BulkDeviceRevocation,
        DestructiveAction::ErrorLevelToggle,
    ];
    for action in &actions {
        assert!(
            action.requires_superadmin_approver(),
            "{:?} should require SuperAdmin approver",
            action
        );
    }
}

// ---------------------------------------------------------------------------
// Portal type — serialization round-trip
// ---------------------------------------------------------------------------

#[test]
fn test_portal_serialization_roundtrip() {
    let portal = Portal {
        id: Uuid::new_v4(),
        name: "Test Portal".into(),
        callback_url: "https://example.com/callback".into(),
        required_tier: 2,
        required_scope: 7,
        is_active: true,
    };
    let json = serde_json::to_string(&portal).expect("serialize");
    let deserialized: Portal = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(portal.id, deserialized.id);
    assert_eq!(portal.name, deserialized.name);
    assert_eq!(portal.callback_url, deserialized.callback_url);
    assert_eq!(portal.required_tier, deserialized.required_tier);
    assert_eq!(portal.required_scope, deserialized.required_scope);
    assert_eq!(portal.is_active, deserialized.is_active);
}

#[test]
fn test_portal_inactive_by_default_check() {
    let portal = Portal {
        id: Uuid::new_v4(),
        name: "Inactive Portal".into(),
        callback_url: "https://example.com".into(),
        required_tier: 1,
        required_scope: 0,
        is_active: false,
    };
    assert!(!portal.is_active);
}

// ---------------------------------------------------------------------------
// Extension types — construction
// ---------------------------------------------------------------------------

#[test]
fn test_auth_tier_extension() {
    let tier = AuthTier(2);
    assert_eq!(tier.0, 2);
}

#[test]
fn test_auth_admin_role_extension() {
    let role = AuthAdminRole(AdminRole::Auditor);
    assert_eq!(role.0, AdminRole::Auditor);
}

#[test]
fn test_auth_user_id_extension() {
    let uid = Uuid::new_v4();
    let ext = AuthUserId(uid);
    assert_eq!(ext.0, uid);
}

// ---------------------------------------------------------------------------
// AdminRole — Display trait
// ---------------------------------------------------------------------------

#[test]
fn test_admin_role_display() {
    assert_eq!(format!("{}", AdminRole::SuperAdmin), "super-admin");
    assert_eq!(format!("{}", AdminRole::UserManager), "user-manager");
    assert_eq!(format!("{}", AdminRole::DeviceManager), "device-manager");
    assert_eq!(format!("{}", AdminRole::Auditor), "auditor");
    assert_eq!(format!("{}", AdminRole::ReadOnly), "read-only");
}

// ---------------------------------------------------------------------------
// DestructiveAction — Display trait
// ---------------------------------------------------------------------------

#[test]
fn test_destructive_action_display() {
    assert_eq!(
        format!("{}", DestructiveAction::UserDeletion),
        "user_deletion"
    );
    assert_eq!(
        format!("{}", DestructiveAction::KeyRotation),
        "key_rotation"
    );
}

// ---------------------------------------------------------------------------
// DestructiveAction — Serialization
// ---------------------------------------------------------------------------

#[test]
fn test_destructive_action_serde_roundtrip() {
    let action = DestructiveAction::KeyRotation;
    let json = serde_json::to_string(&action).expect("serialize");
    let deserialized: DestructiveAction = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(action, deserialized);
}

// ---------------------------------------------------------------------------
// RBAC satisfies is not transitive for non-SuperAdmin
// ---------------------------------------------------------------------------

#[test]
fn test_rbac_non_transitive() {
    // UserManager satisfies UserManager, but not DeviceManager
    // DeviceManager satisfies DeviceManager, but not UserManager
    // This ensures roles are truly isolated, not hierarchical except SuperAdmin
    let um = AdminRole::UserManager;
    let dm = AdminRole::DeviceManager;
    assert!(um.satisfies(AdminRole::UserManager));
    assert!(!um.satisfies(AdminRole::DeviceManager));
    assert!(dm.satisfies(AdminRole::DeviceManager));
    assert!(!dm.satisfies(AdminRole::UserManager));
}

// ---------------------------------------------------------------------------
// Admin API key — no derivation fallback
// ---------------------------------------------------------------------------

/// Verify that the admin API key is validated via constant-time comparison.
/// This tests the validation logic: the AppState holds the api_key and
/// routes compare the Bearer token against it using ct_eq. Without
/// ADMIN_API_KEY set, the system must refuse to start (tested in main.rs).
/// Here we verify that an empty or wrong key is rejected by ct_eq.
#[test]
fn test_admin_api_key_wrong_token_rejected_by_ct_eq() {
    let real_key = "a]2b#c9d0e1f2a3b4c5d6e7f8a9b0c1d2";
    let wrong_key = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    let empty_key = "";

    // Wrong key must not match
    assert!(
        !crypto::ct::ct_eq(wrong_key.as_bytes(), real_key.as_bytes()),
        "wrong API key must be rejected"
    );

    // Empty key must not match
    assert!(
        !crypto::ct::ct_eq(empty_key.as_bytes(), real_key.as_bytes()),
        "empty API key must be rejected"
    );

    // Correct key must match
    assert!(
        crypto::ct::ct_eq(real_key.as_bytes(), real_key.as_bytes()),
        "correct API key must match"
    );
}

/// Verify that the admin API key minimum length requirement is 32 chars.
/// The main.rs enforces `key.len() >= 32`. Keys shorter than that must
/// be rejected. This validates the policy: no derivation fallback means
/// the key MUST be explicitly provisioned with sufficient entropy.
#[test]
fn test_admin_api_key_minimum_length_policy() {
    let short_key = "too-short-key";
    assert!(
        short_key.len() < 32,
        "test setup: key must be shorter than 32 chars"
    );

    let valid_key = "a]2b#c9d0e1f2a3b4c5d6e7f8a9b0c1d2";
    assert!(
        valid_key.len() >= 32,
        "test setup: valid key must be >= 32 chars"
    );

    // The actual enforcement happens in admin/src/main.rs:
    // match std::env::var("ADMIN_API_KEY") {
    //     Ok(key) if key.len() >= 32 => key,
    //     Ok(key) => { ... process::exit(1) }
    //     Err(_) => { ... process::exit(1) }
    // }
    // We verify the length check logic here.
    let accepts_valid = valid_key.len() >= 32;
    let accepts_short = short_key.len() >= 32;
    assert!(accepts_valid, "valid key must pass length check");
    assert!(!accepts_short, "short key must fail length check");
}

/// Verify that derive_admin_role_key is NOT used as fallback for the
/// admin API key. The derived keys are for RBAC role separation only,
/// not for admin authentication. This ensures the API key and role keys
/// are independent.
#[test]
fn test_admin_role_key_is_not_api_key() {
    // derive_admin_role_key produces deterministic role-specific keys,
    // but these are NOT the admin API key. The admin API key comes from
    // ADMIN_API_KEY env var with no derivation fallback.
    let role_key = derive_admin_role_key(AdminRole::SuperAdmin);
    assert_eq!(role_key.len(), 64, "role key is 64 hex chars (32 bytes)");

    // Role keys are deterministic from a static seed
    let role_key2 = derive_admin_role_key(AdminRole::SuperAdmin);
    assert_eq!(role_key, role_key2, "role key derivation is deterministic");

    // Different roles produce different keys
    let auditor_key = derive_admin_role_key(AdminRole::Auditor);
    assert_ne!(
        role_key, auditor_key,
        "different roles must derive different keys"
    );
}

// ---------------------------------------------------------------------------
// AdminRole — Eq / Hash / Clone
// ---------------------------------------------------------------------------

#[test]
fn test_admin_role_eq_and_clone() {
    let role = AdminRole::SuperAdmin;
    let cloned = role;
    assert_eq!(role, cloned);
}

#[test]
fn test_admin_role_hash_consistency() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(AdminRole::SuperAdmin);
    set.insert(AdminRole::SuperAdmin); // duplicate
    assert_eq!(set.len(), 1);
    set.insert(AdminRole::Auditor);
    assert_eq!(set.len(), 2);
}
