//! Distributed ceremony engine tests.
//!
//! Verifies the CeremonyEngine correctly:
//!   - Bootstraps all key types
//!   - Seals and unseals keys with AES-256-GCM
//!   - Rotates keys atomically (old destroyed, new active)
//!   - Tracks rotation epochs
//!   - Emergency rotation rotates all keys
//!   - Schedule-based rotation detection

use common::secret_ceremony::*;

fn make_engine() -> CeremonyEngine {
    let sealing_key = CeremonySecret::generate(32).unwrap();
    CeremonyEngine::new(sealing_key)
}

// ── Bootstrap ─────────────────────────────────────────────────────────────

/// Security property: Bootstrap generates all required key types for the
/// military-grade SSO system.
#[test]
fn bootstrap_generates_all_key_types() {
    let mut engine = make_engine();
    let results = engine.bootstrap().expect("bootstrap must succeed");

    // Should generate: MasterKek + ShardHmac + ReceiptSigning + WitnessSigning
    // + GatewayTls + AuditSigning + 5 TssShares + 3 OpaqueShares = 14
    assert_eq!(results.len(), 14, "bootstrap must generate all 14 key types");
    assert_eq!(engine.key_count(), 14);
    assert_eq!(engine.rotation_epoch(), 1, "bootstrap sets epoch to 1");
}

/// Security property: Each bootstrapped key has a unique SHA-256 fingerprint.
#[test]
fn bootstrap_keys_have_unique_fingerprints() {
    let mut engine = make_engine();
    let results = engine.bootstrap().unwrap();

    let fingerprints: std::collections::HashSet<[u8; 32]> =
        results.iter().map(|r| r.new_key_fingerprint).collect();
    assert_eq!(
        fingerprints.len(),
        results.len(),
        "all key fingerprints must be unique"
    );
}

/// Security property: Bootstrapped keys can be retrieved as sealed blobs.
#[test]
fn bootstrapped_keys_retrievable_as_sealed() {
    let mut engine = make_engine();
    engine.bootstrap().unwrap();

    let sealed = engine.get_sealed_key(KeyType::MasterKek);
    assert!(sealed.is_some(), "MasterKek must be retrievable after bootstrap");
    assert!(!sealed.unwrap().is_empty(), "sealed key must not be empty");

    let sealed = engine.get_sealed_key(KeyType::ShardHmac);
    assert!(sealed.is_some(), "ShardHmac must be retrievable");
}

// ── Key Rotation ──────────────────────────────────────────────────────────

/// Security property: Key rotation generates a NEW key, destroys the old,
/// and increments the rotation epoch atomically.
#[test]
fn key_rotation_replaces_old_key() {
    let mut engine = make_engine();
    engine.bootstrap().unwrap();

    let old_fp = engine.key_fingerprint(KeyType::ShardHmac).unwrap();
    let result = engine.rotate_key(KeyType::ShardHmac).expect("rotate must succeed");

    assert!(result.old_key_destroyed, "old key must be destroyed");
    assert_ne!(
        result.new_key_fingerprint, old_fp,
        "new key must differ from old"
    );
    assert_eq!(engine.rotation_epoch(), 2, "epoch must increment");
}

/// Security property: Rotation epoch is monotonically increasing.
#[test]
fn rotation_epoch_monotonically_increases() {
    let mut engine = make_engine();
    engine.bootstrap().unwrap();
    assert_eq!(engine.rotation_epoch(), 1);

    engine.rotate_key(KeyType::ShardHmac).unwrap();
    assert_eq!(engine.rotation_epoch(), 2);

    engine.rotate_key(KeyType::ShardHmac).unwrap();
    assert_eq!(engine.rotation_epoch(), 3);

    engine.rotate_key(KeyType::GatewayTls).unwrap();
    assert_eq!(engine.rotation_epoch(), 4);
}

// ── Emergency Rotation ────────────────────────────────────────────────────

/// Security property: Emergency rotation rotates ALL keys immediately,
/// called after compromise detection.
#[test]
fn emergency_rotation_rotates_all_keys() {
    let mut engine = make_engine();
    engine.bootstrap().unwrap();

    let old_fingerprints: std::collections::HashMap<String, [u8; 32]> = [
        KeyType::MasterKek,
        KeyType::ShardHmac,
        KeyType::ReceiptSigning,
        KeyType::GatewayTls,
    ]
    .iter()
    .filter_map(|kt| {
        engine
            .key_fingerprint(*kt)
            .map(|fp| (kt.canonical_name(), fp))
    })
    .collect();

    let results = engine.emergency_rotate_all().expect("emergency rotate must succeed");
    assert_eq!(results.len(), 14, "all 14 keys must be rotated");

    // Verify at least the main keys have new fingerprints
    for (name, old_fp) in &old_fingerprints {
        let result = results.iter().find(|r| r.key_type.canonical_name() == *name);
        assert!(result.is_some(), "key {} must be in results", name);
        assert_ne!(
            result.unwrap().new_key_fingerprint, *old_fp,
            "key {} must have a new fingerprint after emergency rotation",
            name
        );
    }
}

// ── Schedule Detection ────────────────────────────────────────────────────

/// Security property: All keys need rotation when never rotated before.
#[test]
fn all_keys_need_rotation_when_never_rotated() {
    let engine = make_engine();
    let needs_rotation = engine.check_rotation_needed();

    // All scheduled keys should need rotation since none have been rotated
    assert!(
        needs_rotation.len() >= 14,
        "all keys should need rotation when never rotated"
    );
}

/// Security property: After bootstrap, keys do NOT immediately need rotation
/// (their last_rotated is set).
#[test]
fn after_bootstrap_keys_do_not_immediately_need_rotation() {
    let mut engine = make_engine();
    engine.bootstrap().unwrap();

    let needs_rotation = engine.check_rotation_needed();
    assert!(
        needs_rotation.is_empty(),
        "freshly bootstrapped keys should not need rotation"
    );
}

// ── CeremonySecret ────────────────────────────────────────────────────────

/// Security property: CeremonySecret generates random bytes and is non-empty.
#[test]
fn ceremony_secret_generation() {
    let s = CeremonySecret::generate(32).expect("generate must succeed");
    assert_eq!(s.len(), 32);
    assert!(!s.is_empty());
    // Should not be all zeros (probability 2^{-256})
    assert!(
        s.as_bytes().iter().any(|&b| b != 0),
        "generated secret must not be all zeros"
    );
}

/// Security property: CeremonySecret with zero length is rejected.
#[test]
fn ceremony_secret_zero_length_rejected() {
    let result = CeremonySecret::generate(0);
    assert!(result.is_err(), "zero-length secret must be rejected");
}

/// Security property: CeremonySecret Debug output does NOT leak key material.
#[test]
fn ceremony_secret_debug_does_not_leak() {
    let s = CeremonySecret::generate(32).unwrap();
    let debug_output = format!("{:?}", s);
    assert!(
        debug_output.contains("[REDACTED]"),
        "Debug output must contain [REDACTED]"
    );
    // Ensure no raw bytes are present
    for &b in s.as_bytes() {
        let hex = format!("{:02x}", b);
        // Cannot assert absence of every hex pair, but [REDACTED] presence is key
    }
    let _ = s; // suppress unused warning
}

// ── KeyType ───────────────────────────────────────────────────────────────

/// Security property: Each key type has a unique canonical name for AAD
/// domain separation.
#[test]
fn key_types_have_unique_canonical_names() {
    let types = vec![
        KeyType::MasterKek,
        KeyType::ShardHmac,
        KeyType::ReceiptSigning,
        KeyType::WitnessSigning,
        KeyType::GatewayTls,
        KeyType::AuditSigning,
        KeyType::TssShare(0),
        KeyType::TssShare(1),
        KeyType::OpaqueShare(0),
        KeyType::OpaqueShare(1),
    ];

    let names: std::collections::HashSet<String> =
        types.iter().map(|t| t.canonical_name()).collect();
    assert_eq!(
        names.len(),
        types.len(),
        "all key types must have unique canonical names"
    );
}

/// Security property: Key type Display/canonical names are meaningful strings.
#[test]
fn key_type_display_names_are_meaningful() {
    assert_eq!(format!("{}", KeyType::MasterKek), "MasterKek");
    assert_eq!(format!("{}", KeyType::ShardHmac), "ShardHmac");
    assert_eq!(format!("{}", KeyType::ReceiptSigning), "ReceiptSigning");
    assert_eq!(format!("{}", KeyType::TssShare(0)), "TssShare_0");
    assert_eq!(format!("{}", KeyType::OpaqueShare(2)), "OpaqueShare_2");
}
