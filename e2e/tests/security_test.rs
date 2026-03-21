//! Comprehensive security test suite — Phase 7 hardening.
//!
//! Validates tier enforcement, receipt chain integrity, token expiry/tamper
//! detection, ratchet forward secrecy, audit chain integrity, Merkle proofs,
//! multi-person ceremony requirements, risk-based step-up, and the module
//! communication matrix.

use audit::log::AuditLog;
use common::actions::{
    check_action_authorization, validate_multi_person_ceremony, CeremonyParticipant,
};
use common::config::SecurityConfig;
use common::network::is_permitted_channel;
use common::types::{
    ActionLevel, AuditEventType, DeviceTier, ModuleId, Receipt, Token, TokenClaims, TokenHeader,
};
use crypto::receipts::{hash_receipt, sign_receipt};
use crypto::threshold::{dkg, verify_group_signature};
use kt::merkle::MerkleTree;
use ratchet::chain::RatchetChain;
use risk::scoring::{RiskEngine, RiskSignals};
use risk::tiers::check_tier_access;
use tss::token_builder::build_token;
use tss::validator::validate_receipt_chain;
use verifier::verify::verify_token;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

// ── Helpers ──────────────────────────────────────────────────────────────

fn now_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64
}

fn build_valid_receipt_chain(signing_key: &[u8; 64]) -> Vec<Receipt> {
    let session_id = [0x01; 32];
    let user_id = Uuid::nil();
    let dpop_hash = [0x02; 32];
    let ts = now_us();

    let mut r1 = Receipt {
        ceremony_session_id: session_id,
        step_id: 1,
        prev_receipt_hash: [0u8; 32],
        user_id,
        dpop_key_hash: dpop_hash,
        timestamp: ts,
        nonce: [0x10; 32],
        signature: Vec::new(),
        ttl_seconds: 30,
    };
    sign_receipt(&mut r1, signing_key);

    let r1_hash = hash_receipt(&r1);
    let mut r2 = Receipt {
        ceremony_session_id: session_id,
        step_id: 2,
        prev_receipt_hash: r1_hash,
        user_id,
        dpop_key_hash: dpop_hash,
        timestamp: ts + 1_000,
        nonce: [0x20; 32],
        signature: Vec::new(),
        ttl_seconds: 30,
    };
    sign_receipt(&mut r2, signing_key);

    vec![r1, r2]
}

// ── 1. Tier enforcement: sensor cannot access sovereign ─────────────────

#[test]
fn tier_enforcement_sensor_cannot_access_sovereign() {
    let result = check_tier_access(DeviceTier::Sensor, DeviceTier::Sovereign);
    assert!(
        result.is_err(),
        "Sensor (tier 3) must not access Sovereign (tier 1) resources"
    );

    // Sovereign accessing itself should be fine
    let result = check_tier_access(DeviceTier::Sovereign, DeviceTier::Sovereign);
    assert!(result.is_ok());

    // Operational accessing Sensor should be fine (lower number = higher privilege)
    let result = check_tier_access(DeviceTier::Operational, DeviceTier::Sensor);
    assert!(result.is_ok());
}

// ── 2. Receipt chain forgery rejected ───────────────────────────────────

#[test]
fn receipt_chain_forgery_rejected() {
    let signing_key = [0x42u8; 64];
    let mut chain = build_valid_receipt_chain(&signing_key);

    // Tamper with the second receipt's prev_receipt_hash
    chain[1].prev_receipt_hash = [0xFF; 32];

    let result = validate_receipt_chain(&chain, &signing_key);
    assert!(
        result.is_err(),
        "tampered receipt chain must be rejected by TSS"
    );
}

// ── 3. Expired token rejected ───────────────────────────────────────────

#[test]
fn expired_token_rejected() {
    let dkg_result = dkg(5, 3);
    let group_key = dkg_result.group.public_key_package.clone();

    // Build a token that expired in the past
    let claims = TokenClaims {
        sub: Uuid::nil(),
        iss: [0xAA; 32],
        iat: 1_000_000,
        exp: 1_000_001, // far in the past (microseconds since epoch)
        scope: 0x0000_000F,
        dpop_hash: [0xBB; 32],
        ceremony_id: [0xCC; 32],
        tier: 2,
        ratchet_epoch: 1,
    };

    let mut signers: Vec<_> = dkg_result.shares.into_iter().take(3).collect();
    let token =
        build_token(&claims, &mut signers, &dkg_result.group, &[0x55u8; 64]).expect("build token should succeed");

    let result = verify_token(&token, &group_key);
    assert!(result.is_err(), "expired token must be rejected");
    let err = result.unwrap_err();
    assert!(
        format!("{err}").contains("expired"),
        "error should mention expiry"
    );
}

// ── 4. Tampered token rejected ──────────────────────────────────────────

#[test]
fn tampered_token_rejected() {
    let dkg_result = dkg(5, 3);
    let group_key = dkg_result.group.public_key_package.clone();

    // Build a valid, non-expired token
    let claims = TokenClaims {
        sub: Uuid::nil(),
        iss: [0xAA; 32],
        iat: now_us(),
        exp: now_us() + 600_000_000, // 10 minutes from now
        scope: 0x0000_000F,
        dpop_hash: [0xBB; 32],
        ceremony_id: [0xCC; 32],
        tier: 2,
        ratchet_epoch: 1,
    };

    let mut signers: Vec<_> = dkg_result.shares.into_iter().take(3).collect();
    let mut token =
        build_token(&claims, &mut signers, &dkg_result.group, &[0x55u8; 64]).expect("build token should succeed");

    // Tamper with claims — change the tier
    token.claims.tier = 1;

    let result = verify_token(&token, &group_key);
    assert!(result.is_err(), "tampered token must be rejected");
}

// ── 5. Ratchet forward secrecy ──────────────────────────────────────────

#[test]
fn ratchet_forward_secrecy() {
    let master = [0x99u8; 64];
    let mut chain = RatchetChain::new(&master);

    // Generate tag at epoch 0
    let claims_bytes = b"test-claims";
    let tag_epoch0 = chain.generate_tag(claims_bytes);

    // Verify it is valid at epoch 0
    assert!(
        chain.verify_tag(claims_bytes, &tag_epoch0, 0),
        "tag should verify at current epoch"
    );

    // Advance the chain past the lookahead window (> 3 epochs)
    let client_e = [0x11u8; 32];
    let server_e = [0x22u8; 32];
    for _ in 0..5 {
        chain.advance(&client_e, &server_e);
    }

    // Old tag should no longer verify — epoch 0 is outside the lookahead window
    assert!(
        !chain.verify_tag(claims_bytes, &tag_epoch0, 0),
        "old epoch tag must NOT verify after advancing past lookahead window"
    );
}

// ── 6. Audit chain integrity ────────────────────────────────────────────

#[test]
fn audit_chain_integrity() {
    let mut log = AuditLog::new();
    log.append(
        AuditEventType::AuthSuccess,
        vec![Uuid::new_v4()],
        vec![Uuid::new_v4()],
        0.1,
        Vec::new(),
    );
    log.append(
        AuditEventType::KeyRotation,
        vec![Uuid::new_v4()],
        vec![Uuid::new_v4()],
        0.0,
        Vec::new(),
    );
    log.append(
        AuditEventType::AuthFailure,
        vec![Uuid::new_v4()],
        vec![Uuid::new_v4()],
        0.5,
        Vec::new(),
    );

    assert!(log.verify_chain(), "untampered audit chain must verify");
    assert_eq!(log.len(), 3);
}

// ── 7. Merkle inclusion proof valid ─────────────────────────────────────

#[test]
fn merkle_inclusion_proof_valid() {
    let mut tree = MerkleTree::new();
    let user1 = Uuid::new_v4();
    let user2 = Uuid::new_v4();
    let cred1 = [0xAA; 32];
    let cred2 = [0xBB; 32];
    let ts = now_us();

    let leaf0 = tree.append_credential_op(&user1, "register", &cred1, ts);
    let _leaf1 = tree.append_credential_op(&user2, "register", &cred2, ts + 1);
    let _leaf2 = tree.append_credential_op(&user1, "rotate", &cred1, ts + 2);
    let _leaf3 = tree.append_credential_op(&user2, "revoke", &cred2, ts + 3);

    let root = tree.root();
    let proof = tree
        .inclusion_proof(0)
        .expect("proof for existing index should succeed");

    assert!(
        MerkleTree::verify_inclusion(&root, &leaf0, &proof, 0),
        "valid inclusion proof must verify"
    );

    // Tampered leaf should fail
    let fake_leaf = [0xFF; 32];
    assert!(
        !MerkleTree::verify_inclusion(&root, &fake_leaf, &proof, 0),
        "tampered leaf must fail verification"
    );
}

// ── 8. Level-4 (Sovereign) action needs 3 participants from 3 depts ────

#[test]
fn action_level_sovereign_needs_three() {
    let auth = check_action_authorization(1, ActionLevel::Sovereign, true, true);
    assert!(
        auth.requires_sovereign,
        "Sovereign actions must require sovereign ceremony"
    );
    assert!(
        auth.requires_two_person,
        "Sovereign actions must require multi-person"
    );

    // Two participants from same department must fail
    let participants_two = vec![
        CeremonyParticipant {
            user_id: Uuid::new_v4(),
            department: "ops".to_string(),
            authenticated_at: now_us(),
            device_id: Uuid::new_v4(),
        },
        CeremonyParticipant {
            user_id: Uuid::new_v4(),
            department: "sec".to_string(),
            authenticated_at: now_us(),
            device_id: Uuid::new_v4(),
        },
    ];
    let result = validate_multi_person_ceremony(&participants_two, ActionLevel::Sovereign);
    assert!(
        result.is_err(),
        "sovereign ceremony with only 2 participants must fail"
    );

    // Three participants from same department must fail
    let participants_same_dept = vec![
        CeremonyParticipant {
            user_id: Uuid::new_v4(),
            department: "ops".to_string(),
            authenticated_at: now_us(),
            device_id: Uuid::new_v4(),
        },
        CeremonyParticipant {
            user_id: Uuid::new_v4(),
            department: "ops".to_string(),
            authenticated_at: now_us(),
            device_id: Uuid::new_v4(),
        },
        CeremonyParticipant {
            user_id: Uuid::new_v4(),
            department: "ops".to_string(),
            authenticated_at: now_us(),
            device_id: Uuid::new_v4(),
        },
    ];
    let result = validate_multi_person_ceremony(&participants_same_dept, ActionLevel::Sovereign);
    assert!(
        result.is_err(),
        "sovereign ceremony with same-department participants must fail"
    );

    // Three participants from three different departments must succeed
    let participants_ok = vec![
        CeremonyParticipant {
            user_id: Uuid::new_v4(),
            department: "ops".to_string(),
            authenticated_at: now_us(),
            device_id: Uuid::new_v4(),
        },
        CeremonyParticipant {
            user_id: Uuid::new_v4(),
            department: "sec".to_string(),
            authenticated_at: now_us(),
            device_id: Uuid::new_v4(),
        },
        CeremonyParticipant {
            user_id: Uuid::new_v4(),
            department: "eng".to_string(),
            authenticated_at: now_us(),
            device_id: Uuid::new_v4(),
        },
    ];
    let result = validate_multi_person_ceremony(&participants_ok, ActionLevel::Sovereign);
    assert!(
        result.is_ok(),
        "sovereign ceremony with 3 participants from 3 departments must succeed"
    );
}

// ── 9. Risk score triggers step-up ──────────────────────────────────────

#[test]
fn risk_score_triggers_step_up() {
    let engine = RiskEngine::new();
    let user = Uuid::new_v4();

    // Normal signals — no step-up
    let normal_signals = RiskSignals {
        device_attestation_age_secs: 10.0,
        geo_velocity_kmh: 0.0,
        is_unusual_network: false,
        is_unusual_time: false,
        unusual_access_score: 0.0,
        recent_failed_attempts: 0,
    };
    let score = engine.compute_score(&user, &normal_signals);
    assert!(
        !engine.requires_step_up(score),
        "normal signals must NOT trigger step-up (score={score})"
    );

    // High-risk signals — step-up required
    let risky_signals = RiskSignals {
        device_attestation_age_secs: 7200.0,
        geo_velocity_kmh: 1500.0,
        is_unusual_network: true,
        is_unusual_time: true,
        unusual_access_score: 0.9,
        recent_failed_attempts: 5,
    };
    let score = engine.compute_score(&user, &risky_signals);
    assert!(
        engine.requires_step_up(score),
        "high-risk signals must trigger step-up (score={score})"
    );
    assert!(
        engine.requires_termination(score),
        "extremely high-risk signals must trigger termination (score={score})"
    );
}

// ── 10. Communication matrix enforced ───────────────────────────────────

#[test]
fn communication_matrix_enforced() {
    // Permitted channels
    assert!(is_permitted_channel(
        ModuleId::Gateway,
        ModuleId::Orchestrator
    ));
    assert!(is_permitted_channel(
        ModuleId::Orchestrator,
        ModuleId::Opaque
    ));
    assert!(is_permitted_channel(ModuleId::Orchestrator, ModuleId::Tss));
    assert!(is_permitted_channel(ModuleId::Orchestrator, ModuleId::Risk));
    assert!(is_permitted_channel(
        ModuleId::Orchestrator,
        ModuleId::Ratchet
    ));
    assert!(is_permitted_channel(ModuleId::Tss, ModuleId::Tss));
    assert!(is_permitted_channel(ModuleId::Verifier, ModuleId::Ratchet));
    assert!(is_permitted_channel(ModuleId::Verifier, ModuleId::Tss));

    // Audit receives from all
    assert!(is_permitted_channel(ModuleId::Gateway, ModuleId::Audit));
    assert!(is_permitted_channel(ModuleId::Risk, ModuleId::Audit));
    assert!(is_permitted_channel(ModuleId::Kt, ModuleId::Audit));

    // Denied channels
    assert!(
        !is_permitted_channel(ModuleId::Gateway, ModuleId::Tss),
        "Gateway must NOT talk directly to TSS"
    );
    assert!(
        !is_permitted_channel(ModuleId::Gateway, ModuleId::Opaque),
        "Gateway must NOT talk directly to OPAQUE"
    );
    assert!(
        !is_permitted_channel(ModuleId::Verifier, ModuleId::Opaque),
        "Verifier must NOT talk to OPAQUE"
    );
    assert!(
        !is_permitted_channel(ModuleId::Gateway, ModuleId::Risk),
        "Gateway must NOT talk directly to Risk"
    );
    assert!(
        !is_permitted_channel(ModuleId::Gateway, ModuleId::Kt),
        "Gateway must NOT talk directly to KT"
    );
    assert!(
        !is_permitted_channel(ModuleId::Opaque, ModuleId::Ratchet),
        "OPAQUE must NOT talk directly to Ratchet"
    );
}

// ── Additional: SecurityConfig sanity ───────────────────────────────────

#[test]
fn security_config_defaults_are_sane() {
    let cfg = SecurityConfig::default();

    // Tier 4 (emergency) must have the shortest lifetime
    assert!(cfg.token_lifetime_tier4_secs < cfg.token_lifetime_tier1_secs);
    assert!(cfg.token_lifetime_tier4_secs < cfg.token_lifetime_tier2_secs);
    assert!(cfg.token_lifetime_tier4_secs < cfg.token_lifetime_tier3_secs);

    // DDoS puzzle difficulty must be higher than normal
    assert!(cfg.puzzle_difficulty_ddos > cfg.puzzle_difficulty_normal);

    // Max ratchet epochs matches expected (28800 / 30 = 960)
    assert_eq!(cfg.max_ratchet_epochs(), 960);
}
