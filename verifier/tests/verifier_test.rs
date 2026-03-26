use common::domain;
use common::error::MilnetError;
use common::types::{Token, TokenClaims, TokenHeader};
use crypto::pq_sign::{generate_pq_keypair, pq_sign, PqSigningKey, PqVerifyingKey};
use crypto::threshold;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

type HmacSha512 = Hmac<Sha512>;

/// Deterministic ratchet key for tests.
fn test_ratchet_key() -> [u8; 64] {
    [0xCD; 64]
}

/// Compute an HMAC-SHA512 ratchet tag (mirrors token_builder logic).
fn compute_ratchet_tag(ratchet_key: &[u8; 64], claims_bytes: &[u8], epoch: u64) -> [u8; 64] {
    let mut mac =
        HmacSha512::new_from_slice(ratchet_key).expect("HMAC-SHA512 accepts any key length");
    mac.update(domain::TOKEN_TAG);
    mac.update(claims_bytes);
    mac.update(&epoch.to_le_bytes());
    mac.finalize().into_bytes().into()
}

/// Lazily-generated PQ keypair shared across tests that don't care about key identity.
fn test_pq_keypair() -> (PqSigningKey, PqVerifyingKey) {
    generate_pq_keypair()
}

/// Helper: build a valid signed token with a real ratchet tag and real PQ signature.
fn build_signed_token(
    dkg: &mut threshold::DkgResult,
    claims: TokenClaims,
    ratchet_key: &[u8; 64],
    pq_sk: &PqSigningKey,
) -> Token {
    // Serialize claims with domain prefix
    let claims_bytes = postcard::to_allocvec(&claims).unwrap();
    let mut message = Vec::with_capacity(domain::FROST_TOKEN.len() + claims_bytes.len());
    message.extend_from_slice(domain::FROST_TOKEN);
    message.extend_from_slice(&claims_bytes);

    let frost_signature =
        threshold::threshold_sign(&mut dkg.shares, &dkg.group, &message, dkg.group.threshold)
            .unwrap();

    let ratchet_tag = compute_ratchet_tag(ratchet_key, &claims_bytes, claims.ratchet_epoch);
    let pq_signature = pq_sign(pq_sk, &message, &frost_signature);

    Token {
        header: TokenHeader {
            version: 1,
            algorithm: 1,
            tier: claims.tier,
        },
        claims,
        ratchet_tag,
        frost_signature,
        pq_signature,
    }
}

/// Helper: build a signed token with a dummy ratchet tag but real PQ signature.
fn build_signed_token_legacy(
    dkg: &mut threshold::DkgResult,
    claims: TokenClaims,
    pq_sk: &PqSigningKey,
) -> Token {
    let claims_bytes = postcard::to_allocvec(&claims).unwrap();
    let mut message = Vec::with_capacity(domain::FROST_TOKEN.len() + claims_bytes.len());
    message.extend_from_slice(domain::FROST_TOKEN);
    message.extend_from_slice(&claims_bytes);

    let frost_signature =
        threshold::threshold_sign(&mut dkg.shares, &dkg.group, &message, dkg.group.threshold)
            .unwrap();

    let pq_signature = pq_sign(pq_sk, &message, &frost_signature);

    Token {
        header: TokenHeader {
            version: 1,
            algorithm: 1,
            tier: claims.tier,
        },
        claims,
        ratchet_tag: [0xAA; 64],
        frost_signature,
        pq_signature,
    }
}

/// Test DPoP client key used across tests.
const TEST_DPOP_KEY: [u8; 32] = [0xDD; 32];

/// Helper: create claims that expire in the future.
/// All claims include DPoP binding and audience since both are now mandatory.
fn future_claims() -> TokenClaims {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64;
    TokenClaims {
        sub: Uuid::new_v4(),
        iss: [0x01; 32],
        iat: now,
        exp: now + 30_000_000, // +30 seconds
        scope: 0x0000_000F,
        dpop_hash: crypto::dpop::dpop_key_hash(&TEST_DPOP_KEY),
        ceremony_id: [0xCC; 32],
        tier: 3,
        ratchet_epoch: 1,
        token_id: [0xAB; 16],
        aud: Some("test-service".to_string()),
        classification: 0,
    }
}

/// Helper: create tier-2 claims for DPoP-mandatory tests.
fn future_claims_tier2() -> TokenClaims {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64;
    TokenClaims {
        sub: Uuid::new_v4(),
        iss: [0x01; 32],
        iat: now,
        exp: now + 30_000_000,
        scope: 0x0000_000F,
        dpop_hash: crypto::dpop::dpop_key_hash(&TEST_DPOP_KEY),
        ceremony_id: [0xCC; 32],
        tier: 2,
        ratchet_epoch: 1,
        token_id: [0xAB; 16],
        aud: Some("test-service".to_string()),
        classification: 0,
    }
}

#[test]
fn valid_token_verifies() {
    let mut dkg = threshold::dkg(5, 3);
    let (pq_sk, pq_vk) = test_pq_keypair();
    let claims = future_claims();
    let expected_sub = claims.sub;
    let expected_scope = claims.scope;
    let expected_tier = claims.tier;

    let token = build_signed_token_legacy(&mut dkg, claims, &pq_sk);
    let result = verifier::verify_token_bound(&token, &dkg.group.public_key_package, &pq_vk, &TEST_DPOP_KEY);

    assert!(result.is_ok(), "expected valid token: {:?}", result.err());
    let verified_claims = result.unwrap();
    assert_eq!(verified_claims.sub, expected_sub);
    assert_eq!(verified_claims.scope, expected_scope);
    assert_eq!(verified_claims.tier, expected_tier);
}

#[test]
fn expired_token_rejected() {
    let mut dkg = threshold::dkg(5, 3);
    let (pq_sk, pq_vk) = test_pq_keypair();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64;

    let claims = TokenClaims {
        sub: Uuid::new_v4(),
        iss: [0x01; 32],
        iat: now - 60_000_000,
        exp: now - 1_000_000, // expired 1 second ago
        scope: 0x0000_000F,
        dpop_hash: [0xBB; 64],
        ceremony_id: [0xCC; 32],
        tier: 1,
        ratchet_epoch: 1,
        token_id: [0xAB; 16],
        aud: Some("test-service".to_string()),
        classification: 0,
    };

    let token = build_signed_token_legacy(&mut dkg, claims, &pq_sk);
    let result = verifier::verify_token(&token, &dkg.group.public_key_package, &pq_vk);

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), MilnetError::CryptoVerification(_)),
        "expected CryptoVerification error for expired token"
    );
}

#[test]
fn tampered_signature_rejected() {
    let mut dkg = threshold::dkg(5, 3);
    let (pq_sk, pq_vk) = test_pq_keypair();
    let claims = future_claims();
    let mut token = build_signed_token_legacy(&mut dkg, claims, &pq_sk);

    // Flip a byte in the FROST signature
    token.frost_signature[0] ^= 0xFF;

    let result = verifier::verify_token_bound(&token, &dkg.group.public_key_package, &pq_vk, &TEST_DPOP_KEY);
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), MilnetError::CryptoVerification(_)),
        "expected CryptoVerification error"
    );
}

#[test]
fn tampered_claims_rejected() {
    let mut dkg = threshold::dkg(5, 3);
    let (pq_sk, pq_vk) = test_pq_keypair();
    let claims = future_claims();
    let mut token = build_signed_token_legacy(&mut dkg, claims, &pq_sk);

    // Modify claims after signing — signature should no longer match
    token.claims.scope = 0xFFFF_FFFF;

    let result = verifier::verify_token_bound(&token, &dkg.group.public_key_package, &pq_vk, &TEST_DPOP_KEY);
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), MilnetError::CryptoVerification(_)),
        "expected CryptoVerification error"
    );
}

#[test]
fn wrong_group_key_rejected() {
    let mut dkg1 = threshold::dkg(5, 3);
    let dkg2 = threshold::dkg(5, 3);
    let (pq_sk, pq_vk) = test_pq_keypair();
    let claims = future_claims();
    let token = build_signed_token_legacy(&mut dkg1, claims, &pq_sk);

    // Verify with a different group's key
    let result = verifier::verify_token_bound(&token, &dkg2.group.public_key_package, &pq_vk, &TEST_DPOP_KEY);
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), MilnetError::CryptoVerification(_)),
        "expected CryptoVerification error"
    );
}

// ── Ratchet-aware verification tests ─────────────────────────────────

#[test]
fn test_ratchet_tag_verifies() {
    let mut dkg = threshold::dkg(5, 3);
    let (pq_sk, pq_vk) = test_pq_keypair();
    let ratchet_key = test_ratchet_key();
    let claims = future_claims();
    let epoch = claims.ratchet_epoch;

    let token = build_signed_token(&mut dkg, claims, &ratchet_key, &pq_sk);
    let result = verifier::verify_token_with_ratchet_bound(
        &token,
        &dkg.group.public_key_package,
        &pq_vk,
        &ratchet_key,
        epoch,
        &TEST_DPOP_KEY,
    );

    assert!(
        result.is_ok(),
        "expected ratchet verification to succeed: {:?}",
        result.err()
    );
}

#[test]
fn test_ratchet_tag_verifies_within_window() {
    let mut dkg = threshold::dkg(5, 3);
    let (pq_sk, pq_vk) = test_pq_keypair();
    let ratchet_key = test_ratchet_key();
    let claims = future_claims(); // ratchet_epoch = 1
    let token_epoch = claims.ratchet_epoch;

    let token = build_signed_token(&mut dkg, claims, &ratchet_key, &pq_sk);

    // Verifier is at epoch = token_epoch + 3 (within window)
    let result = verifier::verify_token_with_ratchet_bound(
        &token,
        &dkg.group.public_key_package,
        &pq_vk,
        &ratchet_key,
        token_epoch + 3,
        &TEST_DPOP_KEY,
    );
    assert!(
        result.is_ok(),
        "epoch +3 should be within window: {:?}",
        result.err()
    );
}

#[test]
fn test_wrong_ratchet_key_rejected() {
    let mut dkg = threshold::dkg(5, 3);
    let (pq_sk, pq_vk) = test_pq_keypair();
    let ratchet_key = test_ratchet_key();
    let wrong_key = [0xEE; 64];
    let claims = future_claims();
    let epoch = claims.ratchet_epoch;

    let token = build_signed_token(&mut dkg, claims, &ratchet_key, &pq_sk);

    let result = verifier::verify_token_with_ratchet_bound(
        &token,
        &dkg.group.public_key_package,
        &pq_vk,
        &wrong_key,
        epoch,
        &TEST_DPOP_KEY,
    );

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), MilnetError::CryptoVerification(_)),
        "expected CryptoVerification error for wrong ratchet key"
    );
}

#[test]
fn test_wrong_epoch_rejected() {
    let mut dkg = threshold::dkg(5, 3);
    let (pq_sk, pq_vk) = test_pq_keypair();
    let ratchet_key = test_ratchet_key();
    let claims = future_claims(); // ratchet_epoch = 1
    let token_epoch = claims.ratchet_epoch;

    let token = build_signed_token(&mut dkg, claims, &ratchet_key, &pq_sk);

    // Verifier is at epoch = token_epoch + 4 (outside +/-3 window)
    let result = verifier::verify_token_with_ratchet_bound(
        &token,
        &dkg.group.public_key_package,
        &pq_vk,
        &ratchet_key,
        token_epoch + 4,
        &TEST_DPOP_KEY,
    );

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), MilnetError::CryptoVerification(_)),
        "expected CryptoVerification error for epoch outside window"
    );
}

// ── Post-quantum signature tests ─────────────────────────────────────

#[test]
fn test_token_with_pq_signature_verifies() {
    let mut dkg = threshold::dkg(5, 3);
    let (pq_sk, pq_vk) = test_pq_keypair();
    let claims = future_claims();

    let token = build_signed_token_legacy(&mut dkg, claims, &pq_sk);

    // Both FROST and PQ signatures must pass
    let result = verifier::verify_token_bound(&token, &dkg.group.public_key_package, &pq_vk, &TEST_DPOP_KEY);
    assert!(result.is_ok(), "token with valid PQ sig should verify: {:?}", result.err());
    // Verify PQ signature is non-empty
    assert!(!token.pq_signature.is_empty(), "pq_signature must not be empty");
}

#[test]
fn test_missing_pq_signature_rejected() {
    let mut dkg = threshold::dkg(5, 3);
    let (pq_sk, pq_vk) = test_pq_keypair();
    let claims = future_claims();

    let mut token = build_signed_token_legacy(&mut dkg, claims, &pq_sk);
    // Strip the PQ signature
    token.pq_signature = Vec::new();

    let result = verifier::verify_token_bound(&token, &dkg.group.public_key_package, &pq_vk, &TEST_DPOP_KEY);
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("missing post-quantum signature"),
        "expected missing PQ sig error, got: {}",
        err_msg
    );
}

#[test]
fn test_wrong_pq_key_rejected() {
    // ML-DSA-65 generates two full keypairs — needs extra stack space.
    std::thread::Builder::new()
        .name("pq-key-test".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let mut dkg = threshold::dkg(5, 3);
            let (pq_sk, _pq_vk) = test_pq_keypair();
            let (_pq_sk2, pq_vk2) = test_pq_keypair();
            let claims = future_claims();

            let token = build_signed_token_legacy(&mut dkg, claims, &pq_sk);

            // Verify with a different PQ key -- must fail
            let result = verifier::verify_token_bound(&token, &dkg.group.public_key_package, &pq_vk2, &TEST_DPOP_KEY);
            assert!(result.is_err());
            assert!(
                matches!(result.unwrap_err(), MilnetError::CryptoVerification(_)),
                "expected CryptoVerification error for wrong PQ key"
            );
        })
        .expect("spawn test thread")
        .join()
        .expect("test thread panicked");
}

#[test]
fn test_tampered_pq_signature_rejected() {
    let mut dkg = threshold::dkg(5, 3);
    let (pq_sk, pq_vk) = test_pq_keypair();
    let claims = future_claims();

    let mut token = build_signed_token_legacy(&mut dkg, claims, &pq_sk);
    // Corrupt the PQ signature
    if let Some(byte) = token.pq_signature.first_mut() {
        *byte ^= 0xFF;
    }

    let result = verifier::verify_token_bound(&token, &dkg.group.public_key_package, &pq_vk, &TEST_DPOP_KEY);
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), MilnetError::CryptoVerification(_)),
        "expected CryptoVerification error for tampered PQ sig"
    );
}

// ── DPoP tier-aware enforcement tests ─────────────────────────────────

#[test]
fn test_tier2_dpop_rejected_without_client_key_in_basic_verify() {
    // HARDENED: verify_token now rejects tokens with DPoP binding but no client key.
    // A DPoP-bound token MUST always be presented with its proof key to prevent
    // token theft. This is the corrected security posture.
    let mut dkg = threshold::dkg(5, 3);
    let (pq_sk, pq_vk) = test_pq_keypair();
    let claims = future_claims_tier2();
    let token = build_signed_token_legacy(&mut dkg, claims, &pq_sk);

    let result = verifier::verify_token(&token, &dkg.group.public_key_package, &pq_vk);
    assert!(result.is_err(), "tier 2 with DPoP binding but no client key must be rejected");
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("DPoP binding") || err.contains("token theft"),
        "error should mention DPoP binding: {err}"
    );
}

#[test]
fn test_tier2_dpop_rejects_with_wrong_client_key() {
    let mut dkg = threshold::dkg(5, 3);
    let (pq_sk, pq_vk) = test_pq_keypair();
    let claims = future_claims_tier2();
    let token = build_signed_token_legacy(&mut dkg, claims, &pq_sk);

    // verify_token_bound with wrong DPoP key should fail
    let result = verifier::verify_token_bound(
        &token,
        &dkg.group.public_key_package,
        &pq_vk,
        &[0xEE; 32], // wrong key, token was bound to [0xDD; 32]
    );
    assert!(result.is_err(), "tier 2 with wrong DPoP client key should fail");
}

#[test]
fn test_tier2_dpop_mandatory_accepts_with_matching_key() {
    let mut dkg = threshold::dkg(5, 3);
    let (pq_sk, pq_vk) = test_pq_keypair();
    let claims = future_claims_tier2();
    let token = build_signed_token_legacy(&mut dkg, claims, &pq_sk);

    // verify_token_bound with the correct DPoP key should pass
    let result = verifier::verify_token_bound(
        &token,
        &dkg.group.public_key_package,
        &pq_vk,
        &[0xDD; 32],
    );
    assert!(result.is_ok(), "tier 2 with matching DPoP key should pass: {:?}", result.err());
}

#[test]
fn test_tier3_dpop_mandatory_rejects_without_client_key() {
    // DPoP is now mandatory for ALL tiers including tier 3 (sensor).
    // MILNET_DPOP_EXEMPT_TIERS is deprecated and ignored.
    let mut dkg = threshold::dkg(5, 3);
    let (pq_sk, pq_vk) = test_pq_keypair();
    let claims = future_claims(); // tier 3 with DPoP binding
    let token = build_signed_token_legacy(&mut dkg, claims, &pq_sk);

    // verify_token passes None for client_dpop_key -> must be rejected for all tiers
    let result = verifier::verify_token(&token, &dkg.group.public_key_package, &pq_vk);
    assert!(result.is_err(), "tier 3 without DPoP client key must be rejected");
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("DPoP binding") || err.contains("token theft"),
        "error should mention DPoP binding: {err}"
    );
}

// ── DPoP Enforcement Strengthening Tests ───────────────────────────────────

#[test]
fn dpop_no_exemptions_for_any_tier() {
    // DPoP is mandatory for ALL tiers — no exemptions possible.
    // Build a tier 3 token with zero dpop_hash (no DPoP binding) — must be rejected.
    let mut dkg = threshold::dkg(5, 3);
    let (pq_sk, pq_vk) = test_pq_keypair();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64;
    let claims = TokenClaims {
        sub: Uuid::new_v4(),
        iss: [0x01; 32],
        iat: now,
        exp: now + 30_000_000,
        scope: 0x0000_000F,
        dpop_hash: [0u8; 64], // No DPoP binding
        ceremony_id: [0xCC; 32],
        tier: 3,
        ratchet_epoch: 1,
        token_id: [0xAB; 16],
        aud: Some("test-service".to_string()),
        classification: 0,
    };

    let token = build_signed_token_legacy(&mut dkg, claims, &pq_sk);

    let result = verifier::verify_token(&token, &dkg.group.public_key_package, &pq_vk);
    assert!(result.is_err(), "tier 3 without DPoP must be rejected");
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("DPoP binding is required") || err.contains("DPoP is mandatory"),
        "error should mention DPoP requirement: {err}"
    );
}

#[test]
fn dpop_replay_cache_detects_replay() {
    // Same proof hash submitted twice should be detected as replay
    let proof_hash: [u8; 64] = [0xAA; 64];
    let first = verifier::verify::is_dpop_replay(&proof_hash);
    assert!(!first, "first submission should not be a replay");
    let second = verifier::verify::is_dpop_replay(&proof_hash);
    assert!(second, "second submission of same proof should be detected as replay");
}

#[test]
fn dpop_replay_cache_allows_different_proofs() {
    let proof_a: [u8; 64] = [0x01; 64];
    let proof_b: [u8; 64] = [0x02; 64];
    assert!(!verifier::verify::is_dpop_replay(&proof_a));
    assert!(!verifier::verify::is_dpop_replay(&proof_b));
}

#[test]
fn dpop_timestamp_tolerance_is_one_second() {
    let tolerance = verifier::verify::dpop_timestamp_tolerance_secs();
    assert_eq!(tolerance, 1, "default DPoP tolerance should be 1 second");
}

// ── Classification Enforcement Tests ────────────────────────────────────────

#[test]
fn classification_enforcement_denies_insufficient_level() {
    use common::classification::ClassificationLevel;
    use common::revocation::SharedRevocationList;

    let mut dkg = threshold::dkg(5, 3);
    let (pq_sk, pq_vk) = test_pq_keypair();

    // Create a token with Unclassified classification (DPoP binding included)
    let mut claims = future_claims();
    claims.classification = ClassificationLevel::Unclassified.as_u8();

    let token = build_signed_token_legacy(&mut dkg, claims, &pq_sk);
    let revocation = SharedRevocationList::new();

    // Verify against a Secret resource requirement
    let result = verifier::verify::verify_token_with_classification(
        &token,
        &dkg.group.public_key_package,
        &pq_vk,
        &revocation,
        Some(&TEST_DPOP_KEY),
        ClassificationLevel::Secret,
    );
    assert!(result.is_err(), "Unclassified token must be denied access to Secret resource");
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("classification denied"), "error should mention classification: {err}");
}

#[test]
fn classification_enforcement_grants_sufficient_level() {
    use common::classification::ClassificationLevel;
    use common::revocation::SharedRevocationList;

    let mut dkg = threshold::dkg(5, 3);
    let (pq_sk, pq_vk) = test_pq_keypair();

    // Create a token with Secret classification (DPoP binding included)
    let mut claims = future_claims();
    claims.classification = ClassificationLevel::Secret.as_u8();

    let token = build_signed_token_legacy(&mut dkg, claims, &pq_sk);
    let revocation = SharedRevocationList::new();

    // Verify against a Confidential resource (lower requirement)
    let result = verifier::verify::verify_token_with_classification(
        &token,
        &dkg.group.public_key_package,
        &pq_vk,
        &revocation,
        Some(&TEST_DPOP_KEY),
        ClassificationLevel::Confidential,
    );
    assert!(result.is_ok(), "Secret token should access Confidential resource: {:?}", result.err());
}
