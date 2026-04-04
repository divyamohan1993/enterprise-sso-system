use crypto::threshold::*;

// ── Pedersen DKG (dealer-free) tests ────────────────────────────────────────

/// SECURITY: dkg_distributed uses Pedersen DKG, not trusted dealer.
/// No single participant ever holds the complete signing key.
#[test]
fn pedersen_dkg_produces_valid_group_signature() {
    let result = dkg_distributed(5, 3);
    assert_eq!(result.shares.len(), 5);
    assert_eq!(result.group.threshold, 3);
    assert_eq!(result.group.total, 5);

    let mut shares = result.shares;
    let message = b"Pedersen DKG test: dealer-free distributed key generation";
    let combined = threshold_sign(&mut shares, &result.group, message, 3).unwrap();
    assert!(verify_group_signature(&result.group, message, &combined));
}

/// SECURITY: Pedersen DKG with 2-of-5 fails (below threshold).
#[test]
fn pedersen_dkg_below_threshold_fails() {
    let result = dkg_distributed(5, 3);
    let mut shares = result.shares;
    let combined = threshold_sign(&mut shares[..2], &result.group, b"test", 3);
    assert!(combined.is_err());
}

/// SECURITY: Different Pedersen DKG ceremonies produce different group keys.
/// This verifies that each ceremony generates fresh randomness.
#[test]
fn pedersen_dkg_ceremonies_produce_different_keys() {
    let r1 = dkg_distributed(5, 3);
    let r2 = dkg_distributed(5, 3);
    // Group verifying keys should differ (different random polynomials)
    let vk1 = format!("{:?}", r1.group.public_key_package);
    let vk2 = format!("{:?}", r2.group.public_key_package);
    assert_ne!(vk1, vk2, "two independent DKG ceremonies must produce different group keys");
}

/// SECURITY: Pedersen DKG with specific signer subset (indices 2,3,4) works.
#[test]
fn pedersen_dkg_arbitrary_signer_subset() {
    let result = dkg_distributed(5, 3);
    let mut shares = result.shares;
    let message = b"subset signing test";
    // Use signers at indices 2, 3, 4 (not the first 3)
    let combined = threshold_sign_with_indices(
        &mut shares,
        &result.group,
        message,
        3,
        &[2, 3, 4],
    ).unwrap();
    assert!(verify_group_signature(&result.group, message, &combined));
}

// ── Original trusted-dealer tests (kept for regression) ─────────────────────

#[test]
fn frost_3_of_5_produces_valid_signature() {
    #[allow(deprecated)]
    let result = dkg(5, 3).expect("DKG ceremony failed");
    let mut shares = result.shares;
    let message = b"test message for threshold signing";

    let combined = threshold_sign(&mut shares, &result.group, message, 3).unwrap();
    assert!(verify_group_signature(&result.group, message, &combined));
}

#[test]
fn frost_2_of_5_fails() {
    let result = dkg(5, 3).expect("DKG ceremony failed");
    let mut shares = result.shares;
    // Only provide 2 signers for a threshold of 3
    let combined = threshold_sign(&mut shares[..2], &result.group, b"test message", 3);
    assert!(combined.is_err());
}

#[test]
fn nonce_counter_increments() {
    let result = dkg(5, 3).expect("DKG ceremony failed");
    let mut shares = result.shares;
    let msg = b"test";

    // First signing: counters go from 0 -> 1 for first 3 signers
    let _ = threshold_sign(&mut shares, &result.group, msg, 3).unwrap();
    assert_eq!(shares[0].nonce_counter.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(shares[1].nonce_counter.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(shares[2].nonce_counter.load(std::sync::atomic::Ordering::SeqCst), 1);

    // Second signing: counters go from 1 -> 2
    let _ = threshold_sign(&mut shares, &result.group, msg, 3).unwrap();
    assert_eq!(shares[0].nonce_counter.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(shares[1].nonce_counter.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[test]
fn different_messages_different_signatures() {
    let result = dkg(5, 3).expect("DKG ceremony failed");
    let mut shares = result.shares;

    let sig_a = threshold_sign(&mut shares, &result.group, b"message A", 3).unwrap();
    let sig_b = threshold_sign(&mut shares, &result.group, b"message B", 3).unwrap();
    assert_ne!(sig_a, sig_b);
}
