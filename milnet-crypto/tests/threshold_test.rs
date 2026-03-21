use milnet_crypto::threshold::*;

#[test]
fn frost_3_of_5_produces_valid_signature() {
    let result = dkg(5, 3);
    let mut shares = result.shares;
    let message = b"test message for threshold signing";

    let combined = threshold_sign(&mut shares, &result.group, message, 3).unwrap();
    assert!(verify_group_signature(&result.group, message, &combined));
}

#[test]
fn frost_2_of_5_fails() {
    let result = dkg(5, 3);
    let mut shares = result.shares;
    // Only provide 2 signers for a threshold of 3
    let combined = threshold_sign(&mut shares[..2], &result.group, b"test message", 3);
    assert!(combined.is_err());
}

#[test]
fn nonce_counter_increments() {
    let result = dkg(5, 3);
    let mut shares = result.shares;
    let msg = b"test";

    // First signing: counters go from 0 -> 1 for first 3 signers
    let _ = threshold_sign(&mut shares, &result.group, msg, 3).unwrap();
    assert_eq!(shares[0].nonce_counter, 1);
    assert_eq!(shares[1].nonce_counter, 1);
    assert_eq!(shares[2].nonce_counter, 1);

    // Second signing: counters go from 1 -> 2
    let _ = threshold_sign(&mut shares, &result.group, msg, 3).unwrap();
    assert_eq!(shares[0].nonce_counter, 2);
    assert_eq!(shares[1].nonce_counter, 2);
}

#[test]
fn different_messages_different_signatures() {
    let result = dkg(5, 3);
    let mut shares = result.shares;

    let sig_a = threshold_sign(&mut shares, &result.group, b"message A", 3).unwrap();
    let sig_b = threshold_sign(&mut shares, &result.group, b"message B", 3).unwrap();
    assert_ne!(sig_a, sig_b);
}
