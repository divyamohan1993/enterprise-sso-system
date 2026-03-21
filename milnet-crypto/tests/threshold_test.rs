use milnet_crypto::threshold::*;

#[test]
fn frost_3_of_5_produces_valid_signature() {
    let result = dkg(5, 3);
    let mut shares = result.shares;
    let message = b"test message for threshold signing";

    // Get 3 partial signatures
    let partials: Vec<_> = shares
        .iter_mut()
        .take(3)
        .map(|s| s.partial_sign(message))
        .collect();

    let combined = combine_partials(&result.group, &partials, message).unwrap();
    assert!(verify_group_signature(&result.group, message, &combined));
}

#[test]
fn frost_2_of_5_fails() {
    let result = dkg(5, 3);
    let mut shares = result.shares;
    let message = b"test message";

    let partials: Vec<_> = shares
        .iter_mut()
        .take(2)
        .map(|s| s.partial_sign(message))
        .collect();

    assert!(combine_partials(&result.group, &partials, message).is_err());
}

#[test]
fn nonce_counter_increments() {
    let result = dkg(5, 3);
    let mut shares = result.shares;
    let msg = b"test";

    let p1 = shares[0].partial_sign(msg);
    let p2 = shares[0].partial_sign(msg);
    assert_eq!(p1.nonce_count, 1);
    assert_eq!(p2.nonce_count, 2);
}

#[test]
fn different_messages_different_signatures() {
    let result = dkg(5, 3);
    let mut shares = result.shares;

    let p1 = shares[0].partial_sign(b"message A");
    let p2 = shares[0].partial_sign(b"message B");
    assert_ne!(p1.signature.to_bytes(), p2.signature.to_bytes());
}
