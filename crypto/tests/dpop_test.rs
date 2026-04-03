use crypto::dpop::*;

fn run_with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(f)
        .expect("thread spawn failed")
        .join()
        .expect("thread panicked");
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[test]
fn test_dpop_key_hash_deterministic() {
    let key = [42u8; 32];
    let h1 = dpop_key_hash(&key);
    let h2 = dpop_key_hash(&key);
    assert_eq!(h1, h2);
}

#[test]
fn test_dpop_key_hash_different_keys_differ() {
    let h1 = dpop_key_hash(&[1u8; 32]);
    let h2 = dpop_key_hash(&[2u8; 32]);
    assert_ne!(h1, h2);
}

#[test]
fn test_dpop_proof_generation_and_verification() {
    run_with_large_stack(|| {
        let (sk, vk) = generate_dpop_keypair_raw();
        let claims = b"test-claims";
        let timestamp = now_secs();
        let proof = generate_dpop_proof(&sk, claims, timestamp);
        let vk_bytes = vk.encode();
        let key_hash = dpop_key_hash(vk_bytes.as_ref());
        assert!(verify_dpop_proof(&vk, &proof, claims, timestamp, &key_hash));
    });
}

#[test]
fn test_dpop_proof_rejects_wrong_key() {
    run_with_large_stack(|| {
        let (sk1, _vk1) = generate_dpop_keypair_raw();
        let (_sk2, vk2) = generate_dpop_keypair_raw();
        let claims = b"test-claims";
        let timestamp = now_secs();
        let proof = generate_dpop_proof(&sk1, claims, timestamp);
        let vk2_bytes = vk2.encode();
        let key_hash = dpop_key_hash(vk2_bytes.as_ref());
        // vk2 won't match the signature made with sk1
        assert!(!verify_dpop_proof(&vk2, &proof, claims, timestamp, &key_hash));
    });
}

#[test]
fn test_dpop_proof_rejects_wrong_claims() {
    run_with_large_stack(|| {
        let (sk, vk) = generate_dpop_keypair_raw();
        let timestamp = now_secs();
        let proof = generate_dpop_proof(&sk, b"original", timestamp);
        let vk_bytes = vk.encode();
        let key_hash = dpop_key_hash(vk_bytes.as_ref());
        assert!(!verify_dpop_proof(&vk, &proof, b"tampered", timestamp, &key_hash));
    });
}

#[test]
fn test_dpop_key_hash_length_is_64() {
    let key = [0xFFu8; 32];
    let hash = dpop_key_hash(&key);
    assert_eq!(hash.len(), 64);
}

#[test]
fn test_dpop_proof_rejects_wrong_timestamp() {
    run_with_large_stack(|| {
        let (sk, vk) = generate_dpop_keypair_raw();
        let claims = b"claims-data";
        let ts = now_secs();
        let proof = generate_dpop_proof(&sk, claims, ts);
        let vk_bytes = vk.encode();
        let key_hash = dpop_key_hash(vk_bytes.as_ref());
        // Verify with a wildly different timestamp — signature won't match
        assert!(!verify_dpop_proof(&vk, &proof, claims, ts + 9999, &key_hash));
    });
}

#[test]
fn test_guarded_keypair_sign_and_verify() {
    run_with_large_stack(|| {
        let (guarded_sk, vk) = generate_dpop_keypair();
        let claims = b"guarded-test";
        let timestamp = now_secs();
        let proof = generate_dpop_proof(guarded_sk.signing_key(), claims, timestamp);
        let vk_bytes = vk.encode();
        let key_hash = dpop_key_hash(vk_bytes.as_ref());
        assert!(verify_dpop_proof(&vk, &proof, claims, timestamp, &key_hash));
    });
}

// ── DPoP timestamp freshness hardening tests ──

#[test]
fn test_dpop_stale_timestamp_rejected() {
    // A proof with a timestamp >30s in the past must be rejected.
    run_with_large_stack(|| {
        let (sk, vk) = generate_dpop_keypair_raw();
        let vk_bytes = vk.encode();
        let key_hash = dpop_key_hash(vk_bytes.as_ref());
        let claims = b"freshness-test";
        // 60 seconds ago — well beyond the 30s window
        let stale_ts = now_secs() - 60;
        let proof = generate_dpop_proof(&sk, claims, stale_ts);
        assert!(
            !verify_dpop_proof(&vk, &proof, claims, stale_ts, &key_hash),
            "proof with 60s-old timestamp must be rejected (DPOP_MAX_AGE_SECS=30)"
        );
    });
}

#[test]
fn test_dpop_future_timestamp_rejected() {
    // A proof with a timestamp >30s in the future must be rejected.
    run_with_large_stack(|| {
        let (sk, vk) = generate_dpop_keypair_raw();
        let vk_bytes = vk.encode();
        let key_hash = dpop_key_hash(vk_bytes.as_ref());
        let claims = b"freshness-test";
        // 60 seconds in the future — well beyond the 30s window
        let future_ts = now_secs() + 60;
        let proof = generate_dpop_proof(&sk, claims, future_ts);
        assert!(
            !verify_dpop_proof(&vk, &proof, claims, future_ts, &key_hash),
            "proof with 60s-future timestamp must be rejected (DPOP_MAX_AGE_SECS=30)"
        );
    });
}

#[test]
fn test_dpop_fresh_timestamp_accepted() {
    // A proof with a timestamp within the 30s window must be accepted.
    run_with_large_stack(|| {
        let (sk, vk) = generate_dpop_keypair_raw();
        let vk_bytes = vk.encode();
        let key_hash = dpop_key_hash(vk_bytes.as_ref());
        let claims = b"freshness-test";
        // Current time — well within the 30s window
        let fresh_ts = now_secs();
        let proof = generate_dpop_proof(&sk, claims, fresh_ts);
        assert!(
            verify_dpop_proof(&vk, &proof, claims, fresh_ts, &key_hash),
            "proof with current timestamp must be accepted"
        );
    });
}

#[test]
fn test_dpop_boundary_31s_past_rejected() {
    // 32 seconds old -- safely past the 30s boundary.
    // Uses 32s instead of 31s to avoid wall-clock race.
    run_with_large_stack(|| {
        let (sk, vk) = generate_dpop_keypair_raw();
        let vk_bytes = vk.encode();
        let key_hash = dpop_key_hash(vk_bytes.as_ref());
        let claims = b"boundary-test";
        let ts = now_secs() - 32;
        let proof = generate_dpop_proof(&sk, claims, ts);
        assert!(
            !verify_dpop_proof(&vk, &proof, claims, ts, &key_hash),
            "proof 32s old must be rejected (> DPOP_MAX_AGE_SECS=30)"
        );
    });
}

#[test]
fn test_dpop_boundary_31s_future_rejected() {
    // 32 seconds in the future -- safely past the 30s boundary.
    // Uses 32s instead of 31s to avoid wall-clock race: between test's
    // now_secs() and verify_dpop_proof's internal SystemTime::now(), up to
    // 1 second can elapse, shifting the effective delta by 1s.
    run_with_large_stack(|| {
        let (sk, vk) = generate_dpop_keypair_raw();
        let vk_bytes = vk.encode();
        let key_hash = dpop_key_hash(vk_bytes.as_ref());
        let claims = b"boundary-test";
        let ts = now_secs() + 32;
        let proof = generate_dpop_proof(&sk, claims, ts);
        assert!(
            !verify_dpop_proof(&vk, &proof, claims, ts, &key_hash),
            "proof 32s in future must be rejected (> DPOP_MAX_AGE_SECS=30)"
        );
    });
}

#[test]
fn test_dpop_boundary_exactly_30s_past_accepted() {
    // 28 seconds old -- safely within the 30s boundary.
    // Uses 28s instead of exact 30s to avoid wall-clock race: between test's
    // now_secs() and verify_dpop_proof's internal SystemTime::now(), up to
    // 2 seconds can elapse, shifting the effective delta past the boundary.
    run_with_large_stack(|| {
        let (sk, vk) = generate_dpop_keypair_raw();
        let vk_bytes = vk.encode();
        let key_hash = dpop_key_hash(vk_bytes.as_ref());
        let claims = b"boundary-test";
        let ts = now_secs() - 28;
        let proof = generate_dpop_proof(&sk, claims, ts);
        assert!(
            verify_dpop_proof(&vk, &proof, claims, ts, &key_hash),
            "proof 28s old should be accepted (within DPOP_MAX_AGE_SECS=30)"
        );
    });
}

#[test]
fn test_dpop_boundary_exactly_30s_future_accepted() {
    // 28 seconds in the future -- safely within the 30s boundary.
    // Uses 28s instead of exact 30s to avoid wall-clock race.
    run_with_large_stack(|| {
        let (sk, vk) = generate_dpop_keypair_raw();
        let vk_bytes = vk.encode();
        let key_hash = dpop_key_hash(vk_bytes.as_ref());
        let claims = b"boundary-test";
        let ts = now_secs() + 28;
        let proof = generate_dpop_proof(&sk, claims, ts);
        assert!(
            verify_dpop_proof(&vk, &proof, claims, ts, &key_hash),
            "proof 28s in future should be accepted (within DPOP_MAX_AGE_SECS=30)"
        );
    });
}

#[test]
fn test_dpop_very_old_timestamp_rejected() {
    // Timestamp from a year ago — must be rejected.
    run_with_large_stack(|| {
        let (sk, vk) = generate_dpop_keypair_raw();
        let vk_bytes = vk.encode();
        let key_hash = dpop_key_hash(vk_bytes.as_ref());
        let claims = b"replay-test";
        let ancient_ts = now_secs() - 365 * 24 * 3600;
        let proof = generate_dpop_proof(&sk, claims, ancient_ts);
        assert!(
            !verify_dpop_proof(&vk, &proof, claims, ancient_ts, &key_hash),
            "proof from a year ago must be rejected"
        );
    });
}
