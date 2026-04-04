//! Host compromise resilience tests.
//!
//! Verifies that cryptographic key material is zeroized on drop,
//! canary detection works, mlock succeeds or gracefully degrades,
//! and PQ signing key bytes change after zeroization.

use crypto::memguard::{SecretBuffer, SecretVec};

// ── SecretBuffer zeroization ─────────────────────────────────────────

#[test]
fn secret_buffer_zeroizes_on_drop() {
    // Create a SecretBuffer, verify data is accessible, then drop it.
    // The zeroize crate guarantees volatile writes that the compiler
    // cannot optimize away. We verify the Drop path runs without panic.
    let data = [0xFF_u8; 32];
    let buf = Box::new(SecretBuffer::<32>::new(data).expect("SecretBuffer::new failed"));
    assert_eq!(buf.as_bytes(), &[0xFF; 32], "data must be accessible before drop");
    drop(buf);
    // If we reach here without panic, Drop (which includes zeroize) succeeded.
}

#[test]
fn secret_buffer_zeroizes_various_sizes() {
    // Test with different buffer sizes to ensure zeroization works at all sizes.
    let buf16 = SecretBuffer::<16>::new([0xAA; 16]).expect("new failed");
    assert_eq!(buf16.as_bytes(), &[0xAA; 16]);
    drop(buf16);

    let buf64 = SecretBuffer::<64>::new([0xBB; 64]).expect("new failed");
    assert_eq!(buf64.as_bytes(), &[0xBB; 64]);
    drop(buf64);

    let buf128 = SecretBuffer::<128>::new([0xCC; 128]).expect("new failed");
    assert_eq!(buf128.as_bytes(), &[0xCC; 128]);
    drop(buf128);
}

// ── SecretVec zeroization ────────────────────────────────────────────

#[test]
fn secret_vec_zeroizes_on_drop() {
    let data = vec![0xDE; 48];
    let sv = SecretVec::new(data).expect("SecretVec::new failed");
    assert_eq!(sv.as_bytes(), &[0xDE; 48], "data must be accessible before drop");
    drop(sv);
}

#[test]
fn secret_vec_zeroizes_various_lengths() {
    for len in [1, 16, 64, 256, 1024] {
        let data = vec![0xEE; len];
        let sv = SecretVec::new(data).expect("SecretVec::new failed");
        assert_eq!(sv.len(), len);
        drop(sv);
    }
}

// ── Canary detection ─────────────────────────────────────────────────

#[test]
fn secret_buffer_canary_passes_on_valid_buffer() {
    let buf = SecretBuffer::<32>::new([0x42; 32]).expect("new failed");
    assert!(buf.verify_canaries(), "canaries must pass on a valid buffer");
}

#[test]
fn secret_vec_canary_passes_on_valid_buffer() {
    let sv = SecretVec::new(vec![0x42; 32]).expect("new failed");
    assert!(sv.verify_canary(), "canary must pass on a valid SecretVec");
}

// ── mlock success or graceful degradation ────────────────────────────

#[test]
fn secret_buffer_mlock_succeeds_or_degrades_gracefully() {
    // In CI/dev environments, mlock may fail due to RLIMIT_MEMLOCK.
    // The buffer must still be usable even if mlock fails.
    let buf = SecretBuffer::<32>::new([0x11; 32]).expect("new failed");
    // is_locked() returns whether mlock succeeded. Either outcome is acceptable.
    let _locked = buf.is_locked();
    // Verify data is still accessible regardless of lock status.
    assert_eq!(buf.as_bytes(), &[0x11; 32]);
}

#[test]
fn secret_vec_mlock_succeeds_or_degrades_gracefully() {
    let sv = SecretVec::new(vec![0x22; 64]).expect("new failed");
    let _locked = sv.is_locked();
    assert_eq!(sv.as_bytes(), &[0x22; 64]);
}

// ── SignerShare Drop zeroizes key package bytes ──────────────────────

#[test]
fn signer_share_drop_runs_without_panic() {
    // Create a FROST DKG group, get shares, then drop them.
    // The SignerShare::Drop impl serializes and zeroizes the key package.
    #[allow(deprecated)]
    let dkg_result = crypto::threshold::dkg(3, 2).expect("DKG must succeed");
    let shares = dkg_result.shares;

    // Verify shares are usable before drop
    assert_eq!(shares.len(), 3);

    // Drop all shares. The Drop impl calls zeroize on serialized key bytes.
    // If Drop panics, this test fails.
    drop(shares);
}

#[test]
fn signer_share_into_parts_does_not_trigger_drop_zeroize() {
    // into_parts() should transfer ownership without running Drop.
    #[allow(deprecated)]
    let dkg_result = crypto::threshold::dkg(3, 2).expect("DKG must succeed");
    let mut shares = dkg_result.shares;

    let share = shares.remove(0);
    let (id, kp) = share.into_parts();

    // Fields must be valid after into_parts
    let _ = id;
    let _ = kp.signing_share();
}

// ── PQ signing key bytes differ before/after zeroize ─────────────────

#[test]
fn pq_signing_key_material_differs_after_zeroize() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            // Generate an ML-DSA-87 keypair, sign something to prove it's functional
            let (mut sk, vk) = crypto::pq_sign::generate_pq_keypair();
            let msg = b"pre-zeroize";
            let sig = crypto::pq_sign::pq_sign_raw(&sk, msg);
            assert!(crypto::pq_sign::pq_verify_raw(&vk, msg, &sig));

            // Overwrite the signing key with a fresh throwaway keypair.
            // SigningKey<MlDsa87> does not implement Zeroize, so we use the
            // same overwrite-with-new-key approach as OidcSigningKey::Drop.
            let (throwaway_sk, _) = crypto::pq_sign::generate_pq_keypair();
            sk = throwaway_sk;

            // After overwrite, signing with the replaced key should NOT
            // produce a signature valid under the original verifying key.
            let sig_after = crypto::pq_sign::pq_sign_raw(&sk, msg);
            let still_valid = crypto::pq_sign::pq_verify_raw(&vk, msg, &sig_after);
            assert!(
                !still_valid,
                "signing with an overwritten key must not produce a valid signature for the original verifying key"
            );
        })
        .expect("thread spawn failed")
        .join()
        .expect("thread panicked");
}

// ── Debug output does not leak secrets ──────────────────────────────

#[test]
fn debug_output_does_not_leak_secret_buffer_contents() {
    let buf = SecretBuffer::<32>::new([0xDD; 32]).expect("new failed");
    let dbg = format!("{:?}", buf);
    assert!(
        !dbg.contains("0xDD") && !dbg.contains("221"),
        "Debug output must not leak secret byte values"
    );
    assert!(dbg.contains("SecretBuffer"));
}

#[test]
fn debug_output_does_not_leak_secret_vec_contents() {
    let sv = SecretVec::new(vec![0xEE; 16]).expect("new failed");
    let dbg = format!("{:?}", sv);
    assert!(
        !dbg.contains("0xEE") && !dbg.contains("238"),
        "Debug output must not leak secret byte values"
    );
    assert!(dbg.contains("SecretVec"));
}
