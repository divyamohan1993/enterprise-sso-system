//! I11 [MED] Key rotation mid-request: rotate while verification is in flight.
//!
//! Two contracts:
//! 1. Tokens issued under generation N still verify with the previous key
//!    after rotation to N+1 (grace window).
//! 2. Tokens issued after rotation verify with the new current key only.
//! No panics under concurrent rotation/verification.

use sso_protocol::tokens::{create_id_token, verify_id_token_with_audience, OidcSigningKey};
use std::sync::{Arc, RwLock};
use std::thread;
use uuid::Uuid;

/// F7 (wave-2 risk-session): verify_id_token now requires an expected
/// audience — the bare claim is ignored to prevent forged-claim smuggling.
/// Tests must pass a non-empty audience to both create and verify.
const TEST_AUDIENCE: &str = "client-A";

#[test]
fn rotation_grace_window_old_token_still_verifies() {
    let mut sk = OidcSigningKey::generate();
    let user = Uuid::new_v4();

    let old_token = create_id_token(
        "https://idp.milnet.mil",
        &user,
        TEST_AUDIENCE,
        None,
        &sk,
    );

    // Capture the OLD verifying key before rotating so we can verify against
    // the previous slot post-rotation.
    let old_vk_clone = {
        // Re-encoding via JWKS json then decoding is overkill; we instead
        // compare epoch behaviour: after rotate, previous_verifying_key()
        // returns the slot the old token was signed under.
        sk.rotate_signing_key();
        sk.previous_verifying_key().expect("previous slot present after rotate").clone()
    };

    // Old token must still verify against the previous slot.
    let claims = verify_id_token_with_audience(&old_token, &old_vk_clone, TEST_AUDIENCE, true)
        .expect("old token must verify against previous-generation key in grace window");
    assert_eq!(claims.sub, user.to_string());

    // A token signed AFTER rotation must verify against the new current key.
    let new_token = create_id_token(
        "https://idp.milnet.mil",
        &user,
        TEST_AUDIENCE,
        None,
        &sk,
    );
    verify_id_token_with_audience(&new_token, sk.verifying_key(), TEST_AUDIENCE, true)
        .expect("new token verifies under current key");
}

#[test]
fn concurrent_rotation_and_verification_no_panic() {
    let sk = Arc::new(RwLock::new(OidcSigningKey::generate()));
    let user = Uuid::new_v4();

    // Pre-sign a batch of tokens with generation 1. All tokens use the same
    // audience so the concurrent verifier threads can verify with a single
    // expected audience (F7 mandates audience binding on every verify).
    let pre_tokens: Vec<String> = (0..32)
        .map(|_| {
            let g = sk.read().unwrap();
            create_id_token(
                "https://idp.milnet.mil",
                &user,
                TEST_AUDIENCE,
                None,
                &g,
            )
        })
        .collect();

    // Rotator thread: rotate the key several times.
    let rotator = {
        let sk = Arc::clone(&sk);
        thread::spawn(move || {
            for _ in 0..5 {
                sk.write().unwrap().rotate_signing_key();
                std::thread::yield_now();
            }
        })
    };

    // Verifier threads: verify each pre-token against current AND previous.
    let verifiers: Vec<_> = pre_tokens
        .into_iter()
        .map(|tok| {
            let sk = Arc::clone(&sk);
            thread::spawn(move || {
                let g = sk.read().unwrap();
                let _ = verify_id_token_with_audience(
                    &tok,
                    g.verifying_key(),
                    TEST_AUDIENCE,
                    true,
                );
                if let Some(prev) = g.previous_verifying_key() {
                    let _ = verify_id_token_with_audience(&tok, prev, TEST_AUDIENCE, true);
                }
            })
        })
        .collect();

    rotator.join().expect("rotator panicked");
    for v in verifiers {
        v.join().expect("verifier panicked");
    }

    // Final state: at least one rotation occurred, no panics, key intact.
    let final_gen = sk.read().unwrap().generation();
    assert!(final_gen >= 2, "rotation must have advanced generation");
}
