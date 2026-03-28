//! SAML XML Signature Wrapping attack test suite.
//!
//! Tests that signing element A and verifying against element B fails
//! (XML signature wrapping prevention), and that SAML response replay
//! across sessions is rejected.
//!
//! Uses ML-DSA-87 (via `crypto::pq_sign`) as the signature primitive, since
//! the system relies on ML-DSA-87 for all post-quantum signing operations.

use crypto::pq_sign::{generate_pq_keypair, pq_sign_raw, pq_verify_raw};

// ── Constants ────────────────────────────────────────────────────────────

/// Simulated session identifiers.
const SESSION_A: &[u8] = b"session-id:AAAA-1111-alpha";
const SESSION_B: &[u8] = b"session-id:BBBB-2222-beta";

// ── Helpers ──────────────────────────────────────────────────────────────

/// Spawn a thread with an 8 MB stack so ML-DSA-87 key generation does not
/// overflow the default 2 MB Rust test thread stack.
fn run_with_large_stack<F, R>(f: F) -> R
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(f)
        .expect("thread spawn failed")
        .join()
        .expect("thread panicked")
}

/// Simulate a SAML-like assertion element with a unique element ID and content.
///
/// Returns a byte blob representing the serialized assertion, including an
/// element_id field bound into the signed content to prevent element
/// substitution (wrapping) attacks.
fn make_assertion(element_id: &str, subject: &str, session_id: &[u8]) -> Vec<u8> {
    // In a real SAML implementation this would be XML; here we use a simple
    // binary format to exercise the same logical binding property:
    //   element_id || ':' || subject || ':' || session_id
    let mut blob = Vec::new();
    blob.extend_from_slice(b"ELEM:");
    blob.extend_from_slice(element_id.as_bytes());
    blob.extend_from_slice(b":SUBJ:");
    blob.extend_from_slice(subject.as_bytes());
    blob.extend_from_slice(b":SID:");
    blob.extend_from_slice(session_id);
    blob
}

/// Sign an assertion element and return the ML-DSA-87 signature bytes.
fn sign_assertion(sk: &crypto::pq_sign::PqSigningKey, element: &[u8]) -> Vec<u8> {
    pq_sign_raw(sk, element)
}

/// Verify that a signature was produced over the expected element.
///
/// Returns `true` only when the signature covers exactly `element`.
fn verify_assertion(
    vk: &crypto::pq_sign::PqVerifyingKey,
    element: &[u8],
    signature: &[u8],
) -> bool {
    pq_verify_raw(vk, element, signature)
}

// ── Test 1: Signing element A, verifying against element B, must fail ────

#[test]
fn test_saml_wrapping_signing_a_verifying_b_fails() {
    run_with_large_stack(|| {
        let (sk, vk) = generate_pq_keypair();

        // Element A: the assertion the IdP actually signed (legitimate element).
        let element_a = make_assertion("elem-id-AAAA", "alice@example.com", SESSION_A);

        // Element B: a forged assertion the attacker wants to authenticate
        // (different element_id, different subject — the "wrapped" element).
        let element_b = make_assertion("elem-id-BBBB", "admin@example.com", SESSION_A);

        // The IdP signs element A.
        let sig = sign_assertion(&sk, &element_a);
        assert!(!sig.is_empty(), "signature over element_a must not be empty");

        // Verifying the signature against element A must succeed (control).
        assert!(
            verify_assertion(&vk, &element_a, &sig),
            "signature verification over the ORIGINAL element_a must succeed; \
             element_id='elem-id-AAAA', subject='alice@example.com'"
        );

        // Wrapping attack: present sig(element_a) as if it were sig(element_b).
        // This MUST fail — the signature is not over element_b.
        assert!(
            !verify_assertion(&vk, &element_b, &sig),
            "XML signature wrapping attack MUST be rejected: \
             sig(element_a) verified against element_b must return false. \
             element_b has element_id='elem-id-BBBB' and subject='admin@example.com', \
             which the IdP never signed"
        );
    });
}

// ── Test 2: Element with same subject but different element_id is rejected ─

#[test]
fn test_saml_wrapping_different_element_id_rejected() {
    run_with_large_stack(|| {
        let (sk, vk) = generate_pq_keypair();

        // The IdP signs a response for the legitimate assertion with id="id-001".
        let signed_element = make_assertion("id-001", "bob@example.com", SESSION_A);
        let sig = sign_assertion(&sk, &signed_element);

        // Attacker duplicates the response and moves the signed assertion to a
        // wrapper element, replacing the element_id with "id-002" while keeping
        // the subject the same (classic XML wrapping pattern).
        let wrapped_element = make_assertion("id-002", "bob@example.com", SESSION_A);

        assert!(
            !verify_assertion(&vk, &wrapped_element, &sig),
            "assertion with a different element_id ('id-002' vs 'id-001') must be \
             rejected even when the subject is identical — the element_id is part \
             of the signed content that prevents wrapping substitution"
        );
    });
}

// ── Test 3: SAML response replay across sessions is rejected ─────────────

#[test]
fn test_saml_response_replay_across_sessions_rejected() {
    run_with_large_stack(|| {
        let (sk, vk) = generate_pq_keypair();

        // Session A: user authenticates and receives a signed assertion bound to
        // session SESSION_A.
        let assertion_session_a =
            make_assertion("id-login-001", "carol@example.com", SESSION_A);
        let sig = sign_assertion(&sk, &assertion_session_a);

        // Replay scenario: attacker attempts to present the same signed assertion
        // in a different session context (SESSION_B).
        // The assertion bound to SESSION_A must not verify against SESSION_B.
        let assertion_session_b =
            make_assertion("id-login-001", "carol@example.com", SESSION_B);

        // Control: original assertion verifies correctly.
        assert!(
            verify_assertion(&vk, &assertion_session_a, &sig),
            "original assertion must verify in session_a; this is the baseline"
        );

        // Replay in a different session must be rejected.
        assert!(
            !verify_assertion(&vk, &assertion_session_b, &sig),
            "SAML response replay across sessions MUST be rejected: \
             sig(assertion_session_a) must NOT verify against assertion_session_b. \
             session_a={:?}, session_b={:?}",
            SESSION_A,
            SESSION_B
        );
    });
}

// ── Test 4: Replay of exact same assertion byte-for-byte is detectable ───

#[test]
fn test_saml_response_replay_same_bytes_detectable() {
    run_with_large_stack(|| {
        let (sk, vk) = generate_pq_keypair();

        // An assertion with a nonce/session ID field is signed.
        let assertion = make_assertion("id-nonce-abc123", "dave@example.com", SESSION_A);
        let sig = sign_assertion(&sk, &assertion);

        // In a correct implementation, a service provider would reject replayed
        // assertion IDs. Here we verify that the signature itself verifies the
        // same bytes (the SP lookup is outside scope), but also verify that a
        // modified nonce (what a correct SP would issue for a new request)
        // produces a verification failure.
        assert!(
            verify_assertion(&vk, &assertion, &sig),
            "original assertion must verify — this is expected"
        );

        // A new authentication request would have a fresh assertion ID.
        // The old sig must NOT cover the new assertion ID.
        let fresh_assertion =
            make_assertion("id-nonce-xyz789", "dave@example.com", SESSION_A);
        assert!(
            !verify_assertion(&vk, &fresh_assertion, &sig),
            "signature over old assertion ID 'id-nonce-abc123' must NOT verify \
             against fresh assertion ID 'id-nonce-xyz789'; replayed signatures \
             must be distinguishable from fresh ones via assertion ID binding"
        );
    });
}

// ── Test 5: Truncated and corrupted signatures are always rejected ────────

#[test]
fn test_saml_malformed_signatures_rejected() {
    run_with_large_stack(|| {
        let (sk, vk) = generate_pq_keypair();

        let element = make_assertion("id-valid", "eve@example.com", SESSION_A);
        let sig = sign_assertion(&sk, &element);

        // Empty signature.
        assert!(
            !verify_assertion(&vk, &element, &[]),
            "empty ML-DSA-87 signature must be rejected for any element"
        );

        // Truncated signature (first half only).
        assert!(
            !verify_assertion(&vk, &element, &sig[..sig.len() / 2]),
            "truncated ML-DSA-87 signature (len={} of original {}) must be rejected",
            sig.len() / 2,
            sig.len()
        );

        // Bit-flipped signature.
        let mut flipped = sig.clone();
        flipped[sig.len() / 3] ^= 0x5A;
        assert!(
            !verify_assertion(&vk, &element, &flipped),
            "bit-flipped ML-DSA-87 signature must be rejected; \
             single byte corruption must be detected"
        );

        // All-zeros signature of the correct length.
        let zero_sig = vec![0u8; sig.len()];
        assert!(
            !verify_assertion(&vk, &element, &zero_sig),
            "all-zeros signature of correct length must be rejected by ML-DSA-87"
        );
    });
}
