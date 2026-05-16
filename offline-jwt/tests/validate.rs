use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use offline_jwt::*;

const ISS: &str = "milnet-issuer";
const AUD: &str = "milnet-rp";

fn enc(v: &serde_json::Value) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap())
}

/// Build a token with an explicit header and payload, signature is 8 bytes.
fn build_token_with(
    header: serde_json::Value,
    payload: serde_json::Value,
) -> String {
    format!(
        "{}.{}.{}",
        enc(&header),
        enc(&payload),
        URL_SAFE_NO_PAD.encode([1u8; 8])
    )
}

fn good_header() -> serde_json::Value {
    serde_json::json!({"alg": "ED25519", "kid": "k1"})
}

fn good_payload() -> serde_json::Value {
    serde_json::json!({"jti": "abc", "iss": ISS, "aud": AUD, "exp": 9999999999_i64})
}

fn build_token() -> String {
    build_token_with(good_header(), good_payload())
}

fn store_k1() -> PinnedTrustStore {
    let mut store = PinnedTrustStore::new();
    store.pin(PinnedKey {
        kid: "k1".into(),
        algorithm: Algorithm::Ed25519,
        public_key_der: vec![],
    });
    store
}

fn fresh_crl() -> RevocationList {
    RevocationList { revoked_jtis: Default::default(), issued_at: 0, valid_until: 9999999999 }
}

fn policy() -> Policy {
    Policy::new(ISS, AUD)
}

#[test]
fn valid_token_passes() {
    let c = validate(
        &build_token(), &store_k1(), &fresh_crl(), &ReplayCache::new(),
        &policy(), 0, |_, _, _| true,
    )
    .unwrap();
    assert_eq!(c.jti, "abc");
}

#[test]
fn replay_rejected() {
    let store = store_k1();
    let crl = fresh_crl();
    let cache = ReplayCache::new();
    let t = build_token();
    validate(&t, &store, &crl, &cache, &policy(), 0, |_, _, _| true).unwrap();
    let err = validate(&t, &store, &crl, &cache, &policy(), 0, |_, _, _| true).unwrap_err();
    assert!(matches!(err, OfflineError::Replayed));
}

#[test]
fn alg_none_rejected() {
    let t = build_token_with(
        serde_json::json!({"alg": "none", "kid": "k1"}),
        good_payload(),
    );
    let err = validate(
        &t, &store_k1(), &fresh_crl(), &ReplayCache::new(), &policy(), 0,
        |_, _, _| true,
    )
    .unwrap_err();
    assert!(matches!(err, OfflineError::AlgNotAllowed));
}

#[test]
fn alg_none_casing_variants_rejected() {
    for variant in ["None", "NONE", "nOnE"] {
        let t = build_token_with(
            serde_json::json!({"alg": variant, "kid": "k1"}),
            good_payload(),
        );
        let err = validate(
            &t, &store_k1(), &fresh_crl(), &ReplayCache::new(), &policy(), 0,
            |_, _, _| true,
        )
        .unwrap_err();
        assert!(matches!(err, OfflineError::AlgNotAllowed), "variant {variant}");
    }
}

#[test]
fn alg_confusion_rejected() {
    // RS256 presented over an Ed25519-pinned kid must be rejected even though
    // the verifier closure would return true.
    let t = build_token_with(
        serde_json::json!({"alg": "RS256", "kid": "k1"}),
        good_payload(),
    );
    // RS256 is not in the default allowlist -> AlgNotAllowed fires first.
    let err = validate(
        &t, &store_k1(), &fresh_crl(), &ReplayCache::new(), &policy(), 0,
        |_, _, _| true,
    )
    .unwrap_err();
    assert!(matches!(err, OfflineError::AlgNotAllowed));

    // With RS256 allowed by policy, the pinned-key binding must still reject it.
    let mut p = policy();
    p.allowed_algs.push(Algorithm::Rs256);
    let err = validate(
        &t, &store_k1(), &fresh_crl(), &ReplayCache::new(), &p, 0,
        |_, _, _| true,
    )
    .unwrap_err();
    assert!(matches!(err, OfflineError::AlgMismatch));
}

#[test]
fn expired_token_rejected() {
    let t = build_token_with(
        good_header(),
        serde_json::json!({"jti": "exp1", "iss": ISS, "aud": AUD, "exp": 100_i64}),
    );
    let err = validate(
        &t, &store_k1(), &fresh_crl(), &ReplayCache::new(), &policy(), 200,
        |_, _, _| true,
    )
    .unwrap_err();
    assert!(matches!(err, OfflineError::Expired));
}

#[test]
fn not_yet_valid_token_rejected() {
    let t = build_token_with(
        good_header(),
        serde_json::json!({
            "jti": "nbf1", "iss": ISS, "aud": AUD,
            "exp": 9999999999_i64, "nbf": 5000_i64
        }),
    );
    let err = validate(
        &t, &store_k1(), &fresh_crl(), &ReplayCache::new(), &policy(), 100,
        |_, _, _| true,
    )
    .unwrap_err();
    assert!(matches!(err, OfflineError::NotYetValid));
}

#[test]
fn revoked_jti_rejected() {
    let mut crl = fresh_crl();
    crl.revoked_jtis.insert("abc".into());
    let err = validate(
        &build_token(), &store_k1(), &crl, &ReplayCache::new(), &policy(), 0,
        |_, _, _| true,
    )
    .unwrap_err();
    assert!(matches!(err, OfflineError::Revoked));
}

#[test]
fn stale_crl_rejected() {
    let crl = RevocationList { revoked_jtis: Default::default(), issued_at: 0, valid_until: 1000 };
    let err = validate(
        &build_token(), &store_k1(), &crl, &ReplayCache::new(), &policy(), 2000,
        |_, _, _| true,
    )
    .unwrap_err();
    assert!(matches!(err, OfflineError::StaleRevocation));
}

#[test]
fn wrong_issuer_rejected() {
    let t = build_token_with(
        good_header(),
        serde_json::json!({"jti": "iss1", "iss": "evil", "aud": AUD, "exp": 9999999999_i64}),
    );
    let err = validate(
        &t, &store_k1(), &fresh_crl(), &ReplayCache::new(), &policy(), 0,
        |_, _, _| true,
    )
    .unwrap_err();
    assert!(matches!(err, OfflineError::IssuerRejected));
}

#[test]
fn wrong_audience_rejected() {
    let t = build_token_with(
        good_header(),
        serde_json::json!({"jti": "aud1", "iss": ISS, "aud": "other-rp", "exp": 9999999999_i64}),
    );
    let err = validate(
        &t, &store_k1(), &fresh_crl(), &ReplayCache::new(), &policy(), 0,
        |_, _, _| true,
    )
    .unwrap_err();
    assert!(matches!(err, OfflineError::AudienceRejected));
}

#[test]
fn audience_array_match_accepted() {
    let t = build_token_with(
        good_header(),
        serde_json::json!({
            "jti": "aud2", "iss": ISS, "aud": ["other-rp", AUD],
            "exp": 9999999999_i64
        }),
    );
    let c = validate(
        &t, &store_k1(), &fresh_crl(), &ReplayCache::new(), &policy(), 0,
        |_, _, _| true,
    )
    .unwrap();
    assert_eq!(c.jti, "aud2");
}

#[test]
fn unknown_kid_rejected() {
    let t = build_token_with(
        serde_json::json!({"alg": "ED25519", "kid": "nope"}),
        good_payload(),
    );
    let err = validate(
        &t, &store_k1(), &fresh_crl(), &ReplayCache::new(), &policy(), 0,
        |_, _, _| true,
    )
    .unwrap_err();
    assert!(matches!(err, OfflineError::UnknownKid));
}

#[test]
fn bad_signature_rejected() {
    let err = validate(
        &build_token(), &store_k1(), &fresh_crl(), &ReplayCache::new(),
        &policy(), 0, |_, _, _| false,
    )
    .unwrap_err();
    assert!(matches!(err, OfflineError::SignatureInvalid));
}

#[test]
fn malformed_token_rejected() {
    for bad in ["", "onlyonesegment", "two.segments", "a.b.c.d"] {
        let err = validate(
            bad, &store_k1(), &fresh_crl(), &ReplayCache::new(), &policy(), 0,
            |_, _, _| true,
        )
        .unwrap_err();
        assert!(matches!(err, OfflineError::Malformed), "input {bad:?}");
    }
}

#[test]
fn oversized_token_rejected() {
    let big = "a".repeat(MAX_TOKEN_LEN + 1);
    let err = validate(
        &big, &store_k1(), &fresh_crl(), &ReplayCache::new(), &policy(), 0,
        |_, _, _| true,
    )
    .unwrap_err();
    assert!(matches!(err, OfflineError::TooLarge));
}

#[test]
fn header_with_injected_key_field_rejected() {
    // jwk/jku/x5u/x5c in the header must be rejected by deny_unknown_fields.
    let t = build_token_with(
        serde_json::json!({"alg": "ED25519", "kid": "k1", "jwk": {"x": "y"}}),
        good_payload(),
    );
    let err = validate(
        &t, &store_k1(), &fresh_crl(), &ReplayCache::new(), &policy(), 0,
        |_, _, _| true,
    )
    .unwrap_err();
    assert!(matches!(err, OfflineError::Malformed));
}

#[test]
fn signing_input_is_original_encoding() {
    // The verify closure must receive base64url(header) || "." || base64url(payload)
    // using the ORIGINAL on-wire encodings (RFC 7515 §5.2).
    let header = good_header();
    let payload = good_payload();
    let expected = format!("{}.{}", enc(&header), enc(&payload));
    let t = build_token_with(header, payload);
    let captured = std::cell::RefCell::new(Vec::new());
    validate(
        &t, &store_k1(), &fresh_crl(), &ReplayCache::new(), &policy(), 0,
        |_, signing_input, _| {
            *captured.borrow_mut() = signing_input.to_vec();
            true
        },
    )
    .unwrap();
    assert_eq!(captured.into_inner(), expected.into_bytes());
}
