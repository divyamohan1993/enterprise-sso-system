//! Additional security property tests for the SSO protocol layer.

use sso_protocol::authorize::AuthorizationStore;
use sso_protocol::clients::ClientRegistry;
use sso_protocol::discovery::OpenIdConfiguration;
use sso_protocol::pkce;
use sso_protocol::tokens;
use sso_protocol::tokens::OidcSigningKey;
use uuid::Uuid;

fn big<F: FnOnce() + Send + 'static>(f: F) {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_pkce_challenge_is_base64url_no_padding() {
    let verifier = "some-random-code-verifier-string-here";
    let challenge = pkce::generate_challenge(verifier);
    // Base64url should not contain +, /, or =
    assert!(!challenge.contains('+'));
    assert!(!challenge.contains('/'));
    assert!(!challenge.contains('='));
}

#[test]
fn test_pkce_empty_verifier_rejected_by_length_check() {
    let challenge = pkce::generate_challenge("");
    assert!(!challenge.is_empty());
    // Empty verifier must be rejected per RFC 7636 (min 43 chars)
    assert!(!pkce::verify_pkce("", &challenge));
}

#[test]
fn test_oidc_discovery_s256_required() {
    let config = OpenIdConfiguration::new("https://sso.mil");
    assert!(config.code_challenge_methods_supported.contains(&"S256".to_string()));
    // Must NOT support "plain" per security requirements
    assert!(!config.code_challenge_methods_supported.contains(&"plain".to_string()));
}

#[test]
fn test_oidc_discovery_only_code_response_type() {
    let config = OpenIdConfiguration::new("https://sso.mil");
    // Should only support "code" (authorization code flow), not "token" (implicit)
    assert!(config.response_types_supported.contains(&"code".to_string()));
    assert!(!config.response_types_supported.contains(&"token".to_string()));
}

#[test]
fn test_oidc_discovery_advertises_mldsa87() {
    let config = OpenIdConfiguration::new("https://sso.mil");
    assert!(config.id_token_signing_alg_values_supported.contains(&"ML-DSA-87".to_string()));
    // Must NOT advertise HS512 (symmetric) or RS256 (legacy RSA)
    assert!(!config.id_token_signing_alg_values_supported.contains(&"HS512".to_string()));
    assert!(!config.id_token_signing_alg_values_supported.contains(&"RS256".to_string()));
}

#[test]
fn test_jwt_signature_changes_with_different_key() {
    big(|| {
        let user_id = Uuid::new_v4();
        let key1 = OidcSigningKey::generate();
        let key2 = OidcSigningKey::generate();
        let t1 = tokens::create_id_token("https://iss", &user_id, "c", None, &key1);
        let t2 = tokens::create_id_token("https://iss", &user_id, "c", None, &key2);
        // Signatures (third JWT segment) must differ
        let sig1 = t1.split('.').nth(2).unwrap();
        let sig2 = t2.split('.').nth(2).unwrap();
        assert_ne!(sig1, sig2);
    });
}

#[test]
fn test_mldsa87_token_verifiable_with_verifying_key() {
    big(|| {
        let user_id = Uuid::new_v4();
        let key = OidcSigningKey::generate();
        let token = tokens::create_id_token("https://iss", &user_id, "c", None, &key);
        // Must verify with the matching verifying key
        let claims = tokens::verify_id_token_with_audience(&token, key.verifying_key(), "c", true).unwrap();
        assert_eq!(claims.sub, user_id.to_string());
    });
}

#[test]
fn test_mldsa87_token_rejected_with_wrong_verifying_key() {
    big(|| {
        let user_id = Uuid::new_v4();
        let key1 = OidcSigningKey::generate();
        let key2 = OidcSigningKey::generate();
        let token = tokens::create_id_token("https://iss", &user_id, "c", None, &key1);
        // Must NOT verify with a different key's verifying key
        assert!(tokens::verify_id_token_with_audience(&token, key2.verifying_key(), "c", true).is_err());
    });
}

#[test]
fn test_auth_code_default_tier_is_2() {
    let mut store = AuthorizationStore::new();
    let user_id = Uuid::new_v4();
    let code = store.create_code_with_tier("c", "https://x.com/cb", user_id, "openid", Some("dummy-challenge".into()), None, 2).unwrap();
    let auth_code = store.consume_code(&code).unwrap();
    assert_eq!(auth_code.tier, 2);
}

#[test]
fn test_client_register_with_id_preserves_fields() {
    let mut registry = ClientRegistry::new();
    let client = registry.register_with_id(
        "fixed-id",
        "fixed-secret",
        "My App",
        vec!["https://app.com/cb".into()],
    ).unwrap();
    assert_eq!(client.client_id, "fixed-id");
    // client_secret is now an Argon2id hash, not the plaintext
    assert_ne!(client.client_secret, "fixed-secret");
    assert!(!client.client_secret.is_empty());
    assert_eq!(client.name, "My App");
    // Validation with the original plaintext must still succeed
    assert!(registry.validate("fixed-id", "fixed-secret").is_some());
}

#[test]
fn test_nonexistent_client_get_returns_none() {
    let registry = ClientRegistry::new();
    assert!(registry.get("does-not-exist").is_none());
}

#[test]
fn test_jwt_tier_values_propagate() {
    big(|| {
        let user_id = Uuid::new_v4();
        let key = OidcSigningKey::generate();
        for tier in 1..=4u8 {
            let token = tokens::create_id_token_with_tier("https://iss", &user_id, "c", None, &key, tier);
            let claims = tokens::verify_id_token_with_audience(&token, key.verifying_key(), "c", true).unwrap();
            assert_eq!(claims.tier, tier, "tier {tier} should propagate into JWT claims");
        }
    });
}

// ===========================================================================
// Hardened security tests for authentication protocols
// ===========================================================================

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

// SECURITY AUDIT: Empty JTI skips replay cache — tokens replayable until expiry
#[test]
fn test_empty_jti_bypasses_replay_protection() {
    big(|| {
        let user_id = Uuid::new_v4();

        // Build a token with an empty JTI by manually constructing claims
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Use raw keypair for manual token construction with empty JTI
        let (sk, vk) = crypto::pq_sign::generate_pq_keypair();

        let header = serde_json::json!({
            "alg": "ML-DSA-87",
            "typ": "JWT",
            "kid": "milnet-mldsa87-v1"
        });
        let claims = serde_json::json!({
            "iss": "https://iss",
            "sub": user_id.to_string(),
            "aud": "client",
            "exp": now + 600,
            "iat": now,
            "nonce": null,
            "auth_time": now,
            "tier": 2,
            "jti": ""
        });

        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{header_b64}.{claims_b64}");

        let signature = crypto::pq_sign::pq_sign_raw(&sk, signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(&signature);
        let token = format!("{signing_input}.{sig_b64}");

        // SECURITY: Empty JTI tokens are now rejected unconditionally.
        // All tokens must carry a unique JTI for replay protection.
        let r1 = tokens::verify_id_token_with_audience(&token, &vk, "client", true);
        assert!(r1.is_err(), "empty-JTI token must be rejected");
        assert!(
            r1.unwrap_err().contains("jti is required"),
            "error must mention JTI requirement"
        );
    });
}

// Ensures only S256 is allowed per CNSA 2.0 requirements
#[test]
fn test_pkce_plain_method_rejected() {
    assert!(pkce::validate_challenge_method(Some("plain")).is_err());
    assert!(pkce::validate_challenge_method(Some("S256")).is_ok());
}

// Authorization codes must be single-use per RFC 6749
#[test]
fn test_auth_code_consumed_on_use() {
    let mut store = AuthorizationStore::new();
    let user_id = Uuid::new_v4();
    let code = store
        .create_code_with_tier(
            "client-1",
            "https://app.example.com/cb",
            user_id,
            "openid",
            Some("dummy-challenge".into()),
            None,
            2,
        )
        .unwrap();

    // First consumption must succeed
    let first = store.consume_code(&code);
    assert!(first.is_some(), "first consume must return the authorization code");

    // Second consumption must return None — code is single-use
    let second = store.consume_code(&code);
    assert!(second.is_none(), "second consume must return None — code already used");
}

// Blocks alg confusion attacks (CVE-2022-21449 class)
#[test]
fn test_token_rejects_algorithm_confusion() {
    big(|| {
        let key = OidcSigningKey::generate();
        let user_id = Uuid::new_v4();
        let token = tokens::create_id_token("https://iss", &user_id, "c", None, &key);

        // Tamper with the header: replace the algorithm with "HS256"
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);

        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let mut header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        header["alg"] = serde_json::json!("HS256");

        let tampered_header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let tampered_token = format!("{}.{}.{}", tampered_header_b64, parts[1], parts[2]);

        // Verification must fail due to algorithm mismatch
        let result = tokens::verify_id_token_with_audience(&tampered_token, key.verifying_key(), "c", true);
        assert!(result.is_err(), "algorithm confusion must be rejected");
        let err = result.unwrap_err();
        assert!(
            err.contains("unsupported algorithm"),
            "error must mention unsupported algorithm, got: {err}"
        );
    });
}

// Client secrets must be Argon2id hashed, never stored as plaintext
#[test]
fn test_client_secret_stored_as_argon2id_hash() {
    let mut registry = ClientRegistry::new();
    let client = registry.register_with_id(
        "test-client-id",
        "super-secret-value",
        "Test App",
        vec!["https://app.example.com/cb".into()],
    ).unwrap();

    // The stored secret must NOT be the plaintext
    assert_ne!(
        client.client_secret, "super-secret-value",
        "client secret must not be stored as plaintext"
    );

    // The stored secret must be a hex-encoded hash (Argon2id output is 32 bytes = 64 hex chars)
    assert_eq!(
        client.client_secret.len(),
        64,
        "stored secret must be a 64-char hex-encoded Argon2id hash"
    );
    assert!(
        client.client_secret.chars().all(|c| c.is_ascii_hexdigit()),
        "stored secret must be valid hex (Argon2id hash)"
    );

    // Validation with the original plaintext must still succeed
    assert!(
        registry.validate("test-client-id", "super-secret-value").is_some(),
        "plaintext secret must validate against the stored hash"
    );

    // Validation with wrong secret must fail
    assert!(
        registry.validate("test-client-id", "wrong-secret").is_none(),
        "wrong secret must not validate"
    );
}

// Implicit grant is banned for military deployments
#[test]
fn test_discovery_no_implicit_grant() {
    let config = OpenIdConfiguration::new("https://sso.mil");

    // response_types_supported must not contain "token" (implicit flow response type)
    assert!(
        !config.response_types_supported.contains(&"token".to_string()),
        "implicit grant response type 'token' must not be advertised"
    );

    // Only "code" (authorization code flow) should be supported
    assert!(
        config.response_types_supported.contains(&"code".to_string()),
        "authorization code response type must be supported"
    );

    // Verify the list contains exactly one entry to prevent future additions slipping through
    assert_eq!(
        config.response_types_supported.len(),
        1,
        "only 'code' response type should be supported — implicit and hybrid flows are banned"
    );
}

// ===========================================================================
// TEST GROUP 2: ID token audience enforcement
// ===========================================================================

#[test]
fn test_verify_id_token_without_audience_always_fails() {
    big(|| {
        let user_id = Uuid::new_v4();
        let key = OidcSigningKey::generate();
        let token = tokens::create_id_token("https://iss", &user_id, "client-a", None, &key);

        // verify_id_token (no audience) must always fail — audience enforcement is mandatory.
        let result = tokens::verify_id_token(&token, key.verifying_key());
        assert!(result.is_err(), "verify_id_token without audience must always fail");
        let err = result.unwrap_err();
        assert!(
            err.to_lowercase().contains("audience"),
            "error must mention audience requirement, got: {err}"
        );
    });
}

#[test]
fn test_verify_id_token_with_correct_audience_succeeds() {
    big(|| {
        let user_id = Uuid::new_v4();
        let key = OidcSigningKey::generate();
        let token = tokens::create_id_token("https://iss", &user_id, "client-x", None, &key);

        let result = tokens::verify_id_token_with_audience(&token, key.verifying_key(), "client-x", true);
        assert!(result.is_ok(), "correct audience must verify successfully");
        let claims = result.unwrap();
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.aud, "client-x");
    });
}

#[test]
fn test_verify_id_token_with_wrong_audience_fails() {
    big(|| {
        let user_id = Uuid::new_v4();
        let key = OidcSigningKey::generate();
        let token = tokens::create_id_token("https://iss", &user_id, "client-a", None, &key);

        // Verify with wrong audience must fail.
        let result = tokens::verify_id_token_with_audience(&token, key.verifying_key(), "client-b", true);
        assert!(result.is_err(), "wrong audience must be rejected");
        let err = result.unwrap_err();
        assert!(
            err.to_lowercase().contains("audience"),
            "error must mention audience mismatch, got: {err}"
        );
    });
}

#[test]
fn test_token_confusion_client_a_rejected_by_client_b() {
    big(|| {
        let user_id = Uuid::new_v4();
        let key = OidcSigningKey::generate();

        // Issue token for client-alpha
        let token_for_alpha = tokens::create_id_token("https://iss", &user_id, "client-alpha", None, &key);

        // Client-alpha verifies successfully
        let ok = tokens::verify_id_token_with_audience(&token_for_alpha, key.verifying_key(), "client-alpha", true);
        assert!(ok.is_ok(), "token must verify for intended audience");

        // Client-beta must reject the token — this is the token confusion attack.
        let rejected = tokens::verify_id_token_with_audience(&token_for_alpha, key.verifying_key(), "client-beta", true);
        assert!(rejected.is_err(), "token issued for client-alpha must be rejected by client-beta");
    });
}
