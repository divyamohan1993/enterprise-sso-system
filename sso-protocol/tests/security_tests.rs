//! Additional security property tests for the SSO protocol layer.

use sso_protocol::authorize::AuthorizationStore;
use sso_protocol::clients::ClientRegistry;
use sso_protocol::discovery::OpenIdConfiguration;
use sso_protocol::pkce;
use sso_protocol::tokens;
use sso_protocol::tokens::OidcSigningKey;
use uuid::Uuid;

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
    let user_id = Uuid::new_v4();
    let key1 = OidcSigningKey::generate();
    let key2 = OidcSigningKey::generate();
    let t1 = tokens::create_id_token("https://iss", &user_id, "c", None, &key1);
    let t2 = tokens::create_id_token("https://iss", &user_id, "c", None, &key2);
    // Signatures (third JWT segment) must differ
    let sig1 = t1.split('.').nth(2).unwrap();
    let sig2 = t2.split('.').nth(2).unwrap();
    assert_ne!(sig1, sig2);
}

#[test]
fn test_mldsa87_token_verifiable_with_verifying_key() {
    let user_id = Uuid::new_v4();
    let key = OidcSigningKey::generate();
    let token = tokens::create_id_token("https://iss", &user_id, "c", None, &key);
    // Must verify with the matching verifying key
    let claims = tokens::verify_id_token(&token, key.verifying_key()).unwrap();
    assert_eq!(claims.sub, user_id.to_string());
}

#[test]
fn test_mldsa87_token_rejected_with_wrong_verifying_key() {
    let user_id = Uuid::new_v4();
    let key1 = OidcSigningKey::generate();
    let key2 = OidcSigningKey::generate();
    let token = tokens::create_id_token("https://iss", &user_id, "c", None, &key1);
    // Must NOT verify with a different key's verifying key
    assert!(tokens::verify_id_token(&token, key2.verifying_key()).is_err());
}

#[test]
fn test_auth_code_default_tier_is_2() {
    let mut store = AuthorizationStore::new();
    let user_id = Uuid::new_v4();
    let code = store.create_code("c", "https://x.com/cb", user_id, "openid", Some("dummy-challenge".into()), None).unwrap();
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
    );
    assert_eq!(client.client_id, "fixed-id");
    assert_eq!(client.client_secret, "fixed-secret");
    assert_eq!(client.name, "My App");
    assert!(registry.validate("fixed-id", "fixed-secret").is_some());
}

#[test]
fn test_nonexistent_client_get_returns_none() {
    let registry = ClientRegistry::new();
    assert!(registry.get("does-not-exist").is_none());
}

#[test]
fn test_jwt_tier_values_propagate() {
    let user_id = Uuid::new_v4();
    let key = OidcSigningKey::generate();
    for tier in 1..=4u8 {
        let token = tokens::create_id_token_with_tier("https://iss", &user_id, "c", None, &key, tier);
        let claims = tokens::verify_id_token(&token, key.verifying_key()).unwrap();
        assert_eq!(claims.tier, tier, "tier {tier} should propagate into JWT claims");
    }
}
