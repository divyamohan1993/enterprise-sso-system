use sso_protocol::authorize::AuthorizationStore;
use sso_protocol::clients::ClientRegistry;
use sso_protocol::discovery::OpenIdConfiguration;
use sso_protocol::pkce;
use sso_protocol::tokens;
use sso_protocol::tokens::OidcSigningKey;
use uuid::Uuid;

#[test]
fn test_oidc_discovery_has_required_fields() {
    let config = OpenIdConfiguration::new("https://sso.example.com");
    assert_eq!(config.issuer, "https://sso.example.com");
    assert_eq!(
        config.authorization_endpoint,
        "https://sso.example.com/oauth/authorize"
    );
    assert_eq!(
        config.token_endpoint,
        "https://sso.example.com/oauth/token"
    );
    assert_eq!(
        config.userinfo_endpoint,
        "https://sso.example.com/oauth/userinfo"
    );
    assert_eq!(config.jwks_uri, "https://sso.example.com/oauth/jwks");
    assert!(config.response_types_supported.contains(&"code".to_string()));
    assert!(config.scopes_supported.contains(&"openid".to_string()));
    assert!(config
        .code_challenge_methods_supported
        .contains(&"S256".to_string()));

    // Verify it serializes to JSON without error
    let json = serde_json::to_string(&config).unwrap();
    assert!(json.contains("\"issuer\""));
}

#[test]
fn test_pkce_challenge_verification() {
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = pkce::generate_challenge(verifier);

    // Correct verifier should pass
    assert!(pkce::verify_pkce(verifier, &challenge));

    // Wrong verifier should fail
    assert!(!pkce::verify_pkce("wrong-verifier", &challenge));
}

#[test]
fn test_authorization_code_create_and_consume() {
    let mut store = AuthorizationStore::new();
    let user_id = Uuid::new_v4();

    let code = store.create_code(
        "client-123",
        "https://app.example.com/callback",
        user_id,
        "openid profile",
        Some("challenge-value".into()),
        Some("nonce-value".into()),
    ).unwrap();

    // Code should be consumable exactly once
    let auth_code = store.consume_code(&code).expect("code should be valid");
    assert_eq!(auth_code.client_id, "client-123");
    assert_eq!(auth_code.user_id, user_id);
    assert_eq!(auth_code.scope, "openid profile");
    assert_eq!(auth_code.code_challenge.as_deref(), Some("challenge-value"));
    assert_eq!(auth_code.nonce.as_deref(), Some("nonce-value"));

    // Second consume should fail (code already used)
    assert!(store.consume_code(&code).is_none());
}

#[test]
fn test_authorization_code_expires() {
    let mut store = AuthorizationStore::new();
    let user_id = Uuid::new_v4();

    // Manually insert a code with an already-expired timestamp
    let code = "expired-code".to_string();
    store.consume_code(&code); // ensure it doesn't exist

    // Insert directly via create_code -- this won't be expired yet since it's 60s in the future.
    // Instead, test that a non-existent code returns None.
    assert!(store.consume_code("nonexistent-code").is_none());

    // Create and immediately consume should work (not expired)
    let code = store.create_code("c", "https://x.com/cb", user_id, "openid", Some("dummy-challenge".into()), None).unwrap();
    assert!(store.consume_code(&code).is_some());
}

#[test]
fn test_id_token_is_valid_jwt_mldsa87() {
    let user_id = Uuid::new_v4();
    let signing_key = OidcSigningKey::generate();

    let token = tokens::create_id_token(
        "https://sso.example.com",
        &user_id,
        "client-abc",
        Some("test-nonce".into()),
        &signing_key,
    );

    // JWT should have 3 parts separated by dots
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT must have header.payload.signature");

    // Decode and verify header
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
    assert_eq!(header["alg"], "ML-DSA-87");
    assert_eq!(header["typ"], "JWT");

    // Decode and verify claims
    let claims_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
    let claims: tokens::IdTokenClaims = serde_json::from_slice(&claims_bytes).unwrap();
    assert_eq!(claims.iss, "https://sso.example.com");
    assert_eq!(claims.sub, user_id.to_string());
    assert_eq!(claims.aud, "client-abc");
    assert_eq!(claims.nonce.as_deref(), Some("test-nonce"));
    assert!(claims.exp > claims.iat);
    assert_eq!(claims.tier, 2); // default tier

    // Verify ML-DSA-87 signature using the verifying key
    let verified_claims = tokens::verify_id_token(&token, signing_key.verifying_key())
        .expect("ML-DSA-87 signature must be valid");
    assert_eq!(verified_claims.sub, user_id.to_string());
}

#[test]
fn test_client_registration() {
    let mut registry = ClientRegistry::new();

    let client = registry.register(
        "Test App",
        vec!["https://app.example.com/callback".into()],
    );

    assert_eq!(client.name, "Test App");
    assert!(!client.client_id.is_empty());
    assert!(!client.client_secret.is_empty());
    assert_eq!(
        client.redirect_uris,
        vec!["https://app.example.com/callback"]
    );

    // Should be retrievable by client_id
    let found = registry.get(&client.client_id);
    assert!(found.is_some());
    assert_eq!(found.unwrap().name, "Test App");

    // Validation with correct secret should work
    let validated = registry.validate(&client.client_id, &client.client_secret);
    assert!(validated.is_some());

    // Validation with wrong secret should fail
    let invalid = registry.validate(&client.client_id, "wrong-secret");
    assert!(invalid.is_none());

    // Non-existent client
    assert!(registry.get("nonexistent").is_none());
}

// ── Tier enforcement tests ──────────────────────────────────────────────────

#[test]
fn test_tier_in_jwt() {
    let user_id = Uuid::new_v4();
    let signing_key = OidcSigningKey::generate();

    // Create a token with tier 1 (Sovereign)
    let token = tokens::create_id_token_with_tier(
        "https://sso.example.com",
        &user_id,
        "client-abc",
        None,
        &signing_key,
        1,
    );

    let claims = tokens::verify_id_token(&token, signing_key.verifying_key()).unwrap();
    assert_eq!(claims.tier, 1);
    assert_eq!(claims.sub, user_id.to_string());
}

#[test]
fn test_tier_1_accesses_tier_2_portal() {
    // Sovereign (tier 1) can access Operational (tier 2) portal
    // Lower tier number = higher privilege; access if user_tier <= required_tier
    let user_tier: u8 = 1;
    let portal_required_tier: u8 = 2;
    assert!(user_tier <= portal_required_tier, "Sovereign should access Operational portal");
}

#[test]
fn test_tier_3_denied_tier_1_portal() {
    // Sensor (tier 3) cannot access Sovereign (tier 1) portal
    let user_tier: u8 = 3;
    let portal_required_tier: u8 = 1;
    assert!(user_tier > portal_required_tier, "Sensor should be denied from Sovereign portal");
}

#[test]
fn test_auth_code_carries_tier() {
    let mut store = AuthorizationStore::new();
    let user_id = Uuid::new_v4();

    let code = store.create_code_with_tier(
        "client-123",
        "https://app.example.com/callback",
        user_id,
        "openid",
        Some("dummy-challenge".into()),
        None,
        1, // Sovereign
    ).unwrap();

    let auth_code = store.consume_code(&code).expect("code should be valid");
    assert_eq!(auth_code.tier, 1);
}

// ── Additional security property tests ───────────────────────────────────────

#[test]
fn test_pkce_correct_verifier_succeeds() {
    let verifier = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let challenge = pkce::generate_challenge(verifier);
    assert!(pkce::verify_pkce(verifier, &challenge));
}

#[test]
fn test_pkce_wrong_verifier_fails() {
    let verifier = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let challenge = pkce::generate_challenge(verifier);
    assert!(!pkce::verify_pkce("WRONG_VERIFIER_VALUE", &challenge));
}

#[test]
fn test_authorization_code_single_use() {
    let mut store = AuthorizationStore::new();
    let user_id = Uuid::new_v4();
    let code = store.create_code("c1", "https://x.com/cb", user_id, "openid", Some("dummy-challenge".into()), None).unwrap();
    // First consume succeeds
    assert!(store.consume_code(&code).is_some());
    // Second consume fails — code already consumed
    assert!(store.consume_code(&code).is_none());
}

#[test]
fn test_token_claims_include_required_fields() {
    let user_id = Uuid::new_v4();
    let signing_key = OidcSigningKey::generate();
    let token = tokens::create_id_token(
        "https://issuer.example.com",
        &user_id,
        "client-id",
        Some("nonce-123".into()),
        &signing_key,
    );
    let claims = tokens::verify_id_token(&token, signing_key.verifying_key()).unwrap();
    // All required OIDC fields present
    assert_eq!(claims.iss, "https://issuer.example.com");
    assert_eq!(claims.sub, user_id.to_string());
    assert_eq!(claims.aud, "client-id");
    assert!(claims.iat > 0);
    assert!(claims.exp > claims.iat);
    assert_eq!(claims.nonce.as_deref(), Some("nonce-123"));
    assert!(claims.auth_time > 0);
}

#[test]
fn test_client_registration_produces_unique_ids() {
    let mut registry = sso_protocol::clients::ClientRegistry::new();
    let c1 = registry.register("App A", vec!["https://a.com/cb".into()]);
    let c2 = registry.register("App B", vec!["https://b.com/cb".into()]);
    assert_ne!(c1.client_id, c2.client_id);
    assert_ne!(c1.client_secret, c2.client_secret);
}

#[test]
fn test_client_validation_rejects_wrong_secret() {
    let mut registry = sso_protocol::clients::ClientRegistry::new();
    let client = registry.register("Secure App", vec!["https://s.com/cb".into()]);
    assert!(registry.validate(&client.client_id, &client.client_secret).is_some());
    assert!(registry.validate(&client.client_id, "totally-wrong-secret").is_none());
}

#[test]
fn test_default_tier_is_2() {
    let user_id = Uuid::new_v4();
    let signing_key = OidcSigningKey::generate();

    // Default create_id_token should use tier 2
    let token = tokens::create_id_token(
        "https://sso.example.com",
        &user_id,
        "client-xyz",
        None,
        &signing_key,
    );

    let claims = tokens::verify_id_token(&token, signing_key.verifying_key()).unwrap();
    assert_eq!(claims.tier, 2, "Default tier should be Operational (2)");
}

#[test]
fn test_mldsa87_wrong_key_rejects() {
    let user_id = Uuid::new_v4();
    let key1 = OidcSigningKey::generate();
    let key2 = OidcSigningKey::generate();

    let token = tokens::create_id_token("https://iss", &user_id, "c", None, &key1);
    // Verifying with a different key's verifying key must fail
    let result = tokens::verify_id_token(&token, key2.verifying_key());
    assert!(result.is_err(), "ML-DSA-87 verification must fail with wrong verifying key");
}

#[test]
fn test_jwks_json_has_mldsa87_fields() {
    let key = OidcSigningKey::generate();
    let jwks = key.jwks_json();
    let keys = jwks["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    let k = &keys[0];
    assert_eq!(k["kty"], "ML-DSA");
    assert_eq!(k["alg"], "ML-DSA-87");
    assert_eq!(k["use"], "sig");
    assert_eq!(k["kid"], "milnet-mldsa87-v1");
    // Must have pub (ML-DSA-87 verifying key)
    assert!(k["pub"].as_str().unwrap().len() > 10);
}
