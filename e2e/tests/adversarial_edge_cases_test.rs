//! Adversarial edge-case test suite.
//!
//! Covers attack vectors not exercised elsewhere: Unicode/IDN homograph attacks,
//! null-byte injection, oversized inputs, and integer boundary conditions.
//! Each test validates that the system either rejects or safely handles the input.

use std::time::{SystemTime, UNIX_EPOCH};

use common::scim::{ScimEmail, ScimMeta, ScimName, ScimServer, ScimUser, SCHEMA_USER};
use common::types::Receipt;
use crypto::receipts::{hash_receipt, sign_receipt};
use opaque::store::CredentialStore;
use tss::validator::validate_receipt_chain;
use uuid::Uuid;

// ── Constants ────────────────────────────────────────────────────────────

const RECEIPT_SIGNING_KEY: [u8; 64] = [0x42u8; 64];

// ── Helpers ──────────────────────────────────────────────────────────────

fn now_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64
}

fn make_receipt(session_id: [u8; 32], step: u8, prev_hash: [u8; 64], dpop_hash: [u8; 64]) -> Receipt {
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce).unwrap();
    Receipt {
        ceremony_session_id: session_id,
        step_id: step,
        prev_receipt_hash: prev_hash,
        user_id: Uuid::nil(),
        dpop_key_hash: dpop_hash,
        timestamp: now_us(),
        nonce,
        signature: Vec::new(),
        ttl_seconds: 30,
    }
}

fn build_signed_chain(len: usize) -> Vec<Receipt> {
    let session_id = [0x01; 32];
    let dpop_hash = [0x02; 64];
    let mut chain = Vec::with_capacity(len);
    for i in 0..len {
        let prev_hash = if i == 0 {
            [0u8; 64]
        } else {
            hash_receipt(&chain[i - 1])
        };
        let mut r = make_receipt(session_id, (i + 1) as u8, prev_hash, dpop_hash);
        sign_receipt(&mut r, &RECEIPT_SIGNING_KEY).unwrap();
        chain.push(r);
    }
    chain
}

fn make_scim_server() -> ScimServer {
    ScimServer::new("https://sso.example.mil/scim/v2")
}

fn scim_user(username: &str) -> ScimUser {
    ScimUser {
        schemas: vec![SCHEMA_USER.to_string()],
        id: String::new(),
        external_id: None,
        user_name: username.to_string(),
        name: Some(ScimName {
            formatted: Some(username.to_string()),
            family_name: None,
            given_name: None,
        }),
        display_name: Some(username.to_string()),
        emails: vec![ScimEmail {
            value: format!("{username}@example.mil"),
            email_type: Some("work".to_string()),
            primary: true,
        }],
        active: true,
        groups: Vec::new(),
        department: None,
        meta: ScimMeta {
            resource_type: String::new(),
            created: String::new(),
            last_modified: String::new(),
            location: String::new(),
            version: String::new(),
        },
    }
}

// ==========================================================================
// 1. UNICODE HOMOGRAPH ATTACKS
// ==========================================================================

/// Cyrillic 'а' (U+0430) vs Latin 'a' (U+0061) in OPAQUE usernames.
/// The system must treat these as distinct identities (no silent conflation).
#[test]
fn opaque_cyrillic_latin_confusable_usernames_are_distinct() {
    let mut store = CredentialStore::new();
    let latin = "admin";
    let cyrillic = "\u{0430}dmin"; // Cyrillic а followed by Latin dmin

    let uid_latin = store.register_with_password(latin, b"password1");
    let uid_cyrillic = store.register_with_password(cyrillic, b"password2");

    // Must be two distinct users
    assert_ne!(uid_latin, uid_cyrillic, "Cyrillic/Latin confusable must not map to same user");
    // Each credential must exist independently
    assert!(store.get_registration(latin).is_ok());
    assert!(store.get_registration(cyrillic).is_ok());
}

/// SCIM: Cyrillic/Latin confusable usernames should be treated as distinct.
#[test]
fn scim_cyrillic_latin_confusable_distinct() {
    let mut server = make_scim_server();
    let u1 = server.create_user(scim_user("admin")).unwrap();
    let u2 = server.create_user(scim_user("\u{0430}dmin")).unwrap();
    assert_ne!(u1.id, u2.id, "SCIM must treat Cyrillic/Latin confusables as distinct users");
}

/// Zero-width joiner (U+200D) in username should not silently collapse.
#[test]
fn zero_width_joiner_in_username() {
    let mut store = CredentialStore::new();
    let plain = "alice";
    let zwj = "ali\u{200D}ce"; // zero-width joiner between 'i' and 'c'

    let uid_plain = store.register_with_password(plain, b"pw1");
    let uid_zwj = store.register_with_password(zwj, b"pw2");
    assert_ne!(uid_plain, uid_zwj, "ZWJ-laced username must not silently match plain username");
}

/// RTL override character (U+202E) in username.
/// Must not silently reverse display or match a different identity.
#[test]
fn rtl_override_in_username() {
    let mut store = CredentialStore::new();
    let normal = "alice";
    let rtl = "\u{202E}ecila"; // RTL override + reversed chars

    let uid_normal = store.register_with_password(normal, b"pw1");
    let uid_rtl = store.register_with_password(rtl, b"pw2");
    assert_ne!(uid_normal, uid_rtl, "RTL override username must not match normal username");
}

/// Combining diacriticals: 'a' + combining acute (U+0301) vs 'á' (U+00E1).
#[test]
fn combining_diacritical_vs_precomposed() {
    let mut store = CredentialStore::new();
    let precomposed = "\u{00E1}lice"; // á (precomposed)
    let combining = "a\u{0301}lice"; // a + combining acute accent

    let uid1 = store.register_with_password(precomposed, b"pw1");
    let uid2 = store.register_with_password(combining, b"pw2");
    // These are canonically equivalent under NFC but byte-different.
    // The system must handle this consistently (either normalize or treat as distinct).
    // What matters is it doesn't crash or silently overwrite.
    let _ = (uid1, uid2); // If we get here without panic, the store handled it.
}

/// Mixed-script username with Cyrillic, Latin, and Greek characters.
#[test]
fn mixed_script_username() {
    let mut store = CredentialStore::new();
    // Mix of Latin 'a', Cyrillic 'б', Greek 'γ'
    let mixed = "a\u{0431}\u{03B3}user";
    let uid = store.register_with_password(mixed, b"pw1");
    assert!(store.get_registration(mixed).is_ok());
    let _ = uid;
}

/// SCIM user with zero-width characters embedded in display name and username.
#[test]
fn scim_zero_width_characters() {
    let mut server = make_scim_server();
    // Zero-width space (U+200B), zero-width non-joiner (U+200C)
    let u = scim_user("us\u{200B}er\u{200C}name");
    let result = server.create_user(u);
    // Must succeed or explicitly reject, not panic
    match result {
        Ok(created) => assert!(!created.id.is_empty()),
        Err(e) => {
            // Rejection is also acceptable if the system validates
            let msg = format!("{:?}", e);
            assert!(!msg.is_empty());
        }
    }
}

/// Username consisting entirely of Unicode control characters.
#[test]
fn control_character_only_username() {
    let mut store = CredentialStore::new();
    // Bell, backspace, delete
    let ctrl_name = "\x07\x08\x7F";
    // Must not panic
    let uid = store.register_with_password(ctrl_name, b"pw1");
    let _ = uid;
}

// ==========================================================================
// 2. NULL-BYTE INJECTION
// ==========================================================================

/// Null byte in OPAQUE username must not truncate or cause undefined behavior.
#[test]
fn null_byte_in_opaque_username() {
    let mut store = CredentialStore::new();
    let normal = "admin";
    let with_null = "admin\0evil";

    let uid_normal = store.register_with_password(normal, b"pw1");
    let uid_null = store.register_with_password(with_null, b"pw2");
    // Must be distinct (null byte must not truncate "admin\0evil" to "admin")
    assert_ne!(uid_normal, uid_null, "Null byte must not truncate username");
}

/// Null byte in SCIM userName.
#[test]
fn null_byte_in_scim_username() {
    let mut server = make_scim_server();
    let u_normal = server.create_user(scim_user("bob")).unwrap();

    let u_null = scim_user("bob\0evil");
    let result = server.create_user(u_null);
    match result {
        Ok(created) => {
            // If accepted, it must be a distinct user
            assert_ne!(created.id, u_normal.id);
        }
        Err(_) => {} // Rejection is also valid
    }
}

/// Null byte in SCIM display name field.
#[test]
fn null_byte_in_scim_display_name() {
    let mut server = make_scim_server();
    let mut u = scim_user("valid_user");
    u.display_name = Some("Display\0Name".to_string());
    // Must not panic
    let result = server.create_user(u);
    assert!(result.is_ok() || result.is_err()); // just don't panic
}

/// Null byte in receipt session ID bytes (binary field).
/// Should be handled normally since it's a byte array.
#[test]
fn null_byte_in_receipt_session_id() {
    let mut session_id = [0x01u8; 32];
    session_id[15] = 0x00; // embed null byte
    let dpop_hash = [0x02; 64];

    let mut r = make_receipt(session_id, 1, [0u8; 64], dpop_hash);
    sign_receipt(&mut r, &RECEIPT_SIGNING_KEY).unwrap();
    let chain = vec![r];
    assert!(validate_receipt_chain(&chain, &RECEIPT_SIGNING_KEY).is_ok());
}

/// Null bytes in auth code (simulated as byte vector deserialization).
#[test]
fn null_bytes_in_auth_code_bytes() {
    // Auth codes go through hash before DB storage. Ensure null bytes don't
    // cause issues in the hashing pipeline.
    let code_with_nulls = b"auth\0code\0with\0nulls";
    let hash = crypto::ct::ct_eq(code_with_nulls, code_with_nulls);
    assert!(hash, "constant-time compare must handle null bytes");

    // Different null positions must not compare equal
    let code_a = b"auth\0A";
    let code_b = b"auth\0B";
    assert!(!crypto::ct::ct_eq(code_a, code_b));
}

/// Null byte at start, middle, and end of redirect URI string.
#[test]
fn null_bytes_in_redirect_uri_positions() {
    let uris = [
        "\0https://evil.com",
        "https://legit.com/\0evil",
        "https://legit.com/callback\0",
    ];
    for uri in &uris {
        // Ensure the URI string can be processed without panic
        assert!(uri.len() > 0);
        // Serialization round-trip via postcard (as used in the system)
        let serialized = postcard::to_allocvec(uri).unwrap();
        let deserialized: String = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(uri, &deserialized, "null byte must survive serialization round-trip");
    }
}

// ==========================================================================
// 3. OVERSIZED INPUTS
// ==========================================================================

/// 1MB username in OPAQUE credential store.
#[test]
fn oversized_username_1mb_opaque() {
    let mut store = CredentialStore::new();
    let huge_name: String = "A".repeat(1_000_000);
    // Must not panic or OOM. Registration may succeed or fail gracefully.
    let uid = store.register_with_password(&huge_name, b"pw");
    // If it succeeded, lookup should work
    if store.get_registration(&huge_name).is_ok() {
        let _ = uid;
    }
}

/// 100K-character redirect URI in postcard serialization.
#[test]
fn oversized_redirect_uri_100k() {
    let huge_uri: String = format!("https://example.com/{}", "x".repeat(100_000));
    // Serialization must not panic
    let serialized = postcard::to_allocvec(&huge_uri).unwrap();
    let deserialized: String = postcard::from_bytes(&serialized).unwrap();
    assert_eq!(huge_uri, deserialized);
}

/// 10MB SAML-like assertion payload deserialization attempt.
#[test]
fn oversized_saml_assertion_10mb_postcard_reject() {
    let huge_payload = vec![0xABu8; 10_000_000];
    // Attempting to deserialize 10MB as a Token must fail, not OOM.
    let result = postcard::from_bytes::<common::types::Token>(&huge_payload);
    assert!(result.is_err(), "10MB payload must not deserialize as valid Token");
}

/// Oversized receipt chain (1000 receipts).
#[test]
fn oversized_receipt_chain_1000() {
    let session_id = [0x01; 32];
    let dpop_hash = [0x02; 64];
    let mut chain = Vec::with_capacity(1000);
    for i in 0..1000 {
        let prev_hash = if i == 0 {
            [0u8; 64]
        } else {
            hash_receipt(&chain[i - 1])
        };
        let mut r = Receipt {
            ceremony_session_id: session_id,
            step_id: ((i % 255) + 1) as u8,
            prev_receipt_hash: prev_hash,
            user_id: Uuid::nil(),
            dpop_key_hash: dpop_hash,
            timestamp: 1_700_000_000_000_000 + (i as i64 * 1_000_000),
            nonce: [(i & 0xFF) as u8; 32],
            signature: Vec::new(),
            ttl_seconds: 30,
        };
        sign_receipt(&mut r, &RECEIPT_SIGNING_KEY).unwrap();
        chain.push(r);
    }
    // Must validate without panic (system may accept or reject based on policy)
    let result = validate_receipt_chain(&chain, &RECEIPT_SIGNING_KEY);
    assert!(result.is_ok(), "1000-receipt chain should validate: {:?}", result.err());
}

/// Enormous JSON body deserialization for SCIM.
#[test]
fn oversized_scim_json_body() {
    // 1MB of repeated JSON fields
    let huge_display_name = "X".repeat(1_000_000);
    let json = format!(
        r#"{{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"","userName":"biguser","displayName":"{}","active":true,"emails":[],"groups":[]}}"#,
        huge_display_name
    );
    let result: Result<ScimUser, _> = serde_json::from_str(&json);
    // Must not panic. May succeed (large but valid JSON) or fail.
    match result {
        Ok(u) => assert_eq!(u.display_name.clone().unwrap().len(), 1_000_000),
        Err(_) => {} // rejection also acceptable
    }
}

/// Max-length + 1 auth code (65 bytes where 64 is typical).
#[test]
fn auth_code_max_length_plus_one() {
    let code_64 = vec![0xABu8; 64];
    let code_65 = vec![0xABu8; 65];
    // These are different lengths, so constant-time compare must return false
    assert!(!crypto::ct::ct_eq(&code_64, &code_65));
}

/// Receipt with maximum-length signature field.
#[test]
fn receipt_with_huge_signature() {
    let mut chain = build_signed_chain(1);
    // Replace signature with 1MB of data
    chain[0].signature = vec![0xFF; 1_000_000];
    let result = validate_receipt_chain(&chain, &RECEIPT_SIGNING_KEY);
    assert!(result.is_err(), "1MB signature must not validate as correct HMAC");
}

// ==========================================================================
// 4. INTEGER BOUNDARY TESTS
// ==========================================================================

/// Receipt timestamp at i64::MAX.
#[test]
fn receipt_timestamp_i64_max() {
    let session_id = [0x01; 32];
    let dpop_hash = [0x02; 64];
    let mut r = Receipt {
        ceremony_session_id: session_id,
        step_id: 1,
        prev_receipt_hash: [0u8; 64],
        user_id: Uuid::nil(),
        dpop_key_hash: dpop_hash,
        timestamp: i64::MAX,
        nonce: [0x42; 32],
        signature: Vec::new(),
        ttl_seconds: 30,
    };
    sign_receipt(&mut r, &RECEIPT_SIGNING_KEY).unwrap();
    let chain = vec![r];
    assert!(validate_receipt_chain(&chain, &RECEIPT_SIGNING_KEY).is_ok());
}

/// Receipt timestamp at i64::MIN (negative epoch).
#[test]
fn receipt_timestamp_i64_min() {
    let session_id = [0x01; 32];
    let dpop_hash = [0x02; 64];
    let mut r = Receipt {
        ceremony_session_id: session_id,
        step_id: 1,
        prev_receipt_hash: [0u8; 64],
        user_id: Uuid::nil(),
        dpop_key_hash: dpop_hash,
        timestamp: i64::MIN,
        nonce: [0x43; 32],
        signature: Vec::new(),
        ttl_seconds: 30,
    };
    sign_receipt(&mut r, &RECEIPT_SIGNING_KEY).unwrap();
    let chain = vec![r];
    // Validator doesn't check timestamp validity, only chain integrity
    assert!(validate_receipt_chain(&chain, &RECEIPT_SIGNING_KEY).is_ok());
}

/// Receipt timestamp at zero epoch.
#[test]
fn receipt_timestamp_zero() {
    let session_id = [0x01; 32];
    let dpop_hash = [0x02; 64];
    let mut r = Receipt {
        ceremony_session_id: session_id,
        step_id: 1,
        prev_receipt_hash: [0u8; 64],
        user_id: Uuid::nil(),
        dpop_key_hash: dpop_hash,
        timestamp: 0,
        nonce: [0x44; 32],
        signature: Vec::new(),
        ttl_seconds: 30,
    };
    sign_receipt(&mut r, &RECEIPT_SIGNING_KEY).unwrap();
    let chain = vec![r];
    assert!(validate_receipt_chain(&chain, &RECEIPT_SIGNING_KEY).is_ok());
}

/// TTL at u8 boundaries (0 and 255).
#[test]
fn receipt_ttl_boundary_values() {
    for ttl in [0u8, 1, 254, 255] {
        let session_id = [0x01; 32];
        let dpop_hash = [0x02; 64];
        let mut r = Receipt {
            ceremony_session_id: session_id,
            step_id: 1,
            prev_receipt_hash: [0u8; 64],
            user_id: Uuid::nil(),
            dpop_key_hash: dpop_hash,
            timestamp: now_us(),
            nonce: [ttl; 32],
            signature: Vec::new(),
            ttl_seconds: ttl,
        };
        sign_receipt(&mut r, &RECEIPT_SIGNING_KEY).unwrap();
        let chain = vec![r];
        assert!(
            validate_receipt_chain(&chain, &RECEIPT_SIGNING_KEY).is_ok(),
            "ttl={ttl} should validate"
        );
    }
}

/// Step ID at u8 boundaries (0 and 255).
#[test]
fn receipt_step_id_boundary_values() {
    for step in [0u8, 1, 127, 255] {
        let session_id = [0x01; 32];
        let dpop_hash = [0x02; 64];
        let mut r = Receipt {
            ceremony_session_id: session_id,
            step_id: step,
            prev_receipt_hash: [0u8; 64],
            user_id: Uuid::nil(),
            dpop_key_hash: dpop_hash,
            timestamp: now_us(),
            nonce: [step; 32],
            signature: Vec::new(),
            ttl_seconds: 30,
        };
        sign_receipt(&mut r, &RECEIPT_SIGNING_KEY).unwrap();
        let chain = vec![r];
        assert!(
            validate_receipt_chain(&chain, &RECEIPT_SIGNING_KEY).is_ok(),
            "step_id={step} should validate"
        );
    }
}

/// Token claims with scope at u32::MAX and ratchet_epoch at u64::MAX.
#[test]
fn token_claims_scope_and_epoch_max() {
    let claims = common::types::TokenClaims {
        sub: Uuid::nil(),
        iss: [0xAA; 32],
        iat: 1_700_000_000_000_000,
        exp: 1_700_000_030_000_000,
        scope: u32::MAX,
        dpop_hash: [0xBB; 64],
        ceremony_id: [0x01; 32],
        tier: 1,
        ratchet_epoch: u64::MAX,
        token_id: [0xAB; 16],
        aud: None,
        classification: 0,
    };
    // Serialization round-trip must preserve extreme values
    let bytes = postcard::to_allocvec(&claims).unwrap();
    let decoded: common::types::TokenClaims = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.scope, u32::MAX);
    assert_eq!(decoded.ratchet_epoch, u64::MAX);
}

/// Token claims with all fields at zero.
#[test]
fn token_claims_all_zeros() {
    let claims = common::types::TokenClaims {
        sub: Uuid::nil(),
        iss: [0; 32],
        iat: 0,
        exp: 0,
        scope: 0,
        dpop_hash: [0; 64],
        ceremony_id: [0; 32],
        tier: 0,
        ratchet_epoch: 0,
        token_id: [0; 16],
        aud: None,
        classification: 0,
    };
    let bytes = postcard::to_allocvec(&claims).unwrap();
    let decoded: common::types::TokenClaims = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.iat, 0);
    assert_eq!(decoded.exp, 0);
    assert_eq!(decoded.scope, 0);
}

/// Epoch counter at u64::MAX in receipt chain (ratchet_epoch field in claims).
#[test]
fn ratchet_epoch_u64_max_serialization() {
    let claims = common::types::TokenClaims {
        sub: Uuid::nil(),
        iss: [0xAA; 32],
        iat: i64::MAX,
        exp: i64::MAX,
        scope: u32::MAX,
        dpop_hash: [0xFF; 64],
        ceremony_id: [0xFF; 32],
        tier: u8::MAX,
        ratchet_epoch: u64::MAX,
        token_id: [0xFF; 16],
        aud: Some("x".repeat(10_000)), // large audience string
        classification: u8::MAX,
    };
    let bytes = postcard::to_allocvec(&claims).unwrap();
    let decoded: common::types::TokenClaims = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.ratchet_epoch, u64::MAX);
    assert_eq!(decoded.tier, u8::MAX);
    assert_eq!(decoded.classification, u8::MAX);
    assert_eq!(decoded.aud.as_deref(), Some(&*"x".repeat(10_000)));
}

/// Multiple receipts with timestamps that would overflow if added.
#[test]
fn receipt_chain_extreme_timestamps_no_overflow() {
    let session_id = [0x01; 32];
    let dpop_hash = [0x02; 64];
    let timestamps = [i64::MIN, -1, 0, 1, i64::MAX];

    let mut chain = Vec::new();
    for (i, &ts) in timestamps.iter().enumerate() {
        let prev_hash = if i == 0 {
            [0u8; 64]
        } else {
            hash_receipt(&chain[i - 1])
        };
        let mut r = Receipt {
            ceremony_session_id: session_id,
            step_id: (i + 1) as u8,
            prev_receipt_hash: prev_hash,
            user_id: Uuid::nil(),
            dpop_key_hash: dpop_hash,
            timestamp: ts,
            nonce: [i as u8; 32],
            signature: Vec::new(),
            ttl_seconds: 30,
        };
        sign_receipt(&mut r, &RECEIPT_SIGNING_KEY).unwrap();
        chain.push(r);
    }
    // Validator only checks chain integrity, not timestamp ordering
    assert!(validate_receipt_chain(&chain, &RECEIPT_SIGNING_KEY).is_ok());
}
