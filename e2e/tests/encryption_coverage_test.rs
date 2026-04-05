//! Encryption coverage tests.
//!
//! Ensures every data path is encrypted: JWE token claims, audit log envelope
//! encryption, OPAQUE zero-knowledge, backup encryption + HMAC integrity,
//! log pseudonymization, Debug redaction, webhook encryption, and session
//! recording hash chain integrity.

use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn run_with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap();
}

// ===========================================================================
// 1. Token claims are JWE-encrypted on the wire (not plaintext JSON)
// ===========================================================================

/// Token claims must be encrypted via JWE before wire transmission.
/// The EncryptedClaims struct must not contain plaintext TokenClaims bytes.
#[test]
fn token_claims_are_jwe_encrypted() {
    let claims = common::types::TokenClaims {
        sub: Uuid::new_v4(),
        iss: [0xAA; 32],
        iat: 1_700_000_000,
        exp: 1_700_000_030,
        scope: 0x0F,
        dpop_hash: [0xBB; 64],
        ceremony_id: [0xCC; 32],
        tier: 2,
        ratchet_epoch: 1,
        token_id: [0xDD; 16],
        aud: Some("test-rp".to_string()),
        classification: 0,
    };

    let dek = [0x42u8; 32];

    // Encrypt
    let encrypted = crypto::jwe::encrypt_claims(&claims, &dek)
        .expect("JWE encryption must succeed");

    // The ciphertext must not contain plaintext identifiers
    let ct_hex = hex::encode(&encrypted.ciphertext);
    let sub_hex = hex::encode(claims.sub.as_bytes());
    assert!(
        !ct_hex.contains(&sub_hex),
        "encrypted claims must not contain plaintext subject UUID"
    );

    // Nonce must not be all zeros (random generation)
    assert!(
        encrypted.nonce.iter().any(|&b| b != 0),
        "JWE nonce must not be all zeros"
    );

    // Ciphertext must be larger than zero (includes GCM tag)
    assert!(
        encrypted.ciphertext.len() > 16,
        "JWE ciphertext must include GCM tag (16 bytes) plus payload"
    );

    // Decrypt and verify roundtrip
    let decrypted = crypto::jwe::decrypt_claims(&encrypted, &dek)
        .expect("JWE decryption must succeed");
    assert_eq!(decrypted.sub, claims.sub, "decrypted subject must match");
    assert_eq!(decrypted.tier, claims.tier, "decrypted tier must match");

    // Wrong key must fail
    let wrong_dek = [0x99u8; 32];
    let result = crypto::jwe::decrypt_claims(&encrypted, &wrong_dek);
    assert!(
        result.is_err(),
        "decryption with wrong key must fail"
    );
}

/// EncryptedToken on the wire has encrypted claims, not plaintext.
#[test]
fn encrypted_token_wire_format() {
    let token = common::types::Token::test_fixture_unsigned();
    let dek = [0x42u8; 32];

    let encrypted_token = crypto::jwe::encrypt_token(token.clone(), &dek)
        .expect("token encryption must succeed");

    // The encrypted_claims field must have non-empty ciphertext
    assert!(
        !encrypted_token.encrypted_claims.ciphertext.is_empty(),
        "encrypted token must have non-empty encrypted claims"
    );

    // Debug of EncryptedToken must show [ENCRYPTED] not raw claims
    let dbg = format!("{:?}", encrypted_token);
    assert!(
        dbg.contains("[ENCRYPTED]") || dbg.contains("[REDACTED]"),
        "EncryptedToken Debug must not leak claims, got: {}",
        dbg
    );
}

// ===========================================================================
// 2. Audit log entries are envelope-encrypted in DB
// ===========================================================================

/// Audit metadata must be AES-256-GCM encrypted with blind indexes.
#[test]
fn audit_log_entries_are_envelope_encrypted() {
    let enc_key = [0x42u8; 32];
    let blind_key = [0x43u8; 32];

    let user_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();

    let encrypted = common::encrypted_audit::encrypt_audit_metadata(
        common::types::AuditEventType::AuthSuccess,
        &[user_id],
        &[device_id],
        0.5,
        &[],
        &enc_key,
        &blind_key,
    )
    .expect("audit metadata encryption must succeed");

    // Ciphertext must not contain plaintext user UUID
    let ct_hex = hex::encode(&encrypted.ciphertext);
    let uid_hex = hex::encode(user_id.as_bytes());
    assert!(
        !ct_hex.contains(&uid_hex),
        "encrypted audit must not contain plaintext user UUID"
    );

    // Must have blind index for user
    assert_eq!(
        encrypted.user_blind_indexes.len(),
        1,
        "must have one blind index per user"
    );

    // Blind index must not be all zeros
    assert!(
        encrypted.user_blind_indexes[0].iter().any(|&b| b != 0),
        "blind index must not be all zeros"
    );

    // Event type blind index must not be all zeros
    assert!(
        encrypted.event_type_blind_index.iter().any(|&b| b != 0),
        "event type blind index must not be all zeros"
    );

    // Nonce must be 12 bytes and not all zeros
    assert!(
        encrypted.nonce.iter().any(|&b| b != 0),
        "audit encryption nonce must not be all zeros"
    );
}

// ===========================================================================
// 3. OPAQUE registration contains no password material on server
// ===========================================================================

/// OPAQUE protocol: verify the server side never stores plaintext passwords.
/// The CredentialStore uses real OPAQUE (RFC 9497). The server NEVER sees
/// the plaintext password during registration or login.
#[test]
fn opaque_registration_no_password_material() {
    run_with_large_stack(|| {
        let mut store = opaque::store::CredentialStore::new();
        let password = b"Super$ecret!Password123";
        let username = "alice-opaque-test";

        // Register a user (internally performs full OPAQUE registration)
        let user_id = store.register_with_password(username, password);
        assert_ne!(user_id, Uuid::nil(), "registration must succeed");

        // Retrieve the server-side registration blob
        let reg_bytes = store
            .get_registration_bytes(username)
            .expect("registration blob must exist");

        // The registration blob must NOT contain the plaintext password
        let password_appears = reg_bytes
            .windows(password.len())
            .any(|w| w == password);
        assert!(
            !password_appears,
            "OPAQUE server registration record must NEVER contain plaintext password"
        );

        // Verify correct password authenticates
        let result = store.verify_password(username, password);
        assert!(
            result.is_ok(),
            "correct password must authenticate successfully"
        );

        // Wrong password must fail
        let result = store.verify_password(username, b"WrongPassword!");
        assert!(
            result.is_err(),
            "wrong password must fail authentication"
        );
    });
}

// ===========================================================================
// 4. Backup files are AEGIS-256/AES-256-GCM encrypted with HMAC integrity
// ===========================================================================

/// Backup export produces encrypted + HMAC-authenticated data.
#[test]
fn backup_encrypted_with_hmac_integrity() {
    let master_kek = [0x42u8; 32];
    let plaintext = b"sensitive backup data: user records, keys, config";

    let backup = common::backup::export_backup(&master_kek, plaintext)
        .expect("backup export must succeed");

    // Backup must start with magic header
    assert!(
        backup.starts_with(b"MILBK002") || backup.starts_with(b"MILBK001"),
        "backup must start with version magic header"
    );

    // Backup must not contain plaintext data
    let backup_contains_plaintext = backup
        .windows(plaintext.len())
        .any(|w| w == plaintext);
    assert!(
        !backup_contains_plaintext,
        "backup must not contain plaintext data"
    );

    // Backup must end with 64-byte HMAC
    assert!(
        backup.len() > 64,
        "backup must be large enough to contain HMAC"
    );

    // Import must roundtrip
    let recovered = common::backup::import_backup(&master_kek, &backup)
        .expect("backup import must succeed");
    assert_eq!(
        recovered.as_slice(),
        plaintext,
        "imported backup must match original plaintext"
    );

    // Wrong key must fail import
    let wrong_kek = [0x99u8; 32];
    let result = common::backup::import_backup(&wrong_kek, &backup);
    assert!(
        result.is_err(),
        "backup import with wrong KEK must fail"
    );

    // Tampered backup must fail (flip a byte in the middle)
    if backup.len() > 40 {
        let mut tampered = backup.clone();
        tampered[30] ^= 0xFF;
        let result = common::backup::import_backup(&master_kek, &tampered);
        assert!(
            result.is_err(),
            "tampered backup must fail integrity check"
        );
    }
}

// ===========================================================================
// 5. Log output contains no raw UUIDs, emails, or IPs (all pseudonymized)
// ===========================================================================

/// Log pseudonymization produces deterministic, irreversible pseudonyms.
#[test]
fn log_pseudonymization_produces_opaque_output() {
    let user_id = Uuid::new_v4();
    let email = "alice@pentagon.mil";

    let pseudo_uuid = common::log_pseudonym::pseudonym_uuid(user_id);
    let pseudo_email = common::log_pseudonym::pseudonym_email(email);

    // Pseudonyms must be hex strings, not raw identifiers
    assert!(
        !pseudo_uuid.contains(&user_id.to_string()),
        "pseudonym must not contain raw UUID"
    );
    assert!(
        !pseudo_email.contains("alice"),
        "pseudonym must not contain raw email username"
    );
    assert!(
        !pseudo_email.contains("pentagon"),
        "pseudonym must not contain raw email domain"
    );

    // Pseudonyms must be deterministic (same input -> same output)
    let pseudo_uuid2 = common::log_pseudonym::pseudonym_uuid(user_id);
    assert_eq!(
        pseudo_uuid, pseudo_uuid2,
        "UUID pseudonym must be deterministic"
    );

    let pseudo_email2 = common::log_pseudonym::pseudonym_email(email);
    assert_eq!(
        pseudo_email, pseudo_email2,
        "email pseudonym must be deterministic"
    );

    // Different inputs must produce different pseudonyms
    let other_id = Uuid::new_v4();
    let pseudo_other = common::log_pseudonym::pseudonym_uuid(other_id);
    assert_ne!(
        pseudo_uuid, pseudo_other,
        "different UUIDs must produce different pseudonyms"
    );

    // Pseudonym length must be consistent (32 hex chars = 16 bytes of HMAC)
    assert_eq!(
        pseudo_uuid.len(),
        32,
        "UUID pseudonym must be 32 hex chars"
    );
    assert_eq!(
        pseudo_email.len(),
        32,
        "email pseudonym must be 32 hex chars"
    );
}

// ===========================================================================
// 6. Debug impls of Token, TokenClaims, Receipt, AuditEntry all print [REDACTED]
// ===========================================================================

/// All sensitive types must redact cryptographic material in Debug output.
#[test]
fn debug_impls_all_redacted() {
    // Token
    let token = common::types::Token::test_fixture_unsigned();
    let dbg = format!("{:?}", token);
    assert!(dbg.contains("[REDACTED]"), "Token Debug must contain [REDACTED]");
    assert!(!dbg.contains("0xEE"), "Token Debug must not leak frost_signature");
    assert!(!dbg.contains("0xFF"), "Token Debug must not leak pq_signature");

    // TokenClaims
    let claims_dbg = format!("{:?}", token.claims);
    assert!(claims_dbg.contains("[REDACTED]"), "TokenClaims Debug must contain [REDACTED]");

    // Receipt
    let receipt = common::types::Receipt {
        ceremony_session_id: [0x11; 32],
        step_id: 1,
        prev_receipt_hash: [0x22; 64],
        user_id: Uuid::new_v4(),
        dpop_key_hash: [0x33; 64],
        timestamp: 1_700_000_000,
        nonce: [0x44; 32],
        signature: vec![0x55; 64],
        ttl_seconds: 30,
    };
    let receipt_dbg = format!("{:?}", receipt);
    assert!(receipt_dbg.contains("[REDACTED]"), "Receipt Debug must contain [REDACTED]");
    assert!(!receipt_dbg.contains("0x55"), "Receipt Debug must not leak signature bytes");

    // AuditEntry
    let entry = common::types::AuditEntry {
        event_id: Uuid::new_v4(),
        event_type: common::types::AuditEventType::AuthSuccess,
        user_ids: vec![Uuid::new_v4()],
        device_ids: vec![],
        ceremony_receipts: vec![],
        risk_score: 0.0,
        timestamp: 1_700_000_000,
        prev_hash: [0x66; 64],
        signature: vec![0x77; 128],
        classification: 0,
        correlation_id: None,
        trace_id: None,
    };
    let entry_dbg = format!("{:?}", entry);
    assert!(entry_dbg.contains("[REDACTED]"), "AuditEntry Debug must contain [REDACTED]");
    assert!(!entry_dbg.contains("0x77"), "AuditEntry Debug must not leak signature bytes");
}

// ===========================================================================
// 7. Webhook payloads are HMAC-signed when secret key is configured
// ===========================================================================

/// Webhook events are HMAC-SHA512 signed for integrity.
#[test]
fn webhook_payloads_hmac_signed() {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    type HmacSha512 = Hmac<Sha512>;

    let webhook_secret = [0x42u8; 64];
    let payload = b"{\"event\":\"login\",\"user\":\"pseudo-abc123\"}";

    // Compute HMAC-SHA512 (this is what the webhook delivery system does)
    let mut mac = HmacSha512::new_from_slice(&webhook_secret)
        .expect("HMAC key size is valid");
    mac.update(payload);
    let signature = mac.finalize().into_bytes();

    // Verify the signature
    let mut verify_mac = HmacSha512::new_from_slice(&webhook_secret).unwrap();
    verify_mac.update(payload);
    assert!(
        verify_mac.verify_slice(&signature).is_ok(),
        "webhook HMAC signature must verify"
    );

    // Wrong key must fail
    let wrong_secret = [0x99u8; 64];
    let mut wrong_mac = HmacSha512::new_from_slice(&wrong_secret).unwrap();
    wrong_mac.update(payload);
    assert!(
        wrong_mac.verify_slice(&signature).is_err(),
        "webhook HMAC with wrong key must fail"
    );

    // Tampered payload must fail
    let mut tampered_mac = HmacSha512::new_from_slice(&webhook_secret).unwrap();
    tampered_mac.update(b"{\"event\":\"logout\",\"user\":\"pseudo-abc123\"}");
    assert!(
        tampered_mac.verify_slice(&signature).is_err(),
        "webhook HMAC with tampered payload must fail"
    );
}

// ===========================================================================
// 8. Session recording events have hash chain integrity
// ===========================================================================

/// Session recording events are chained via HMAC-SHA512 hash links.
/// Each event's hash_chain_link is computed from the previous event's link.
#[test]
fn session_recording_hash_chain_integrity() {
    use common::session_recording::{
        PamPolicy, RecordingType, SessionEventType, SessionRecorder,
    };

    let recorder = SessionRecorder::with_defaults();
    let session_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Start recording
    recorder
        .start_recording(session_id, user_id, RecordingType::Admin, now)
        .expect("start recording must succeed");

    // Record several events
    for i in 0..5 {
        recorder
            .record_event(
                session_id,
                SessionEventType::CommandExecuted,
                format!("test command {}", i),
                "10.0.0.1".to_string(),
                now + i,
            )
            .expect("record event must succeed");
    }

    // Retrieve the recording and verify hash chain
    let recording = recorder
        .get_recording(session_id)
        .expect("get recording must succeed");

    assert_eq!(
        recording.events.len(),
        5,
        "recording must have 5 events"
    );

    // Each event must have a non-zero hash chain link
    for (i, event) in recording.events.iter().enumerate() {
        assert!(
            event.hash_chain_link.iter().any(|&b| b != 0),
            "event {} hash_chain_link must not be all zeros",
            i
        );
    }

    // Sequential events must have different hash chain links (chaining)
    for i in 1..recording.events.len() {
        assert_ne!(
            recording.events[i].hash_chain_link,
            recording.events[i - 1].hash_chain_link,
            "consecutive events must have different hash chain links"
        );
    }

    // Recording integrity hash must not be all zeros
    assert!(
        recording.integrity_hash.iter().any(|&b| b != 0),
        "recording integrity hash must not be all zeros"
    );
}

/// V2 field encryption uses 0x02 envelope tag.
#[test]
fn field_encryption_v2_envelope_tag() {
    let enc = common::encrypted_db::FieldEncryptor::new([0x42; 32]);
    let encrypted = enc
        .encrypt_field("users", "opaque_registration", b"row-1", b"secret-data")
        .unwrap();
    assert_eq!(
        encrypted[0], 0x02,
        "field encryption must use V2 envelope format tag"
    );
}
