//! End-to-end disaster recovery tests.
//!
//! Validates that the MILNET SSO system can survive a complete disaster
//! scenario: backup all critical state (KEK-encrypted), destroy it,
//! restore from backup, and resume operations with full cryptographic
//! integrity.

use common::backup::{export_backup, import_backup};
use crypto::threshold::{dkg, threshold_sign, verify_group_signature, DkgResult};

/// DR safety margin for FROST nonce counters on disaster recovery restore.
/// FROST nonce reuse enables private key extraction (two signatures with the
/// same nonce reveal the signing share), so on DR restore we MUST advance
/// every nonce counter by at least this margin to guarantee no nonce is ever
/// reused from a pre-disaster signing session.
const DR_SAFETY_MARGIN: u64 = 10_000;

/// Generate a random 32-byte KEK for testing.
fn random_kek() -> [u8; 32] {
    let mut kek = [0u8; 32];
    getrandom::getrandom(&mut kek).unwrap();
    kek
}

/// Mock database state for backup/restore testing.
#[derive(Debug, Clone, PartialEq)]
struct MockDbState {
    users: Vec<(String, String)>,       // (user_id, username)
    sessions: Vec<(String, u64)>,       // (session_id, created_at)
    tokens: Vec<(String, Vec<u8>)>,     // (token_id, token_bytes)
}

impl MockDbState {
    fn sample() -> Self {
        Self {
            users: vec![
                ("u001".into(), "alice".into()),
                ("u002".into(), "bob".into()),
                ("u003".into(), "charlie".into()),
            ],
            sessions: vec![
                ("s001".into(), 1700000000),
                ("s002".into(), 1700001000),
            ],
            tokens: vec![
                ("t001".into(), vec![0xAA; 64]),
                ("t002".into(), vec![0xBB; 64]),
            ],
        }
    }

    /// Serialize to bytes (simple deterministic encoding).
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Users
        buf.extend_from_slice(&(self.users.len() as u32).to_le_bytes());
        for (id, name) in &self.users {
            buf.extend_from_slice(&(id.len() as u32).to_le_bytes());
            buf.extend_from_slice(id.as_bytes());
            buf.extend_from_slice(&(name.len() as u32).to_le_bytes());
            buf.extend_from_slice(name.as_bytes());
        }
        // Sessions
        buf.extend_from_slice(&(self.sessions.len() as u32).to_le_bytes());
        for (id, ts) in &self.sessions {
            buf.extend_from_slice(&(id.len() as u32).to_le_bytes());
            buf.extend_from_slice(id.as_bytes());
            buf.extend_from_slice(&ts.to_le_bytes());
        }
        // Tokens
        buf.extend_from_slice(&(self.tokens.len() as u32).to_le_bytes());
        for (id, data) in &self.tokens {
            buf.extend_from_slice(&(id.len() as u32).to_le_bytes());
            buf.extend_from_slice(id.as_bytes());
            buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
            buf.extend_from_slice(data);
        }
        buf
    }

    /// Deserialize from bytes.
    fn from_bytes(data: &[u8]) -> Result<Self, String> {
        let mut pos = 0;

        let read_u32 = |pos: &mut usize| -> Result<u32, String> {
            if *pos + 4 > data.len() {
                return Err("truncated u32".into());
            }
            let val = u32::from_le_bytes(
                data[*pos..*pos + 4]
                    .try_into()
                    .map_err(|_| "u32 parse error")?,
            );
            *pos += 4;
            Ok(val)
        };

        let read_u64 = |pos: &mut usize| -> Result<u64, String> {
            if *pos + 8 > data.len() {
                return Err("truncated u64".into());
            }
            let val = u64::from_le_bytes(
                data[*pos..*pos + 8]
                    .try_into()
                    .map_err(|_| "u64 parse error")?,
            );
            *pos += 8;
            Ok(val)
        };

        let read_bytes = |pos: &mut usize, len: usize| -> Result<Vec<u8>, String> {
            if *pos + len > data.len() {
                return Err("truncated bytes".into());
            }
            let b = data[*pos..*pos + len].to_vec();
            *pos += len;
            Ok(b)
        };

        let read_string = |pos: &mut usize| -> Result<String, String> {
            let len = read_u32(pos)? as usize;
            let bytes = read_bytes(pos, len)?;
            String::from_utf8(bytes).map_err(|_| "invalid utf-8".into())
        };

        // Users
        let user_count = read_u32(&mut pos)? as usize;
        let mut users = Vec::with_capacity(user_count);
        for _ in 0..user_count {
            let id = read_string(&mut pos)?;
            let name = read_string(&mut pos)?;
            users.push((id, name));
        }

        // Sessions
        let session_count = read_u32(&mut pos)? as usize;
        let mut sessions = Vec::with_capacity(session_count);
        for _ in 0..session_count {
            let id = read_string(&mut pos)?;
            let ts = read_u64(&mut pos)?;
            sessions.push((id, ts));
        }

        // Tokens
        let token_count = read_u32(&mut pos)? as usize;
        let mut tokens = Vec::with_capacity(token_count);
        for _ in 0..token_count {
            let id = read_string(&mut pos)?;
            let len = read_u32(&mut pos)? as usize;
            let data = read_bytes(&mut pos, len)?;
            tokens.push((id, data));
        }

        Ok(Self {
            users,
            sessions,
            tokens,
        })
    }
}

/// Serialize FROST key shares to bytes for backup.
/// Format: count(u32) || for each share: id_bytes_len(u32) || id_bytes || key_pkg_len(u32) || key_pkg_bytes
fn serialize_frost_shares(dkg_result: &DkgResult) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(dkg_result.shares.len() as u32).to_le_bytes());
    for share in &dkg_result.shares {
        let id_bytes = share
            .identifier
            .serialize();
        buf.extend_from_slice(&(id_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&id_bytes);
        let key_bytes = share
            .key_package
            .serialize()
            .expect("key package serialization");
        buf.extend_from_slice(&(key_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&key_bytes);
    }
    // Public key package
    let pub_bytes = dkg_result
        .group
        .public_key_package
        .serialize()
        .expect("public key package serialization");
    buf.extend_from_slice(&(pub_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(&pub_bytes);
    // Threshold and total
    buf.extend_from_slice(&(dkg_result.group.threshold as u32).to_le_bytes());
    buf.extend_from_slice(&(dkg_result.group.total as u32).to_le_bytes());
    buf
}

/// Deserialize FROST shares from bytes.
fn deserialize_frost_shares(data: &[u8]) -> Result<DkgResult, String> {
    use crypto::threshold::{SignerShare, ThresholdGroup};
    use frost_ristretto255 as frost;
    use frost::keys::{KeyPackage, PublicKeyPackage};

    let mut pos = 0;

    let read_u32 = |pos: &mut usize| -> Result<u32, String> {
        if *pos + 4 > data.len() {
            return Err("truncated".into());
        }
        let val = u32::from_le_bytes(
            data[*pos..*pos + 4]
                .try_into()
                .map_err(|_| "parse error")?,
        );
        *pos += 4;
        Ok(val)
    };

    let count = read_u32(&mut pos)? as usize;
    let mut shares = Vec::with_capacity(count);
    for _ in 0..count {
        let id_len = read_u32(&mut pos)? as usize;
        if pos + id_len > data.len() {
            return Err("truncated id".into());
        }
        let id_bytes = &data[pos..pos + id_len];
        pos += id_len;
        let identifier = frost::Identifier::deserialize(id_bytes)
            .map_err(|e| format!("id deser: {e}"))?;

        let key_len = read_u32(&mut pos)? as usize;
        if pos + key_len > data.len() {
            return Err("truncated key".into());
        }
        let key_bytes = &data[pos..pos + key_len];
        pos += key_len;
        let key_package = KeyPackage::deserialize(key_bytes)
            .map_err(|e| format!("key deser: {e}"))?;

        // DR restore: advance nonce counter by DR_SAFETY_MARGIN to prevent
        // FROST nonce reuse. Nonce reuse = private key extraction.
        shares.push(SignerShare {
            identifier,
            key_package,
            nonce_counter: std::sync::atomic::AtomicU64::new(DR_SAFETY_MARGIN),
        });
    }

    let pub_len = read_u32(&mut pos)? as usize;
    if pos + pub_len > data.len() {
        return Err("truncated public key package".into());
    }
    let pub_bytes = &data[pos..pos + pub_len];
    pos += pub_len;
    let public_key_package = PublicKeyPackage::deserialize(pub_bytes)
        .map_err(|e| format!("pub deser: {e}"))?;

    let threshold = read_u32(&mut pos)? as usize;
    let total = read_u32(&mut pos)? as usize;

    Ok(DkgResult {
        group: ThresholdGroup {
            threshold,
            total,
            public_key_package,
        },
        shares,
    })
}

// ---------------------------------------------------------------------------
// Test 1: Full backup/restore cycle
// ---------------------------------------------------------------------------

#[test]
fn test_full_backup_restore_cycle() {
    // Step 1: Generate a master KEK
    let master_kek = random_kek();

    // Step 2: Create FROST key shares (3-of-5 threshold)
    let dkg_result = dkg(5, 3);
    let frost_bytes = serialize_frost_shares(&dkg_result);

    // Step 3: Create mock DB state
    let db_state = MockDbState::sample();
    let db_bytes = db_state.to_bytes();

    // Step 4: Combine all components into a single backup payload
    // Format: frost_len(u64) || frost_bytes || db_bytes
    let mut payload = Vec::new();
    payload.extend_from_slice(&(frost_bytes.len() as u64).to_le_bytes());
    payload.extend_from_slice(&frost_bytes);
    payload.extend_from_slice(&db_bytes);

    // Step 5: Export encrypted backup
    let backup_blob = export_backup(&master_kek, &payload)
        .expect("backup export must succeed");

    // Step 6: Simulate disaster - clear all state
    drop(dkg_result);
    let _ = db_state; // original state kept for comparison

    // Step 7: Restore from backup
    let restored_payload = import_backup(&master_kek, &backup_blob)
        .expect("backup import must succeed");

    // Step 8: Parse restored data
    assert_eq!(restored_payload, payload, "restored payload must match original");

    let frost_len = u64::from_le_bytes(
        restored_payload[..8].try_into().unwrap()
    ) as usize;
    let restored_frost_bytes = &restored_payload[8..8 + frost_len];
    let restored_db_bytes = &restored_payload[8 + frost_len..];

    // Step 9: Verify FROST shares are intact and can still sign
    let mut restored_dkg = deserialize_frost_shares(restored_frost_bytes)
        .expect("FROST share deserialization must succeed");

    let message = b"post-disaster signing test";
    let signature = threshold_sign(
        &mut restored_dkg.shares,
        &restored_dkg.group,
        message,
        3,
    )
    .expect("threshold signing with restored shares must succeed");

    assert!(
        verify_group_signature(&restored_dkg.group, message, &signature),
        "signature from restored FROST shares must verify"
    );

    // Step 10: Verify DB state matches original
    let restored_db = MockDbState::from_bytes(restored_db_bytes)
        .expect("DB state deserialization must succeed");
    assert_eq!(restored_db, db_state, "restored DB state must match original");
}

// ---------------------------------------------------------------------------
// Test 2: Backup/restore with key rotation
// ---------------------------------------------------------------------------

#[test]
fn test_backup_restore_with_key_rotation() {
    let test_data = b"critical system state for key rotation test";

    // Create backup with KEK v1
    let kek_v1 = random_kek();
    let backup_v1 = export_backup(&kek_v1, test_data)
        .expect("export with KEK v1 must succeed");

    // Rotate to KEK v2
    let kek_v2 = random_kek();

    // Verify old backup still restores with KEK v1
    let restored_from_v1 = import_backup(&kek_v1, &backup_v1)
        .expect("import with KEK v1 must succeed after rotation");
    assert_eq!(
        &restored_from_v1, test_data,
        "data restored with KEK v1 must match original"
    );

    // Create new backup with KEK v2
    let backup_v2 = export_backup(&kek_v2, test_data)
        .expect("export with KEK v2 must succeed");

    // Verify new backup restores with KEK v2
    let restored_from_v2 = import_backup(&kek_v2, &backup_v2)
        .expect("import with KEK v2 must succeed");
    assert_eq!(
        &restored_from_v2, test_data,
        "data restored with KEK v2 must match original"
    );

    // Verify KEK v1 cannot restore KEK v2 backup
    assert!(
        import_backup(&kek_v1, &backup_v2).is_err(),
        "KEK v1 must NOT decrypt backup encrypted with KEK v2"
    );

    // Verify KEK v2 cannot restore KEK v1 backup
    assert!(
        import_backup(&kek_v2, &backup_v1).is_err(),
        "KEK v2 must NOT decrypt backup encrypted with KEK v1"
    );
}

// ---------------------------------------------------------------------------
// Test 3: Partial share recovery
// ---------------------------------------------------------------------------

#[test]
fn test_partial_share_recovery() {
    // Create FROST group with 5 shares, threshold 3
    let dkg_result = dkg(5, 3);
    let message = b"partial recovery signing test";

    // Back up all 5 shares individually (each encrypted with its own backup)
    let master_kek = random_kek();
    let mut share_backups = Vec::new();
    for share in &dkg_result.shares {
        let id_bytes = share.identifier.serialize();
        let key_bytes = share.key_package.serialize()
            .expect("serialize key package");
        let mut share_data = Vec::new();
        share_data.extend_from_slice(&(id_bytes.len() as u32).to_le_bytes());
        share_data.extend_from_slice(&id_bytes);
        share_data.extend_from_slice(&(key_bytes.len() as u32).to_le_bytes());
        share_data.extend_from_slice(&key_bytes);
        let backup = export_backup(&master_kek, &share_data)
            .expect("individual share backup must succeed");
        share_backups.push(backup);
    }

    // Simulate losing shares 3 and 4 (indices 3 and 4 — we keep 0,1,2)
    // Restore shares 0, 1, 2 from backup
    let mut restored_shares = Vec::new();
    for (i, backup) in share_backups.iter().enumerate() {
        if i >= 3 {
            continue; // "lost" shares
        }
        let share_data = import_backup(&master_kek, backup)
            .expect("share restore must succeed");

        let mut pos = 0;
        let id_len = u32::from_le_bytes(
            share_data[pos..pos + 4].try_into().unwrap(),
        ) as usize;
        pos += 4;
        let id_bytes = &share_data[pos..pos + id_len];
        pos += id_len;
        let key_len = u32::from_le_bytes(
            share_data[pos..pos + 4].try_into().unwrap(),
        ) as usize;
        pos += 4;
        let key_bytes = &share_data[pos..pos + key_len];

        use frost_ristretto255 as frost;
        let identifier = frost::Identifier::deserialize(id_bytes)
            .expect("deserialize identifier");
        let key_package = frost::keys::KeyPackage::deserialize(key_bytes)
            .expect("deserialize key package");

        // DR restore: advance nonce counter by DR_SAFETY_MARGIN to prevent
        // FROST nonce reuse. Nonce reuse = private key extraction.
        restored_shares.push(crypto::threshold::SignerShare {
            identifier,
            key_package,
            nonce_counter: std::sync::atomic::AtomicU64::new(DR_SAFETY_MARGIN),
        });
    }

    assert_eq!(restored_shares.len(), 3, "must have recovered 3 shares");

    // Verify 3-of-5 threshold signing still works with restored shares
    let signature = threshold_sign(
        &mut restored_shares,
        &dkg_result.group,
        message,
        3,
    )
    .expect("threshold signing with 3 restored shares must succeed");

    assert!(
        verify_group_signature(&dkg_result.group, message, &signature),
        "signature from 3 restored shares must verify against group key"
    );
}

// ---------------------------------------------------------------------------
// Test 4: Backup integrity under corruption
// ---------------------------------------------------------------------------

#[test]
fn test_backup_integrity_under_corruption() {
    let master_kek = random_kek();
    let data = b"integrity test data that must survive";
    let backup = export_backup(&master_kek, data)
        .expect("export must succeed");

    // Corrupt a byte in the ciphertext body
    {
        let mut corrupted = backup.clone();
        // Byte 30 is within the encrypted data for any reasonable backup
        if corrupted.len() > 30 {
            corrupted[30] ^= 0xFF;
        }
        assert!(
            import_backup(&master_kek, &corrupted).is_err(),
            "corrupted ciphertext must fail import"
        );
    }

    // Corrupt a byte in the HMAC (last 64 bytes)
    {
        let mut corrupted = backup.clone();
        let hmac_start = corrupted.len() - 64;
        corrupted[hmac_start] ^= 0x01;
        assert!(
            import_backup(&master_kek, &corrupted).is_err(),
            "corrupted HMAC must fail import"
        );
    }

    // Corrupt the version field
    {
        let mut corrupted = backup.clone();
        corrupted[8] ^= 0xFF; // version is at offset 8-9
        assert!(
            import_backup(&master_kek, &corrupted).is_err(),
            "corrupted version must fail import"
        );
    }

    // Truncated backup: only first 20 bytes
    {
        let truncated = &backup[..20];
        assert!(
            import_backup(&master_kek, truncated).is_err(),
            "truncated backup must fail import"
        );
    }

    // Truncated backup: missing last byte of HMAC
    {
        let truncated = &backup[..backup.len() - 1];
        assert!(
            import_backup(&master_kek, truncated).is_err(),
            "backup with truncated HMAC must fail import"
        );
    }

    // Wrong magic bytes
    {
        let mut wrong_magic = backup.clone();
        wrong_magic[0] = b'X';
        wrong_magic[1] = b'Y';
        assert!(
            import_backup(&master_kek, &wrong_magic).is_err(),
            "wrong magic bytes must fail import"
        );
    }

    // Completely empty input
    {
        assert!(
            import_backup(&master_kek, &[]).is_err(),
            "empty backup must fail import"
        );
    }

    // Single byte input
    {
        assert!(
            import_backup(&master_kek, &[0x00]).is_err(),
            "single-byte backup must fail import"
        );
    }

    // Verify the original backup is still valid
    let restored = import_backup(&master_kek, &backup)
        .expect("original backup must still import successfully");
    assert_eq!(&restored, data);
}

// ---------------------------------------------------------------------------
// Test 5: Cross-version backup compatibility (v1 and v2)
// ---------------------------------------------------------------------------

#[test]
fn test_cross_version_backup_compatibility() {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use hmac::{Hmac, Mac};
    use sha2::Sha512;

    type HmacSha512 = Hmac<Sha512>;

    let master_kek = random_kek();
    let data = b"cross-version compatibility test payload";

    // Derive the same keys that backup.rs uses internally
    let enc_key = {
        let hk = hkdf::Hkdf::<Sha512>::new(Some(b"MILNET-BACKUP-ENCRYPT-v1"), &master_kek);
        let mut okm = [0u8; 32];
        hk.expand(b"backup-aes-key", &mut okm).unwrap();
        okm
    };
    let hmac_key = {
        let hk = hkdf::Hkdf::<Sha512>::new(Some(b"MILNET-BACKUP-HMAC-v1"), &master_kek);
        let mut okm = [0u8; 64];
        hk.expand(b"backup-hmac-key", &mut okm).unwrap();
        okm
    };

    // Manually construct a v1 backup (MILBK001, version=1, AES-256-GCM)
    let v1_backup = {
        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes).unwrap();

        let cipher = Aes256Gcm::new_from_slice(&enc_key).unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, aes_gcm::aead::Payload { msg: &data[..], aad: b"" })
            .unwrap();

        let version_v1: u16 = 1;
        let encrypted_data_len = ciphertext.len() as u64;

        let mut backup = Vec::new();
        backup.extend_from_slice(b"MILBK001");
        backup.extend_from_slice(&version_v1.to_le_bytes());
        backup.extend_from_slice(&nonce_bytes);
        backup.extend_from_slice(&encrypted_data_len.to_le_bytes());
        backup.extend_from_slice(&ciphertext);

        let mut mac = <HmacSha512 as hmac::Mac>::new_from_slice(&hmac_key).unwrap();
        mac.update(&backup);
        let hmac_result = mac.finalize().into_bytes();
        backup.extend_from_slice(&hmac_result);

        backup
    };

    // Create a v2 backup using the standard API
    let v2_backup = export_backup(&master_kek, data)
        .expect("v2 export must succeed");

    // Verify both formats have correct magic bytes
    assert_eq!(&v1_backup[..8], b"MILBK001");
    assert_eq!(&v2_backup[..8], b"MILBK002");

    // Import v1 backup — must succeed
    let restored_v1 = import_backup(&master_kek, &v1_backup)
        .expect("v1 backup import must succeed");
    assert_eq!(&restored_v1, data, "v1 restored data must match original");

    // Import v2 backup — must succeed
    let restored_v2 = import_backup(&master_kek, &v2_backup)
        .expect("v2 backup import must succeed");
    assert_eq!(&restored_v2, data, "v2 restored data must match original");

    // Both restore to the same plaintext
    assert_eq!(
        restored_v1, restored_v2,
        "v1 and v2 backups must restore to identical plaintext"
    );

    // v1 and v2 ciphertext blobs must differ (different format, different nonces)
    assert_ne!(
        v1_backup, v2_backup,
        "v1 and v2 backup blobs must differ"
    );

    // Verify wrong KEK fails for both versions
    let wrong_kek = random_kek();
    assert!(
        import_backup(&wrong_kek, &v1_backup).is_err(),
        "wrong KEK must fail v1 import"
    );
    assert!(
        import_backup(&wrong_kek, &v2_backup).is_err(),
        "wrong KEK must fail v2 import"
    );
}
