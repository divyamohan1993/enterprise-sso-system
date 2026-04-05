//! Encrypted audit metadata layer.
//!
//! Encrypts sensitive fields (user_ids, device_ids, event_type, risk_score,
//! ceremony_receipts) before storage. Provides blind indexes for searchability
//! using HMAC-SHA512 (truncated to 32 bytes for index size compatibility).

use crate::types::{AuditEventType, Receipt};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use uuid::Uuid;

/// AAD for audit metadata encryption.
const AUDIT_METADATA_AAD: &[u8] = b"MILNET-AUDIT-META-v1";

/// Domain separator for audit blind index derivation.
const AUDIT_BLIND_INDEX_KEY_DOMAIN: &[u8] = b"MILNET-AUDIT-BLIND-v1";

type HmacSha512 = Hmac<Sha512>;

/// Encrypted audit metadata — stored alongside the hash-chain fields.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedAuditMetadata {
    /// AES-256-GCM nonce.
    pub nonce: [u8; 12],
    /// Encrypted blob containing serialized AuditMetadataPlaintext.
    pub ciphertext: Vec<u8>,
    /// HMAC-SHA512 blind indexes (truncated to 32 bytes) for each user_id (for search).
    pub user_blind_indexes: Vec<[u8; 32]>,
    /// HMAC-SHA512 blind index (truncated to 32 bytes) for event_type (for filtering).
    pub event_type_blind_index: [u8; 32],
}

/// The plaintext metadata that gets encrypted.
#[derive(Clone, Serialize, Deserialize)]
struct AuditMetadataPlaintext {
    pub event_type: AuditEventType,
    pub user_ids: Vec<Uuid>,
    pub device_ids: Vec<Uuid>,
    pub risk_score: f64,
    pub ceremony_receipts: Vec<Receipt>,
}

/// Encrypt audit metadata for an entry.
///
/// Sensitive fields are AES-256-GCM encrypted with the provided key. Blind
/// indexes are computed using HMAC-SHA512 (truncated to 32 bytes) so that encrypted entries remain
/// searchable by user_id or event_type without exposing plaintext.
pub fn encrypt_audit_metadata(
    event_type: AuditEventType,
    user_ids: &[Uuid],
    device_ids: &[Uuid],
    risk_score: f64,
    ceremony_receipts: &[Receipt],
    encryption_key: &[u8; 32],
    blind_index_key: &[u8; 32],
) -> Result<EncryptedAuditMetadata, String> {
    let plaintext_meta = AuditMetadataPlaintext {
        event_type,
        user_ids: user_ids.to_vec(),
        device_ids: device_ids.to_vec(),
        risk_score,
        ceremony_receipts: ceremony_receipts.to_vec(),
    };

    let plaintext = postcard::to_allocvec(&plaintext_meta)
        .map_err(|e| format!("audit metadata serialization failed: {e}"))?;

    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| format!("nonce generation failed: {e}"))?;

    let cipher = match Aes256Gcm::new_from_slice(encryption_key) {
        Ok(c) => c,
        Err(_) => return Err("AES-256-GCM key init failed for encrypted audit".into()),
    };
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: &plaintext,
                aad: AUDIT_METADATA_AAD,
            },
        )
        .map_err(|e| format!("audit metadata encryption failed: {e}"))?;

    // Compute blind indexes
    let user_blind_indexes: Vec<[u8; 32]> = user_ids
        .iter()
        .map(|uid| compute_blind_index(blind_index_key, uid.as_bytes()))
        .collect();

    let event_type_bytes = postcard::to_allocvec(&event_type).unwrap_or_default();
    let event_type_blind_index = compute_blind_index(blind_index_key, &event_type_bytes);

    Ok(EncryptedAuditMetadata {
        nonce: nonce_bytes,
        ciphertext,
        user_blind_indexes,
        event_type_blind_index,
    })
}

/// Decrypt audit metadata.
///
/// Returns `(event_type, user_ids, device_ids, risk_score, ceremony_receipts)`
/// on success, or an error if the ciphertext is tampered or the key is wrong.
pub fn decrypt_audit_metadata(
    encrypted: &EncryptedAuditMetadata,
    encryption_key: &[u8; 32],
) -> Result<(AuditEventType, Vec<Uuid>, Vec<Uuid>, f64, Vec<Receipt>), String> {
    let cipher = match Aes256Gcm::new_from_slice(encryption_key) {
        Ok(c) => c,
        Err(_) => return Err("AES-256-GCM key init failed for encrypted audit".into()),
    };
    let nonce = Nonce::from_slice(&encrypted.nonce);

    let plaintext = cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: &encrypted.ciphertext,
                aad: AUDIT_METADATA_AAD,
            },
        )
        .map_err(|_| "audit metadata decryption failed — tampered or wrong key".to_string())?;

    let meta: AuditMetadataPlaintext = postcard::from_bytes(&plaintext)
        .map_err(|e| format!("audit metadata deserialization failed: {e}"))?;

    Ok((
        meta.event_type,
        meta.user_ids,
        meta.device_ids,
        meta.risk_score,
        meta.ceremony_receipts,
    ))
}

/// Compute a blind index using HMAC-SHA512, truncated to 32 bytes for index compatibility.
///
/// CNSA 2.0 requires SHA-512 as the minimum hash strength. The output is
/// truncated to 32 bytes to maintain the same blind index size as the previous
/// HMAC-SHA256 implementation, preserving storage layout and search compatibility.
fn compute_blind_index(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha512 as Mac>::new_from_slice(key).unwrap_or_else(|e| {
        tracing::error!("FATAL: HMAC-SHA512 key init failed for audit blind index: {e}");
        std::process::exit(1);
    });
    mac.update(AUDIT_BLIND_INDEX_KEY_DOMAIN);
    mac.update(data);
    let full_hash = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&full_hash[..32]);
    out
}

/// Compute a blind index for searching by user ID.
///
/// The returned value can be compared against `EncryptedAuditMetadata::user_blind_indexes`
/// to find entries belonging to a specific user without decryption.
pub fn search_user_blind_index(blind_index_key: &[u8; 32], user_id: &Uuid) -> [u8; 32] {
    compute_blind_index(blind_index_key, user_id.as_bytes())
}

/// Compute a blind index for searching by event type.
///
/// The returned value can be compared against `EncryptedAuditMetadata::event_type_blind_index`
/// to filter entries by event type without decryption.
pub fn search_event_type_blind_index(
    blind_index_key: &[u8; 32],
    event_type: &AuditEventType,
) -> [u8; 32] {
    let event_bytes = postcard::to_allocvec(event_type).unwrap_or_default();
    compute_blind_index(blind_index_key, &event_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::AuditEventType;

    fn test_keys() -> ([u8; 32], [u8; 32]) {
        let mut enc_key = [0u8; 32];
        let mut blind_key = [0u8; 32];
        getrandom::getrandom(&mut enc_key).unwrap();
        getrandom::getrandom(&mut blind_key).unwrap();
        (enc_key, blind_key)
    }

    #[test]
    fn round_trip_encrypt_decrypt() {
        let (enc_key, blind_key) = test_keys();
        let user_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let event_type = AuditEventType::AuthSuccess;
        let risk_score = 0.42;
        let receipts = vec![crate::types::Receipt::test_fixture()];

        let encrypted = encrypt_audit_metadata(
            event_type,
            &[user_id],
            &[device_id],
            risk_score,
            &receipts,
            &enc_key,
            &blind_key,
        )
        .expect("encryption must succeed");

        let (dec_event, dec_users, dec_devices, dec_risk, dec_receipts) =
            decrypt_audit_metadata(&encrypted, &enc_key).expect("decryption must succeed");

        assert_eq!(dec_event, event_type);
        assert_eq!(dec_users, vec![user_id]);
        assert_eq!(dec_devices, vec![device_id]);
        assert!((dec_risk - risk_score).abs() < f64::EPSILON);
        assert_eq!(dec_receipts.len(), 1);
        assert_eq!(dec_receipts[0].step_id, receipts[0].step_id);
    }

    #[test]
    fn wrong_key_fails() {
        let (enc_key, blind_key) = test_keys();
        let encrypted = encrypt_audit_metadata(
            AuditEventType::AuthFailure,
            &[Uuid::new_v4()],
            &[],
            0.0,
            &[],
            &enc_key,
            &blind_key,
        )
        .unwrap();

        let mut wrong_key = [0u8; 32];
        getrandom::getrandom(&mut wrong_key).unwrap();
        let result = decrypt_audit_metadata(&encrypted, &wrong_key);
        assert!(result.is_err(), "decryption with wrong key must fail");
        assert!(
            result.unwrap_err().contains("tampered or wrong key"),
            "error must mention tamper/wrong key"
        );
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (enc_key, blind_key) = test_keys();
        let mut encrypted = encrypt_audit_metadata(
            AuditEventType::KeyRotation,
            &[],
            &[],
            1.0,
            &[],
            &enc_key,
            &blind_key,
        )
        .unwrap();

        // Flip a byte in the ciphertext
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 0xFF;
        }

        let result = decrypt_audit_metadata(&encrypted, &enc_key);
        assert!(result.is_err(), "tampered ciphertext must fail decryption");
    }

    #[test]
    fn blind_index_deterministic() {
        let (_, blind_key) = test_keys();
        let user_id = Uuid::new_v4();

        let idx1 = search_user_blind_index(&blind_key, &user_id);
        let idx2 = search_user_blind_index(&blind_key, &user_id);
        assert_eq!(idx1, idx2, "blind index must be deterministic");
    }

    #[test]
    fn blind_index_different_users() {
        let (_, blind_key) = test_keys();
        let user_a = Uuid::new_v4();
        let user_b = Uuid::new_v4();

        let idx_a = search_user_blind_index(&blind_key, &user_a);
        let idx_b = search_user_blind_index(&blind_key, &user_b);
        assert_ne!(
            idx_a, idx_b,
            "different users must produce different blind indexes"
        );
    }

    #[test]
    fn blind_index_search_matches() {
        let (enc_key, blind_key) = test_keys();
        let user_id = Uuid::new_v4();

        let encrypted = encrypt_audit_metadata(
            AuditEventType::MfaEnabled,
            &[user_id],
            &[],
            0.0,
            &[],
            &enc_key,
            &blind_key,
        )
        .unwrap();

        let search_idx = search_user_blind_index(&blind_key, &user_id);
        assert!(
            encrypted.user_blind_indexes.contains(&search_idx),
            "search blind index must match stored blind index"
        );

        // Event type blind index must also match
        let event_search = search_event_type_blind_index(&blind_key, &AuditEventType::MfaEnabled);
        assert_eq!(
            encrypted.event_type_blind_index, event_search,
            "event type blind index must match"
        );
    }

    #[test]
    fn nonce_uniqueness() {
        let (enc_key, blind_key) = test_keys();

        let enc1 = encrypt_audit_metadata(
            AuditEventType::AuthSuccess,
            &[],
            &[],
            0.0,
            &[],
            &enc_key,
            &blind_key,
        )
        .unwrap();

        let enc2 = encrypt_audit_metadata(
            AuditEventType::AuthSuccess,
            &[],
            &[],
            0.0,
            &[],
            &enc_key,
            &blind_key,
        )
        .unwrap();

        assert_ne!(
            enc1.nonce, enc2.nonce,
            "nonces must be unique across encryptions"
        );
        assert_ne!(
            enc1.ciphertext, enc2.ciphertext,
            "ciphertexts must differ due to unique nonces"
        );
    }
}
