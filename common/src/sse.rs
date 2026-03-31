//! Searchable Symmetric Encryption (SSE) — Blind Index for Zero-Trust DB.
//!
//! The database NEVER sees plaintext. Encrypted fields are searchable via a
//! blind index: HMAC-SHA512 truncated to 32 bytes. The blind key is derived
//! from a master key via HKDF-SHA512 with a domain separator.
//!
//! Wire format for ciphertext: `algo_id (1) || nonce || ciphertext || tag`.
//! This is the same format used by `crypto::symmetric` and `encrypted_db` so
//! blobs are interoperable across the stack.

use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::Zeroize;

type HmacSha512 = Hmac<Sha512>;

const BLIND_INDEX_DOMAIN: &[u8] = b"MILNET-BLIND-INDEX-v1";

const ALGO_ID_AEGIS256: u8 = 0x01;
const ALGO_ID_AES256GCM: u8 = 0x02;

// ---------------------------------------------------------------------------
// BlindIndex
// ---------------------------------------------------------------------------

/// A keyed blind-index computer backed by HMAC-SHA512.
pub struct BlindIndex {
    blind_key: [u8; 64],
}

impl BlindIndex {
    /// Construct from a raw 64-byte key.
    pub fn new(blind_key: [u8; 64]) -> Self {
        Self { blind_key }
    }

    /// Derive a blind index key from a 32-byte master key and a purpose string.
    ///
    /// Uses HKDF-SHA512 with `BLIND_INDEX_DOMAIN` as salt so keys are
    /// domain-separated from all other HKDF usages in the system.
    pub fn derive_from_master(master: &[u8; 32], purpose: &str) -> Self {
        use hkdf::Hkdf;
        let hk = Hkdf::<Sha512>::new(Some(BLIND_INDEX_DOMAIN), master);
        let mut key = [0u8; 64];
        // 64 ≤ 255 * HashLen(64) — always valid for HKDF-SHA512.
        if let Err(e) = hk.expand(purpose.as_bytes(), &mut key) {
            tracing::error!("FATAL: HKDF-SHA512 expand failed for SSE blind index key: {e}");
            std::process::exit(1);
        }
        Self { blind_key: key }
    }

    /// Compute a 32-byte blind index for `plaintext` (HMAC-SHA512 truncated).
    pub fn compute(&self, plaintext: &[u8]) -> [u8; 32] {
        let full = self.compute_full(plaintext);
        let mut truncated = [0u8; 32];
        truncated.copy_from_slice(&full[..32]);
        truncated
    }

    /// Compute the full 64-byte HMAC-SHA512 blind index.
    pub fn compute_full(&self, plaintext: &[u8]) -> [u8; 64] {
        let mut mac = HmacSha512::new_from_slice(&self.blind_key)
            .unwrap_or_else(|e| {
                tracing::error!("FATAL: HMAC-SHA512 key init failed for SSE blind index: {e}");
                std::process::exit(1);
            });
        mac.update(BLIND_INDEX_DOMAIN);
        mac.update(plaintext);
        let result = mac.finalize().into_bytes();
        let mut out = [0u8; 64];
        out.copy_from_slice(&result);
        out
    }
}

impl Drop for BlindIndex {
    fn drop(&mut self) {
        self.blind_key.zeroize();
    }
}

// ---------------------------------------------------------------------------
// EncryptedField
// ---------------------------------------------------------------------------

/// An encrypted database field together with its searchable blind index.
#[derive(Clone)]
pub struct EncryptedField {
    /// 32-byte truncated HMAC-SHA512 blind index (stored in DB, never plaintext).
    pub blind_index: [u8; 32],
    /// AEAD ciphertext. Wire format: `algo_id (1) || nonce || ciphertext || tag`.
    pub ciphertext: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Symmetric helpers (AEGIS-256 / AES-256-GCM, FIPS-aware)
// ---------------------------------------------------------------------------

fn sym_encrypt(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    if crate::fips::is_fips_mode() {
        sym_encrypt_aes256gcm(key, plaintext, aad)
    } else {
        sym_encrypt_aegis256(key, plaintext, aad)
    }
}

fn sym_encrypt_aegis256(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    use aegis::aegis256::Aegis256;
    const NONCE_LEN: usize = 32;
    const TAG_LEN: usize = 32;

    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| format!("AEGIS-256 nonce generation failed: {e}"))?;

    let (ct, tag) = Aegis256::<TAG_LEN>::new(key, &nonce).encrypt(plaintext, aad);

    let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len() + TAG_LEN);
    out.push(ALGO_ID_AEGIS256);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    Ok(out)
}

fn sym_encrypt_aes256gcm(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use aes_gcm::aead::Aead;
    const NONCE_LEN: usize = 12;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| format!("AES-256-GCM nonce generation failed: {e}"))?;

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("bad key: {e}"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, aes_gcm::aead::Payload { msg: plaintext, aad })
        .map_err(|e| format!("AES-256-GCM encryption failed: {e}"))?;

    let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
    out.push(ALGO_ID_AES256GCM);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn sym_decrypt(key: &[u8; 32], sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let first = sealed.first().copied().ok_or("empty ciphertext")?;
    match first {
        ALGO_ID_AEGIS256 => sym_decrypt_aegis256(key, sealed.get(1..).ok_or("truncated blob")?, aad),
        ALGO_ID_AES256GCM => sym_decrypt_aes256gcm(key, sealed.get(1..).ok_or("truncated blob")?, aad),
        _ => Err(format!("unknown algo_id: 0x{first:02x}")),
    }
}

fn sym_decrypt_aegis256(key: &[u8; 32], blob: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    use aegis::aegis256::Aegis256;
    const NONCE_LEN: usize = 32;
    const TAG_LEN: usize = 32;

    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err("AEGIS-256 blob too short".to_string());
    }
    let nonce: [u8; NONCE_LEN] = blob[..NONCE_LEN].try_into().map_err(|_| "nonce slice")?;
    let rest = &blob[NONCE_LEN..];
    let tag_offset = rest.len().checked_sub(TAG_LEN).ok_or("AEGIS-256: too short for tag")?;
    let ciphertext = &rest[..tag_offset];
    let tag: [u8; TAG_LEN] = rest[tag_offset..].try_into().map_err(|_| "tag slice")?;

    Aegis256::<TAG_LEN>::new(key, &nonce)
        .decrypt(ciphertext, &tag, aad)
        .map_err(|e| format!("AEGIS-256 decryption failed: {e}"))
}

fn sym_decrypt_aes256gcm(key: &[u8; 32], blob: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use aes_gcm::aead::Aead;
    const NONCE_LEN: usize = 12;
    const TAG_LEN: usize = 16;

    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err("AES-256-GCM blob too short".to_string());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("bad key: {e}"))?;
    let nonce = Nonce::from_slice(&blob[..NONCE_LEN]);
    cipher
        .decrypt(nonce, aes_gcm::aead::Payload { msg: &blob[NONCE_LEN..], aad })
        .map_err(|e| format!("AES-256-GCM decryption failed: {e}"))
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Encrypt a field for storage with a searchable blind index.
///
/// * `blind_key`  — keyed HMAC material for the blind index.
/// * `enc_key`    — 32-byte AEAD key for the field ciphertext.
/// * `plaintext`  — the value to encrypt.
/// * `field_name` — used as AAD so each field is domain-separated.
pub fn encrypt_searchable(
    blind_key: &BlindIndex,
    enc_key: &[u8; 32],
    plaintext: &[u8],
    field_name: &str,
) -> Result<EncryptedField, String> {
    let blind_index = blind_key.compute(plaintext);
    let ciphertext = sym_encrypt(enc_key, plaintext, field_name.as_bytes())?;
    Ok(EncryptedField { blind_index, ciphertext })
}

/// Compute a search index for querying — identical to `blind_key.compute(search_term)`.
///
/// The caller compares the returned value against stored `EncryptedField::blind_index`
/// bytes without ever sending plaintext to the DB.
pub fn search_index(blind_key: &BlindIndex, search_term: &[u8]) -> [u8; 32] {
    blind_key.compute(search_term)
}

/// Decrypt an encrypted field produced by `encrypt_searchable`.
pub fn decrypt_field(
    enc_key: &[u8; 32],
    ciphertext: &[u8],
    field_name: &str,
) -> Result<Vec<u8>, String> {
    sym_decrypt(enc_key, ciphertext, field_name.as_bytes())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn random_key_32() -> [u8; 32] {
        let mut k = [0u8; 32];
        getrandom::getrandom(&mut k).unwrap();
        k
    }

    fn random_key_64() -> [u8; 64] {
        let mut k = [0u8; 64];
        getrandom::getrandom(&mut k).unwrap();
        k
    }

    #[test]
    fn test_blind_index_deterministic() {
        let key = random_key_64();
        let bi = BlindIndex::new(key);
        let idx1 = bi.compute(b"alice@army.mil");
        let idx2 = bi.compute(b"alice@army.mil");
        assert_eq!(idx1, idx2, "blind index must be deterministic");
    }

    #[test]
    fn test_blind_index_different_inputs() {
        let key = random_key_64();
        let bi = BlindIndex::new(key);
        let idx1 = bi.compute(b"alice@army.mil");
        let idx2 = bi.compute(b"bob@army.mil");
        assert_ne!(idx1, idx2, "different inputs must produce different indices");
    }

    #[test]
    fn test_blind_index_derive_from_master() {
        let master = random_key_32();
        let bi = BlindIndex::derive_from_master(&master, "email");
        let idx = bi.compute(b"test@navy.mil");
        assert_ne!(idx, [0u8; 32], "blind index must be non-zero");
    }

    #[test]
    fn test_encrypt_searchable_roundtrip() {
        let master = random_key_32();
        let bi = BlindIndex::derive_from_master(&master, "username");
        let enc_key = random_key_32();
        let plaintext = b"james.smith042";

        let field = encrypt_searchable(&bi, &enc_key, plaintext, "username").unwrap();

        // Search by blind index
        let si = search_index(&bi, plaintext);
        assert_eq!(si, field.blind_index, "search index must match stored blind index");

        // Decrypt and verify
        let recovered = decrypt_field(&enc_key, &field.ciphertext, "username").unwrap();
        assert_eq!(recovered, plaintext, "decrypted value must match original");
    }

    #[test]
    fn test_search_index_matches_stored() {
        let master = random_key_32();
        let bi = BlindIndex::derive_from_master(&master, "military_id");
        let enc_key = random_key_32();
        let plaintext = b"1234567890";

        let field = encrypt_searchable(&bi, &enc_key, plaintext, "military_id").unwrap();
        let si = search_index(&bi, plaintext);

        assert_eq!(si, field.blind_index, "search index must match stored blind index");
    }

    #[test]
    fn test_blind_index_zeroized_on_drop() {
        // Verify the Drop impl compiles and runs without panic.
        // Post-drop memory inspection is not possible in safe Rust.
        let key = random_key_64();
        let bi = BlindIndex::new(key);
        let idx = bi.compute(b"zeroize test");
        drop(bi);
        // Reaching here confirms Drop ran successfully.
        assert_ne!(idx, [0u8; 32]);
    }

    #[test]
    fn test_encrypt_searchable_different_fields() {
        // Same plaintext, different field_name → different ciphertext (AAD differs).
        let master = random_key_32();
        let bi = BlindIndex::derive_from_master(&master, "field");
        let enc_key = random_key_32();
        let plaintext = b"sensitive_value";

        let field_a = encrypt_searchable(&bi, &enc_key, plaintext, "email").unwrap();
        let field_b = encrypt_searchable(&bi, &enc_key, plaintext, "username").unwrap();

        // Ciphertexts must differ: different AAD binds to different ciphertext domains,
        // and fresh random nonces add additional uniqueness.
        assert_ne!(
            field_a.ciphertext, field_b.ciphertext,
            "different field names must produce different ciphertexts"
        );
    }
}
