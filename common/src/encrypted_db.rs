//! Hardened PostgreSQL persistence layer with envelope encryption at rest.
//!
//! Every sensitive BYTEA column is encrypted with AES-256-GCM before INSERT
//! and decrypted after SELECT. Data encryption keys (DEKs) are per-table,
//! derived from a key encryption key (KEK) via HKDF-SHA512.
//!
//! # Encrypted columns
//! | Table              | Column              | AAD context         |
//! |--------------------|---------------------|---------------------|
//! | users              | opaque_registration | users:opaque        |
//! | users              | email_encrypted     | users:email         |
//! | users              | username_encrypted  | users:username      |
//! | users              | duress_pin_hash     | users:duress        |
//! | fido_credentials   | public_key          | fido:pubkey         |
//! | portals            | client_secret       | portals:secret      |
//! | key_material       | key_bytes           | keymaterial:bytes    |
//! | audit_log          | signature           | audit:sig           |
//! | audit_log          | data                | audit:data          |
//! | ratchet_sessions   | chain_key_encrypted | ratchet:chain_key   |
//! | witness_checkpoints| signature           | witness:sig         |

use sqlx::PgPool;
use zeroize::Zeroize;

/// Version tag prepended to the new envelope format (per-operation DEK).
const ENVELOPE_V2_TAG: u8 = 0x02;

/// Size of the wrapped DEK blob: wrap_nonce(12) + encrypted_dek(32) + gcm_tag(16) = 60 bytes.
const WRAPPED_DEK_LEN: usize = 12 + 32 + 16;

/// Envelope-encryption context carried alongside the database pool.
/// Services that need encrypted storage must initialise this at startup.
pub struct EncryptedPool {
    pub pool: PgPool,
    /// Per-table KEK derivation seed (from master key hierarchy).
    /// In production this comes from HSM; here it is loaded from env / sealed storage.
    master_kek: [u8; 32],
}

impl EncryptedPool {
    /// Wrap a raw pool with envelope encryption using the given master KEK.
    pub fn new(pool: PgPool, master_kek: [u8; 32]) -> Self {
        Self { pool, master_kek }
    }

    /// Derive a per-table KEK using HKDF-SHA512.
    fn table_kek(&self, table: &str) -> Result<[u8; 32], String> {
        use hkdf::Hkdf;
        use sha2::Sha512;
        let hk = Hkdf::<Sha512>::new(Some(b"MILNET-TABLE-KEK-v1"), &self.master_kek);
        let mut okm = [0u8; 32];
        hk.expand(table.as_bytes(), &mut okm)
            .map_err(|_| "HKDF-SHA512 table KEK derivation failed".to_string())?;
        Ok(okm)
    }

    /// Encrypt a plaintext value for a specific table/column/row.
    ///
    /// Uses envelope encryption: a per-operation DEK encrypts the data, then
    /// the DEK is wrapped (encrypted) with the table KEK.
    ///
    /// Wire format (v2):
    /// `ENVELOPE_V2_TAG(1) || wrap_nonce(12) || wrapped_dek(48) || data_nonce(12) || ciphertext || tag(16)`
    pub fn encrypt_field(&self, table: &str, column: &str, row_id: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        use aes_gcm::aead::Aead;

        // Generate per-operation DEK
        let mut dek = [0u8; 32];
        getrandom::getrandom(&mut dek)
            .map_err(|e| format!("OS entropy failure during DEK generation: {e}"))?;

        // Encrypt plaintext with DEK
        let dek_cipher = Aes256Gcm::new_from_slice(&dek)
            .map_err(|_| "AES-256-GCM cipher initialization failed".to_string())?;
        let mut data_nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut data_nonce_bytes)
            .map_err(|e| format!("OS entropy failure during nonce generation: {e}"))?;
        let data_nonce = Nonce::from_slice(&data_nonce_bytes);
        let aad = build_aad(table, column, row_id);
        let ciphertext = dek_cipher
            .encrypt(data_nonce, aes_gcm::aead::Payload { msg: plaintext, aad: &aad })
            .map_err(|_| "AES-256-GCM encryption failed".to_string())?;

        // Wrap DEK with table KEK
        let kek = self.table_kek(table)?;
        let kek_cipher = Aes256Gcm::new_from_slice(&kek)
            .map_err(|_| "AES-256-GCM cipher initialization failed".to_string())?;
        let mut wrap_nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut wrap_nonce_bytes)
            .map_err(|e| format!("OS entropy failure during wrap nonce generation: {e}"))?;
        let wrap_nonce = Nonce::from_slice(&wrap_nonce_bytes);
        let wrapped_dek = kek_cipher
            .encrypt(wrap_nonce, aes_gcm::aead::Payload { msg: dek.as_ref(), aad: b"MILNET-KEK-WRAP-v1" })
            .map_err(|_| "AES-256-GCM DEK wrap failed".to_string())?;

        // Zeroize DEK
        dek.zeroize();

        // Output: version(1) || wrap_nonce(12) || wrapped_dek(48) || data_nonce(12) || ciphertext+tag
        let mut out = Vec::with_capacity(1 + 12 + wrapped_dek.len() + 12 + ciphertext.len());
        out.push(ENVELOPE_V2_TAG);
        out.extend_from_slice(&wrap_nonce_bytes);
        out.extend_from_slice(&wrapped_dek);
        out.extend_from_slice(&data_nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt a sealed field value. Returns plaintext or error.
    ///
    /// Supports both:
    /// - V2 envelope format (first byte == `ENVELOPE_V2_TAG`): per-operation DEK
    /// - Legacy format (any other first byte): direct KEK encryption
    pub fn decrypt_field(&self, table: &str, column: &str, row_id: &[u8], sealed: &[u8]) -> Result<Vec<u8>, String> {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        use aes_gcm::aead::Aead;

        if sealed.is_empty() {
            return Err("sealed data is empty".into());
        }

        if sealed[0] == ENVELOPE_V2_TAG {
            // V2 envelope format: version(1) || wrap_nonce(12) || wrapped_dek(48) || data_nonce(12) || ciphertext+tag
            let min_v2_len = 1 + WRAPPED_DEK_LEN + 12 + 16;
            if sealed.len() < min_v2_len {
                return Err("V2 sealed data too short".into());
            }

            // Layout after version byte: wrap_nonce(12) || wrapped_dek(48) || data_nonce(12) || data_ct
            let rest = &sealed[1..];
            let wrap_nonce_bytes = &rest[..12];
            let wrapped_dek_ct = &rest[12..WRAPPED_DEK_LEN];
            let data_nonce_bytes = &rest[WRAPPED_DEK_LEN..WRAPPED_DEK_LEN + 12];
            let data_ct = &rest[WRAPPED_DEK_LEN + 12..];

            // Unwrap DEK
            let kek = self.table_kek(table)?;
            let kek_cipher = Aes256Gcm::new_from_slice(&kek)
                .map_err(|_| "AES-256-GCM cipher initialization failed".to_string())?;
            let wrap_nonce = Nonce::from_slice(wrap_nonce_bytes);
            let mut dek_bytes = kek_cipher
                .decrypt(wrap_nonce, aes_gcm::aead::Payload { msg: wrapped_dek_ct, aad: b"MILNET-KEK-WRAP-v1" })
                .map_err(|_| "DEK unwrap failed — tampered or wrong KEK".to_string())?;

            if dek_bytes.len() != 32 {
                dek_bytes.zeroize();
                return Err("unwrapped DEK has wrong length".into());
            }

            // Decrypt data with DEK
            let dek_cipher = Aes256Gcm::new_from_slice(&dek_bytes)
                .map_err(|_| "AES-256-GCM cipher initialization failed".to_string())?;
            let data_nonce = Nonce::from_slice(data_nonce_bytes);
            let aad = build_aad(table, column, row_id);
            let result = dek_cipher
                .decrypt(data_nonce, aes_gcm::aead::Payload { msg: data_ct, aad: &aad })
                .map_err(|_| "AES-256-GCM decryption failed — tampered or wrong key".to_string());

            // Zeroize DEK
            dek_bytes.zeroize();

            result
        } else {
            // Legacy format: nonce(12) || ciphertext || tag(16)
            if sealed.len() < 12 + 16 {
                return Err("sealed data too short for nonce + tag".into());
            }

            let kek = self.table_kek(table)?;
            let cipher = Aes256Gcm::new_from_slice(&kek)
                .map_err(|_| "AES-256-GCM cipher initialization failed".to_string())?;

            let nonce = Nonce::from_slice(&sealed[..12]);
            let ciphertext = &sealed[12..];
            let aad = build_aad(table, column, row_id);

            cipher
                .decrypt(nonce, aes_gcm::aead::Payload { msg: ciphertext, aad: &aad })
                .map_err(|_| "AES-256-GCM decryption failed — tampered or wrong key".to_string())
        }
    }

    /// Encrypt an optional field (returns None if input is None).
    pub fn encrypt_optional(&self, table: &str, column: &str, row_id: &[u8], plaintext: Option<&[u8]>) -> Result<Option<Vec<u8>>, String> {
        match plaintext {
            Some(pt) => self.encrypt_field(table, column, row_id, pt).map(Some),
            None => Ok(None),
        }
    }

    /// Decrypt an optional sealed field.
    pub fn decrypt_optional(&self, table: &str, column: &str, row_id: &[u8], sealed: Option<&[u8]>) -> Result<Option<Vec<u8>>, String> {
        match sealed {
            None => Ok(None),
            Some(s) => self.decrypt_field(table, column, row_id, s).map(Some),
        }
    }

    /// Raw pool access for non-sensitive queries.
    pub fn raw(&self) -> &PgPool {
        &self.pool
    }
}

impl Drop for EncryptedPool {
    fn drop(&mut self) {
        self.master_kek.zeroize();
    }
}

/// Build AAD that binds ciphertext to its storage location.
fn build_aad(table: &str, column: &str, row_id: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(14 + table.len() + column.len() + row_id.len() + 2);
    aad.extend_from_slice(b"MILNET-AAD-v1:");
    aad.extend_from_slice(table.as_bytes());
    aad.push(b':');
    aad.extend_from_slice(column.as_bytes());
    aad.push(b':');
    aad.extend_from_slice(row_id);
    aad
}

/// Store key material with envelope encryption.
pub async fn store_key_encrypted(epool: &EncryptedPool, name: &str, key_bytes: &[u8]) -> Result<(), String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let encrypted = epool.encrypt_field("key_material", "key_bytes", name.as_bytes(), key_bytes)?;

    sqlx::query(
        "INSERT INTO key_material (key_name, key_bytes, created_at) VALUES ($1, $2, $3) \
         ON CONFLICT (key_name) DO UPDATE SET key_bytes = $2, rotated_at = $3"
    )
    .bind(name)
    .bind(&encrypted)
    .bind(now)
    .execute(&epool.pool)
    .await
    .map_err(|e| format!("failed to store key material: {e}"))?;
    Ok(())
}

/// Load and decrypt key material from the database.
pub async fn load_key_encrypted(epool: &EncryptedPool, name: &str) -> Option<Vec<u8>> {
    let encrypted: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT key_bytes FROM key_material WHERE key_name = $1"
    )
    .bind(name)
    .fetch_optional(&epool.pool)
    .await
    .ok()
    .flatten();

    match encrypted {
        Some(sealed) => {
            epool.decrypt_field("key_material", "key_bytes", name.as_bytes(), &sealed).ok()
        }
        None => None,
    }
}

/// Load or generate a 64-byte key with envelope encryption.
pub async fn load_or_generate_key_64_encrypted(epool: &EncryptedPool, name: &str) -> Result<[u8; 64], String> {
    if let Some(existing) = load_key_encrypted(epool, name).await {
        if existing.len() == 64 {
            let mut key = [0u8; 64];
            key.copy_from_slice(&existing);
            return Ok(key);
        }
    }
    let mut key = [0u8; 64];
    getrandom::getrandom(&mut key)
        .map_err(|e| format!("OS entropy failure during key generation: {e}"))?;
    store_key_encrypted(epool, name, &key).await?;
    Ok(key)
}

/// Load or generate a 32-byte key with envelope encryption.
pub async fn load_or_generate_key_32_encrypted(epool: &EncryptedPool, name: &str) -> Result<[u8; 32], String> {
    if let Some(existing) = load_key_encrypted(epool, name).await {
        if existing.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&existing);
            return Ok(key);
        }
    }
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key)
        .map_err(|e| format!("OS entropy failure during key generation: {e}"))?;
    store_key_encrypted(epool, name, &key).await?;
    Ok(key)
}

/// Initialize an encrypted pool with the given master KEK.
pub fn wrap_pool(pool: PgPool, master_kek: [u8; 32]) -> EncryptedPool {
    EncryptedPool::new(pool, master_kek)
}

/// Encrypt a ratchet chain key for storage in the `ratchet_sessions` table.
///
/// Uses the table KEK derived from `ratchet_sessions` with AAD binding to
/// the specific session ID: `MILNET-AAD-v1:ratchet_sessions:chain_key:{session_id}`.
///
/// Returns `nonce(12) || ciphertext || tag(16)`.
pub fn encrypt_ratchet_key(epool: &EncryptedPool, session_id: &uuid::Uuid, chain_key: &[u8]) -> Result<Vec<u8>, String> {
    epool.encrypt_field("ratchet_sessions", "chain_key", session_id.as_bytes(), chain_key)
}

/// Decrypt a ratchet chain key loaded from the `ratchet_sessions` table.
///
/// Uses the table KEK derived from `ratchet_sessions` with the same AAD
/// that was used during encryption.
pub fn decrypt_ratchet_key(epool: &EncryptedPool, session_id: &uuid::Uuid, sealed: &[u8]) -> Result<Vec<u8>, String> {
    epool.decrypt_field("ratchet_sessions", "chain_key", session_id.as_bytes(), sealed)
}

// Algorithm identifier constants for the PII wire format.
// These mirror crypto::symmetric constants to keep the blobs compatible.
const PII_ALGO_ID_AEGIS256: u8 = 0x01;
const PII_ALGO_ID_AES256GCM: u8 = 0x02;

/// Encrypt a PII field with compliance enforcement and AEGIS-256/AES-256-GCM.
///
/// Before encrypting, the compliance engine is consulted to ensure that PII
/// encryption is required under the active regime.  If the check passes the
/// value is encrypted with AEGIS-256 (default) or AES-256-GCM (FIPS mode).
///
/// Wire format: `algo_id (1) || nonce || ciphertext || tag`.
/// The format is identical to `crypto::symmetric::encrypt` for interoperability.
pub fn encrypt_pii_field(
    field_name: &str,
    value: &[u8],
    key: &[u8; 32],
    compliance: &crate::compliance::ComplianceEngine,
) -> Result<Vec<u8>, crate::error::MilnetError> {
    compliance
        .check_pii_encryption(true, field_name)
        .map_err(|v| crate::error::MilnetError::CryptoVerification(v.detail))?;

    let aad = field_name.as_bytes();

    if crate::fips::is_fips_mode() {
        pii_encrypt_aes256gcm(key, value, aad)
    } else {
        pii_encrypt_aegis256(key, value, aad)
    }
    .map_err(|e| crate::error::MilnetError::CryptoVerification(e))
}

fn pii_encrypt_aegis256(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    use aegis::aegis256::Aegis256;
    const NONCE_LEN: usize = 32;
    const TAG_LEN: usize = 32;

    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| format!("AEGIS-256 nonce generation failed: {e}"))?;

    let (ciphertext, tag) = Aegis256::<TAG_LEN>::new(key, &nonce).encrypt(plaintext, aad);

    let mut out = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len() + TAG_LEN);
    out.push(PII_ALGO_ID_AEGIS256);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&tag);
    Ok(out)
}

fn pii_encrypt_aes256gcm(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use aes_gcm::aead::Aead;
    const NONCE_LEN: usize = 12;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| format!("AES-256-GCM nonce generation failed: {e}"))?;

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| "AES-256-GCM cipher initialization failed".to_string())?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, aes_gcm::aead::Payload { msg: plaintext, aad })
        .map_err(|e| format!("AES-256-GCM encryption failed: {e}"))?;

    let mut out = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
    out.push(PII_ALGO_ID_AES256GCM);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a PII field encrypted by `encrypt_pii_field`.
///
/// Reads the algorithm byte from the wire format and dispatches to the
/// appropriate AEAD backend.
pub fn decrypt_pii_field(
    field_name: &str,
    sealed: &[u8],
    key: &[u8; 32],
) -> Result<Vec<u8>, crate::error::MilnetError> {
    let aad = field_name.as_bytes();
    if sealed.is_empty() {
        return Err(crate::error::MilnetError::CryptoVerification(
            "PII sealed blob is empty".to_string(),
        ));
    }
    match sealed[0] {
        PII_ALGO_ID_AEGIS256 => pii_decrypt_aegis256(key, &sealed[1..], aad),
        PII_ALGO_ID_AES256GCM => pii_decrypt_aes256gcm(key, &sealed[1..], aad),
        other => Err(crate::error::MilnetError::CryptoVerification(format!(
            "Unknown PII algo_id: 0x{:02x}",
            other
        ))),
    }
}

fn pii_decrypt_aegis256(key: &[u8; 32], blob: &[u8], aad: &[u8]) -> Result<Vec<u8>, crate::error::MilnetError> {
    use aegis::aegis256::Aegis256;
    const NONCE_LEN: usize = 32;
    const TAG_LEN: usize = 32;

    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(crate::error::MilnetError::CryptoVerification(
            "AEGIS-256 blob too short".to_string(),
        ));
    }
    let nonce: &[u8; NONCE_LEN] = blob[..NONCE_LEN].try_into()
        .map_err(|_| crate::error::MilnetError::CryptoVerification(
            "AEGIS-256 nonce extraction failed".to_string(),
        ))?;
    let rest = &blob[NONCE_LEN..];
    let (ciphertext, tag_slice) = rest.split_at(rest.len() - TAG_LEN);
    let tag: [u8; TAG_LEN] = tag_slice.try_into()
        .map_err(|_| crate::error::MilnetError::CryptoVerification(
            "AEGIS-256 tag extraction failed".to_string(),
        ))?;

    Aegis256::<TAG_LEN>::new(key, nonce)
        .decrypt(ciphertext, &tag, aad)
        .map_err(|_| crate::error::MilnetError::CryptoVerification(
            "AEGIS-256 PII decryption failed — tampered or wrong key".to_string(),
        ))
}

fn pii_decrypt_aes256gcm(key: &[u8; 32], blob: &[u8], aad: &[u8]) -> Result<Vec<u8>, crate::error::MilnetError> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use aes_gcm::aead::Aead;
    const NONCE_LEN: usize = 12;

    if blob.len() < NONCE_LEN + 16 {
        return Err(crate::error::MilnetError::CryptoVerification(
            "AES-256-GCM PII blob too short".to_string(),
        ));
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| crate::error::MilnetError::CryptoVerification(
            "AES-256-GCM cipher initialization failed".to_string(),
        ))?;
    let nonce = Nonce::from_slice(&blob[..NONCE_LEN]);
    cipher
        .decrypt(nonce, aes_gcm::aead::Payload { msg: &blob[NONCE_LEN..], aad })
        .map_err(|_| crate::error::MilnetError::CryptoVerification(
            "AES-256-GCM PII decryption failed — tampered or wrong key".to_string(),
        ))
}

/// Standalone encryption engine for testing without a database connection.
/// Uses the same envelope encryption (per-operation DEK) logic as EncryptedPool.
pub struct FieldEncryptor {
    master_kek: [u8; 32],
}

impl FieldEncryptor {
    pub fn new(master_kek: [u8; 32]) -> Self {
        Self { master_kek }
    }

    pub fn table_kek(&self, table: &str) -> Result<[u8; 32], String> {
        use hkdf::Hkdf;
        use sha2::Sha512;
        let hk = Hkdf::<Sha512>::new(Some(b"MILNET-TABLE-KEK-v1"), &self.master_kek);
        let mut okm = [0u8; 32];
        hk.expand(table.as_bytes(), &mut okm)
            .map_err(|_| "HKDF-SHA512 table KEK derivation failed".to_string())?;
        Ok(okm)
    }

    pub fn encrypt_field(&self, table: &str, column: &str, row_id: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        use aes_gcm::aead::Aead;

        // Generate per-operation DEK
        let mut dek = [0u8; 32];
        getrandom::getrandom(&mut dek)
            .map_err(|e| format!("OS entropy failure during DEK generation: {e}"))?;

        // Encrypt plaintext with DEK
        let dek_cipher = Aes256Gcm::new_from_slice(&dek)
            .map_err(|_| "AES-256-GCM cipher initialization failed".to_string())?;
        let mut data_nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut data_nonce_bytes)
            .map_err(|e| format!("OS entropy failure during nonce generation: {e}"))?;
        let data_nonce = Nonce::from_slice(&data_nonce_bytes);
        let aad = build_aad(table, column, row_id);
        let ciphertext = dek_cipher
            .encrypt(data_nonce, aes_gcm::aead::Payload { msg: plaintext, aad: &aad })
            .map_err(|_| "AES-256-GCM encryption failed".to_string())?;

        // Wrap DEK with table KEK
        let kek = self.table_kek(table)?;
        let kek_cipher = Aes256Gcm::new_from_slice(&kek)
            .map_err(|_| "AES-256-GCM cipher initialization failed".to_string())?;
        let mut wrap_nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut wrap_nonce_bytes)
            .map_err(|e| format!("OS entropy failure during wrap nonce generation: {e}"))?;
        let wrap_nonce = Nonce::from_slice(&wrap_nonce_bytes);
        let wrapped_dek = kek_cipher
            .encrypt(wrap_nonce, aes_gcm::aead::Payload { msg: dek.as_ref(), aad: b"MILNET-KEK-WRAP-v1" })
            .map_err(|_| "AES-256-GCM DEK wrap failed".to_string())?;

        // Zeroize DEK
        dek.zeroize();

        // Output: version(1) || wrap_nonce(12) || wrapped_dek(48) || data_nonce(12) || ciphertext+tag
        let mut out = Vec::with_capacity(1 + 12 + wrapped_dek.len() + 12 + ciphertext.len());
        out.push(ENVELOPE_V2_TAG);
        out.extend_from_slice(&wrap_nonce_bytes);
        out.extend_from_slice(&wrapped_dek);
        out.extend_from_slice(&data_nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn decrypt_field(&self, table: &str, column: &str, row_id: &[u8], sealed: &[u8]) -> Result<Vec<u8>, String> {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        use aes_gcm::aead::Aead;

        if sealed.is_empty() {
            return Err("sealed data is empty".into());
        }

        if sealed[0] == ENVELOPE_V2_TAG {
            // V2 envelope format
            let min_v2_len = 1 + WRAPPED_DEK_LEN + 12 + 16;
            if sealed.len() < min_v2_len {
                return Err("V2 sealed data too short".into());
            }

            let rest = &sealed[1..];
            let wrap_nonce_bytes = &rest[..12];
            let wrapped_dek_ct = &rest[12..WRAPPED_DEK_LEN];
            let data_nonce_bytes = &rest[WRAPPED_DEK_LEN..WRAPPED_DEK_LEN + 12];
            let data_ct = &rest[WRAPPED_DEK_LEN + 12..];

            // Unwrap DEK
            let kek = self.table_kek(table)?;
            let kek_cipher = Aes256Gcm::new_from_slice(&kek)
                .map_err(|_| "AES-256-GCM cipher initialization failed".to_string())?;
            let wrap_nonce = Nonce::from_slice(wrap_nonce_bytes);
            let mut dek_bytes = kek_cipher
                .decrypt(wrap_nonce, aes_gcm::aead::Payload { msg: wrapped_dek_ct, aad: b"MILNET-KEK-WRAP-v1" })
                .map_err(|_| "DEK unwrap failed".to_string())?;

            if dek_bytes.len() != 32 {
                dek_bytes.zeroize();
                return Err("unwrapped DEK has wrong length".into());
            }

            // Decrypt data with DEK
            let dek_cipher = Aes256Gcm::new_from_slice(&dek_bytes)
                .map_err(|_| "AES-256-GCM cipher initialization failed".to_string())?;
            let data_nonce = Nonce::from_slice(data_nonce_bytes);
            let aad = build_aad(table, column, row_id);
            let result = dek_cipher
                .decrypt(data_nonce, aes_gcm::aead::Payload { msg: data_ct, aad: &aad })
                .map_err(|_| "decryption failed".to_string());

            // Zeroize DEK
            dek_bytes.zeroize();

            result
        } else {
            // Legacy format: nonce(12) || ciphertext || tag(16)
            if sealed.len() < 12 + 16 {
                return Err("sealed data too short".into());
            }
            let kek = self.table_kek(table)?;
            let cipher = Aes256Gcm::new_from_slice(&kek)
                .map_err(|_| "AES-256-GCM cipher initialization failed".to_string())?;
            let nonce = Nonce::from_slice(&sealed[..12]);
            let aad = build_aad(table, column, row_id);

            cipher
                .decrypt(nonce, aes_gcm::aead::Payload { msg: &sealed[12..], aad: &aad })
                .map_err(|_| "decryption failed".to_string())
        }
    }
}

impl Drop for FieldEncryptor {
    fn drop(&mut self) {
        self.master_kek.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_encryptor() -> FieldEncryptor {
        let mut kek = [0u8; 32];
        getrandom::getrandom(&mut kek).unwrap();
        FieldEncryptor::new(kek)
    }

    #[test]
    fn build_aad_produces_correct_format() {
        let aad = build_aad("users", "opaque_registration", b"test-uuid");
        assert_eq!(&aad, b"MILNET-AAD-v1:users:opaque_registration:test-uuid");
    }

    #[test]
    fn build_aad_different_inputs_produce_different_aads() {
        let aad1 = build_aad("users", "opaque_registration", b"uuid-1");
        let aad2 = build_aad("users", "opaque_registration", b"uuid-2");
        let aad3 = build_aad("fido_credentials", "public_key", b"uuid-1");
        assert_ne!(aad1, aad2);
        assert_ne!(aad1, aad3);
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let enc = make_encryptor();
        let plaintext = b"top secret opaque registration data";
        let row_id = b"550e8400-e29b-41d4-a716-446655440000";

        let sealed = enc.encrypt_field("users", "opaque_registration", row_id, plaintext).unwrap();
        assert_ne!(&sealed, plaintext.as_slice());
        // V2 format: version(1) + wrap_nonce(12) + wrapped_dek(48) + data_nonce(12) + plaintext + tag(16)
        assert!(sealed.len() >= 1 + 60 + 12 + plaintext.len() + 16);
        // First byte must be the V2 tag
        assert_eq!(sealed[0], ENVELOPE_V2_TAG);

        let decrypted = enc.decrypt_field("users", "opaque_registration", row_id, &sealed).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn wrong_aad_fails_decrypt() {
        let enc = make_encryptor();
        let plaintext = b"secret data";
        let row_id = b"row-1";

        let sealed = enc.encrypt_field("users", "opaque_registration", row_id, plaintext).unwrap();

        assert!(enc.decrypt_field("fido_credentials", "opaque_registration", row_id, &sealed).is_err());
        assert!(enc.decrypt_field("users", "duress_pin_hash", row_id, &sealed).is_err());
        assert!(enc.decrypt_field("users", "opaque_registration", b"row-2", &sealed).is_err());
    }

    #[test]
    fn different_encryptions_produce_different_ciphertexts() {
        let enc = make_encryptor();
        let plaintext = b"same plaintext";
        let row_id = b"row-1";

        let sealed1 = enc.encrypt_field("users", "opaque", row_id, plaintext).unwrap();
        let sealed2 = enc.encrypt_field("users", "opaque", row_id, plaintext).unwrap();
        assert_ne!(sealed1, sealed2);

        let pt1 = enc.decrypt_field("users", "opaque", row_id, &sealed1).unwrap();
        let pt2 = enc.decrypt_field("users", "opaque", row_id, &sealed2).unwrap();
        assert_eq!(pt1, pt2);
    }

    #[test]
    fn tampered_ciphertext_fails_decrypt() {
        let enc = make_encryptor();
        let mut sealed = enc.encrypt_field("users", "opaque", b"r1", b"sensitive data").unwrap();
        if sealed.len() > 15 { sealed[15] ^= 0xFF; }
        assert!(enc.decrypt_field("users", "opaque", b"r1", &sealed).is_err());
    }

    #[test]
    fn too_short_sealed_data_fails() {
        let enc = make_encryptor();
        assert!(enc.decrypt_field("users", "opaque", b"r1", &[0u8; 10]).is_err());
    }

    #[test]
    fn table_kek_derivation_is_deterministic() {
        let kek = [42u8; 32];
        let e1 = FieldEncryptor::new(kek);
        let e2 = FieldEncryptor::new(kek);
        assert_eq!(e1.table_kek("users"), e2.table_kek("users"));
    }

    #[test]
    fn different_tables_get_different_keks() {
        let enc = make_encryptor();
        let k1 = enc.table_kek("users");
        let k2 = enc.table_kek("fido_credentials");
        let k3 = enc.table_kek("key_material");
        assert_ne!(k1, k2);
        assert_ne!(k1, k3);
        assert_ne!(k2, k3);
    }

    // ── V2 envelope encryption hardening tests ──

    #[test]
    fn encrypt_decrypt_v2_roundtrip_multiple_fields() {
        let enc = FieldEncryptor::new([0x42; 32]);
        for i in 0..10 {
            let data = format!("sensitive-data-{}", i);
            let row_id = format!("row-{}", i);
            let ct = enc.encrypt_field("users", "opaque", row_id.as_bytes(), data.as_bytes()).unwrap();
            assert_eq!(ct[0], 0x02, "must use V2 envelope tag");
            let pt = enc.decrypt_field("users", "opaque", row_id.as_bytes(), &ct).unwrap();
            assert_eq!(pt, data.as_bytes());
        }
    }

    #[test]
    fn encrypt_different_plaintext_produces_different_ciphertext() {
        let enc = FieldEncryptor::new([0x42; 32]);
        let ct1 = enc.encrypt_field("users", "opaque", b"r1", b"data-a").unwrap();
        let ct2 = enc.encrypt_field("users", "opaque", b"r1", b"data-b").unwrap();
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn encrypt_same_plaintext_produces_different_ciphertext_random_dek() {
        // Random DEK + random nonce = different ciphertext each time
        let enc = FieldEncryptor::new([0x42; 32]);
        let ct1 = enc.encrypt_field("users", "opaque", b"r1", b"same data").unwrap();
        let ct2 = enc.encrypt_field("users", "opaque", b"r1", b"same data").unwrap();
        assert_ne!(ct1, ct2, "same plaintext must produce different ciphertext (random DEK)");
    }

    #[test]
    fn decrypt_with_wrong_kek_fails() {
        let enc1 = FieldEncryptor::new([0x42; 32]);
        let enc2 = FieldEncryptor::new([0x43; 32]);
        let ct = enc1.encrypt_field("users", "opaque", b"r1", b"secret").unwrap();
        let result = enc2.decrypt_field("users", "opaque", b"r1", &ct);
        assert!(result.is_err(), "wrong KEK must fail decryption");
    }

    #[test]
    fn decrypt_truncated_v2_ciphertext_fails() {
        let enc = FieldEncryptor::new([0x42; 32]);
        let ct = enc.encrypt_field("users", "opaque", b"r1", b"data").unwrap();
        // Truncate to just the tag + wrap_nonce (13 bytes)
        let truncated = &ct[..13];
        let result = enc.decrypt_field("users", "opaque", b"r1", truncated);
        assert!(result.is_err(), "truncated ciphertext must fail");
    }

    #[test]
    fn decrypt_corrupted_wrapped_dek_fails() {
        let enc = FieldEncryptor::new([0x42; 32]);
        let mut ct = enc.encrypt_field("users", "opaque", b"r1", b"data").unwrap();
        // Corrupt a byte in the wrapped DEK region (bytes 13..61)
        if ct.len() > 20 {
            ct[15] ^= 0xFF;
        }
        let result = enc.decrypt_field("users", "opaque", b"r1", &ct);
        assert!(result.is_err(), "corrupted wrapped DEK must fail");
    }

    // ── PII encryption enforcement tests ──

    fn make_compliance_engine() -> crate::compliance::ComplianceEngine {
        crate::compliance::ComplianceEngine::new(
            crate::compliance::ComplianceConfig::indian_govt_default(),
        )
    }

    fn make_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        getrandom::getrandom(&mut k).unwrap();
        k
    }

    #[test]
    fn test_pii_field_encrypted_roundtrip() {
        let compliance = make_compliance_engine();
        let key = make_key();
        let plaintext = b"user@example.mil";

        let sealed = encrypt_pii_field("email", plaintext, &key, &compliance)
            .expect("encrypt_pii_field must succeed");

        // Sealed blob must differ from plaintext
        assert_ne!(&sealed, plaintext.as_slice());
        // Must be longer than plaintext (nonce + tag overhead)
        assert!(sealed.len() > plaintext.len());

        // Round-trip via decrypt_pii_field
        let recovered = decrypt_pii_field("email", &sealed, &key)
            .expect("decrypt_pii_field must succeed");
        assert_eq!(&recovered, plaintext.as_slice());
    }

    #[test]
    fn test_pii_field_compliance_check_enforced() {
        // Create a config where pii_encryption_required = false
        let config = crate::compliance::ComplianceConfig {
            regime: crate::compliance::ComplianceRegime::IndianGovt,
            data_residency_regions: vec!["asia-south1".to_string()],
            audit_retention_days: 365,
            require_data_classification: true,
            max_classification_level: 3,
            pii_encryption_required: false, // PII encryption NOT required
            cross_border_transfer_blocked: true,
            cert_in_incident_reporting_hours: 6,
            itar_controls_enabled: false,
            meity_empanelled_cloud_only: true,
        };
        let compliance = crate::compliance::ComplianceEngine::new(config);
        let key = make_key();

        // encrypt_pii_field passes `is_encrypted=true`, so check_pii_encryption
        // returns Ok regardless of the pii_encryption_required flag.
        // This verifies the function signature is correct and the call succeeds.
        let result = encrypt_pii_field("email", b"test", &key, &compliance);
        assert!(
            result.is_ok(),
            "encrypt_pii_field should succeed when passing is_encrypted=true: {:?}",
            result
        );

        // Verify the compliance engine itself does not flag unencrypted PII
        // when pii_encryption_required=false
        let check = compliance.check_pii_encryption(false, "email");
        assert!(check.is_ok(), "no violation when pii_encryption_required=false");

        // A standard engine (pii_encryption_required=true) DOES flag unencrypted PII
        let strict = make_compliance_engine();
        let violation = strict.check_pii_encryption(false, "email");
        assert!(violation.is_err(), "strict engine must flag unencrypted PII");
    }

    #[test]
    fn test_pii_field_uses_aegis256_default() {
        // In non-FIPS mode (default in tests), AEGIS-256 is selected.
        // The sealed blob starts with PII_ALGO_ID_AEGIS256 (0x01).
        let compliance = make_compliance_engine();
        let key = make_key();

        let sealed = encrypt_pii_field("email", b"test@mil.gov", &key, &compliance)
            .expect("encrypt_pii_field must succeed");

        // Verify the algorithm byte is set (first byte of wire format)
        assert!(!sealed.is_empty(), "sealed blob must not be empty");
        let algo_byte = sealed[0];
        // Either AEGIS-256 (0x01) or AES-256-GCM (0x02) depending on FIPS mode
        assert!(
            algo_byte == PII_ALGO_ID_AEGIS256 || algo_byte == PII_ALGO_ID_AES256GCM,
            "first byte must be a known algo_id, got 0x{:02x}",
            algo_byte
        );

        // In tests FIPS is off, so default is AEGIS-256
        if !crate::fips::is_fips_mode() {
            assert_eq!(
                algo_byte,
                PII_ALGO_ID_AEGIS256,
                "non-FIPS mode should use AEGIS-256 (0x01)"
            );
        }
    }
}
