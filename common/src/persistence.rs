use sqlx::PgPool;

use crate::config::SecurityConfig;

/// Magic header prepended to encrypted key material.
/// Presence of this header indicates the bytes are already envelope-encrypted.
const ENCRYPTED_KEY_MAGIC: &[u8; 8] = b"MENC0001";

fn generate_random_bytes_32() -> [u8; 32] {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).expect("OS entropy source must be available");
    buf
}

fn generate_random_bytes_64() -> [u8; 64] {
    let mut buf = [0u8; 64];
    getrandom::getrandom(&mut buf).expect("OS entropy source must be available");
    buf
}

/// Derive a domain-separated encryption key from the given master KEK
/// using HKDF-SHA512 for key-material-at-rest encryption.
fn derive_key_material_kek(master_kek: &[u8; 32]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha512;
    let hk = Hkdf::<Sha512>::new(Some(b"MILNET-KEY-MATERIAL-v1"), master_kek);
    let mut okm = [0u8; 32];
    hk.expand(b"key_material:key_bytes", &mut okm)
        .expect("32-byte HKDF expand must succeed");
    okm
}

/// Encrypt key bytes using AES-256-GCM with a domain-separated key derived from the master KEK.
/// Returns `MAGIC(8) || nonce(12) || ciphertext || tag(16)`.
fn encrypt_key_bytes(master_kek: &[u8; 32], name: &str, key_bytes: &[u8]) -> Vec<u8> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

    let kek = derive_key_material_kek(master_kek);
    let cipher = Aes256Gcm::new_from_slice(&kek).expect("32-byte key");

    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes).expect("OS entropy");
    let nonce = Nonce::from_slice(&nonce_bytes);

    // AAD binds ciphertext to the key name
    let mut aad = Vec::with_capacity(32 + name.len());
    aad.extend_from_slice(b"MILNET-KEY-MATERIAL-v1:");
    aad.extend_from_slice(name.as_bytes());

    let ciphertext = cipher
        .encrypt(nonce, aes_gcm::aead::Payload { msg: key_bytes, aad: &aad })
        .expect("AES-256-GCM encryption must not fail with valid key");

    let mut out = Vec::with_capacity(8 + 12 + ciphertext.len());
    out.extend_from_slice(ENCRYPTED_KEY_MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    out
}

/// Decrypt key bytes previously encrypted with `encrypt_key_bytes`.
fn decrypt_key_bytes(master_kek: &[u8; 32], name: &str, sealed: &[u8]) -> Result<Vec<u8>, String> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

    if sealed.len() < 8 + 12 + 16 {
        return Err("sealed key data too short".into());
    }
    if &sealed[..8] != ENCRYPTED_KEY_MAGIC {
        return Err("missing encrypted key magic header — data may be plaintext".into());
    }

    let kek = derive_key_material_kek(master_kek);
    let cipher = Aes256Gcm::new_from_slice(&kek).expect("32-byte key");

    let nonce = Nonce::from_slice(&sealed[8..20]);
    let ciphertext = &sealed[20..];

    let mut aad = Vec::with_capacity(32 + name.len());
    aad.extend_from_slice(b"MILNET-KEY-MATERIAL-v1:");
    aad.extend_from_slice(name.as_bytes());

    cipher
        .decrypt(nonce, aes_gcm::aead::Payload { msg: ciphertext, aad: &aad })
        .map_err(|_| "AES-256-GCM decryption failed — tampered or wrong key".to_string())
}

/// Returns true if the given bytes start with the encrypted key magic header.
fn is_encrypted(data: &[u8]) -> bool {
    data.len() >= 8 && &data[..8] == ENCRYPTED_KEY_MAGIC
}

/// Store key material into PostgreSQL with AES-256-GCM encryption at rest.
///
/// If `master_kek` is provided, key bytes are encrypted before storage.
/// If `SecurityConfig::default().require_encryption_at_rest` is true and no KEK
/// is provided, this function will refuse to store plaintext and will panic.
#[must_use = "store_key returns false if encryption-at-rest policy prevents storage"]
pub async fn store_key(pool: &PgPool, name: &str, key_bytes: &[u8], master_kek: Option<&[u8; 32]>) -> bool {
    let config = SecurityConfig::default();

    let bytes_to_store = match master_kek {
        Some(kek) => encrypt_key_bytes(kek, name, key_bytes),
        None => {
            if config.require_encryption_at_rest {
                // Policy requires encryption at rest — check if already encrypted
                if !is_encrypted(key_bytes) {
                    // REFUSE to store plaintext key material
                    return false;
                }
            }
            key_bytes.to_vec()
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    match sqlx::query(
        "INSERT INTO key_material (key_name, key_bytes, created_at) VALUES ($1, $2, $3) ON CONFLICT (key_name) DO UPDATE SET key_bytes = $2, rotated_at = $3"
    )
    .bind(name)
    .bind(&bytes_to_store)
    .bind(now)
    .execute(pool)
    .await {
        Ok(_) => true,
        Err(e) => {
            tracing::error!("CRITICAL: failed to store key material '{}': {}", name, e);
            false
        }
    }
}

/// Load key material from PostgreSQL, decrypting if a master KEK is provided.
///
/// If `master_kek` is provided and the stored data has the encrypted magic header,
/// decryption is performed. If the header is missing but `require_encryption_at_rest`
/// is true, the data is rejected (returns None) to prevent loading unprotected keys.
pub async fn load_key(pool: &PgPool, name: &str, master_kek: Option<&[u8; 32]>) -> Option<Vec<u8>> {
    let raw: Option<Vec<u8>> = sqlx::query_scalar("SELECT key_bytes FROM key_material WHERE key_name = $1")
        .bind(name)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();

    let data = raw?;

    match master_kek {
        Some(kek) => {
            if is_encrypted(&data) {
                decrypt_key_bytes(kek, name, &data).ok()
            } else {
                // Stored data is not encrypted but we have a KEK —
                // reject if policy requires encryption at rest
                let config = SecurityConfig::default();
                if config.require_encryption_at_rest {
                    None
                } else {
                    Some(data)
                }
            }
        }
        None => {
            let config = SecurityConfig::default();
            if config.require_encryption_at_rest && !is_encrypted(&data) {
                // Policy violation: plaintext key material in database
                None
            } else {
                Some(data)
            }
        }
    }
}

pub async fn load_or_generate_key_64(pool: &PgPool, name: &str, master_kek: Option<&[u8; 32]>) -> [u8; 64] {
    if let Some(existing) = load_key(pool, name, master_kek).await {
        if existing.len() == 64 {
            let mut key = [0u8; 64];
            key.copy_from_slice(&existing);
            return key;
        }
    }
    let key = generate_random_bytes_64();
    if !store_key(pool, name, &key, master_kek).await {
        tracing::error!("CRITICAL: failed to persist generated key '{}'", name);
    }
    key
}

pub async fn load_or_generate_key_32(pool: &PgPool, name: &str, master_kek: Option<&[u8; 32]>) -> [u8; 32] {
    if let Some(existing) = load_key(pool, name, master_kek).await {
        if existing.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&existing);
            return key;
        }
    }
    let key = generate_random_bytes_32();
    if !store_key(pool, name, &key, master_kek).await {
        tracing::error!("CRITICAL: failed to persist generated key '{}'", name);
    }
    key
}
