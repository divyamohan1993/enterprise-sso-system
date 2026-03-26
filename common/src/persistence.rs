use sqlx::PgPool;

use crate::config::SecurityConfig;

/// Magic header prepended to encrypted key material.
/// Presence of this header indicates the bytes are already envelope-encrypted.
const ENCRYPTED_KEY_MAGIC: &[u8; 8] = b"MENC0001";

/// Generate random bytes with retry logic, returning an error instead of panicking
/// on entropy exhaustion.
fn generate_random_bytes(buf: &mut [u8]) -> Result<(), String> {
    for attempt in 0..3 {
        if getrandom::getrandom(buf).is_ok() {
            return Ok(());
        }
        tracing::error!("entropy source failed, attempt {}/3", attempt + 1);
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    Err("OS CSPRNG unavailable after 3 retries".into())
}

fn generate_random_bytes_32() -> Result<[u8; 32], String> {
    let mut buf = [0u8; 32];
    generate_random_bytes(&mut buf)?;
    Ok(buf)
}

fn generate_random_bytes_64() -> Result<[u8; 64], String> {
    let mut buf = [0u8; 64];
    generate_random_bytes(&mut buf)?;
    Ok(buf)
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
fn encrypt_key_bytes(master_kek: &[u8; 32], name: &str, key_bytes: &[u8]) -> Result<Vec<u8>, String> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

    let kek = derive_key_material_kek(master_kek);
    let cipher = Aes256Gcm::new_from_slice(&kek).expect("32-byte key");

    let mut nonce_bytes = [0u8; 12];
    generate_random_bytes(&mut nonce_bytes)?;
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
    Ok(out)
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

/// Enforce the encryption-at-rest policy.
///
/// In production mode (`MILNET_PRODUCTION` is set), `require_encryption_at_rest`
/// MUST be true. If it is false, this function panics immediately to prevent
/// any possibility of storing or loading plaintext key material in production.
///
/// This is called at the entry point of every store/load path.
fn enforce_encryption_policy(config: &SecurityConfig) {
    if crate::sealed_keys::is_production() && !config.require_encryption_at_rest {
        panic!(
            "FATAL: require_encryption_at_rest is false while MILNET_PRODUCTION is set. \
             Encryption at rest cannot be disabled in production."
        );
    }
}

/// Validate the magic header on loaded data.
///
/// In production mode, ALL loaded key material MUST carry the encrypted magic
/// header. Data without the header is rejected unconditionally.
fn validate_magic_header(data: &[u8], name: &str) -> Result<(), String> {
    if !is_encrypted(data) {
        if crate::sealed_keys::is_production() {
            return Err(format!(
                "SECURITY VIOLATION: key '{}' loaded without encryption magic header in production mode",
                name
            ));
        }
        let config = SecurityConfig::default();
        if config.require_encryption_at_rest {
            return Err(format!(
                "key '{}' missing encryption magic header and require_encryption_at_rest is true",
                name
            ));
        }
    }
    Ok(())
}

/// Store key material into PostgreSQL with AES-256-GCM encryption at rest.
///
/// If `master_kek` is provided, key bytes are encrypted before storage.
/// In production mode, encryption at rest is mandatory; this function will
/// panic if `require_encryption_at_rest` is false when `MILNET_PRODUCTION` is set,
/// and will refuse to store plaintext key material.
#[must_use = "store_key returns false if encryption-at-rest policy prevents storage"]
pub async fn store_key(pool: &PgPool, name: &str, key_bytes: &[u8], master_kek: Option<&[u8; 32]>) -> bool {
    let config = SecurityConfig::default();
    enforce_encryption_policy(&config);

    let bytes_to_store = match master_kek {
        Some(kek) => match encrypt_key_bytes(kek, name, key_bytes) {
            Ok(enc) => enc,
            Err(e) => {
                tracing::error!("CRITICAL: failed to encrypt key '{}': {}", name, e);
                return false;
            }
        },
        None => {
            if crate::sealed_keys::is_production() {
                // Production mode: NEVER store plaintext key material
                tracing::error!(
                    "SECURITY VIOLATION: attempted to store key '{}' without KEK in production",
                    name
                );
                return false;
            }
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
/// All load paths validate the magic header. In production mode, data without
/// the encrypted magic header is unconditionally rejected. When
/// `require_encryption_at_rest` is true (the default), unencrypted data is
/// also rejected regardless of production mode.
pub async fn load_key(pool: &PgPool, name: &str, master_kek: Option<&[u8; 32]>) -> Option<Vec<u8>> {
    let config = SecurityConfig::default();
    enforce_encryption_policy(&config);

    let raw: Option<Vec<u8>> = sqlx::query_scalar("SELECT key_bytes FROM key_material WHERE key_name = $1")
        .bind(name)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();

    let data = raw?;

    // Validate magic header on ALL load paths
    if let Err(e) = validate_magic_header(&data, name) {
        tracing::error!("{}", e);
        if crate::sealed_keys::is_production() || config.require_encryption_at_rest {
            return None;
        }
    }

    match master_kek {
        Some(kek) => {
            if is_encrypted(&data) {
                decrypt_key_bytes(kek, name, &data).ok()
            } else {
                // Stored data is not encrypted but we have a KEK —
                // reject in production or when policy requires encryption at rest
                if crate::sealed_keys::is_production() || config.require_encryption_at_rest {
                    None
                } else {
                    Some(data)
                }
            }
        }
        None => {
            if crate::sealed_keys::is_production() {
                // Production mode: ALWAYS require KEK for loading
                tracing::error!(
                    "SECURITY VIOLATION: attempted to load key '{}' without KEK in production",
                    name
                );
                None
            } else if config.require_encryption_at_rest && !is_encrypted(&data) {
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
    let key = match generate_random_bytes_64() {
        Ok(k) => k,
        Err(e) => {
            tracing::error!("CRITICAL: entropy failure generating key '{}': {}", name, e);
            return [0u8; 64]; // caller must handle zero key
        }
    };
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
    let key = match generate_random_bytes_32() {
        Ok(k) => k,
        Err(e) => {
            tracing::error!("CRITICAL: entropy failure generating key '{}': {}", name, e);
            return [0u8; 32]; // caller must handle zero key
        }
    };
    if !store_key(pool, name, &key, master_kek).await {
        tracing::error!("CRITICAL: failed to persist generated key '{}'", name);
    }
    key
}
