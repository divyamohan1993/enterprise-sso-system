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

pub fn generate_random_bytes_32() -> Result<[u8; 32], String> {
    let mut buf = [0u8; 32];
    generate_random_bytes(&mut buf)?;
    Ok(buf)
}

pub fn generate_random_bytes_64() -> Result<[u8; 64], String> {
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
    if let Err(e) = hk.expand(b"key_material:key_bytes", &mut okm) {
        tracing::error!("FATAL: HKDF-SHA512 expand failed for key material KEK: {e}");
        std::process::exit(1);
    }
    okm
}

/// Encrypt key bytes using AES-256-GCM with a domain-separated key derived from the master KEK.
/// Returns `MAGIC(8) || nonce(12) || ciphertext || tag(16)`.
fn encrypt_key_bytes(master_kek: &[u8; 32], name: &str, key_bytes: &[u8]) -> Result<Vec<u8>, String> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

    let kek = derive_key_material_kek(master_kek);
    let cipher = match Aes256Gcm::new_from_slice(&kek) {
        Ok(c) => c,
        Err(_) => return Err("AES-256-GCM key init failed for key material".into()),
    };

    let mut nonce_bytes = [0u8; 12];
    generate_random_bytes(&mut nonce_bytes)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    // AAD binds ciphertext to the key name
    let mut aad = Vec::with_capacity(32 + name.len());
    aad.extend_from_slice(b"MILNET-KEY-MATERIAL-v1:");
    aad.extend_from_slice(name.as_bytes());

    let ciphertext = cipher
        .encrypt(nonce, aes_gcm::aead::Payload { msg: key_bytes, aad: &aad })
        .map_err(|e| format!("AES-256-GCM encryption failed for key material: {e}"))?;

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
    let cipher = match Aes256Gcm::new_from_slice(&kek) {
        Ok(c) => c,
        Err(_) => return Err("AES-256-GCM key init failed for key material".into()),
    };

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
/// `require_encryption_at_rest` MUST be true. If it is false, this function
/// panics immediately to prevent any possibility of storing or loading
/// plaintext key material. There is only one mode: production.
///
/// This is called at the entry point of every store/load path.
fn enforce_encryption_policy(config: &SecurityConfig) {
    if !config.require_encryption_at_rest {
        panic!(
            "FATAL: require_encryption_at_rest is false. \
             Encryption at rest cannot be disabled."
        );
    }
}

/// Validate the magic header on loaded data.
///
/// In production mode, ALL loaded key material MUST carry the encrypted magic
/// header. Data without the header is rejected unconditionally.
fn validate_magic_header(data: &[u8], name: &str) -> Result<(), String> {
    if !is_encrypted(data) {
        return Err(format!(
            "SECURITY VIOLATION: key '{}' loaded without encryption magic header",
            name
        ));
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
            // NEVER store plaintext key material without KEK
            tracing::error!(
                "SECURITY VIOLATION: attempted to store key '{}' without KEK",
                name
            );
            return false;
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
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
        return None;
    }

    match master_kek {
        Some(kek) => {
            if is_encrypted(&data) {
                decrypt_key_bytes(kek, name, &data).ok()
            } else {
                // Data is not encrypted — reject unconditionally
                None
            }
        }
        None => {
            // ALWAYS require KEK for loading
            tracing::error!(
                "SECURITY VIOLATION: attempted to load key '{}' without KEK",
                name
            );
            None
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
            panic!(
                "FATAL: entropy source failure generating key '{}': {}. \
                 Cannot continue safely — a zero key would compromise all encryption. \
                 File: {}:{}",
                name, e, file!(), line!()
            );
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
            panic!(
                "FATAL: entropy source failure generating key '{}': {}. \
                 Cannot continue safely — a zero key would compromise all encryption. \
                 File: {}:{}",
                name, e, file!(), line!()
            );
        }
    };
    if !store_key(pool, name, &key, master_kek).await {
        tracing::error!("CRITICAL: failed to persist generated key '{}'", name);
    }
    key
}
