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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_random_bytes_32_returns_non_zero() {
        let buf = generate_random_bytes_32().expect("CSPRNG should succeed");
        // Probability of all-zero 32 bytes from CSPRNG is 2^-256.
        assert_ne!(buf, [0u8; 32], "random bytes must not be all zeros");
    }

    #[test]
    fn generate_random_bytes_64_returns_non_zero() {
        let buf = generate_random_bytes_64().expect("CSPRNG should succeed");
        assert_ne!(buf, [0u8; 64], "random bytes must not be all zeros");
    }

    #[test]
    fn generate_random_bytes_32_produces_unique_output() {
        let a = generate_random_bytes_32().unwrap();
        let b = generate_random_bytes_32().unwrap();
        assert_ne!(a, b, "two consecutive calls must produce different output");
    }

    #[test]
    fn generate_random_bytes_64_produces_unique_output() {
        let a = generate_random_bytes_64().unwrap();
        let b = generate_random_bytes_64().unwrap();
        assert_ne!(a, b, "two consecutive calls must produce different output");
    }

    #[test]
    fn encrypted_key_magic_header_is_8_bytes() {
        assert_eq!(ENCRYPTED_KEY_MAGIC.len(), 8);
        assert_eq!(ENCRYPTED_KEY_MAGIC, b"MENC0001");
    }

    #[test]
    fn is_encrypted_detects_magic_header() {
        let mut data = vec![0u8; 100];
        data[..8].copy_from_slice(ENCRYPTED_KEY_MAGIC);
        assert!(is_encrypted(&data));
    }

    #[test]
    fn is_encrypted_rejects_missing_header() {
        assert!(!is_encrypted(&[0u8; 100]));
        assert!(!is_encrypted(&[]));
        assert!(!is_encrypted(&[0u8; 7])); // too short
    }

    #[test]
    fn derive_key_material_kek_is_deterministic() {
        let master = [0x42u8; 32];
        let k1 = derive_key_material_kek(&master);
        let k2 = derive_key_material_kek(&master);
        assert_eq!(k1, k2, "same master KEK must produce same derived key");
    }

    #[test]
    fn derive_key_material_kek_different_inputs_differ() {
        let k1 = derive_key_material_kek(&[0x01; 32]);
        let k2 = derive_key_material_kek(&[0x02; 32]);
        assert_ne!(k1, k2, "different master KEKs must produce different derived keys");
    }

    #[test]
    fn encrypt_then_decrypt_roundtrips() {
        let master_kek = [0xAA; 32];
        let plaintext = b"secret key material for testing";
        let name = "test-key";

        let sealed = encrypt_key_bytes(&master_kek, name, plaintext)
            .expect("encryption must succeed");

        // Sealed must start with magic header.
        assert_eq!(&sealed[..8], ENCRYPTED_KEY_MAGIC);
        // Sealed must be longer than plaintext (magic + nonce + tag).
        assert!(sealed.len() > plaintext.len() + 8 + 12);

        let recovered = decrypt_key_bytes(&master_kek, name, &sealed)
            .expect("decryption must succeed");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn decrypt_rejects_wrong_key() {
        let master_kek = [0xAA; 32];
        let wrong_kek = [0xBB; 32];
        let plaintext = b"sensitive material";
        let name = "test-key";

        let sealed = encrypt_key_bytes(&master_kek, name, plaintext).unwrap();
        let result = decrypt_key_bytes(&wrong_kek, name, &sealed);
        assert!(result.is_err(), "decryption with wrong KEK must fail");
    }

    #[test]
    fn decrypt_rejects_wrong_name_aad() {
        let master_kek = [0xAA; 32];
        let plaintext = b"sensitive material";

        let sealed = encrypt_key_bytes(&master_kek, "correct-name", plaintext).unwrap();
        let result = decrypt_key_bytes(&master_kek, "wrong-name", &sealed);
        assert!(result.is_err(), "decryption with wrong AAD (name) must fail");
    }

    #[test]
    fn decrypt_rejects_truncated_data() {
        let result = decrypt_key_bytes(&[0xAA; 32], "key", &[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_rejects_missing_magic_header() {
        // Correct length but no magic header.
        let result = decrypt_key_bytes(&[0xAA; 32], "key", &[0u8; 100]);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("magic header"),
            "error must mention missing magic header"
        );
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        let master_kek = [0xCC; 32];
        let plaintext = b"do not tamper";
        let name = "integrity-test";

        let mut sealed = encrypt_key_bytes(&master_kek, name, plaintext).unwrap();
        // Flip a byte in the ciphertext portion (after magic + nonce).
        let tamper_idx = 8 + 12 + 1;
        if tamper_idx < sealed.len() {
            sealed[tamper_idx] ^= 0xFF;
        }
        let result = decrypt_key_bytes(&master_kek, name, &sealed);
        assert!(result.is_err(), "tampered ciphertext must be rejected");
    }

    #[test]
    fn validate_magic_header_accepts_encrypted_data() {
        let mut data = vec![0u8; 50];
        data[..8].copy_from_slice(ENCRYPTED_KEY_MAGIC);
        assert!(validate_magic_header(&data, "test").is_ok());
    }

    #[test]
    fn validate_magic_header_rejects_plaintext() {
        let data = vec![0u8; 50];
        let result = validate_magic_header(&data, "test-key");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("SECURITY VIOLATION"));
    }

    #[test]
    #[should_panic(expected = "require_encryption_at_rest")]
    fn enforce_encryption_policy_panics_when_disabled() {
        let mut config = SecurityConfig::default();
        config.require_encryption_at_rest = false;
        enforce_encryption_policy(&config);
    }

    #[test]
    fn enforce_encryption_policy_passes_when_enabled() {
        let config = SecurityConfig::default();
        // Must not panic.
        enforce_encryption_policy(&config);
    }

    #[test]
    fn encrypt_key_bytes_produces_different_ciphertexts_for_same_plaintext() {
        // Each encryption uses a fresh random nonce.
        let master_kek = [0xDD; 32];
        let plaintext = b"same input twice";
        let name = "nonce-test";

        let sealed1 = encrypt_key_bytes(&master_kek, name, plaintext).unwrap();
        let sealed2 = encrypt_key_bytes(&master_kek, name, plaintext).unwrap();
        assert_ne!(
            sealed1, sealed2,
            "same plaintext must produce different ciphertext (random nonce)"
        );

        // Both must decrypt to the same value.
        let p1 = decrypt_key_bytes(&master_kek, name, &sealed1).unwrap();
        let p2 = decrypt_key_bytes(&master_kek, name, &sealed2).unwrap();
        assert_eq!(p1, p2);
        assert_eq!(p1, plaintext);
    }
}
