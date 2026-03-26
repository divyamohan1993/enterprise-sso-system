//! Hardened key loading for inter-service communication.
//!
//! All services MUST use the same SHARD HMAC key and receipt signing key.
//! Keys are loaded from sealed storage (encrypted env vars) and unwrapped
//! using the master KEK. Raw plaintext env vars are rejected in production mode.
//!
//! # Key Loading Hierarchy
//! 1. Check for sealed (encrypted) key in env: `{NAME}_SEALED`
//! 2. Unwrap with master KEK via HKDF-SHA512
//! 3. Zeroize the env var memory after loading
//! 4. If neither sealed nor raw key is available AND production mode is off,
//!    fall back to deterministic dev key (with loud warning)
//!
//! # Production Mode
//! Set `MILNET_PRODUCTION=1` to enforce:
//! - No dev key fallbacks (hard fail)
//! - Sealed keys required
//! - Master KEK must come from env `MILNET_MASTER_KEK` (hex-encoded)

use std::sync::OnceLock;
use zeroize::Zeroize;

/// Master KEK storage with memory protection.
/// The key is mlock'd to prevent swapping and marked MADV_DONTDUMP to exclude
/// from core dumps. This is critical: the master KEK decrypts every other key
/// in the system.
struct ProtectedKek {
    key: [u8; 32],
}

impl ProtectedKek {
    fn new(key: [u8; 32]) -> Self {
        let kek = Self { key };
        // Lock the key into physical RAM — prevent swap exposure
        #[cfg(unix)]
        unsafe {
            let ptr = kek.key.as_ptr() as *const libc::c_void;
            let len = std::mem::size_of_val(&kek.key);
            let _ = libc::mlock(ptr, len);
            // Exclude from core dumps
            let _ = libc::madvise(ptr as *mut libc::c_void, len, libc::MADV_DONTDUMP);
        }
        kek
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

impl Drop for ProtectedKek {
    fn drop(&mut self) {
        self.key.zeroize();
        #[cfg(unix)]
        unsafe {
            let ptr = self.key.as_ptr() as *const libc::c_void;
            let len = std::mem::size_of_val(&self.key);
            let _ = libc::munlock(ptr, len);
        }
    }
}

// SAFETY: The key is only written once via OnceLock and then read-only.
unsafe impl Sync for ProtectedKek {}
unsafe impl Send for ProtectedKek {}

static MASTER_KEK_CACHE: OnceLock<ProtectedKek> = OnceLock::new();

/// Returns a reference to the cached master KEK, loading it once on first call.
/// The KEK is mlock'd into physical RAM and excluded from core dumps.
pub fn cached_master_kek() -> &'static [u8; 32] {
    MASTER_KEK_CACHE.get_or_init(|| ProtectedKek::new(load_master_kek())).as_bytes()
}

/// Whether the system is running in production mode.
/// In production, dev key fallbacks are forbidden.
/// Returns `true` only if `MILNET_PRODUCTION` is set to `"1"` or `"true"` (case-insensitive).
pub fn is_production() -> bool {
    match std::env::var("MILNET_PRODUCTION") {
        Ok(val) => val == "1" || val.eq_ignore_ascii_case("true"),
        Err(_) => false,
    }
}

/// Load the master KEK from environment.
/// Returns 32-byte key derived from `MILNET_MASTER_KEK` (hex-encoded, 64 chars).
/// In dev mode, falls back to a deterministic key.
///
/// After reading, the env var is removed from the process environment to
/// prevent leakage via `/proc/pid/environ`, and the in-memory String is
/// zeroized.
///
/// NOTE: In production, this should be called once at startup and the result
/// cached by the caller. The env var is removed after first read.
pub fn load_master_kek() -> [u8; 32] {
    use zeroize::Zeroize;
    match std::env::var("MILNET_MASTER_KEK") {
        Ok(mut hex_str) if hex_str.len() >= 64 => {
            // Remove from process environment to prevent /proc/pid/environ leakage.
            // Callers should cache the returned key.
            #[cfg(not(test))]
            std::env::remove_var("MILNET_MASTER_KEK");
            let mut key = [0u8; 32];
            for (i, chunk) in hex_str.as_bytes().chunks(2).take(32).enumerate() {
                let hex = std::str::from_utf8(chunk)
                    .unwrap_or_else(|_| { eprintln!("FATAL: MILNET_MASTER_KEK contains invalid UTF-8 at byte {}", i * 2); std::process::exit(1); });
                key[i] = u8::from_str_radix(hex, 16)
                    .unwrap_or_else(|_| { eprintln!("FATAL: MILNET_MASTER_KEK contains invalid hex '{}' at position {}", hex, i * 2); std::process::exit(1); });
            }
            // Reject all-zero keys
            if key.iter().all(|&b| b == 0) {
                eprintln!("FATAL: all-zero key detected in MILNET_MASTER_KEK"); std::process::exit(1);
            }
            // Zeroize the hex string in memory
            zeroize_string(&mut hex_str);
            hex_str.zeroize();
            key
        }
        _ => {
            if is_production() {
                eprintln!("FATAL: MILNET_MASTER_KEK not set in production mode. Refusing to start."); std::process::exit(1);
            }
            eprintln!("WARNING: MILNET_MASTER_KEK not set. Using deterministic dev KEK. NOT FOR PRODUCTION.");
            let mut key = [0u8; 32];
            use sha2::{Digest, Sha512};
            let hash = Sha512::digest(b"MILNET-DEV-MASTER-KEK-NOT-FOR-PRODUCTION");
            key.copy_from_slice(&hash[..32]);
            // Reject all-zero keys even in dev mode
            if key.iter().all(|&b| b == 0) {
                eprintln!("FATAL: all-zero key detected in dev master KEK derivation"); std::process::exit(1);
            }
            key
        }
    }
}

/// Load the shared SHARD HMAC key with sealed key support.
pub fn load_shard_hmac_key_sealed() -> [u8; 64] {
    load_key_hardened(
        "SHARD_HMAC_KEY",
        "shard-hmac",
        b"MILNET-DEV-SHARD-HMAC-KEY-NOT-FOR-PRODUCTION!!!!!",
    )
}

/// Derive a per-module SHARD HMAC key from the master KEK.
///
/// Each module gets a unique key derived via HKDF-SHA512 with the module name
/// as domain separator. This prevents one compromised module from impersonating
/// another on the SHARD channel. Both endpoints of a channel must derive the
/// same key by using a canonical channel name.
pub fn derive_module_hmac_key(module_a: &str, module_b: &str) -> [u8; 64] {
    let master_kek = cached_master_kek();
    // Canonical ordering: alphabetically sort module names for consistent derivation
    let (first, second) = if module_a <= module_b {
        (module_a, module_b)
    } else {
        (module_b, module_a)
    };
    let domain = format!("MILNET-SHARD-CHANNEL-v1:{}:{}", first, second);

    use hkdf::Hkdf;
    use sha2::Sha512;
    let hk = Hkdf::<Sha512>::new(Some(domain.as_bytes()), master_kek);
    let mut okm = [0u8; 64];
    hk.expand(b"shard-channel-hmac", &mut okm)
        .expect("64-byte HKDF expand must succeed");
    okm
}

/// Load the shared receipt signing key with sealed key support.
pub fn load_receipt_signing_key_sealed() -> [u8; 64] {
    load_key_hardened(
        "RECEIPT_SIGNING_KEY",
        "receipt-sign",
        b"MILNET-DEV-RECEIPT-KEY-NOT-FOR-PRODUCTION!!!!!!!!",
    )
}

/// Hardened key loading with sealed key support.
///
/// After reading, env vars are removed from the process environment and
/// the in-memory Strings are zeroized to prevent leakage.
fn load_key_hardened(var: &str, purpose: &str, dev_seed: &[u8]) -> [u8; 64] {
    use zeroize::Zeroize;
    let sealed_var = format!("{var}_SEALED");

    // 1. Try sealed key
    if let Ok(mut hex_str) = std::env::var(&sealed_var) {
        // Remove from process environment immediately
        #[cfg(not(test))]
        std::env::remove_var(&sealed_var);
        let result = unseal_key_from_hex(&hex_str, purpose);
        zeroize_string(&mut hex_str);
        hex_str.zeroize();
        if let Some(key) = result {
            // Reject all-zero keys
            if key.iter().all(|&b| b == 0) {
                eprintln!("FATAL: all-zero key detected after unsealing {var}"); std::process::exit(1);
            }
            eprintln!("INFO: {var} loaded from sealed storage.");
            return key;
        }
        eprintln!("WARNING: {sealed_var} present but unseal failed. Trying raw.");
    }

    // 2. Try raw key (blocked in production)
    if let Ok(mut hex_str) = std::env::var(var) {
        // Remove from process environment immediately
        #[cfg(not(test))]
        std::env::remove_var(var);
        if hex_str.len() >= 128 {
            if is_production() {
                zeroize_string(&mut hex_str);
                hex_str.zeroize();
                eprintln!(
                    "FATAL: Raw (unencrypted) {var} detected in production mode. \
                     Use {sealed_var} with sealed keys instead."
                );
                std::process::exit(1);
            }
            eprintln!("WARNING: {var} loaded as raw plaintext. Use sealed keys in production.");
            let mut key = [0u8; 64];
            for (i, chunk) in hex_str.as_bytes().chunks(2).take(64).enumerate() {
                let hex = std::str::from_utf8(chunk)
                    .unwrap_or_else(|_| { eprintln!("FATAL: {var} contains invalid UTF-8 at byte {}", i * 2); std::process::exit(1); });
                key[i] = u8::from_str_radix(hex, 16)
                    .unwrap_or_else(|_| { eprintln!("FATAL: {var} contains invalid hex '{}' at position {}", hex, i * 2); std::process::exit(1); });
            }
            // Reject all-zero keys
            if key.iter().all(|&b| b == 0) {
                eprintln!("FATAL: all-zero key detected in {var}"); std::process::exit(1);
            }
            zeroize_string(&mut hex_str);
            hex_str.zeroize();
            return key;
        }
        zeroize_string(&mut hex_str);
        hex_str.zeroize();
    }

    // 3. Dev fallback
    if is_production() {
        eprintln!(
                    "FATAL: {var} not set and no sealed key found. \
             Cannot start in production mode without keys."
                );
                std::process::exit(1);
    }

    eprintln!(
        "WARNING: {var} not set or invalid. Using deterministic dev key. NOT FOR PRODUCTION."
    );
    deterministic_dev_key(dev_seed)
}

/// Unseal a hex-encoded sealed key using the master KEK.
fn unseal_key_from_hex(hex_str: &str, purpose: &str) -> Option<[u8; 64]> {
    let sealed_bytes: Vec<u8> = (0..hex_str.len())
        .step_by(2)
        .filter_map(|i| {
            hex_str.get(i..i + 2).and_then(|s| u8::from_str_radix(s, 16).ok())
        })
        .collect();

    if sealed_bytes.len() < 12 + 16 + 64 {
        return None;
    }

    let master_kek = cached_master_kek();
    let unseal_key = derive_unseal_key(master_kek, purpose);

    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use aes_gcm::aead::Aead;

    let cipher = Aes256Gcm::new_from_slice(&unseal_key).ok()?;
    let nonce = Nonce::from_slice(&sealed_bytes[..12]);
    let aad = format!("MILNET-SEALED-KEY-v1:{purpose}");
    let plaintext = cipher
        .decrypt(nonce, aes_gcm::aead::Payload {
            msg: &sealed_bytes[12..],
            aad: aad.as_bytes(),
        })
        .ok()?;

    if plaintext.len() != 64 {
        return None;
    }

    let mut key = [0u8; 64];
    key.copy_from_slice(&plaintext);
    // Zeroize the intermediate plaintext Vec to prevent heap fragment leakage
    let mut plaintext = plaintext;
    use zeroize::Zeroize;
    plaintext.zeroize();
    Some(key)
}

/// Derive an unseal key for a specific purpose from the master KEK.
fn derive_unseal_key(master_kek: &[u8; 32], purpose: &str) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha512;
    let hk = Hkdf::<Sha512>::new(Some(b"MILNET-UNSEAL-v1"), master_kek);
    let mut okm = [0u8; 32];
    hk.expand(purpose.as_bytes(), &mut okm)
        .expect("32-byte HKDF expand must succeed");
    okm
}

/// Generate a deterministic dev key from a seed (NOT FOR PRODUCTION).
fn deterministic_dev_key(seed: &[u8]) -> [u8; 64] {
    use sha2::{Digest, Sha512};
    let hash = Sha512::digest(seed);
    let mut key = [0u8; 64];
    key.copy_from_slice(&hash);
    // Reject all-zero keys
    if key.iter().all(|&b| b == 0) {
        eprintln!("FATAL: all-zero key detected in deterministic dev key derivation"); std::process::exit(1);
    }
    key
}

/// Seal a 64-byte key for storage in env vars or files.
/// Used by operators to prepare sealed keys for deployment.
pub fn seal_key_for_storage(key: &[u8; 64], purpose: &str) -> Vec<u8> {
    let master_kek = cached_master_kek();
    let seal_key = derive_unseal_key(master_kek, purpose);

    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use aes_gcm::aead::Aead;

    let cipher = Aes256Gcm::new_from_slice(&seal_key).expect("32-byte key");

    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes).expect("OS entropy");
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aad = format!("MILNET-SEALED-KEY-v1:{purpose}");
    let ciphertext = cipher
        .encrypt(nonce, aes_gcm::aead::Payload {
            msg: key.as_slice(),
            aad: aad.as_bytes(),
        })
        .expect("AES-256-GCM encryption must not fail");

    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    out
}

/// Detect whether an HSM backend is configured via environment.
///
/// Returns the HSM backend name if `MILNET_HSM_BACKEND` is set and valid.
/// Valid values: `pkcs11`, `aws-kms`, `tpm2`, `software`.
pub fn hsm_backend_from_env() -> Option<String> {
    std::env::var("MILNET_HSM_BACKEND").ok().filter(|s| {
        matches!(
            s.to_lowercase().as_str(),
            "pkcs11" | "aws-kms" | "awskms" | "kms" | "tpm2" | "tpm" | "software" | "soft" | "dev"
        )
    })
}

/// Load the master KEK with HSM awareness.
///
/// If `MILNET_HSM_BACKEND` is set, this returns a sentinel value indicating
/// that the caller should use the HSM key manager (`crypto::hsm::HsmKeyManager`)
/// instead of a raw key. The sentinel is all-zeros, which is detected by the
/// crypto layer as "use HSM path".
///
/// If `MILNET_HSM_BACKEND` is not set, falls back to [`load_master_kek`].
///
/// # Usage
/// ```ignore
/// let kek = load_master_kek_hsm_aware();
/// if kek == [0u8; 32] {
///     // HSM backend configured — use HsmKeyManager
///     let config = crypto::hsm::HsmConfig::from_env();
///     let source = crypto::hsm::create_key_source(&config)?;
///     let master_key = source.load_master_key()?;
/// } else {
///     // Software/env var path
///     let master_key = crypto::seal::MasterKey::from_bytes(kek);
/// }
/// ```
pub fn load_master_kek_hsm_aware() -> [u8; 32] {
    if let Some(backend) = hsm_backend_from_env() {
        let is_software = matches!(
            backend.to_lowercase().as_str(),
            "software" | "soft" | "dev"
        );
        if !is_software {
            eprintln!(
                "INFO: HSM backend '{}' detected. Master KEK will be loaded from HSM.",
                backend
            );
            // Return sentinel — caller must use HsmKeyManager.
            return [0u8; 32];
        }
        // Software HSM is forbidden in production — silent fallback would mask
        // a misconfiguration that leaves keys unprotected by hardware.
        if is_production() {
            eprintln!(
                    "FATAL: Software HSM backend forbidden in production. \
                 Set MILNET_HSM_BACKEND to pkcs11/aws-kms/tpm2"
                );
                std::process::exit(1);
        }
        // Software backend (dev only): fall through to normal env var loading.
        eprintln!(
            "INFO: Software HSM backend detected. Falling back to env var key loading."
        );
    }
    load_master_kek()
}

/// Convert sealed bytes to hex string for env var storage.
pub fn sealed_to_hex(sealed: &[u8]) -> String {
    sealed.iter().map(|b| format!("{b:02x}")).collect()
}

/// Securely zeroize a string using volatile writes (cannot be optimized away).
/// Delegates to the `zeroize` crate which guarantees memory is actually cleared.
pub fn zeroize_string(s: &mut String) {
    use zeroize::Zeroize;
    s.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_dev_key_is_consistent() {
        let key1 = deterministic_dev_key(b"test-seed");
        let key2 = deterministic_dev_key(b"test-seed");
        assert_eq!(key1, key2);
    }

    #[test]
    fn different_seeds_produce_different_keys() {
        let key1 = deterministic_dev_key(b"seed-a");
        let key2 = deterministic_dev_key(b"seed-b");
        assert_ne!(key1, key2);
    }

    #[test]
    fn derive_unseal_key_deterministic() {
        let master = [42u8; 32];
        let k1 = derive_unseal_key(&master, "shard-hmac");
        let k2 = derive_unseal_key(&master, "shard-hmac");
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_unseal_key_different_purposes() {
        let master = [42u8; 32];
        let k1 = derive_unseal_key(&master, "shard-hmac");
        let k2 = derive_unseal_key(&master, "receipt-sign");
        assert_ne!(k1, k2);
    }

    #[test]
    fn seal_unseal_round_trip() {
        std::env::set_var("MILNET_MASTER_KEK", "2a".repeat(32));

        let mut original_key = [0u8; 64];
        getrandom::getrandom(&mut original_key).unwrap();

        let sealed = seal_key_for_storage(&original_key, "test-purpose");
        let hex_sealed = sealed_to_hex(&sealed);

        let recovered = unseal_key_from_hex(&hex_sealed, "test-purpose");
        assert!(recovered.is_some());
        assert_eq!(recovered.unwrap(), original_key);

        std::env::remove_var("MILNET_MASTER_KEK");
    }

    #[test]
    fn wrong_purpose_fails_unseal() {
        std::env::set_var("MILNET_MASTER_KEK", "2a".repeat(32));

        let original_key = [99u8; 64];
        let sealed = seal_key_for_storage(&original_key, "purpose-a");
        let hex_sealed = sealed_to_hex(&sealed);

        let recovered = unseal_key_from_hex(&hex_sealed, "purpose-b");
        assert!(recovered.is_none());

        std::env::remove_var("MILNET_MASTER_KEK");
    }

    #[test]
    fn tampered_sealed_data_fails() {
        std::env::set_var("MILNET_MASTER_KEK", "2a".repeat(32));

        let original_key = [77u8; 64];
        let mut sealed = seal_key_for_storage(&original_key, "test");
        if sealed.len() > 20 {
            sealed[20] ^= 0xFF;
        }
        let hex_sealed = sealed_to_hex(&sealed);

        let recovered = unseal_key_from_hex(&hex_sealed, "test");
        assert!(recovered.is_none());

        std::env::remove_var("MILNET_MASTER_KEK");
    }
}
