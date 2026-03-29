//! Duress PIN protocol (spec Section 7, Errata B.4)
//! A secondary PIN that appears to work but silently triggers lockdown.
//!
//! CNSA 2.0 compliance: All PIN hashing uses SHA-512 family.
//! Legacy v1 SHA-256 path upgraded to SHA-512 (v1b).
//! New installations use HKDF-SHA512 (v2).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Version tag prepended to HKDF-based hashes to distinguish from legacy SHA-256.
const HKDF_V2_TAG: u8 = 0x02;

/// Version tag for legacy SHA-256 hashes — no longer generated, only accepted
/// for backward compatibility during migration.
const SHA256_V1_TAG: u8 = 0x01;

/// Version tag for upgraded legacy path using SHA-512 (CNSA 2.0 compliant).
const SHA512_V1B_TAG: u8 = 0x03;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuressConfig {
    pub user_id: Uuid,
    /// PIN hash bytes. Format: version_tag(1) || hash_data(variable).
    /// v1 = SHA-256 (32 bytes payload) [legacy, read-only],
    /// v1b = SHA-512 (64 bytes payload) [CNSA 2.0 upgrade of v1],
    /// v2 = HKDF-SHA512 (64 bytes payload).
    pub normal_pin_hash: Vec<u8>,
    pub duress_pin_hash: Vec<u8>,
    /// Random salt for HKDF-based PIN hashing (v2+).
    pub salt: [u8; 32],
}

#[derive(Debug, Clone, PartialEq)]
pub enum PinVerification {
    Normal,  // Legitimate authentication
    Duress,  // Coercion detected — fake success, trigger alert
    Invalid, // Wrong PIN
}

/// Hash a PIN using HKDF-SHA512 with domain separation and salt (v2 format).
/// Returns version_tag(1) || hkdf_output(64).
fn hash_pin_v2(pin: &[u8], salt: &[u8; 32]) -> Vec<u8> {
    use hkdf::Hkdf;
    use sha2::Sha512;

    let hk = Hkdf::<Sha512>::new(Some(salt), pin);
    let mut okm = [0u8; 64];
    hk.expand(b"MILNET-DURESS-PIN-v2", &mut okm)
        .expect("64-byte HKDF expand must succeed");

    let mut result = Vec::with_capacity(1 + 64);
    result.push(HKDF_V2_TAG);
    result.extend_from_slice(&okm);
    result
}

/// Hash a PIN using SHA-512 with domain separation (v1b format, CNSA 2.0 compliant).
/// Returns version_tag(1) || sha512_hash(64).
fn hash_pin_v1b(pin: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(b"MILNET-SSO-v2-DURESS-PIN");
    hasher.update(pin);
    let hash: [u8; 64] = hasher.finalize().into();

    let mut result = Vec::with_capacity(1 + 64);
    result.push(SHA512_V1B_TAG);
    result.extend_from_slice(&hash);
    result
}

/// Hash a PIN using legacy SHA-256 with domain separation (v1 format).
/// Returns version_tag(1) || sha256_hash(32).
/// DEPRECATED: Only used for verifying existing v1 hashes during migration.
/// Not CNSA 2.0 compliant — retained solely for backward compatibility.
fn hash_pin_v1(pin: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"MILNET-SSO-v1-DURESS-PIN");
    hasher.update(pin);
    let hash: [u8; 32] = hasher.finalize().into();

    let mut result = Vec::with_capacity(1 + 32);
    result.push(SHA256_V1_TAG);
    result.extend_from_slice(&hash);
    result
}

/// Constant-time comparison of a candidate hash against a stored hash.
/// Handles v1 (SHA-256, legacy), v1b (SHA-512, CNSA 2.0), and v2 (HKDF-SHA512) formats.
fn verify_pin_hash(pin: &[u8], stored: &[u8], salt: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;

    if stored.is_empty() {
        return false;
    }

    match stored[0] {
        HKDF_V2_TAG => {
            let candidate = hash_pin_v2(pin, salt);
            candidate.ct_eq(stored).into()
        }
        SHA512_V1B_TAG => {
            let candidate = hash_pin_v1b(pin);
            candidate.ct_eq(stored).into()
        }
        SHA256_V1_TAG => {
            // Legacy SHA-256 path — accepted for backward compatibility only.
            // New DuressConfig instances always use v2 (HKDF-SHA512).
            let candidate = hash_pin_v1(pin);
            candidate.ct_eq(stored).into()
        }
        _ => {
            // Legacy format without version tag: treat as raw SHA-512 (64 bytes)
            // for backward compatibility with pre-versioned data.
            // CNSA 2.0: upgraded from SHA-256 to SHA-512.
            if stored.len() == 64 {
                use sha2::{Digest, Sha512};
                let mut hasher = Sha512::new();
                hasher.update(b"MILNET-SSO-v2-DURESS-PIN");
                hasher.update(pin);
                let hash: [u8; 64] = hasher.finalize().into();
                hash.ct_eq(stored).into()
            } else if stored.len() == 32 {
                // Very old legacy format (SHA-256, 32 bytes, no tag).
                // Retained for migration path only. Not CNSA 2.0 compliant.
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(b"MILNET-SSO-v1-DURESS-PIN");
                hasher.update(pin);
                let hash: [u8; 32] = hasher.finalize().into();
                hash.ct_eq(stored).into()
            } else {
                false
            }
        }
    }
}

impl DuressConfig {
    /// Create a new DuressConfig using HKDF-SHA512 (v2) PIN hashing.
    ///
    /// # Errors
    ///
    /// Returns an error if `normal_pin` and `duress_pin` produce the same
    /// hash (i.e. the PINs are identical).  The duress PIN must be distinct
    /// from the normal PIN to avoid accidental lockdown.
    pub fn new(user_id: Uuid, normal_pin: &[u8], duress_pin: &[u8]) -> Result<Self, &'static str> {
        let mut salt = [0u8; 32];
        getrandom::getrandom(&mut salt).expect("OS entropy source must be available");

        let normal_pin_hash = hash_pin_v2(normal_pin, &salt);
        let duress_pin_hash = hash_pin_v2(duress_pin, &salt);

        // Constant-time comparison to verify PINs produce different hashes.
        use subtle::ConstantTimeEq;
        if normal_pin_hash.ct_eq(&duress_pin_hash).into() {
            return Err("duress PIN must differ from normal PIN");
        }

        Ok(Self {
            user_id,
            normal_pin_hash,
            duress_pin_hash,
            salt,
        })
    }

    /// Verify a PIN against both normal and duress hashes.
    /// Supports legacy SHA-256 (v1), SHA-512 (v1b), and HKDF-SHA512 (v2) formats
    /// for backward compatibility.
    pub fn verify_pin(&self, pin: &[u8]) -> PinVerification {
        let is_normal = verify_pin_hash(pin, &self.normal_pin_hash, &self.salt);
        let is_duress = verify_pin_hash(pin, &self.duress_pin_hash, &self.salt);

        if is_normal {
            PinVerification::Normal
        } else if is_duress {
            PinVerification::Duress
        } else {
            PinVerification::Invalid
        }
    }
}

/// Duress alert — generated when duress PIN is detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuressAlert {
    pub user_id: Uuid,
    pub timestamp: i64,
    pub fake_token_issued: bool,
    pub lockdown_triggered: bool,
}
