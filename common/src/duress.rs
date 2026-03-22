//! Duress PIN protocol (spec Section 7, Errata B.4)
//! A secondary PIN that appears to work but silently triggers lockdown.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Version tag prepended to HKDF-based hashes to distinguish from legacy SHA-256.
const HKDF_V2_TAG: u8 = 0x02;

/// Version tag for legacy SHA-256 hashes (implicit in old data, explicit here).
const SHA256_V1_TAG: u8 = 0x01;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuressConfig {
    pub user_id: Uuid,
    /// PIN hash bytes. Format: version_tag(1) || hash_data(variable).
    /// v1 = SHA-256 (32 bytes payload), v2 = HKDF-SHA512 (64 bytes payload).
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

/// Hash a PIN using legacy SHA-256 with domain separation (v1 format).
/// Returns version_tag(1) || sha256_hash(32).
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
/// Handles both v1 (SHA-256) and v2 (HKDF-SHA512) formats.
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
        SHA256_V1_TAG => {
            let candidate = hash_pin_v1(pin);
            candidate.ct_eq(stored).into()
        }
        _ => {
            // Legacy format without version tag: treat as raw SHA-256 (32 bytes)
            // for backward compatibility with pre-versioned data.
            if stored.len() == 32 {
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
    pub fn new(user_id: Uuid, normal_pin: &[u8], duress_pin: &[u8]) -> Self {
        let mut salt = [0u8; 32];
        getrandom::getrandom(&mut salt).expect("OS entropy source must be available");

        let normal_pin_hash = hash_pin_v2(normal_pin, &salt);
        let duress_pin_hash = hash_pin_v2(duress_pin, &salt);

        Self {
            user_id,
            normal_pin_hash,
            duress_pin_hash,
            salt,
        }
    }

    /// Verify a PIN against both normal and duress hashes.
    /// Supports both legacy SHA-256 (v1) and HKDF-SHA512 (v2) formats
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
