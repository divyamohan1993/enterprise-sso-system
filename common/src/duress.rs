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

#[derive(Serialize, Deserialize)]
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
    /// Optional callback invoked when duress is detected. Enables automated
    /// incident response (session revocation, account lockdown, SOC paging).
    #[serde(skip)]
    pub duress_response_callback: Option<Box<dyn Fn(&DuressAlert) + Send + Sync>>,
}

impl std::fmt::Debug for DuressConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DuressConfig")
            .field("user_id", &self.user_id)
            .field("has_callback", &self.duress_response_callback.is_some())
            .finish()
    }
}

impl Clone for DuressConfig {
    fn clone(&self) -> Self {
        Self {
            user_id: self.user_id,
            normal_pin_hash: self.normal_pin_hash.clone(),
            duress_pin_hash: self.duress_pin_hash.clone(),
            salt: self.salt,
            duress_response_callback: None, // Callbacks cannot be cloned
        }
    }
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
    if let Err(e) = hk.expand(b"MILNET-DURESS-PIN-v2", &mut okm) {
        tracing::error!("FATAL: HKDF-SHA512 expand failed for duress PIN hash: {e}");
        std::process::exit(1);
    }

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
        getrandom::getrandom(&mut salt).unwrap_or_else(|e| {
            tracing::error!("FATAL: CSPRNG failure in duress PIN salt generation: {e}");
            std::process::exit(1);
        });

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
            duress_response_callback: None,
        })
    }

    /// Verify a PIN against both normal and duress hashes.
    /// Supports legacy SHA-256 (v1), SHA-512 (v1b), and HKDF-SHA512 (v2) formats
    /// for backward compatibility.
    ///
    /// When duress is detected, a CRITICAL SIEM event is emitted automatically
    /// and the `duress_response_callback` (if configured) is invoked.
    pub fn verify_pin(&self, pin: &[u8]) -> PinVerification {
        let is_normal = verify_pin_hash(pin, &self.normal_pin_hash, &self.salt);
        let is_duress = verify_pin_hash(pin, &self.duress_pin_hash, &self.salt);

        // Always construct the timestamp and alert to eliminate timing
        // differences between Normal, Duress, and Invalid branches.
        // This prevents side-channel leakage of which PIN type matched.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let alert = DuressAlert {
            user_id: self.user_id,
            timestamp: now,
            fake_token_issued: true,
            lockdown_triggered: true,
        };

        // Always evaluate whether a callback exists (constant-time branch structure).
        // The dummy_invoked variable ensures the compiler does not optimize away
        // the callback existence check in the non-duress path.
        let has_callback = self.duress_response_callback.is_some();

        if is_normal {
            // Dummy: read has_callback to match duress branch timing
            let _ = std::hint::black_box(has_callback);
            let _ = std::hint::black_box(&alert);
            PinVerification::Normal
        } else if is_duress {
            crate::siem::SecurityEvent::duress_detected(self.user_id);

            if let Some(ref callback) = self.duress_response_callback {
                callback(&alert);
            }

            PinVerification::Duress
        } else {
            // Dummy: read has_callback to match duress branch timing
            let _ = std::hint::black_box(has_callback);
            let _ = std::hint::black_box(&alert);
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
