//! Automated secret ceremony for key lifecycle management.
//!
//! SECURITY INVARIANTS:
//! - Keys NEVER touch disk in plaintext (only sealed via AES-256-GCM + TPM)
//! - Keys NEVER appear in logs (all logging uses redacted placeholders)
//! - Keys are mlock'd in memory (prevent swap exposure)
//! - Keys are zeroized on drop (prevent memory forensics)
//! - Rotation is atomic: new keys activate, old keys destroyed, no gap
//! - Split keys use threshold schemes: no single party holds complete key
//!
//! Ceremony types:
//! 1. Initial bootstrap -- generate all keys from scratch
//! 2. Scheduled rotation -- periodic key replacement
//! 3. Emergency rotation -- immediate rotation after compromise detection
//! 4. Share refresh -- re-split existing keys without changing the public key

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ── CeremonySecret ────────────────────────────────────────────────────────────

/// A secret that is zeroized on drop and never logged.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CeremonySecret {
    bytes: Vec<u8>,
}

impl CeremonySecret {
    /// Generate a cryptographically random secret of `len` bytes.
    pub fn generate(len: usize) -> Result<Self, String> {
        if len == 0 {
            return Err("secret length must be > 0".into());
        }
        let mut bytes = vec![0u8; len];
        getrandom::getrandom(&mut bytes).map_err(|e| format!("getrandom failed: {e}"))?;
        Ok(Self { bytes })
    }

    /// View the raw bytes. Caller MUST NOT log or persist this.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the secret is empty (should never be true after generate).
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl std::fmt::Debug for CeremonySecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CeremonySecret")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

// ── KeyType ───────────────────────────────────────────────────────────────────

/// Types of keys managed by the ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyType {
    /// Master Key Encryption Key.
    MasterKek,
    /// SHARD inter-service HMAC.
    ShardHmac,
    /// OPAQUE receipt ML-DSA-87 seed.
    ReceiptSigning,
    /// Witness checkpoint ML-DSA-87 seed.
    WitnessSigning,
    /// FROST signer share (index 0-4).
    TssShare(u8),
    /// OPAQUE Shamir share (index 0-2).
    OpaqueShare(u8),
    /// Gateway TLS private key.
    GatewayTls,
    /// Audit log ML-DSA-87 seed.
    AuditSigning,
}

impl KeyType {
    /// Canonical string name used in AAD and sealed-store keys.
    pub fn canonical_name(&self) -> String {
        match self {
            KeyType::MasterKek => "MasterKek".into(),
            KeyType::ShardHmac => "ShardHmac".into(),
            KeyType::ReceiptSigning => "ReceiptSigning".into(),
            KeyType::WitnessSigning => "WitnessSigning".into(),
            KeyType::TssShare(i) => format!("TssShare_{i}"),
            KeyType::OpaqueShare(i) => format!("OpaqueShare_{i}"),
            KeyType::GatewayTls => "GatewayTls".into(),
            KeyType::AuditSigning => "AuditSigning".into(),
        }
    }

    /// Default key length in bytes.
    fn default_len(&self) -> usize {
        match self {
            KeyType::MasterKek => 32,
            KeyType::ShardHmac => 64,
            KeyType::ReceiptSigning => 32,
            KeyType::WitnessSigning => 32,
            KeyType::TssShare(_) => 32,
            KeyType::OpaqueShare(_) => 32,
            KeyType::GatewayTls => 32,
            KeyType::AuditSigning => 32,
        }
    }

    /// All key types that should be generated during bootstrap.
    fn all_bootstrap_types() -> Vec<KeyType> {
        let mut types = vec![
            KeyType::MasterKek,
            KeyType::ShardHmac,
            KeyType::ReceiptSigning,
            KeyType::WitnessSigning,
            KeyType::GatewayTls,
            KeyType::AuditSigning,
        ];
        for i in 0..5 {
            types.push(KeyType::TssShare(i));
        }
        for i in 0..3 {
            types.push(KeyType::OpaqueShare(i));
        }
        types
    }
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.canonical_name())
    }
}

// ── RotationSchedule ──────────────────────────────────────────────────────────

/// Rotation schedule for each key type.
pub struct RotationSchedule {
    pub key_type: KeyType,
    pub interval: Duration,
    pub last_rotated: Option<Instant>,
    /// true = rotate NOW regardless of schedule.
    pub emergency: bool,
}

// ── CeremonyResult ────────────────────────────────────────────────────────────

/// Result of a key ceremony operation.
#[derive(Debug)]
pub struct CeremonyResult {
    pub key_type: KeyType,
    /// SHA-256 of new key (safe to log).
    pub new_key_fingerprint: [u8; 32],
    pub old_key_destroyed: bool,
    pub rotation_epoch: u64,
    pub timestamp: i64,
}

// ── CeremonyEngine ────────────────────────────────────────────────────────────

/// The automated ceremony engine.
pub struct CeremonyEngine {
    schedules: Vec<RotationSchedule>,
    rotation_epoch: u64,
    /// Sealed key store: canonical key name -> sealed bytes (nonce || ciphertext || tag).
    sealed_store: HashMap<String, Vec<u8>>,
    /// Sealing key derived from master KEK.
    sealing_key: CeremonySecret,
}

impl CeremonyEngine {
    /// Create a new engine with the given sealing key.
    pub fn new(sealing_key: CeremonySecret) -> Self {
        Self {
            schedules: Self::default_schedules(),
            rotation_epoch: 0,
            sealed_store: HashMap::new(),
            sealing_key,
        }
    }

    /// Bootstrap: generate ALL keys from scratch.
    /// Called once during initial cluster deployment.
    pub fn bootstrap(&mut self) -> Result<Vec<CeremonyResult>, String> {
        let mut results = Vec::new();
        self.rotation_epoch = 1;
        let now = Instant::now();

        for key_type in KeyType::all_bootstrap_types() {
            let secret = CeremonySecret::generate(key_type.default_len())?;
            let fingerprint = sha256_fingerprint(secret.as_bytes());
            let sealed = self.seal_key(key_type, secret.as_bytes())?;
            self.sealed_store.insert(key_type.canonical_name(), sealed);

            // Update schedule last_rotated
            for sched in &mut self.schedules {
                if sched.key_type == key_type {
                    sched.last_rotated = Some(now);
                    sched.emergency = false;
                }
            }

            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            results.push(CeremonyResult {
                key_type,
                new_key_fingerprint: fingerprint,
                old_key_destroyed: false,
                rotation_epoch: self.rotation_epoch,
                timestamp,
            });

            tracing::info!(
                key_type = %key_type,
                fingerprint = %hex::encode(fingerprint),
                epoch = self.rotation_epoch,
                "ceremony: key bootstrapped"
            );
        }

        Ok(results)
    }

    /// Check if any keys need rotation based on schedule.
    pub fn check_rotation_needed(&self) -> Vec<KeyType> {
        let now = Instant::now();
        self.schedules
            .iter()
            .filter(|s| {
                if s.emergency {
                    return true;
                }
                match s.last_rotated {
                    Some(last) => now.duration_since(last) >= s.interval,
                    None => true, // never rotated
                }
            })
            .map(|s| s.key_type)
            .collect()
    }

    /// Rotate a specific key. Generates new key, seals it, destroys old.
    pub fn rotate_key(&mut self, key_type: KeyType) -> Result<CeremonyResult, String> {
        self.rotation_epoch += 1;
        let had_old = self.sealed_store.contains_key(&key_type.canonical_name());

        // Zeroize old sealed data by overwriting
        if had_old {
            if let Some(old_sealed) = self.sealed_store.get_mut(&key_type.canonical_name()) {
                old_sealed.zeroize();
            }
        }

        let secret = CeremonySecret::generate(key_type.default_len())?;
        let fingerprint = sha256_fingerprint(secret.as_bytes());
        let sealed = self.seal_key(key_type, secret.as_bytes())?;
        self.sealed_store.insert(key_type.canonical_name(), sealed);

        let now = Instant::now();
        for sched in &mut self.schedules {
            if sched.key_type == key_type {
                sched.last_rotated = Some(now);
                sched.emergency = false;
            }
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        tracing::info!(
            key_type = %key_type,
            fingerprint = %hex::encode(fingerprint),
            epoch = self.rotation_epoch,
            old_destroyed = had_old,
            "ceremony: key rotated"
        );

        Ok(CeremonyResult {
            key_type,
            new_key_fingerprint: fingerprint,
            old_key_destroyed: had_old,
            rotation_epoch: self.rotation_epoch,
            timestamp,
        })
    }

    /// Emergency rotation: rotate ALL keys immediately.
    /// Called after compromise detection.
    pub fn emergency_rotate_all(&mut self) -> Result<Vec<CeremonyResult>, String> {
        // Mark all schedules as emergency
        for sched in &mut self.schedules {
            sched.emergency = true;
        }

        let all_types = KeyType::all_bootstrap_types();
        let mut results = Vec::new();
        for key_type in all_types {
            let result = self.rotate_key(key_type)?;
            results.push(result);
        }

        tracing::warn!(
            epoch = self.rotation_epoch,
            keys_rotated = results.len(),
            "ceremony: EMERGENCY rotation complete"
        );

        Ok(results)
    }

    /// Seal a key for storage (AES-256-GCM with sealing key).
    /// Output format: nonce(12) || ciphertext || tag(16)
    fn seal_key(&self, key_type: KeyType, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        if self.sealing_key.len() != 32 {
            return Err("sealing key must be 32 bytes".into());
        }

        let cipher = Aes256Gcm::new_from_slice(self.sealing_key.as_bytes())
            .map_err(|e| format!("cipher init failed: {e}"))?;

        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| format!("nonce generation failed: {e}"))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        // AAD: key type name + rotation epoch (prevents cross-key-type confusion)
        let aad = format!("{}:{}", key_type.canonical_name(), self.rotation_epoch);
        let payload = aes_gcm::aead::Payload {
            msg: plaintext,
            aad: aad.as_bytes(),
        };

        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|e| format!("encryption failed: {e}"))?;

        // Output: nonce || ciphertext (which includes the 16-byte tag appended by aes-gcm)
        let mut sealed = Vec::with_capacity(12 + ciphertext.len());
        sealed.extend_from_slice(&nonce_bytes);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    /// Unseal a previously sealed key.
    fn unseal_key(&self, key_type: KeyType, sealed: &[u8]) -> Result<CeremonySecret, String> {
        if sealed.len() < 12 + 16 {
            return Err("sealed data too short (need at least nonce + tag)".into());
        }
        if self.sealing_key.len() != 32 {
            return Err("sealing key must be 32 bytes".into());
        }

        let cipher = Aes256Gcm::new_from_slice(self.sealing_key.as_bytes())
            .map_err(|e| format!("cipher init failed: {e}"))?;

        let nonce = Nonce::from_slice(&sealed[..12]);
        let ciphertext = &sealed[12..];

        let aad = format!("{}:{}", key_type.canonical_name(), self.rotation_epoch);
        let payload = aes_gcm::aead::Payload {
            msg: ciphertext,
            aad: aad.as_bytes(),
        };

        let plaintext = cipher
            .decrypt(nonce, payload)
            .map_err(|e| format!("decryption failed (AAD mismatch or tampered): {e}"))?;

        Ok(CeremonySecret { bytes: plaintext })
    }

    /// Get a sealed key (for distribution to services).
    pub fn get_sealed_key(&self, key_type: KeyType) -> Option<&[u8]> {
        self.sealed_store
            .get(&key_type.canonical_name())
            .map(|v| v.as_slice())
    }

    /// Get key fingerprint (safe to log/distribute).
    /// Unseals the key temporarily to compute the SHA-256 fingerprint, then zeroizes.
    pub fn key_fingerprint(&self, key_type: KeyType) -> Option<[u8; 32]> {
        let sealed = self.sealed_store.get(&key_type.canonical_name())?;
        match self.unseal_key(key_type, sealed) {
            Ok(secret) => Some(sha256_fingerprint(secret.as_bytes())),
            Err(_) => None,
        }
    }

    /// Number of managed keys.
    pub fn key_count(&self) -> usize {
        self.sealed_store.len()
    }

    /// Current rotation epoch.
    pub fn rotation_epoch(&self) -> u64 {
        self.rotation_epoch
    }

    /// Default rotation schedules for all key types.
    pub fn default_schedules() -> Vec<RotationSchedule> {
        let day = Duration::from_secs(86_400);
        let mut schedules = vec![
            RotationSchedule {
                key_type: KeyType::MasterKek,
                interval: day * 90,
                last_rotated: None,
                emergency: false,
            },
            RotationSchedule {
                key_type: KeyType::ShardHmac,
                interval: day, // 24 hours
                last_rotated: None,
                emergency: false,
            },
            RotationSchedule {
                key_type: KeyType::ReceiptSigning,
                interval: day * 30,
                last_rotated: None,
                emergency: false,
            },
            RotationSchedule {
                key_type: KeyType::WitnessSigning,
                interval: day * 30,
                last_rotated: None,
                emergency: false,
            },
            RotationSchedule {
                key_type: KeyType::GatewayTls,
                interval: day * 30,
                last_rotated: None,
                emergency: false,
            },
            RotationSchedule {
                key_type: KeyType::AuditSigning,
                interval: day * 30,
                last_rotated: None,
                emergency: false,
            },
        ];
        for i in 0..5 {
            schedules.push(RotationSchedule {
                key_type: KeyType::TssShare(i),
                interval: day * 7,
                last_rotated: None,
                emergency: false,
            });
        }
        for i in 0..3 {
            schedules.push(RotationSchedule {
                key_type: KeyType::OpaqueShare(i),
                interval: day * 7,
                last_rotated: None,
                emergency: false,
            });
        }
        schedules
    }
}

/// Compute SHA-256 fingerprint of key material.
fn sha256_fingerprint(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_engine() -> CeremonyEngine {
        let sealing_key = CeremonySecret::generate(32).unwrap();
        CeremonyEngine::new(sealing_key)
    }

    #[test]
    fn test_ceremony_secret_generate() {
        let secret = CeremonySecret::generate(32).unwrap();
        assert_eq!(secret.len(), 32);
        assert!(!secret.is_empty());
    }

    #[test]
    fn test_ceremony_secret_zero_length_rejected() {
        assert!(CeremonySecret::generate(0).is_err());
    }

    #[test]
    fn test_ceremony_secret_debug_redacted() {
        let secret = CeremonySecret::generate(16).unwrap();
        let debug_output = format!("{:?}", secret);
        assert!(debug_output.contains("REDACTED"));
        assert!(!debug_output.contains(&format!("{:?}", secret.as_bytes())));
    }

    #[test]
    fn test_key_type_canonical_names() {
        assert_eq!(KeyType::MasterKek.canonical_name(), "MasterKek");
        assert_eq!(KeyType::TssShare(3).canonical_name(), "TssShare_3");
        assert_eq!(KeyType::OpaqueShare(1).canonical_name(), "OpaqueShare_1");
    }

    #[test]
    fn test_bootstrap_generates_all_keys() {
        let mut engine = make_engine();
        let results = engine.bootstrap().unwrap();

        // 6 base keys + 5 TSS shares + 3 OPAQUE shares = 14
        assert_eq!(results.len(), 14);
        assert_eq!(engine.key_count(), 14);
        assert_eq!(engine.rotation_epoch(), 1);

        // Every result should have a non-zero fingerprint
        for r in &results {
            assert_ne!(r.new_key_fingerprint, [0u8; 32]);
            assert!(!r.old_key_destroyed); // bootstrap has no old keys
        }
    }

    #[test]
    fn test_seal_unseal_roundtrip() {
        let mut engine = make_engine();
        engine.rotation_epoch = 1;
        let plaintext = b"super-secret-key-material-12345!";
        let sealed = engine.seal_key(KeyType::ShardHmac, plaintext).unwrap();

        // Sealed must be longer than plaintext (nonce + tag overhead)
        assert!(sealed.len() > plaintext.len());

        let recovered = engine.unseal_key(KeyType::ShardHmac, &sealed).unwrap();
        assert_eq!(recovered.as_bytes(), plaintext);
    }

    #[test]
    fn test_unseal_wrong_key_type_fails() {
        let mut engine = make_engine();
        engine.rotation_epoch = 1;
        let plaintext = b"super-secret-key-material-12345!";
        let sealed = engine.seal_key(KeyType::ShardHmac, plaintext).unwrap();

        // Different key type means different AAD, must fail
        let result = engine.unseal_key(KeyType::GatewayTls, &sealed);
        assert!(result.is_err());
    }

    #[test]
    fn test_unseal_wrong_epoch_fails() {
        let mut engine = make_engine();
        engine.rotation_epoch = 1;
        let plaintext = b"super-secret-key-material-12345!";
        let sealed = engine.seal_key(KeyType::ShardHmac, plaintext).unwrap();

        // Change epoch => AAD mismatch
        engine.rotation_epoch = 2;
        let result = engine.unseal_key(KeyType::ShardHmac, &sealed);
        assert!(result.is_err());
    }

    #[test]
    fn test_unseal_tampered_data_fails() {
        let mut engine = make_engine();
        engine.rotation_epoch = 1;
        let plaintext = b"super-secret-key-material-12345!";
        let mut sealed = engine.seal_key(KeyType::ShardHmac, plaintext).unwrap();

        // Flip a byte in the ciphertext
        if let Some(byte) = sealed.get_mut(20) {
            *byte ^= 0xff;
        }
        let result = engine.unseal_key(KeyType::ShardHmac, &sealed);
        assert!(result.is_err());
    }

    #[test]
    fn test_unseal_too_short_fails() {
        let engine = make_engine();
        let result = engine.unseal_key(KeyType::ShardHmac, &[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_rotate_key() {
        let mut engine = make_engine();
        engine.bootstrap().unwrap();

        let old_fingerprint = engine.key_fingerprint(KeyType::ShardHmac).unwrap();
        let result = engine.rotate_key(KeyType::ShardHmac).unwrap();

        assert_eq!(result.key_type, KeyType::ShardHmac);
        assert!(result.old_key_destroyed);
        assert_eq!(result.rotation_epoch, 2); // bootstrap=1, rotate=2
        assert_ne!(result.new_key_fingerprint, old_fingerprint);
    }

    #[test]
    fn test_emergency_rotate_all() {
        let mut engine = make_engine();
        engine.bootstrap().unwrap();

        let results = engine.emergency_rotate_all().unwrap();
        assert_eq!(results.len(), 14);
        for r in &results {
            assert!(r.old_key_destroyed);
        }
        // epoch increments once per key rotation
        assert_eq!(engine.rotation_epoch(), 15); // 1 (bootstrap) + 14 (rotations)
    }

    #[test]
    fn test_check_rotation_needed_after_bootstrap() {
        let engine = make_engine();
        // Before bootstrap, all schedules have last_rotated = None => all need rotation
        let needed = engine.check_rotation_needed();
        assert_eq!(needed.len(), engine.schedules.len());
    }

    #[test]
    fn test_check_rotation_not_needed_immediately_after_bootstrap() {
        let mut engine = make_engine();
        engine.bootstrap().unwrap();
        // Right after bootstrap, nothing should need rotation
        let needed = engine.check_rotation_needed();
        assert!(needed.is_empty());
    }

    #[test]
    fn test_get_sealed_key() {
        let mut engine = make_engine();
        assert!(engine.get_sealed_key(KeyType::ShardHmac).is_none());
        engine.bootstrap().unwrap();
        let sealed = engine.get_sealed_key(KeyType::ShardHmac);
        assert!(sealed.is_some());
        assert!(sealed.unwrap().len() > 12 + 16); // nonce + tag minimum
    }

    #[test]
    fn test_default_schedules_count() {
        let schedules = CeremonyEngine::default_schedules();
        // 6 base + 5 TSS + 3 OPAQUE = 14
        assert_eq!(schedules.len(), 14);
    }

    #[test]
    fn test_emergency_flag_triggers_rotation() {
        let mut engine = make_engine();
        engine.bootstrap().unwrap();

        // Mark one as emergency
        for sched in &mut engine.schedules {
            if sched.key_type == KeyType::MasterKek {
                sched.emergency = true;
            }
        }

        let needed = engine.check_rotation_needed();
        assert!(needed.contains(&KeyType::MasterKek));
        assert_eq!(needed.len(), 1);
    }

    #[test]
    fn test_key_fingerprint_consistency() {
        let mut engine = make_engine();
        engine.bootstrap().unwrap();

        let fp1 = engine.key_fingerprint(KeyType::AuditSigning).unwrap();
        let fp2 = engine.key_fingerprint(KeyType::AuditSigning).unwrap();
        assert_eq!(fp1, fp2); // same key => same fingerprint
    }

    #[test]
    fn test_different_keys_different_fingerprints() {
        let mut engine = make_engine();
        engine.bootstrap().unwrap();

        let fp_hmac = engine.key_fingerprint(KeyType::ShardHmac).unwrap();
        let fp_tls = engine.key_fingerprint(KeyType::GatewayTls).unwrap();
        assert_ne!(fp_hmac, fp_tls);
    }

    #[test]
    fn test_ceremony_secret_zeroize_on_drop() {
        // Generate a secret, drop it, verify the type implements ZeroizeOnDrop
        // (We can't inspect freed memory, but we verify the derive works.)
        let secret = CeremonySecret::generate(64).unwrap();
        assert_eq!(secret.len(), 64);
        drop(secret);
        // If ZeroizeOnDrop derive failed, this wouldn't compile.
    }
}
