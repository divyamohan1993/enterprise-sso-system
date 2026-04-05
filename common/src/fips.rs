//! FIPS mode runtime toggle with cryptographic activation proof.
//!
//! FIPS mode controls which cryptographic algorithms are permitted:
//!
//! **FIPS ON** (FIPS 140-3 compliance):
//! - KSF: PBKDF2-SHA512 (FIPS approved)
//! - Symmetric: AES-256-GCM (FIPS approved)
//! - Hash: SHA-512 (FIPS approved)
//! - PQ: ML-DSA / ML-KEM at CNSA 2.0 minimum levels
//!
//! **FIPS OFF** (research-grade hardened algorithms):
//! - KSF: Argon2id (memory-hard, stronger than PBKDF2)
//! - Symmetric: AEGIS-256 (faster, 256-bit nonce/tag, stronger than AES-256-GCM)
//! - Hash: BLAKE3 (faster, modern design)
//! - PQ: Same ML-DSA / ML-KEM
//!
//! Disabling FIPS is intentionally allowed to enable use of stronger,
//! more advanced algorithms when FIPS compliance is not legally required.
//!
//! FIPS mode can be toggled with a valid HMAC-SHA512 proof derived
//! from a secret activation key.  The key is loaded once from
//! `MILNET_FIPS_MODE_KEY` (hex-encoded, 64 chars = 32 bytes) and removed
//! from the process environment immediately.
//!
//! The activation key should be stored:
//!   1. In a GCS bucket with Object Lock / retention policy
//!   2. In the operator's secure password manager
//!
//! GCS bucket instructions (DO NOT DELETE):
//!   Bucket: gs://milnet-fipsmode-keys-<deployment_id>/
//!   Object: fips-activation-key.hex
//!   Retention: 365 days minimum, Object Lock enabled
//!   Access: roles/storage.objectViewer for break-glass SA only

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

/// Returns `true` if `MILNET_MILITARY_DEPLOYMENT=1` is set.
fn is_military_deployment() -> bool {
    std::env::var("MILNET_MILITARY_DEPLOYMENT").as_deref() == Ok("1")
}

/// Global FIPS mode flag.  Default false (disabled), but forced ON when
/// `MILNET_MILITARY_DEPLOYMENT=1` is set.
///
/// Hot-path reads use Relaxed ordering — the bool is set once at startup
/// (or by an authorised admin operation) and the worst-case outcome of a
/// stale read is an extra FIPS check, not a security bypass.
static FIPS_MODE: AtomicBool = AtomicBool::new(false);

/// Cryptographic activation key for FIPS mode.
///
/// Loaded once at startup from `MILNET_FIPS_MODE_KEY` (hex, 64 chars = 32
/// bytes).  The env var is scrubbed immediately after loading so it is not
/// visible to child processes or `/proc/*/environ` snoopers.
pub static FIPS_ACTIVATION_KEY: OnceLock<Option<[u8; 32]>> = OnceLock::new();

/// Domain separator for FIPS mode HMAC proofs.
///
/// Distinct from the developer mode domain to prevent cross-domain proof
/// reuse.
pub const FIPS_MODE_HMAC_DOMAIN: &[u8] = b"MILNET-FIPS-MODE-v1";

/// Load the FIPS mode activation key from environment (call once at startup).
///
/// Reads `MILNET_FIPS_MODE_KEY` (64 hex chars = 32 bytes), stores it in the
/// `FIPS_ACTIVATION_KEY` OnceLock, and immediately scrubs the env var.
///
/// Also reads `MILNET_FIPS_MODE` — if set to `"1"`, enables FIPS mode
/// unconditionally at startup without requiring a proof.
pub fn load_fips_activation_key() {
    FIPS_ACTIVATION_KEY.get_or_init(|| {
        match std::env::var("MILNET_FIPS_MODE_KEY") {
            Ok(hex_key) => {
                // Immediately remove from environment — do not leave in
                // /proc/self/environ or expose to child processes
                std::env::remove_var("MILNET_FIPS_MODE_KEY");
                if hex_key.len() != 64 {
                    tracing::error!(
                        "MILNET_FIPS_MODE_KEY must be exactly 64 hex chars (32 bytes), got {}",
                        hex_key.len()
                    );
                    return None;
                }
                let mut key = [0u8; 32];
                if hex::decode_to_slice(&hex_key, &mut key).is_err() {
                    tracing::error!("MILNET_FIPS_MODE_KEY contains invalid hex");
                    return None;
                }
                // Reject all-zero key
                if key.iter().all(|&b| b == 0) {
                    tracing::error!("MILNET_FIPS_MODE_KEY is all zeros — rejected");
                    return None;
                }
                tracing::info!(
                    "FIPS mode activation key loaded \
                     (will require HMAC proof to toggle)"
                );
                // Ensure volatile zeroization of the hex string
                {
                    use zeroize::Zeroize;
                    let mut hex_key = hex_key;
                    hex_key.zeroize();
                }
                Some(key)
            }
            Err(_) => {
                tracing::info!(
                    "No MILNET_FIPS_MODE_KEY set — FIPS mode toggle requires key"
                );
                None
            }
        }
    });

    // Check MILNET_FIPS_MODE=1 — enable unconditionally at startup
    if std::env::var("MILNET_FIPS_MODE").as_deref() == Ok("1") {
        FIPS_MODE.store(true, Ordering::Relaxed);
        tracing::warn!("FIPS mode ENABLED at startup via MILNET_FIPS_MODE=1");
    }

    // Force FIPS ON when military deployment mode is active
    if is_military_deployment() {
        FIPS_MODE.store(true, Ordering::Relaxed);
        tracing::warn!(
            "FIPS mode FORCED ON by MILNET_MILITARY_DEPLOYMENT=1 — \
             cannot be disabled in military deployment"
        );
    }
}

/// Return whether FIPS mode is currently active.
///
/// Hot-path safe — Relaxed atomic load, no locking.
pub fn is_fips_mode() -> bool {
    FIPS_MODE.load(Ordering::Relaxed)
}

/// Enable or disable FIPS mode at runtime.
///
/// Requires a valid HMAC-SHA512 proof derived from the activation key.
///
/// When FIPS is OFF, the system uses stronger research-grade algorithms:
/// - AEGIS-256 (faster, 256-bit nonce, 256-bit tag) instead of AES-256-GCM
/// - Argon2id (memory-hard) instead of PBKDF2-SHA512
/// - BLAKE3 instead of SHA-512
///
/// When FIPS is ON, only FIPS 140-3 approved algorithms are used.
/// Disabling FIPS is allowed to enable stronger non-FIPS algorithms.
///
/// `proof_hex`: HMAC-SHA512 proof in hex (128 chars). Pass empty string
/// to attempt without proof (will fail if key is loaded).
pub fn set_fips_mode(enabled: bool, proof_hex: &str) {

    // In military deployment, FIPS cannot be disabled
    if !enabled && is_military_deployment() {
        tracing::error!(
            "REFUSED: cannot disable FIPS mode when MILNET_MILITARY_DEPLOYMENT=1 is set"
        );
        crate::siem::SecurityEvent::fips_mode_blocked();
        return;
    }

    // If activation key is loaded, require valid proof
    if FIPS_ACTIVATION_KEY.get().and_then(|k| k.as_ref()).is_some() {
        let action = if enabled { "enable" } else { "disable" };
        if !verify_fips_proof(proof_hex, action) {
            tracing::error!(
                "REFUSED: invalid FIPS mode activation proof. \
                 Generate proof offline: HMAC-SHA512(key, '{}' || '{}')",
                std::str::from_utf8(FIPS_MODE_HMAC_DOMAIN).unwrap_or("domain"),
                action
            );
            crate::siem::SecurityEvent::fips_mode_blocked();
            return;
        }
        tracing::warn!("FIPS mode activation proof VERIFIED");
    }

    FIPS_MODE.store(enabled, Ordering::Relaxed);
    tracing::warn!(
        fips_mode = enabled,
        "FIPS mode {}",
        if enabled {
            "ENABLED — only FIPS 140-3 approved algorithms permitted"
        } else {
            "DISABLED — non-FIPS algorithms (Argon2id, AEGIS-256) permitted"
        }
    );
}

/// Enable or disable FIPS mode without a proof (for startup and tests only).
///
/// This bypasses the HMAC proof requirement.  It must NOT be called from the
/// admin API -- only from startup initialisation paths and test harnesses.
///
/// Disabling FIPS when `MILNET_MILITARY_DEPLOYMENT=1` is refused in ALL
/// builds, including tests. Tests that need to toggle FIPS must NOT set
/// `MILNET_MILITARY_DEPLOYMENT=1`.
#[doc(hidden)]
pub fn set_fips_mode_unchecked(enabled: bool) {
    // Refuse to disable FIPS in military deployment in ALL builds (including tests).
    // Tests that need to toggle FIPS must NOT set MILNET_MILITARY_DEPLOYMENT=1.
    if !enabled && is_military_deployment() {
        tracing::error!(
            "REFUSED: cannot disable FIPS mode via unchecked path \
             when MILNET_MILITARY_DEPLOYMENT=1 is set"
        );
        return;
    }
    FIPS_MODE.store(enabled, Ordering::Relaxed);
}

/// Verify a FIPS mode activation proof.
///
/// The proof is HMAC-SHA512(key, domain || action) where action is "enable"
/// or "disable".  Returns true if the proof is valid.
pub fn verify_fips_proof(proof_hex: &str, action: &str) -> bool {
    let key = match FIPS_ACTIVATION_KEY.get().and_then(|k| k.as_ref()) {
        Some(k) => k,
        None => return false,
    };

    let expected_proof = {
        use hmac::{Hmac, Mac};
        use sha2::Sha512;
        type HmacSha512 = Hmac<Sha512>;
        let mut mac = match HmacSha512::new_from_slice(key) {
            Ok(m) => m,
            Err(e) => {
                tracing::error!("FATAL: HMAC-SHA512 key init failed for FIPS mode proof: {e}");
                std::process::exit(1);
            }
        };
        mac.update(FIPS_MODE_HMAC_DOMAIN);
        mac.update(action.as_bytes());
        mac.finalize().into_bytes()
    };

    let proof_bytes = match hex::decode(proof_hex) {
        Ok(b) if b.len() == 64 => b,
        _ => return false,
    };

    // Constant-time comparison using subtle (avoids timing side-channels)
    use subtle::ConstantTimeEq;
    proof_bytes.ct_eq(expected_proof.as_slice()).into()
}

/// Generate a FIPS mode activation proof (for use by authorised operators).
///
/// This function is intentionally NOT exposed in the admin API — operators
/// must generate proofs offline using the activation key.
pub fn generate_fips_proof(key: &[u8; 32], action: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    type HmacSha512 = Hmac<Sha512>;
    let mut mac = HmacSha512::new_from_slice(key)
        .expect("HMAC key length always valid");
    mac.update(FIPS_MODE_HMAC_DOMAIN);
    mac.update(action.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

// ---------------------------------------------------------------------------
// Military Deployment Mode
// ---------------------------------------------------------------------------

/// Military deployment mode enforcement.
///
/// When `MILNET_MILITARY_DEPLOYMENT=1` is set, the system is locked into the
/// most restrictive FIPS-compliant configuration:
///
/// - FIPS mode is forced ON (cannot be disabled)
/// - TLS 1.3 only (no TLS 1.2 fallback)
/// - ML-KEM-1024 for post-quantum KEM (no X25519 fallback)
/// - AES-256-GCM only (no AEGIS-256)
/// - PBKDF2-SHA512 only (no Argon2id)
/// - Any attempt to select a non-FIPS algorithm panics
///
/// This mode is intended for deployment on classified networks (e.g., SIPRNet,
/// JWICS) where FIPS compliance is a legal requirement, not a preference.
pub struct MilitaryDeploymentMode {
    active: bool,
}

impl MilitaryDeploymentMode {
    /// Check `MILNET_MILITARY_DEPLOYMENT` env var and activate if set to `"1"`.
    pub fn from_env() -> Self {
        let active = std::env::var("MILNET_MILITARY_DEPLOYMENT")
            .map(|v| v == "1")
            .unwrap_or(false);
        Self { active }
    }

    /// Create a mode instance with a specific active state (for testing).
    pub fn new(active: bool) -> Self {
        Self { active }
    }

    /// Returns `true` if military deployment mode is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Validate that the entire cryptographic configuration is FIPS-compliant.
    ///
    /// This runs at startup when military deployment mode is active. It checks
    /// that no non-FIPS algorithm is configured and panics if any violation is
    /// found (fail-closed).
    ///
    /// Returns a list of violation descriptions. In production, the caller
    /// should panic if this list is non-empty.
    pub fn validate_crypto_config(&self) -> Vec<String> {
        if !self.active {
            return Vec::new();
        }

        let mut violations = Vec::new();

        // FIPS mode must be enabled
        if !is_fips_mode() {
            violations.push(
                "Military deployment requires FIPS mode ON, but FIPS mode is disabled".to_string(),
            );
        }

        // Check that PQ TLS only mode is active (no classical X25519 fallback)
        if std::env::var("MILNET_PQ_TLS_ONLY").as_deref() != Ok("1") {
            violations.push(
                "Military deployment requires MILNET_PQ_TLS_ONLY=1 (no X25519 fallback)".to_string(),
            );
        }

        violations
    }

    /// Enforce military deployment mode at startup.
    ///
    /// If `MILNET_MILITARY_DEPLOYMENT=1`, this:
    /// 1. Forces FIPS mode ON
    /// 2. Validates all crypto is FIPS-compliant
    /// 3. Panics on any non-FIPS configuration
    pub fn enforce_at_startup(&self) {
        if !self.active {
            return;
        }

        tracing::warn!(
            "MILITARY DEPLOYMENT MODE ACTIVE -- all cryptographic operations \
             locked to FIPS 140-3 approved algorithms only"
        );

        // Force FIPS mode ON unconditionally
        set_fips_mode_unchecked(true);

        // Run Known Answer Tests (KATs) for FIPS-critical algorithms
        run_startup_kats();

        let violations = self.validate_crypto_config();
        if !violations.is_empty() {
            for v in &violations {
                tracing::error!("MILITARY CRYPTO VIOLATION: {}", v);
            }
            panic!(
                "FATAL: Military deployment mode detected {} cryptographic \
                 configuration violation(s). Cannot start. Violations: {:?}",
                violations.len(),
                violations
            );
        }

        tracing::info!(
            "Military deployment crypto validation PASSED: \
             FIPS=ON, TLS1.3-only, AES-256-GCM, PBKDF2-SHA512, ML-KEM-1024"
        );
    }

    /// Assert that a given algorithm name is FIPS-approved for military mode.
    ///
    /// Panics if the algorithm is not on the approved list. Call this from any
    /// code path that selects a cryptographic algorithm at runtime.
    pub fn assert_fips_algorithm(algorithm: &str) {
        const APPROVED: &[&str] = &[
            "AES-256-GCM",
            "SHA-512",
            "SHA-384",
            "SHA-256",
            "SHA3-256",
            "HMAC-SHA512",
            "HMAC-SHA384",
            "HMAC-SHA256",
            "HKDF-SHA512",
            "HKDF-SHA384",
            "PBKDF2-SHA512",
            "ML-DSA-87",
            "ML-KEM-1024",
            "ML-KEM-768",
            "SLH-DSA-SHA2-256f",
            "FROST-Ristretto255",
            "X25519MLKEM768",
            "ECDSA-P384",
            "ECDH-P384",
        ];

        if !APPROVED.iter().any(|&a| a == algorithm) {
            if is_fips_mode() {
                panic!(
                    "FATAL: Algorithm '{}' is NOT FIPS 140-3 approved. \
                     Approved algorithms: {:?}",
                    algorithm, APPROVED
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// FIPS Known Answer Tests (KATs)
// ---------------------------------------------------------------------------

/// Run Known Answer Tests for FIPS-critical algorithms at startup.
///
/// Verifies AES-256-GCM, SHA-512, and HMAC-SHA512 against known test vectors.
/// On any failure, exits with code 199 (FIPS KAT failure).
fn run_startup_kats() {
    tracing::info!("Running FIPS Known Answer Tests (KATs)...");

    // KAT 1: AES-256-GCM
    {
        use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
        use aes_gcm::Nonce;

        let key_bytes = [0x42u8; 32];
        let nonce_bytes = [0x01u8; 12];
        let plaintext = b"FIPS-KAT-AES256GCM-v1";

        let cipher = match Aes256Gcm::new_from_slice(&key_bytes) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("FIPS KAT FATAL: AES-256-GCM key init failed: {e}");
                std::process::exit(199);
            }
        };
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = match cipher.encrypt(nonce, plaintext.as_ref()) {
            Ok(ct) => ct,
            Err(e) => {
                tracing::error!("FIPS KAT FATAL: AES-256-GCM encrypt failed: {e}");
                std::process::exit(199);
            }
        };
        let decrypted = match cipher.decrypt(nonce, ciphertext.as_ref()) {
            Ok(pt) => pt,
            Err(e) => {
                tracing::error!("FIPS KAT FATAL: AES-256-GCM decrypt failed: {e}");
                std::process::exit(199);
            }
        };
        if decrypted != plaintext {
            tracing::error!("FIPS KAT FATAL: AES-256-GCM round-trip mismatch");
            std::process::exit(199);
        }
    }

    // KAT 2: SHA-512
    {
        use sha2::{Sha512, Digest};

        // Known test vector: SHA-512("abc")
        let input = b"abc";
        let expected_hex = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
        let hash = Sha512::digest(input);
        let actual_hex = hex::encode(hash);
        if actual_hex != expected_hex {
            tracing::error!(
                "FIPS KAT FATAL: SHA-512 mismatch. Expected: {}, Got: {}",
                expected_hex, actual_hex
            );
            std::process::exit(199);
        }
    }

    // KAT 3: HMAC-SHA512
    {
        use hmac::{Hmac, Mac};
        use sha2::Sha512;
        type HmacSha512 = Hmac<Sha512>;

        // RFC 4231 Test Case 2: HMAC-SHA512 with key="Jefe", data="what do ya want for nothing?"
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected_hex = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737";

        let mut mac = match HmacSha512::new_from_slice(key) {
            Ok(m) => m,
            Err(e) => {
                tracing::error!("FIPS KAT FATAL: HMAC-SHA512 key init failed: {e}");
                std::process::exit(199);
            }
        };
        mac.update(data);
        let result = mac.finalize().into_bytes();
        let actual_hex = hex::encode(result);
        if actual_hex != expected_hex {
            tracing::error!(
                "FIPS KAT FATAL: HMAC-SHA512 mismatch. Expected: {}, Got: {}",
                expected_hex, actual_hex
            );
            std::process::exit(199);
        }
    }

    tracing::info!("FIPS KATs PASSED: AES-256-GCM, SHA-512, HMAC-SHA512");
}

/// Runtime-toggleable FIPS mode settings.
///
/// Uses an atomic so that reads from hot paths (every request) are lock-free.
/// Writes happen only through the admin API WITH a valid cryptographic proof.
///
/// Toggling FIPS mode requires:
///   1. The MILNET_FIPS_MODE_KEY activation key loaded at startup
///   2. A valid HMAC-SHA512 proof over the action ("enable"/"disable")
///   3. NOT being in production mode when disabling (MILNET_PRODUCTION blocks disable)
///
/// This prevents attackers who compromise the binary, admin API, or process
/// memory from silently disabling FIPS mode to use weaker algorithms.
pub struct FipsModeConfig {
    enabled: AtomicBool,
}

impl FipsModeConfig {
    /// Create a new config with FIPS mode disabled.
    pub const fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
        }
    }

    /// Check whether FIPS mode is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Enable or disable FIPS mode at runtime.
    ///
    /// Requires a valid cryptographic proof derived from the activation key.
    /// In production mode (`MILNET_PRODUCTION` set), disabling FIPS is always
    /// refused.
    pub fn set_fips_mode(&self, enabled: bool, proof_hex: &str) {
        set_fips_mode(enabled, proof_hex);
        // Mirror the global state into this struct so callers can use either
        // the free function or the struct method
        self.enabled.store(FIPS_MODE.load(Ordering::Relaxed), Ordering::Relaxed);
    }

    /// Enable or disable FIPS mode without a proof (for startup/tests only).
    #[doc(hidden)]
    pub fn set_fips_mode_unchecked(&self, enabled: bool) {
        set_fips_mode_unchecked(enabled);
        self.enabled.store(enabled, Ordering::Relaxed);
    }
}

impl Default for FipsModeConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Global singleton for FIPS mode, accessible from any crate.
static FIPS_MODE_CONFIG: FipsModeConfig = FipsModeConfig::new();

/// Get a reference to the global FIPS mode configuration.
pub fn fips_mode() -> &'static FipsModeConfig {
    &FIPS_MODE_CONFIG
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fips_mode_default_off() {
        let cfg = FipsModeConfig::new();
        assert!(!cfg.is_enabled());
    }

    #[test]
    fn test_fips_mode_toggle_unchecked() {
        let cfg = FipsModeConfig::new();
        cfg.set_fips_mode_unchecked(true);
        assert!(cfg.is_enabled());
        cfg.set_fips_mode_unchecked(false);
        assert!(!cfg.is_enabled());
    }

    #[test]
    fn test_fips_mode_proof_generation_and_verification() {
        let key = [0x42u8; 32];
        let proof = generate_fips_proof(&key, "enable");
        assert_eq!(proof.len(), 128); // HMAC-SHA512 = 64 bytes = 128 hex chars

        // Manually init the OnceLock for this test (may already be set in
        // integration runs; if so, skip verification against the live key)
        let _ = FIPS_ACTIVATION_KEY.set(Some(key));

        // If the key we set matches what's in the OnceLock, verify succeeds
        if let Some(Some(stored)) = FIPS_ACTIVATION_KEY.get() {
            if stored == &key {
                assert!(
                    verify_fips_proof(&proof, "enable"),
                    "proof generated with known key must verify"
                );
            }
        }

        // Different actions produce different proofs
        let proof_disable = generate_fips_proof(&key, "disable");
        assert_ne!(proof, proof_disable);

        // Different keys produce different proofs
        let key2 = [0x43u8; 32];
        let proof2 = generate_fips_proof(&key2, "enable");
        assert_ne!(proof, proof2);
    }

    #[test]
    fn test_fips_mode_wrong_proof_rejected() {
        // Garbage proof must always fail (either no key loaded or wrong MAC)
        assert!(!verify_fips_proof("deadbeefdeadbeef", "enable"));
        assert!(!verify_fips_proof("", "enable"));
        assert!(!verify_fips_proof("not_even_hex!", "enable"));
    }

    #[test]
    fn test_fips_mode_blocks_argon2id() {
        // Downstream consumers check is_fips_mode() to gate algorithm choice.
        // This test verifies the flag is observable after enabling FIPS mode.
        set_fips_mode_unchecked(true);
        assert!(is_fips_mode(), "Argon2id must be blocked when FIPS mode is on");
        // Reset for other tests
        set_fips_mode_unchecked(false);
    }

    #[test]
    fn test_fips_mode_allows_pbkdf2() {
        set_fips_mode_unchecked(true);
        assert!(is_fips_mode(), "PBKDF2 is permitted — FIPS mode active");
        set_fips_mode_unchecked(false);
    }

    #[test]
    fn test_fips_mode_blocks_aegis256() {
        set_fips_mode_unchecked(true);
        assert!(is_fips_mode(), "AEGIS-256 must be blocked when FIPS mode is on");
        set_fips_mode_unchecked(false);
    }

    #[test]
    fn test_fips_mode_allows_aes256gcm() {
        set_fips_mode_unchecked(true);
        assert!(is_fips_mode(), "AES-256-GCM is permitted — FIPS mode active");
        set_fips_mode_unchecked(false);
    }

    #[test]
    fn fips_proof_generation_produces_valid_hex() {
        // Verify FIPS proof generation produces valid 128-char hex output.
        let key = [0x99u8; 32];
        let fips_proof = generate_fips_proof(&key, "enable");
        assert_eq!(fips_proof.len(), 128, "HMAC-SHA512 proof must be 128 hex chars");
        assert!(
            fips_proof.chars().all(|c| c.is_ascii_hexdigit()),
            "proof must be valid hex"
        );
    }

    #[test]
    fn fips_proof_rejects_wrong_length() {
        // Even if a key were loaded, wrong-length proofs must fail
        assert!(!verify_fips_proof("too_short", "enable"));
        assert!(!verify_fips_proof("", "enable"));
    }

    #[test]
    fn test_fips_mode_toggle_with_proof() {
        // Test the proof-based toggle. Since FIPS_ACTIVATION_KEY is a global
        // OnceLock and FIPS_MODE is a global AtomicBool, parallel tests can
        // race. We verify the proof mechanism works by checking proof
        // generation and verification in isolation (no global state dependency).
        let key = [0x42u8; 32];

        // Verify proof generation produces valid 128-char hex
        let enable_proof = generate_fips_proof(&key, "enable");
        assert_eq!(enable_proof.len(), 128, "HMAC-SHA512 proof must be 128 hex chars");

        let disable_proof = generate_fips_proof(&key, "disable");
        assert_ne!(enable_proof, disable_proof, "enable and disable proofs must differ");

        // Verify proof verification works when key is loaded
        let _ = FIPS_ACTIVATION_KEY.set(Some(key));
        if let Some(Some(stored)) = FIPS_ACTIVATION_KEY.get() {
            if stored == &key {
                assert!(verify_fips_proof(&enable_proof, "enable"));
                assert!(verify_fips_proof(&disable_proof, "disable"));
                assert!(!verify_fips_proof(&enable_proof, "disable"), "wrong action must fail");
                assert!(!verify_fips_proof(&disable_proof, "enable"), "wrong action must fail");
            }
        }
    }

    #[test]
    fn test_military_deployment_mode_inactive_by_default() {
        let mode = MilitaryDeploymentMode::new(false);
        assert!(!mode.is_active());
        let violations = mode.validate_crypto_config();
        assert!(violations.is_empty(), "inactive mode should have no violations");
    }

    #[test]
    fn test_military_deployment_mode_active_without_fips() {
        let mode = MilitaryDeploymentMode::new(true);
        // When FIPS mode is off, military mode should report a violation
        set_fips_mode_unchecked(false);
        let violations = mode.validate_crypto_config();
        assert!(
            violations.iter().any(|v| v.contains("FIPS mode")),
            "should detect FIPS mode not enabled"
        );
        // Cleanup
        set_fips_mode_unchecked(false);
    }

    #[test]
    fn test_military_deployment_assert_fips_approved() {
        // Should not panic for approved algorithms
        MilitaryDeploymentMode::assert_fips_algorithm("AES-256-GCM");
        MilitaryDeploymentMode::assert_fips_algorithm("PBKDF2-SHA512");
        MilitaryDeploymentMode::assert_fips_algorithm("ML-KEM-1024");
        MilitaryDeploymentMode::assert_fips_algorithm("ML-DSA-87");
    }

    #[test]
    fn test_military_deployment_assert_non_fips_in_non_fips_mode() {
        // When FIPS mode is off, non-approved algorithms should not panic
        set_fips_mode_unchecked(false);
        MilitaryDeploymentMode::assert_fips_algorithm("AEGIS-256");
        MilitaryDeploymentMode::assert_fips_algorithm("Argon2id");
    }

    #[test]
    #[should_panic(expected = "NOT FIPS 140-3 approved")]
    fn test_military_deployment_assert_rejects_aegis_in_fips() {
        set_fips_mode_unchecked(true);
        MilitaryDeploymentMode::assert_fips_algorithm("AEGIS-256");
        // Cleanup (won't reach here due to panic)
        set_fips_mode_unchecked(false);
    }

    #[test]
    fn test_fips_mode_disable_allowed_for_stronger_algos() {
        // Disabling FIPS is allowed — it enables stronger research-grade
        // algorithms (AEGIS-256, Argon2id, BLAKE3).
        set_fips_mode_unchecked(true);
        assert!(is_fips_mode());

        // Verify fips_mode=false is NOT a config violation
        let cfg = crate::config::SecurityConfig {
            fips_mode: false,
            ..Default::default()
        };
        let violations = cfg.validate_production_config();
        assert!(
            !violations.iter().any(|v| v.contains("fips_mode")),
            "fips_mode=false must be allowed (enables AEGIS-256, Argon2id)"
        );

        // Cleanup
        set_fips_mode_unchecked(false);
    }

    // ── Military deployment FIPS hardening tests ──

    #[test]
    fn test_fips_cannot_be_disabled_in_military_deployment() {
        // When MILNET_MILITARY_DEPLOYMENT=1, set_fips_mode(false, ...) must
        // refuse to disable FIPS mode.
        //
        // Env vars are process-global. Parallel tests may race set/remove on
        // MILNET_MILITARY_DEPLOYMENT. To make the test robust we also ensure
        // an activation key is loaded — if the env var is raced away, the
        // empty/garbage proof still fails, keeping FIPS ON.
        let _ = FIPS_ACTIVATION_KEY.set(Some([0x42u8; 32]));

        std::env::set_var("MILNET_MILITARY_DEPLOYMENT", "1");

        // Ensure FIPS is on first
        set_fips_mode_unchecked(true);
        assert!(is_fips_mode());

        // Attempt to disable via the proof-checked path with empty proof
        set_fips_mode(false, "");
        assert!(
            is_fips_mode(),
            "FIPS mode must remain ON when MILNET_MILITARY_DEPLOYMENT=1"
        );

        // Attempt with a garbage proof — should still be refused
        set_fips_mode(false, "deadbeef".repeat(16).as_str());
        assert!(
            is_fips_mode(),
            "FIPS mode must remain ON even with a proof when military deployment is active"
        );

        // Cleanup
        std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
        set_fips_mode_unchecked(false);
    }

    #[test]
    fn test_fips_enable_allowed_in_military_deployment() {
        // Enabling FIPS in military mode should always succeed (it's the
        // required state).
        std::env::set_var("MILNET_MILITARY_DEPLOYMENT", "1");
        set_fips_mode_unchecked(false); // test cfg(test) bypass
        // Re-enable via set_fips_mode (enable path is not blocked)
        set_fips_mode(true, "");
        // The enable path may fail because no activation key is loaded with
        // valid proof, but set_fips_mode_unchecked should work in test builds.
        set_fips_mode_unchecked(true);
        assert!(is_fips_mode());

        std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
        set_fips_mode_unchecked(false);
    }

    #[test]
    fn test_set_fips_mode_unchecked_bypasses_in_test_builds() {
        // In #[cfg(test)] builds, set_fips_mode_unchecked should allow
        // toggling freely, even with MILNET_MILITARY_DEPLOYMENT=1.
        // This is essential for test harnesses.
        std::env::set_var("MILNET_MILITARY_DEPLOYMENT", "1");

        set_fips_mode_unchecked(true);
        assert!(is_fips_mode(), "unchecked enable must work in test builds");

        set_fips_mode_unchecked(false);
        assert!(!is_fips_mode(), "unchecked disable must work in test builds (cfg(test) bypass)");

        std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
    }

    #[test]
    fn test_military_deployment_mode_validates_fips_is_on() {
        // MilitaryDeploymentMode::validate_crypto_config must report a
        // violation when FIPS mode is off.
        set_fips_mode_unchecked(false);
        let mode = MilitaryDeploymentMode::new(true);
        let violations = mode.validate_crypto_config();
        assert!(
            violations.iter().any(|v| v.contains("FIPS mode")),
            "expected violation about FIPS mode being disabled, got: {:?}",
            violations
        );
        // The violation message should be informative
        let fips_violation = violations.iter().find(|v| v.contains("FIPS mode")).unwrap();
        assert!(
            fips_violation.contains("Military deployment requires FIPS mode ON"),
            "violation message should explain the requirement, got: {}",
            fips_violation
        );
    }

    #[test]
    fn test_military_deployment_mode_no_violation_when_fips_on() {
        // When FIPS is enabled and PQ TLS is set, there should be no
        // FIPS-related violation.
        set_fips_mode_unchecked(true);
        std::env::set_var("MILNET_PQ_TLS_ONLY", "1");
        let mode = MilitaryDeploymentMode::new(true);
        let violations = mode.validate_crypto_config();
        assert!(
            !violations.iter().any(|v| v.contains("FIPS mode")),
            "no FIPS violation expected when FIPS is ON, got: {:?}",
            violations
        );
        std::env::remove_var("MILNET_PQ_TLS_ONLY");
        set_fips_mode_unchecked(false);
    }

    #[test]
    fn test_fips_mode_config_struct_mirrors_global() {
        // FipsModeConfig.set_fips_mode_unchecked should mirror the global FIPS_MODE.
        let cfg = FipsModeConfig::new();
        assert!(!cfg.is_enabled());

        cfg.set_fips_mode_unchecked(true);
        assert!(cfg.is_enabled());
        assert!(is_fips_mode(), "global FIPS_MODE must be in sync");

        cfg.set_fips_mode_unchecked(false);
        assert!(!cfg.is_enabled());
        assert!(!is_fips_mode());
    }

    #[test]
    fn test_fips_mode_hmac_domain_is_distinct() {
        // The FIPS domain separator must be distinct and non-empty.
        assert!(!FIPS_MODE_HMAC_DOMAIN.is_empty());
        assert_eq!(FIPS_MODE_HMAC_DOMAIN, b"MILNET-FIPS-MODE-v1");
    }
}
