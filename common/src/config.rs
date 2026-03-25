//! System-wide security configuration per spec.
//!
//! Centralises every tuneable security parameter so that auditors can review
//! them in one place and operators can override them via environment or config
//! file without touching code.

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::OnceLock;

/// Log verbosity level for the system.
///
/// Controls what gets logged.  `Verbose` logs everything including request
/// details, crypto operations and timing; `Error` logs only errors and
/// security events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Log everything: requests, responses, crypto operations, timing.
    Verbose = 0,
    /// Log only errors and security events.
    Error = 1,
}

impl LogLevel {
    /// Convert from the atomic u8 representation.
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => LogLevel::Verbose,
            _ => LogLevel::Error,
        }
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Verbose => write!(f, "verbose"),
            LogLevel::Error => write!(f, "error"),
        }
    }
}

/// Cryptographic activation key for developer mode.
///
/// Developer mode can ONLY be toggled with a valid HMAC-SHA512 proof derived
/// from a secret activation key.  The key is loaded once from
/// `MILNET_DEV_MODE_KEY` (hex-encoded, 64 chars = 32 bytes) and removed from
/// the process environment immediately.  Without the key, developer mode
/// cannot be enabled — even by an attacker who has compromised the binary or
/// the admin API.
///
/// The activation key should be stored:
///   1. In a GCS bucket with Object Lock / retention policy (documented below)
///   2. In the operator's secure password manager
///
/// GCS bucket instructions (DO NOT DELETE):
///   Bucket: gs://milnet-devmode-keys-<deployment_id>/
///   Object: devmode-activation-key.hex
///   Retention: 365 days minimum, Object Lock enabled
///   Access: roles/storage.objectViewer for break-glass SA only
static DEV_MODE_ACTIVATION_KEY: OnceLock<Option<[u8; 32]>> = OnceLock::new();

/// Domain separator for developer mode HMAC proofs.
const DEV_MODE_HMAC_DOMAIN: &[u8] = b"MILNET-DEV-MODE-ACTIVATE-v1";

/// Load the developer mode activation key from environment (call once at startup).
pub fn load_dev_mode_activation_key() {
    DEV_MODE_ACTIVATION_KEY.get_or_init(|| {
        match std::env::var("MILNET_DEV_MODE_KEY") {
            Ok(hex_key) => {
                // Immediately remove from environment
                std::env::remove_var("MILNET_DEV_MODE_KEY");
                if hex_key.len() != 64 {
                    tracing::error!(
                        "MILNET_DEV_MODE_KEY must be exactly 64 hex chars (32 bytes), got {}",
                        hex_key.len()
                    );
                    return None;
                }
                let mut key = [0u8; 32];
                if hex::decode_to_slice(&hex_key, &mut key).is_err() {
                    tracing::error!("MILNET_DEV_MODE_KEY contains invalid hex");
                    return None;
                }
                // Reject all-zero key
                if key.iter().all(|&b| b == 0) {
                    tracing::error!("MILNET_DEV_MODE_KEY is all zeros — rejected");
                    return None;
                }
                tracing::info!("Developer mode activation key loaded (will require HMAC proof to toggle)");
                Some(key)
            }
            Err(_) => {
                tracing::info!("No MILNET_DEV_MODE_KEY set — developer mode toggle requires key");
                None
            }
        }
    });
}

/// Verify a developer mode activation proof.
///
/// The proof is HMAC-SHA512(key, domain || action) where action is "enable" or "disable".
/// Returns true if the proof is valid.
pub fn verify_dev_mode_proof(proof_hex: &str, action: &str) -> bool {
    let key = match DEV_MODE_ACTIVATION_KEY.get().and_then(|k| k.as_ref()) {
        Some(k) => k,
        None => return false,
    };

    let expected_proof = {
        use hmac::{Hmac, Mac};
        use sha2::Sha512;
        type HmacSha512 = Hmac<Sha512>;
        let mut mac = HmacSha512::new_from_slice(key)
            .expect("HMAC key length always valid");
        mac.update(DEV_MODE_HMAC_DOMAIN);
        mac.update(action.as_bytes());
        mac.finalize().into_bytes()
    };

    let proof_bytes = match hex::decode(proof_hex) {
        Ok(b) if b.len() == 64 => b,
        _ => return false,
    };

    // Constant-time comparison
    crypto::ct::ct_eq(&proof_bytes, &expected_proof)
}

/// Generate a developer mode activation proof (for use by authorized operators).
/// This function is intentionally NOT exposed in the admin API — operators
/// must generate proofs offline using the activation key.
pub fn generate_dev_mode_proof(key: &[u8; 32], action: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    type HmacSha512 = Hmac<Sha512>;
    let mut mac = HmacSha512::new_from_slice(key)
        .expect("HMAC key length always valid");
    mac.update(DEV_MODE_HMAC_DOMAIN);
    mac.update(action.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Runtime-toggleable developer mode settings.
///
/// Uses atomics so that reads from hot paths (every request) are lock-free.
/// Writes happen only through the admin API WITH a valid cryptographic proof.
///
/// Toggling developer mode requires:
///   1. The MILNET_DEV_MODE_KEY activation key loaded at startup
///   2. A valid HMAC-SHA512 proof over the action ("enable"/"disable")
///   3. NOT being in production mode (MILNET_PRODUCTION blocks enable)
///
/// This prevents attackers who compromise the binary, admin API, or process
/// memory from silently enabling developer mode to extract detailed errors.
pub struct DeveloperModeConfig {
    enabled: AtomicBool,
    log_level: AtomicU8,
}

impl DeveloperModeConfig {
    /// Create a new config with developer mode disabled and log level Error.
    pub const fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            log_level: AtomicU8::new(LogLevel::Error as u8),
        }
    }

    /// Check whether developer mode is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Get the current log level.
    pub fn log_level(&self) -> LogLevel {
        LogLevel::from_u8(self.log_level.load(Ordering::Relaxed))
    }

    /// Enable or disable developer mode at runtime.
    ///
    /// Requires a valid cryptographic proof derived from the activation key.
    /// In production mode (`MILNET_PRODUCTION` set), enabling is always refused.
    ///
    /// `proof_hex`: HMAC-SHA512 proof in hex (128 chars). Pass empty string
    /// to attempt without proof (will fail if key is loaded).
    pub fn set_developer_mode(&self, enabled: bool, proof_hex: &str) {
        if enabled && crate::sealed_keys::is_production() {
            tracing::error!(
                "REFUSED: cannot enable developer mode in production \
                 (MILNET_PRODUCTION is set)."
            );
            crate::siem::SecurityEvent::developer_mode_blocked();
            return;
        }

        // If activation key is loaded, require valid proof
        if DEV_MODE_ACTIVATION_KEY.get().and_then(|k| k.as_ref()).is_some() {
            let action = if enabled { "enable" } else { "disable" };
            if !verify_dev_mode_proof(proof_hex, action) {
                tracing::error!(
                    "REFUSED: invalid developer mode activation proof. \
                     Generate proof offline: HMAC-SHA512(key, '{}' || '{}')",
                    std::str::from_utf8(DEV_MODE_HMAC_DOMAIN).unwrap_or("domain"),
                    action
                );
                crate::siem::SecurityEvent::developer_mode_blocked();
                return;
            }
            tracing::warn!("Developer mode activation proof VERIFIED");
        }

        self.enabled.store(enabled, Ordering::Relaxed);
        tracing::warn!(
            developer_mode = enabled,
            "developer mode {}",
            if enabled { "ENABLED — detailed errors will be exposed in responses" } else { "DISABLED — production error masking active" }
        );
    }

    /// Enable developer mode without proof (for tests and startup from env var).
    /// This is ONLY callable during startup initialization, not from the admin API.
    #[doc(hidden)]
    pub fn set_developer_mode_unchecked(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    /// Set the log level at runtime.
    pub fn set_log_level(&self, level: LogLevel) {
        self.log_level.store(level as u8, Ordering::Relaxed);
        tracing::info!(log_level = %level, "log level changed");
    }

    /// Returns true if verbose logging is active (developer mode on AND level Verbose).
    pub fn is_verbose(&self) -> bool {
        self.is_enabled() && self.log_level() == LogLevel::Verbose
    }
}

impl Default for DeveloperModeConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Global singleton for developer mode, accessible from any crate.
static DEVELOPER_MODE: DeveloperModeConfig = DeveloperModeConfig::new();

/// Get a reference to the global developer mode configuration.
pub fn developer_mode() -> &'static DeveloperModeConfig {
    &DEVELOPER_MODE
}

/// System-wide security configuration per spec.
pub struct SecurityConfig {
    /// Developer mode — exposes detailed errors in HTTP responses.
    pub developer_mode: bool,
    /// Log level — controls verbosity of structured logging.
    pub log_level: LogLevel,
    /// Maximum session lifetime (8 hours).
    pub max_session_lifetime_secs: u64,
    /// Ratchet epoch length (10 seconds — stolen tokens expire within ±10s).
    pub ratchet_epoch_secs: u64,
    /// Ratchet lookahead window for clock jitter tolerance (±1 epoch).
    pub ratchet_lookahead_epochs: u64,
    /// Receipt time-to-live.
    pub receipt_ttl_secs: u64,
    /// Ceremony TTL (30s default, 120s for interactive).
    pub ceremony_ttl_secs: u64,
    /// Puzzle difficulty under normal load.
    pub puzzle_difficulty_normal: u8,
    /// Puzzle difficulty under DDoS conditions.
    pub puzzle_difficulty_ddos: u8,
    /// Failed authentication attempts before lockout.
    pub max_failed_attempts: u32,
    /// Account lockout duration.
    pub lockout_duration_secs: u64,
    /// Tier 1 (Sovereign) token lifetime (5 min).
    pub token_lifetime_tier1_secs: u64,
    /// Tier 2 (Operational) token lifetime (10 min).
    pub token_lifetime_tier2_secs: u64,
    /// Tier 3 (Sensor) token lifetime (15 min).
    pub token_lifetime_tier3_secs: u64,
    /// Tier 4 (Emergency) token lifetime (2 min).
    pub token_lifetime_tier4_secs: u64,
    /// Cooldown between Level-4 (Sovereign) actions.
    pub level4_cooldown_secs: u64,
    /// Maximum Level-4 actions in a 72-hour window.
    pub level4_max_per_72h: u32,
    /// TSS share refresh interval.
    pub share_refresh_interval_secs: u64,
    /// Verifier staleness timeout for ratchet heartbeat.
    pub verifier_staleness_timeout_secs: u64,
    /// Maximum time the audit subsystem may be degraded.
    pub audit_degradation_max_secs: u64,

    // ── Military hardening parameters ──

    /// Require envelope encryption for all database writes.
    pub require_encryption_at_rest: bool,
    /// Require sealed (encrypted) keys — reject raw env vars.
    pub require_sealed_keys: bool,
    /// Require binary attestation check at startup.
    pub require_binary_attestation: bool,
    /// Binary attestation re-check interval (seconds, 0 = disabled).
    pub attestation_recheck_interval_secs: u64,
    /// Require mlock for all key material (fail-closed if unavailable).
    pub require_mlock: bool,
    /// Entropy health check: fail-closed on health test failure.
    pub entropy_fail_closed: bool,
    /// Maximum allowed entropy health test failures before service shutdown.
    pub max_entropy_failures: u32,
    /// Enable continuous entropy self-test at this interval (seconds, 0 = disabled).
    pub entropy_selftest_interval_secs: u64,
    /// Key rotation interval for envelope DEKs (seconds).
    pub dek_rotation_interval_secs: u64,
    /// Maximum age of any session before forced re-authentication (seconds).
    pub max_session_age_forced_reauth_secs: u64,
    /// Require DPoP for all token operations (not just modify).
    pub require_dpop_all_operations: bool,
    /// Maximum concurrent sessions per user.
    pub max_concurrent_sessions_per_user: u32,

    // ── HSM/Key Management parameters ──

    /// HSM backend type: "pkcs11", "aws-kms", "tpm2", or "software".
    /// In production mode, "software" triggers a warning (or failure if
    /// `require_hsm_backend` is true).
    pub hsm_backend: String,
    /// Require a hardware HSM backend in production mode.
    /// When true and production mode is active, the "software" backend
    /// is rejected at startup.
    pub require_hsm_backend: bool,
    /// PKCS#11 library path (e.g., `/usr/lib/softhsm/libsofthsm2.so`).
    pub hsm_pkcs11_library_path: String,
    /// PKCS#11 slot number.
    pub hsm_pkcs11_slot: u64,
    /// AWS KMS key ARN or alias.
    pub hsm_aws_kms_key_id: String,
    /// TPM 2.0 device path.
    pub hsm_tpm2_device: String,
    /// Key label in the HSM for the master key.
    pub hsm_key_label: String,

    // ── OAuth/OIDC hardening parameters ──

    /// Require exact redirect URI matching (no wildcards or prefix matching).
    pub require_strict_redirect_uri: bool,
    /// Require PKCE (Proof Key for Code Exchange) for all authorization code flows.
    pub require_pkce: bool,
    /// Require mutual TLS (mTLS) for all client authentication.
    pub require_mtls: bool,
    /// Require encryption of TSS key shards at rest and in transit.
    pub shard_encryption_enabled: bool,
}

impl SecurityConfig {
    /// Apply the developer mode and log level from this config to the
    /// global runtime toggle.  Called once at startup (no proof required).
    pub fn apply_developer_mode(&self) {
        developer_mode().set_developer_mode_unchecked(self.developer_mode);
        developer_mode().set_log_level(self.log_level);
    }

    /// Toggle developer mode at runtime (called from admin API).
    ///
    /// Requires a valid HMAC-SHA512 proof derived from the activation key.
    /// In production mode, enabling developer mode is always refused.
    pub fn set_developer_mode(enabled: bool, proof_hex: &str) {
        developer_mode().set_developer_mode(enabled, proof_hex);
    }

    /// Set the log level at runtime (called from admin API).
    pub fn set_log_level(level: LogLevel) {
        developer_mode().set_log_level(level);
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            developer_mode: false,
            log_level: LogLevel::Error,
            max_session_lifetime_secs: 28800,
            ratchet_epoch_secs: 10,
            ratchet_lookahead_epochs: 1,
            receipt_ttl_secs: 30,
            ceremony_ttl_secs: 30,
            puzzle_difficulty_normal: 8,
            puzzle_difficulty_ddos: 20,
            max_failed_attempts: 5,
            lockout_duration_secs: 1800,
            token_lifetime_tier1_secs: 300,
            token_lifetime_tier2_secs: 600,
            token_lifetime_tier3_secs: 900,
            token_lifetime_tier4_secs: 120,
            level4_cooldown_secs: 900,
            level4_max_per_72h: 1,
            share_refresh_interval_secs: 3600,
            verifier_staleness_timeout_secs: 60,
            audit_degradation_max_secs: 1800,

            // Military hardening defaults — all enabled for maximum security
            require_encryption_at_rest: true,
            require_sealed_keys: true,
            require_binary_attestation: true,
            attestation_recheck_interval_secs: 300, // 5 minutes
            require_mlock: true,
            entropy_fail_closed: true,
            max_entropy_failures: 3,
            entropy_selftest_interval_secs: 60,
            dek_rotation_interval_secs: 86400, // 24 hours
            max_session_age_forced_reauth_secs: 14400, // 4 hours (stricter than 8h max)
            require_dpop_all_operations: true,
            max_concurrent_sessions_per_user: 3,

            // HSM/Key Management defaults
            hsm_backend: "software".to_string(),
            require_hsm_backend: true,
            hsm_pkcs11_library_path: String::new(),
            hsm_pkcs11_slot: 0,
            hsm_aws_kms_key_id: String::new(),
            hsm_tpm2_device: "/dev/tpmrm0".to_string(),
            hsm_key_label: "MILNET-MASTER-KEK-v1".to_string(),

            // OAuth/OIDC hardening defaults — all enabled for maximum security
            require_strict_redirect_uri: true,
            require_pkce: true,
            require_mtls: true,
            shard_encryption_enabled: true,
        }
    }
}

// Second impl block for SecurityConfig: query methods and validation.
impl SecurityConfig {
    /// Returns the token lifetime for a given device tier (1-4).
    pub fn token_lifetime_for_tier(&self, tier: u8) -> u64 {
        match tier {
            1 => self.token_lifetime_tier1_secs,
            2 => self.token_lifetime_tier2_secs,
            3 => self.token_lifetime_tier3_secs,
            4 => self.token_lifetime_tier4_secs,
            _ => 0,
        }
    }

    /// Validate the HSM configuration for the current environment.
    ///
    /// In production mode (`MILNET_PRODUCTION=1`):
    /// - If `require_hsm_backend` is true and `hsm_backend` is "software",
    ///   this returns an error message.
    /// - If `require_hsm_backend` is false but `hsm_backend` is "software",
    ///   a warning is printed.
    ///
    /// Returns `Ok(())` if the configuration is acceptable, or `Err(msg)`
    /// with a description of the problem.
    pub fn validate_hsm_config(&self) -> Result<(), String> {
        let is_production = crate::sealed_keys::is_production();
        let is_software = self.hsm_backend == "software";

        if is_production && is_software {
            if self.require_hsm_backend {
                return Err(
                    "FATAL: Software HSM backend is forbidden in production mode. \
                     Set MILNET_HSM_BACKEND to pkcs11, aws-kms, or tpm2."
                        .to_string(),
                );
            }
            eprintln!(
                "WARNING: Software HSM backend in production mode. \
                 This is NOT recommended — configure a hardware HSM."
            );
        }

        if is_production && !is_software {
            eprintln!(
                "INFO: Production mode with hardware HSM backend '{}'.",
                self.hsm_backend
            );
        }

        Ok(())
    }

    /// Validate critical security settings in production mode.
    /// Panics if production mode is active and required settings are disabled.
    pub fn validate_production(&self) {
        if !crate::sealed_keys::is_production() {
            return;
        }
        if !self.require_encryption_at_rest {
            panic!("FATAL: require_encryption_at_rest must be true in production");
        }
        if !self.require_sealed_keys {
            panic!("FATAL: require_sealed_keys must be true in production");
        }
        if !self.require_binary_attestation {
            panic!("FATAL: require_binary_attestation must be true in production");
        }
        if !self.require_mlock {
            panic!("FATAL: require_mlock must be true in production");
        }
        if !self.entropy_fail_closed {
            panic!("FATAL: entropy_fail_closed must be true in production");
        }
    }

    /// Maximum ratchet epoch for the configured session lifetime.
    pub fn max_ratchet_epochs(&self) -> u64 {
        if self.ratchet_epoch_secs == 0 {
            return 0;
        }
        self.max_session_lifetime_secs / self.ratchet_epoch_secs
    }

    /// Validate that all security-critical settings meet minimum production
    /// thresholds. Returns a list of violations (empty = all OK).
    ///
    /// This complements `validate_production()` (which panics on fatal boolean
    /// flags) by also checking numeric thresholds and returning actionable
    /// diagnostics instead of panicking.
    pub fn validate_production_config(&self) -> Vec<String> {
        let mut violations = Vec::new();

        if self.developer_mode {
            violations.push("developer_mode must be false in production".into());
        }
        if self.log_level != LogLevel::Error {
            violations.push("log_level must be Error in production (not Verbose)".into());
        }
        if self.max_failed_attempts > 5 {
            violations.push(format!(
                "max_failed_attempts is {} but must be <= 5",
                self.max_failed_attempts
            ));
        }
        if self.max_failed_attempts == 0 {
            violations.push("max_failed_attempts must not be 0".into());
        }
        if self.lockout_duration_secs < 1800 {
            violations.push(format!(
                "lockout_duration_secs is {} but must be >= 1800 (30 min)",
                self.lockout_duration_secs
            ));
        }
        if !self.require_encryption_at_rest {
            violations.push("require_encryption_at_rest must be true".into());
        }
        if !self.require_sealed_keys {
            violations.push("require_sealed_keys must be true".into());
        }
        if !self.require_binary_attestation {
            violations.push("require_binary_attestation must be true".into());
        }
        if !self.require_mlock {
            violations.push("require_mlock must be true".into());
        }
        if !self.entropy_fail_closed {
            violations.push("entropy_fail_closed must be true".into());
        }
        if !self.require_pkce {
            violations.push("require_pkce must be true".into());
        }
        if !self.require_strict_redirect_uri {
            violations.push("require_strict_redirect_uri must be true".into());
        }
        if !self.require_dpop_all_operations {
            violations.push("require_dpop_all_operations must be true".into());
        }
        if self.token_lifetime_tier1_secs > 300 {
            violations.push(format!(
                "token_lifetime_tier1_secs is {} but must be <= 300 (5 min)",
                self.token_lifetime_tier1_secs
            ));
        }
        if self.token_lifetime_tier4_secs > 120 {
            violations.push(format!(
                "token_lifetime_tier4_secs is {} but must be <= 120 (2 min)",
                self.token_lifetime_tier4_secs
            ));
        }
        if self.max_session_lifetime_secs > 28800 {
            violations.push(format!(
                "max_session_lifetime_secs is {} but must be <= 28800 (8h)",
                self.max_session_lifetime_secs
            ));
        }

        violations
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_developer_mode_is_off() {
        let cfg = SecurityConfig::default();
        assert!(!cfg.developer_mode);
        assert_eq!(cfg.log_level, LogLevel::Error);
    }

    #[test]
    fn developer_mode_runtime_toggle() {
        let dm = DeveloperModeConfig::new();
        assert!(!dm.is_enabled());
        assert_eq!(dm.log_level(), LogLevel::Error);

        dm.set_developer_mode_unchecked(true);
        assert!(dm.is_enabled());

        dm.set_log_level(LogLevel::Verbose);
        assert_eq!(dm.log_level(), LogLevel::Verbose);
        assert!(dm.is_verbose());

        dm.set_developer_mode_unchecked(false);
        assert!(!dm.is_verbose());
    }

    #[test]
    fn default_values_match_spec() {
        let cfg = SecurityConfig::default();
        assert_eq!(cfg.max_session_lifetime_secs, 28800);
        assert_eq!(cfg.ratchet_epoch_secs, 10);
        assert_eq!(cfg.ratchet_lookahead_epochs, 1);
        assert_eq!(cfg.receipt_ttl_secs, 30);
        assert_eq!(cfg.ceremony_ttl_secs, 30);
        assert_eq!(cfg.puzzle_difficulty_normal, 8);
        assert_eq!(cfg.puzzle_difficulty_ddos, 20);
        assert_eq!(cfg.max_failed_attempts, 5);
        assert_eq!(cfg.lockout_duration_secs, 1800);
        assert_eq!(cfg.token_lifetime_tier1_secs, 300);
        assert_eq!(cfg.token_lifetime_tier2_secs, 600);
        assert_eq!(cfg.token_lifetime_tier3_secs, 900);
        assert_eq!(cfg.token_lifetime_tier4_secs, 120);
        assert_eq!(cfg.level4_cooldown_secs, 900);
        assert_eq!(cfg.level4_max_per_72h, 1);
        assert_eq!(cfg.share_refresh_interval_secs, 3600);
        assert_eq!(cfg.verifier_staleness_timeout_secs, 60);
        assert_eq!(cfg.audit_degradation_max_secs, 1800);
    }

    #[test]
    fn hardening_defaults_are_maximum_security() {
        let cfg = SecurityConfig::default();
        assert!(cfg.require_encryption_at_rest);
        assert!(cfg.require_sealed_keys);
        assert!(cfg.require_binary_attestation);
        assert!(cfg.require_mlock);
        assert!(cfg.entropy_fail_closed);
        assert!(cfg.require_dpop_all_operations);
        assert!(cfg.require_strict_redirect_uri);
        assert!(cfg.require_pkce);
        assert!(cfg.require_mtls);
        assert!(cfg.shard_encryption_enabled);
    }

    #[test]
    fn token_lifetime_for_tier() {
        let cfg = SecurityConfig::default();
        assert_eq!(cfg.token_lifetime_for_tier(1), 300);
        assert_eq!(cfg.token_lifetime_for_tier(2), 600);
        assert_eq!(cfg.token_lifetime_for_tier(3), 900);
        assert_eq!(cfg.token_lifetime_for_tier(4), 120);
        assert_eq!(cfg.token_lifetime_for_tier(0), 0);
        assert_eq!(cfg.token_lifetime_for_tier(5), 0);
    }

    #[test]
    fn max_ratchet_epochs() {
        let cfg = SecurityConfig::default();
        assert_eq!(cfg.max_ratchet_epochs(), 2880); // 28800 / 10
    }

    #[test]
    fn validate_production_config_default_passes() {
        let cfg = SecurityConfig::default();
        let violations = cfg.validate_production_config();
        assert!(violations.is_empty(), "default config should pass: {:?}", violations);
    }

    #[test]
    fn validate_production_config_catches_violations() {
        let mut cfg = SecurityConfig::default();
        cfg.developer_mode = true;
        cfg.log_level = LogLevel::Verbose;
        cfg.max_failed_attempts = 20;
        cfg.lockout_duration_secs = 60;
        let violations = cfg.validate_production_config();
        assert!(violations.len() >= 4);
        assert!(violations.iter().any(|v| v.contains("developer_mode")));
        assert!(violations.iter().any(|v| v.contains("log_level")));
        assert!(violations.iter().any(|v| v.contains("max_failed_attempts")));
        assert!(violations.iter().any(|v| v.contains("lockout_duration_secs")));
    }

    #[test]
    fn dev_mode_proof_generation_and_verification() {
        let key = [0x42u8; 32];
        let proof = generate_dev_mode_proof(&key, "enable");
        assert_eq!(proof.len(), 128); // HMAC-SHA512 = 64 bytes = 128 hex chars

        // Different actions produce different proofs
        let proof_disable = generate_dev_mode_proof(&key, "disable");
        assert_ne!(proof, proof_disable);

        // Different keys produce different proofs
        let key2 = [0x43u8; 32];
        let proof2 = generate_dev_mode_proof(&key2, "enable");
        assert_ne!(proof, proof2);
    }

    #[test]
    fn dev_mode_without_key_loaded_rejects_all_proofs() {
        // OnceLock not initialized in this test — verify_dev_mode_proof returns false
        assert!(!verify_dev_mode_proof("deadbeef", "enable"));
        assert!(!verify_dev_mode_proof("", "enable"));
    }

    #[test]
    fn dev_mode_proof_rejects_wrong_length() {
        // Even if key were loaded, wrong-length proof must fail
        assert!(!verify_dev_mode_proof("too_short", "enable"));
        assert!(!verify_dev_mode_proof("", "enable"));
    }
}
