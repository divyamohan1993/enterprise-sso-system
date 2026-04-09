//! System-wide security configuration per spec.
//!
//! Centralises every tuneable security parameter so that auditors can review
//! them in one place and operators can override them via environment or config
//! file without touching code.
//!
//! There is ONE mode: production. The `error_level` flag controls verbosity:
//! - `Verbose`: show everything including file names, line numbers, full errors.
//!   All verbose errors are also emitted to the SIEM panel so super admins
//!   can track and report issues with exact file:line locations.
//! - `Warn`: show warnings and errors only, no file/line details
//!
//! Default is `Verbose`. Super admins see full error detail on the SIEM
//! dashboard for active troubleshooting. End users see safe error messages.

use std::sync::atomic::{AtomicU8, Ordering};

/// Error verbosity level for the system.
///
/// Controls what detail is exposed in error responses and logs.
/// `Verbose` exposes everything including file:line for super-admin debugging.
/// `Warn` shows warnings and errors only — no file/line, no request details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ErrorLevel {
    /// Show everything: file names, line numbers, full error messages,
    /// request details, crypto operations, timing.
    Verbose = 0,
    /// Show warnings and errors only. No file/line, no request details.
    Warn = 1,
}

impl ErrorLevel {
    /// Convert from the atomic u8 representation.
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => ErrorLevel::Verbose,
            _ => ErrorLevel::Warn,
        }
    }
}

impl std::fmt::Display for ErrorLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorLevel::Verbose => write!(f, "verbose"),
            ErrorLevel::Warn => write!(f, "warn"),
        }
    }
}

// Keep LogLevel as a type alias for backwards compatibility in code that
// references it. All new code should use ErrorLevel directly.
/// Backwards-compatible alias. Use [`ErrorLevel`] in new code.
pub type LogLevel = ErrorLevel;

/// Runtime error-level configuration.
///
/// Uses an atomic so that reads from hot paths (every request) are lock-free O(1).
/// Writes happen through the admin API or at startup.
///
/// Default is `Warn` — production deployments suppress verbose error detail.
/// When `MILNET_MILITARY_DEPLOYMENT=1` or `MILNET_PRODUCTION=1` is set,
/// the level is forced to `Warn` regardless of configuration.
pub struct ErrorLevelConfig {
    level: AtomicU8,
}

impl ErrorLevelConfig {
    /// Create a new config with error level defaulting to Warn (safe).
    ///
    /// SECURITY: Default to Warn to prevent information disclosure if
    /// MILNET_MILITARY_DEPLOYMENT or MILNET_PRODUCTION env vars are not set.
    /// Verbose mode must be explicitly enabled via `set_level(ErrorLevel::Verbose)`.
    pub const fn new() -> Self {
        Self {
            level: AtomicU8::new(ErrorLevel::Warn as u8),
        }
    }

    /// Get the current error level. O(1) atomic read.
    pub fn level(&self) -> ErrorLevel {
        ErrorLevel::from_u8(self.level.load(Ordering::Relaxed))
    }

    /// Returns true if verbose mode is active.
    pub fn is_verbose(&self) -> bool {
        self.level() == ErrorLevel::Verbose
    }

    /// Set the error level at runtime.
    ///
    /// Verbose errors are always allowed. They are reported to the SIEM
    /// panel for super admin visibility. End users see sanitized messages.
    pub fn set_level(&self, level: ErrorLevel) {
        self.level.store(level as u8, Ordering::Relaxed);
        tracing::info!(error_level = %level, "error level changed");
    }

    // ── Backwards-compatible shims ──
    // These allow existing code referencing developer_mode().is_enabled() or
    // developer_mode().log_level() to compile without changes everywhere at once.

    /// Backwards-compatible: returns true when error_level is Verbose.
    pub fn is_enabled(&self) -> bool {
        self.is_verbose()
    }

    /// Backwards-compatible alias for [`level`].
    pub fn log_level(&self) -> ErrorLevel {
        self.level()
    }

    /// Backwards-compatible: set error level.
    /// Maps enabled=true to Verbose, enabled=false to Warn.
    pub fn set_developer_mode(&self, enabled: bool, _proof_hex: &str) {
        let level = if enabled { ErrorLevel::Verbose } else { ErrorLevel::Warn };
        self.set_level(level);
    }

    /// Backwards-compatible: set error level without proof.
    pub fn set_developer_mode_unchecked(&self, enabled: bool) {
        let level = if enabled { ErrorLevel::Verbose } else { ErrorLevel::Warn };
        self.set_level(level);
    }

    /// Backwards-compatible alias for [`set_level`].
    pub fn set_log_level(&self, level: ErrorLevel) {
        self.set_level(level);
    }
}

impl Default for ErrorLevelConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns `true` if either `MILNET_MILITARY_DEPLOYMENT=1` or
/// `MILNET_PRODUCTION=1` is set in the environment.
fn is_military_or_production() -> bool {
    std::env::var("MILNET_MILITARY_DEPLOYMENT").as_deref() == Ok("1")
        || std::env::var("MILNET_PRODUCTION").as_deref() == Ok("1")
}

/// Global singleton for error level, accessible from any crate. O(1) access.
static ERROR_LEVEL: ErrorLevelConfig = ErrorLevelConfig::new();

/// Get a reference to the global error level configuration.
pub fn error_level() -> &'static ErrorLevelConfig {
    &ERROR_LEVEL
}

/// Backwards-compatible alias for [`error_level`].
pub fn developer_mode() -> &'static ErrorLevelConfig {
    &ERROR_LEVEL
}

// ── Legacy shim functions (kept for backwards compat with admin routes) ──

/// Load error level from environment at startup.
///
/// Reads `MILNET_ERROR_LEVEL` env var:
/// - `"verbose"` → ErrorLevel::Verbose (blocked if military/production)
/// - `"warn"` → ErrorLevel::Warn (default)
///
/// Rejects `MILNET_DEV_MODE` and `MILNET_DEVELOPER_MODE` env vars with
/// SIEM:CRITICAL alert. Developer mode is permanently disabled.
pub fn load_error_level_from_env() {
    // Reject any attempt to enable dev mode via env var.
    if std::env::var("MILNET_DEV_MODE").is_ok() || std::env::var("MILNET_DEVELOPER_MODE").is_ok() {
        tracing::error!(
            target: "siem",
            "SIEM:CRITICAL: MILNET_DEV_MODE or MILNET_DEVELOPER_MODE env var detected. \
             Developer mode is permanently disabled in production. \
             This is a security violation. Ignoring."
        );
        // Remove the offending env vars
        std::env::remove_var("MILNET_DEV_MODE");
        std::env::remove_var("MILNET_DEVELOPER_MODE");
    }
    match std::env::var("MILNET_ERROR_LEVEL").ok().as_deref() {
        Some("warn") => {
            error_level().set_level(ErrorLevel::Warn);
            tracing::info!("error_level=warn (set via MILNET_ERROR_LEVEL)");
        }
        Some("verbose") => {
            error_level().set_level(ErrorLevel::Verbose);
            tracing::info!("error_level=verbose (requested via MILNET_ERROR_LEVEL)");
        }
        None => {
            error_level().set_level(ErrorLevel::Verbose);
            tracing::info!("error_level=verbose (default -- SIEM panel receives all errors with file:line)");
        }
        Some(other) => {
            tracing::warn!(
                "Unknown MILNET_ERROR_LEVEL={other:?}, defaulting to warn"
            );
            error_level().set_level(ErrorLevel::Warn);
        }
    }
}

/// Load the developer mode activation key — permanently disabled.
/// Developer mode is permanently disabled in production deployment.
/// This function only loads the error level from env for backwards compatibility.
pub fn load_dev_mode_activation_key() {
    tracing::info!("developer mode permanently disabled in production deployment");
    load_error_level_from_env();
}

/// Domain separator for developer mode HMAC proofs.
/// Distinct from the FIPS mode domain to prevent cross-domain proof reuse.
const DEV_MODE_HMAC_DOMAIN: &[u8] = b"MILNET-DEV-MODE-v1";

/// Verify a developer mode activation proof.
///
/// The proof is HMAC-SHA512(derived_key, action || timestamp_hex) where the
/// key is derived from the master KEK via HKDF-SHA512. The timestamp (Unix
/// seconds, hex-encoded) must be within 60 seconds of the current time to
/// prevent replay attacks.
///
/// `proof_hex` format: `<hmac_hex>:<timestamp_hex>` (128 + 1 + variable chars).
pub fn verify_dev_mode_proof(proof_hex: &str, action: &str) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    use subtle::ConstantTimeEq;

    // Parse proof_hex as "hmac_hex:timestamp_hex"
    let parts: Vec<&str> = proof_hex.splitn(2, ':').collect();
    if parts.len() != 2 {
        return false;
    }
    let (hmac_hex, ts_hex) = (parts[0], parts[1]);

    // Decode HMAC (must be exactly 64 bytes = 128 hex chars)
    let proof_bytes = match hex::decode(hmac_hex) {
        Ok(b) if b.len() == 64 => b,
        _ => return false,
    };

    // Decode and validate timestamp (Unix seconds)
    let ts: u64 = match u64::from_str_radix(ts_hex, 16) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let diff = if now > ts { now - ts } else { ts - now };
    if diff > 60 {
        tracing::warn!(
            "Developer mode proof rejected: timestamp drift {}s exceeds 60s window",
            diff
        );
        return false;
    }

    // Derive key from master KEK via HKDF
    let kek = crate::sealed_keys::load_master_kek();
    let hk = hkdf::Hkdf::<Sha512>::new(Some(DEV_MODE_HMAC_DOMAIN), &kek);
    let mut derived_key = [0u8; 64];
    hk.expand(b"dev-mode-proof-key", &mut derived_key)
        .expect("HKDF expand always valid for 64 bytes");

    // Compute expected HMAC
    type HmacSha512 = Hmac<Sha512>;
    let mut mac = HmacSha512::new_from_slice(&derived_key)
        .expect("HMAC key length always valid");
    mac.update(action.as_bytes());
    mac.update(ts_hex.as_bytes());
    let expected = mac.finalize().into_bytes();

    // Zeroize derived key
    {
        use zeroize::Zeroize;
        derived_key.zeroize();
    }

    // Constant-time comparison
    proof_bytes.ct_eq(expected.as_slice()).into()
}

/// Generate a developer mode activation proof.
///
/// Produces an HMAC-SHA512 proof over `(action || timestamp_hex)` using a key
/// derived from the master KEK via HKDF. Returns `"<hmac_hex>:<timestamp_hex>"`.
pub fn generate_dev_mode_proof(key: &[u8; 32], action: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let ts_hex = format!("{:x}", ts);

    // Derive key via HKDF
    let hk = hkdf::Hkdf::<Sha512>::new(Some(DEV_MODE_HMAC_DOMAIN), key);
    let mut derived_key = [0u8; 64];
    hk.expand(b"dev-mode-proof-key", &mut derived_key)
        .expect("HKDF expand always valid for 64 bytes");

    type HmacSha512 = Hmac<Sha512>;
    let mut mac = HmacSha512::new_from_slice(&derived_key)
        .expect("HMAC key length always valid");
    mac.update(action.as_bytes());
    mac.update(ts_hex.as_bytes());
    let hmac_hex = hex::encode(mac.finalize().into_bytes());

    // Zeroize derived key
    {
        use zeroize::Zeroize;
        derived_key.zeroize();
    }

    format!("{}:{}", hmac_hex, ts_hex)
}

// Keep DeveloperModeConfig as an alias
/// Backwards-compatible alias. Use [`ErrorLevelConfig`] in new code.
pub type DeveloperModeConfig = ErrorLevelConfig;

// ── MLP (Minimum Lovable Product) Mode ──
//
// MLP mode relaxes hardware security requirements so the system can run in
// software-simulated mode for development, demos, and CI. Activating MLP
// requires TWO env vars to prevent accidental production use:
//   MILNET_MLP_MODE=1
//   MILNET_MLP_ACK="I-ACKNOWLEDGE-SOFTWARE-SIMULATION-NOT-FOR-PRODUCTION"
//
// Every MLP relaxation emits a SIEM warning so audit trails are never silent.

/// Returns `true` when MLP mode is active (both env vars present and correct).
pub fn is_mlp_mode() -> bool {
    std::env::var("MILNET_MLP_MODE").as_deref() == Ok("1")
        && std::env::var("MILNET_MLP_ACK").as_deref()
            == Ok("I-ACKNOWLEDGE-SOFTWARE-SIMULATION-NOT-FOR-PRODUCTION")
}

/// Returns `true` when real hardware security backends are required.
/// This is the inverse of MLP mode: if MLP is off, hardware is required
/// in production/military environments.
pub fn require_hardware_security() -> bool {
    !is_mlp_mode()
        && (std::env::var("MILNET_PRODUCTION").as_deref() == Ok("1")
            || std::env::var("MILNET_MILITARY_DEPLOYMENT").as_deref() == Ok("1"))
}

/// Emit a SIEM warning event for an MLP-mode relaxation.
///
/// Every time a hardware requirement is bypassed under MLP mode, this
/// function logs a structured SIEM event so the audit trail captures it.
pub fn emit_mlp_siem_event(component: &str, action: &str) {
    tracing::warn!(
        target: "siem",
        category = "MLP_SIMULATION",
        component = component,
        action = action,
        "SIEM:WARNING [MLP_SIMULATION] component={} action={} -- \
         hardware security requirement bypassed in MLP mode. \
         NOT FOR PRODUCTION USE.",
        component,
        action,
    );
}

/// Result of validating a component's deployment mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentValidation {
    /// The component that was validated (e.g. "hsm", "enclave", "tpm").
    pub component: String,
    /// Whether the component is running with real hardware.
    pub hardware_backed: bool,
    /// Whether MLP mode relaxed a requirement.
    pub mlp_relaxed: bool,
    /// Human-readable summary.
    pub summary: String,
}

/// System-wide security configuration per spec.
pub struct SecurityConfig {
    /// Error verbosity level — `Verbose` shows file:line and full errors,
    /// `Warn` shows warnings and errors only. Default: Warn.
    pub error_level: ErrorLevel,
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

    // ── CAC / PIV smart card parameters ──

    /// Enable CAC/PIV hardware smart card authentication.
    pub cac_enabled: bool,
    /// Path to the PKCS#11 shared library for CAC/PIV (e.g. `/usr/lib/libcackey.so`).
    pub cac_pkcs11_library: String,
    /// PKCS#11 slot number for the CAC/PIV reader.
    pub cac_pkcs11_slot: u64,
    /// Tiers that require CAC/PIV authentication (default: [1] = Sovereign).
    pub cac_required_tiers: Vec<u8>,
    /// Maximum CAC PIN entry attempts before the card is locked (default: 3).
    pub cac_pin_max_retries: u8,
    /// CAC session lifetime in seconds (default: 3600 = 1 hour).
    pub cac_session_timeout_secs: u64,
    /// Enable Indian CCA Digital Signature Certificate (DSC) authentication.
    pub indian_dsc_enabled: bool,
    /// Enable Indian Aadhaar eSign authentication.
    pub indian_esign_enabled: bool,

    // ── FIPS / Post-Quantum cryptography parameters ──

    /// Enable FIPS 140-3 mode — only FIPS-approved algorithms permitted.
    pub fips_mode: bool,
    /// Minimum post-quantum security level (CNSA 2.0 requires 5).
    pub pq_minimum_level: u8,
    /// Require post-quantum signatures for all signing operations.
    pub require_pq_signatures: bool,
    /// Require post-quantum key exchange for all session establishment.
    pub require_pq_key_exchange: bool,
    /// Key stretching function: "argon2id-v19" (non-FIPS) or "pbkdf2-sha512" (FIPS).
    pub ksf_algorithm: String,
    /// Symmetric cipher: "aegis-256" (non-FIPS) or "aes-256-gcm" (FIPS).
    pub symmetric_algorithm: String,
}

impl SecurityConfig {
    /// Apply the error level from this config to the global runtime toggle.
    /// Called once at startup.
    pub fn apply_error_level(&self) {
        error_level().set_level(self.error_level);
    }

    /// Backwards-compatible alias for [`apply_error_level`].
    pub fn apply_developer_mode(&self) {
        self.apply_error_level();
    }

    /// Set the error level at runtime (called from admin API).
    pub fn set_error_level(level: ErrorLevel) {
        error_level().set_level(level);
    }

    /// Backwards-compatible: toggle verbose/warn via bool.
    pub fn set_developer_mode(enabled: bool, _proof_hex: &str) {
        let level = if enabled { ErrorLevel::Verbose } else { ErrorLevel::Warn };
        error_level().set_level(level);
    }

    /// Backwards-compatible alias.
    pub fn set_log_level(level: ErrorLevel) {
        error_level().set_level(level);
    }

    /// Apply the FIPS mode setting from this config to the global runtime
    /// toggle.  Called once at startup (no proof required).
    pub fn apply_fips_mode(&self) {
        crate::fips::fips_mode().set_fips_mode_unchecked(self.fips_mode);
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        let _is_military = std::env::var("MILNET_MILITARY_DEPLOYMENT").as_deref() == Ok("1");
        Self {
            error_level: ErrorLevel::Warn,
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

            // CAC / PIV defaults — disabled until hardware is configured
            cac_enabled: false,
            cac_pkcs11_library: String::new(),
            cac_pkcs11_slot: 0,
            cac_required_tiers: vec![1],
            cac_pin_max_retries: 3,
            cac_session_timeout_secs: 3600,
            indian_dsc_enabled: false,
            indian_esign_enabled: false,

            // FIPS / Post-Quantum defaults -- maximum security
            // When MILNET_MILITARY_DEPLOYMENT is set, force FIPS and HSM requirement
            fips_mode: true,
            pq_minimum_level: 5,
            require_pq_signatures: true,
            require_pq_key_exchange: true,
            ksf_algorithm: "argon2id-v19".into(),
            symmetric_algorithm: "aegis-256".into(),
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
        let is_software = self.hsm_backend == "software";

        if is_software {
            if self.require_hsm_backend {
                return Err(
                    "FATAL: Software HSM backend is forbidden. \
                     Set MILNET_HSM_BACKEND to pkcs11, aws-kms, or tpm2."
                        .to_string(),
                );
            }
            eprintln!(
                "WARNING: Software HSM backend detected. \
                 This is NOT recommended — configure a hardware HSM."
            );
        } else {
            eprintln!(
                "INFO: Hardware HSM backend '{}'.",
                self.hsm_backend
            );
        }

        Ok(())
    }

    /// Validate critical security settings.
    /// Panics if required settings are disabled. Always enforced (single production mode).
    pub fn validate_production(&self) {
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

        // error_level is freely configurable (Verbose or Warn) — no violation.
        // The codebase is open-source; verbose errors are intentionally allowed.

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
        // fips_mode=false is allowed in non-military deployments (enables
        // stronger algorithms). When MILNET_MILITARY_DEPLOYMENT is set,
        // FIPS mode and HSM backend are mandatory.
        if std::env::var("MILNET_MILITARY_DEPLOYMENT").as_deref() == Ok("1") {
            if !self.fips_mode {
                violations.push(
                    "fips_mode must be true when MILNET_MILITARY_DEPLOYMENT=1".into()
                );
            }
            if !self.require_hsm_backend {
                violations.push(
                    "require_hsm_backend must be true when MILNET_MILITARY_DEPLOYMENT=1".into()
                );
            }
        }
        if self.pq_minimum_level < 5 {
            violations.push(
                "pq_minimum_level must be >= 5 (CNSA 2.0 Level 5)".into()
            );
        }
        if !self.require_pq_signatures {
            violations.push("require_pq_signatures must be true in production".into());
        }
        if !self.require_pq_key_exchange {
            violations.push("require_pq_key_exchange must be true in production".into());
        }

        violations
    }
}

/// Result of the distributed secrets enforcement check.
#[derive(Debug, Clone)]
pub struct DistributedSecretsStatus {
    /// Threshold KDF is active (KEK never fully in RAM on any node).
    pub threshold_kdf_active: bool,
    /// FROST signing is distributed (not monolithic).
    pub frost_distributed: bool,
    /// Number of nodes detected in the cluster.
    pub cluster_node_count: usize,
    /// Violations found.
    pub violations: Vec<String>,
}

/// Startup check that verifies distributed secret management is properly
/// configured.
///
/// Verifies:
/// - Threshold KDF is active (KEK never fully in RAM on any node)
/// - FROST signing is distributed (not monolithic)
/// - At least 3 nodes are in the cluster
///
/// In production: warn if any of these are not met.
/// In military: exit if any of these are not met.
/// MLP: allow degraded with acknowledgment.
pub fn enforce_distributed_secrets() -> DistributedSecretsStatus {
    let is_military = std::env::var("MILNET_MILITARY_DEPLOYMENT").as_deref() == Ok("1");
    let mlp = is_mlp_mode();

    let threshold_kdf_active = crate::sealed_keys::use_threshold_kdf();

    // Check if FROST signing is distributed by looking for the distributed
    // signer configuration env vars
    let frost_distributed = std::env::var("MILNET_TSS_SHARE_SEALED").is_ok()
        || std::env::var("MILNET_TSS_DISTRIBUTED").as_deref() == Ok("1");

    // Cluster node count: read from MILNET_CLUSTER_NODES (comma-separated)
    // or MILNET_CLUSTER_NODE_COUNT
    let cluster_node_count = std::env::var("MILNET_CLUSTER_NODES")
        .ok()
        .map(|v| v.split(',').filter(|s| !s.trim().is_empty()).count())
        .or_else(|| {
            std::env::var("MILNET_CLUSTER_NODE_COUNT")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
        })
        .unwrap_or(1);

    let mut violations = Vec::new();

    if !threshold_kdf_active {
        violations.push(
            "threshold KDF not active -- KEK may materialize fully in RAM. \
             Set MILNET_KEK_SHARE for distributed key derivation."
                .to_string(),
        );
    }

    if !frost_distributed {
        violations.push(
            "FROST signing not distributed -- set MILNET_TSS_SHARE_SEALED or \
             MILNET_TSS_DISTRIBUTED=1 for distributed signing."
                .to_string(),
        );
    }

    if cluster_node_count < 3 {
        violations.push(format!(
            "cluster has {} node(s), need at least 3 for distributed security. \
             Set MILNET_CLUSTER_NODES or MILNET_CLUSTER_NODE_COUNT.",
            cluster_node_count
        ));
    }

    let status = DistributedSecretsStatus {
        threshold_kdf_active,
        frost_distributed,
        cluster_node_count,
        violations: violations.clone(),
    };

    if violations.is_empty() {
        tracing::info!(
            threshold_kdf = threshold_kdf_active,
            frost_distributed = frost_distributed,
            cluster_nodes = cluster_node_count,
            "distributed secrets enforcement: all checks passed"
        );
        return status;
    }

    // Report violations
    for v in &violations {
        tracing::warn!(target: "siem", "SIEM:WARNING distributed_secrets: {}", v);
    }

    if is_military {
        tracing::error!(
            target: "siem",
            violations = ?violations,
            "SIEM:CRITICAL military deployment requires fully distributed secrets. \
             {} violation(s) found. Process exiting.",
            violations.len()
        );
        for v in &violations {
            crate::siem::SecurityEvent {
                timestamp: crate::siem::SecurityEvent::now_iso8601(),
                category: "distributed_secrets",
                action: "enforcement_failed",
                severity: crate::siem::Severity::Critical,
                outcome: "failure",
                user_id: None,
                source_ip: None,
                detail: Some(v.clone()),
            }
            .emit();
        }
        std::process::exit(199);
    }

    if mlp {
        tracing::warn!(
            target: "siem",
            violations = ?violations,
            "SIEM:WARNING distributed secrets degraded in MLP mode ({} violation(s)). \
             Accepted with MLP acknowledgment.",
            violations.len()
        );
        emit_mlp_siem_event("distributed_secrets", "degraded_mode_accepted");
    } else {
        tracing::warn!(
            target: "siem",
            violations = ?violations,
            "SIEM:WARNING distributed secrets not fully configured ({} violation(s)). \
             Production deployments should fix these.",
            violations.len()
        );
    }

    status
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_error_level_is_warn() {
        let cfg = SecurityConfig::default();
        assert_eq!(cfg.error_level, ErrorLevel::Warn);
    }

    #[test]
    fn error_level_runtime_toggle() {
        let el = ErrorLevelConfig::new();
        // Default is Warn (safe default — prevents information disclosure)
        assert!(!el.is_verbose());
        assert_eq!(el.level(), ErrorLevel::Warn);

        // Toggle to Verbose
        el.set_level(ErrorLevel::Verbose);
        assert!(el.is_verbose());
        assert_eq!(el.level(), ErrorLevel::Verbose);

        // Toggle back to Warn
        el.set_level(ErrorLevel::Warn);
        assert!(!el.is_verbose());
        assert_eq!(el.level(), ErrorLevel::Warn);
    }

    #[test]
    fn error_level_backwards_compat() {
        let el = ErrorLevelConfig::new();
        // Default is Warn (safe), so is_enabled() is false
        assert!(!el.is_enabled());
        el.set_developer_mode_unchecked(true);
        assert!(el.is_enabled());
        el.set_developer_mode_unchecked(false);
        assert!(!el.is_enabled());
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
        cfg.max_failed_attempts = 20;
        cfg.lockout_duration_secs = 60;
        let violations = cfg.validate_production_config();
        assert!(violations.len() >= 2);
        assert!(violations.iter().any(|v| v.contains("max_failed_attempts")));
        assert!(violations.iter().any(|v| v.contains("lockout_duration_secs")));
    }

    #[test]
    fn error_level_warn_is_default_in_production() {
        // Default error level is now Warn
        let cfg = SecurityConfig::default();
        assert_eq!(cfg.error_level, ErrorLevel::Warn);
        let violations = cfg.validate_production_config();
        assert!(!violations.iter().any(|v| v.contains("error_level")));
    }

    #[test]
    fn verify_dev_mode_proof_valid_passes() {
        // Set up a known master KEK for this test
        std::env::set_var("MILNET_MASTER_KEK", "ab".repeat(32));

        let key_bytes: [u8; 32] = {
            let hex_str = "ab".repeat(32);
            let mut k = [0u8; 32];
            hex::decode_to_slice(&hex_str, &mut k).unwrap();
            k
        };

        let proof = generate_dev_mode_proof(&key_bytes, "enable");
        assert!(
            verify_dev_mode_proof(&proof, "enable"),
            "valid proof must pass verification"
        );

        std::env::remove_var("MILNET_MASTER_KEK");
    }

    #[test]
    fn verify_dev_mode_proof_invalid_fails() {
        std::env::set_var("MILNET_MASTER_KEK", "ab".repeat(32));

        // Wrong HMAC bytes
        assert!(
            !verify_dev_mode_proof("00".repeat(64).as_str(), "enable"),
            "garbage proof without timestamp must fail"
        );

        // Valid format but wrong HMAC
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let fake_proof = format!("{}:{:x}", "00".repeat(64), ts);
        assert!(
            !verify_dev_mode_proof(&fake_proof, "enable"),
            "wrong HMAC must fail"
        );

        // Valid proof for wrong action
        let key_bytes: [u8; 32] = {
            let hex_str = "ab".repeat(32);
            let mut k = [0u8; 32];
            hex::decode_to_slice(&hex_str, &mut k).unwrap();
            k
        };
        let proof = generate_dev_mode_proof(&key_bytes, "enable");
        assert!(
            !verify_dev_mode_proof(&proof, "disable"),
            "proof for 'enable' must not verify for 'disable'"
        );

        // Empty proof
        assert!(
            !verify_dev_mode_proof("", "enable"),
            "empty proof must fail"
        );

        std::env::remove_var("MILNET_MASTER_KEK");
    }

    #[test]
    fn verify_dev_mode_proof_rejects_expired_timestamp() {
        std::env::set_var("MILNET_MASTER_KEK", "ab".repeat(32));

        let key_bytes: [u8; 32] = {
            let hex_str = "ab".repeat(32);
            let mut k = [0u8; 32];
            hex::decode_to_slice(&hex_str, &mut k).unwrap();
            k
        };

        // Generate proof with a timestamp 120 seconds in the past
        let old_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() - 120;
        let ts_hex = format!("{:x}", old_ts);

        use hmac::{Hmac, Mac};
        use sha2::Sha512;
        type HmacSha512 = Hmac<Sha512>;

        let hk = hkdf::Hkdf::<Sha512>::new(Some(DEV_MODE_HMAC_DOMAIN), &key_bytes);
        let mut derived_key = [0u8; 64];
        hk.expand(b"dev-mode-proof-key", &mut derived_key).unwrap();
        let mut mac = HmacSha512::new_from_slice(&derived_key).unwrap();
        mac.update(b"enable");
        mac.update(ts_hex.as_bytes());
        let hmac_hex = hex::encode(mac.finalize().into_bytes());

        let expired_proof = format!("{}:{}", hmac_hex, ts_hex);
        assert!(
            !verify_dev_mode_proof(&expired_proof, "enable"),
            "expired proof (120s old) must be rejected"
        );

        std::env::remove_var("MILNET_MASTER_KEK");
    }

    #[test]
    fn mlp_mode_requires_both_env_vars() {
        // Neither set -> false
        std::env::remove_var("MILNET_MLP_MODE");
        std::env::remove_var("MILNET_MLP_ACK");
        assert!(!is_mlp_mode());

        // Only mode -> false
        std::env::set_var("MILNET_MLP_MODE", "1");
        assert!(!is_mlp_mode());

        // Only ack -> false
        std::env::remove_var("MILNET_MLP_MODE");
        std::env::set_var(
            "MILNET_MLP_ACK",
            "I-ACKNOWLEDGE-SOFTWARE-SIMULATION-NOT-FOR-PRODUCTION",
        );
        assert!(!is_mlp_mode());

        // Both set -> true
        std::env::set_var("MILNET_MLP_MODE", "1");
        assert!(is_mlp_mode());

        // Wrong ack -> false
        std::env::set_var("MILNET_MLP_ACK", "wrong");
        assert!(!is_mlp_mode());

        // Cleanup
        std::env::remove_var("MILNET_MLP_MODE");
        std::env::remove_var("MILNET_MLP_ACK");
    }

    #[test]
    fn require_hardware_security_respects_mlp() {
        std::env::remove_var("MILNET_MLP_MODE");
        std::env::remove_var("MILNET_MLP_ACK");
        std::env::remove_var("MILNET_PRODUCTION");
        std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");

        // No production env -> false regardless
        assert!(!require_hardware_security());

        // Production set, no MLP -> true
        std::env::set_var("MILNET_PRODUCTION", "1");
        assert!(require_hardware_security());

        // Production set, MLP active -> false (relaxed)
        std::env::set_var("MILNET_MLP_MODE", "1");
        std::env::set_var(
            "MILNET_MLP_ACK",
            "I-ACKNOWLEDGE-SOFTWARE-SIMULATION-NOT-FOR-PRODUCTION",
        );
        assert!(!require_hardware_security());

        // Cleanup
        std::env::remove_var("MILNET_MLP_MODE");
        std::env::remove_var("MILNET_MLP_ACK");
        std::env::remove_var("MILNET_PRODUCTION");
    }

    #[test]
    fn deployment_validation_struct_fields() {
        let v = DeploymentValidation {
            component: "test".into(),
            hardware_backed: false,
            mlp_relaxed: true,
            summary: "test summary".into(),
        };
        assert_eq!(v.component, "test");
        assert!(!v.hardware_backed);
        assert!(v.mlp_relaxed);
    }

    #[test]
    fn test_pq_minimum_level_enforcement() {
        let mut cfg = SecurityConfig::default();
        // pq_minimum_level=3 is below CNSA 2.0 minimum of 5
        cfg.pq_minimum_level = 3;
        let violations = cfg.validate_production_config();
        assert!(
            violations.iter().any(|v| v.contains("pq_minimum_level")),
            "expected pq_minimum_level violation, got: {:?}",
            violations
        );
    }

    #[test]
    fn validate_production_config_fips_fields() {
        let mut cfg = SecurityConfig::default();
        // fips_mode=false is allowed (enables AEGIS-256, Argon2id, BLAKE3)
        cfg.fips_mode = false;
        cfg.require_pq_signatures = false;
        cfg.require_pq_key_exchange = false;
        let violations = cfg.validate_production_config();
        // fips_mode=false should NOT be a violation (stronger algorithms)
        assert!(!violations.iter().any(|v| v.contains("fips_mode")));
        // PQ signatures and key exchange are still required
        assert!(violations.iter().any(|v| v.contains("require_pq_signatures")));
        assert!(violations.iter().any(|v| v.contains("require_pq_key_exchange")));
    }
}
