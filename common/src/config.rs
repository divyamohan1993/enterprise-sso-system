//! System-wide security configuration per spec.
//!
//! Centralises every tuneable security parameter so that auditors can review
//! them in one place and operators can override them via environment or config
//! file without touching code.

/// System-wide security configuration per spec.
pub struct SecurityConfig {
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

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
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

    /// Maximum ratchet epoch for the configured session lifetime.
    pub fn max_ratchet_epochs(&self) -> u64 {
        if self.ratchet_epoch_secs == 0 {
            return 0;
        }
        self.max_session_lifetime_secs / self.ratchet_epoch_secs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
