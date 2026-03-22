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
