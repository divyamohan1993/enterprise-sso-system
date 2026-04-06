use common::config::{SecurityConfig, ErrorLevel, ErrorLevelConfig};

#[test]
fn test_default_max_session_lifetime() {
    let c = SecurityConfig::default();
    assert_eq!(c.max_session_lifetime_secs, 28800); // 8 hours
}

#[test]
fn test_token_lifetime_tier1_is_shortest_operational() {
    let c = SecurityConfig::default();
    assert!(c.token_lifetime_for_tier(1) < c.token_lifetime_for_tier(2));
    assert!(c.token_lifetime_for_tier(2) < c.token_lifetime_for_tier(3));
}

#[test]
fn test_token_lifetime_tier4_emergency_short() {
    let c = SecurityConfig::default();
    assert_eq!(c.token_lifetime_for_tier(4), 120); // 2 min
    assert!(c.token_lifetime_for_tier(4) < c.token_lifetime_for_tier(1));
}

#[test]
fn test_invalid_tier_returns_zero() {
    let c = SecurityConfig::default();
    assert_eq!(c.token_lifetime_for_tier(0), 0);
    assert_eq!(c.token_lifetime_for_tier(5), 0);
    assert_eq!(c.token_lifetime_for_tier(255), 0);
}

#[test]
fn test_max_ratchet_epochs() {
    let c = SecurityConfig::default();
    assert_eq!(c.max_ratchet_epochs(), 2880); // 28800/10
}

#[test]
fn test_level4_cooldown_is_15_min() {
    let c = SecurityConfig::default();
    assert_eq!(c.level4_cooldown_secs, 900);
}

#[test]
fn test_level4_max_per_72h() {
    let c = SecurityConfig::default();
    assert_eq!(c.level4_max_per_72h, 1);
}

#[test]
fn test_puzzle_difficulty_ddos_higher() {
    let c = SecurityConfig::default();
    assert!(c.puzzle_difficulty_ddos > c.puzzle_difficulty_normal);
}

#[test]
fn test_ratchet_epoch_zero_returns_zero_max_epochs() {
    let mut c = SecurityConfig::default();
    c.ratchet_epoch_secs = 0;
    assert_eq!(c.max_ratchet_epochs(), 0);
}

#[test]
fn test_lockout_duration_is_30_min() {
    let c = SecurityConfig::default();
    assert_eq!(c.lockout_duration_secs, 1800);
}

#[test]
fn test_max_failed_attempts_is_5() {
    let c = SecurityConfig::default();
    assert_eq!(c.max_failed_attempts, 5);
}

#[test]
fn test_ceremony_ttl_default() {
    let c = SecurityConfig::default();
    assert_eq!(c.ceremony_ttl_secs, 30);
}

#[test]
fn test_receipt_ttl_default() {
    let c = SecurityConfig::default();
    assert_eq!(c.receipt_ttl_secs, 30);
}

#[test]
fn test_share_refresh_interval_is_1h() {
    let c = SecurityConfig::default();
    assert_eq!(c.share_refresh_interval_secs, 3600);
}

#[test]
fn test_verifier_staleness_timeout_is_60s() {
    let c = SecurityConfig::default();
    assert_eq!(c.verifier_staleness_timeout_secs, 60);
}

#[test]
fn test_audit_degradation_max_is_30_min() {
    let c = SecurityConfig::default();
    assert_eq!(c.audit_degradation_max_secs, 1800);
}

#[test]
fn test_tier1_shorter_than_tier3() {
    let c = SecurityConfig::default();
    assert!(c.token_lifetime_for_tier(1) < c.token_lifetime_for_tier(3));
}

#[test]
fn test_ratchet_lookahead_is_1() {
    let c = SecurityConfig::default();
    assert_eq!(c.ratchet_lookahead_epochs, 1);
}

#[test]
fn test_ratchet_epoch_is_10s() {
    let c = SecurityConfig::default();
    assert_eq!(c.ratchet_epoch_secs, 10);
}

#[test]
fn test_session_covers_many_ratchet_epochs() {
    let c = SecurityConfig::default();
    // Session lifetime should cover significantly more than lookahead epochs
    assert!(c.max_ratchet_epochs() > c.ratchet_lookahead_epochs * 10);
}

// ── Error verbosity hardening tests ──

#[test]
fn test_default_error_level_is_warn_not_verbose() {
    // The default error level MUST be Warn (not Verbose) to prevent
    // information leakage in production deployments.
    let cfg = SecurityConfig::default();
    assert_eq!(cfg.error_level, ErrorLevel::Warn);
    assert_ne!(cfg.error_level, ErrorLevel::Verbose);
}

#[test]
fn test_error_level_config_defaults_to_verbose() {
    // The runtime ErrorLevelConfig singleton defaults to Verbose.
    let elc = ErrorLevelConfig::new();
    assert_eq!(elc.level(), ErrorLevel::Verbose);
    assert!(elc.is_verbose());
    assert!(elc.is_enabled()); // backwards-compat alias
}

#[test]
fn test_military_deployment_allows_verbose() {
    // Verbose is always allowed. Verbose errors go to the SIEM panel
    // for super admin visibility; end users see sanitized messages.
    std::env::set_var("MILNET_MILITARY_DEPLOYMENT", "1");
    let elc = ErrorLevelConfig::new();
    elc.set_level(ErrorLevel::Verbose);
    assert_eq!(elc.level(), ErrorLevel::Verbose, "verbose must be allowed in military deployment");
    assert!(elc.is_verbose());
    std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
}

#[test]
fn test_production_env_allows_verbose() {
    // Verbose is always allowed. Verbose errors go to the SIEM panel
    // for super admin visibility; end users see sanitized messages.
    std::env::set_var("MILNET_PRODUCTION", "1");
    let elc = ErrorLevelConfig::new();
    elc.set_level(ErrorLevel::Verbose);
    assert_eq!(elc.level(), ErrorLevel::Verbose, "verbose must be allowed in production");
    std::env::remove_var("MILNET_PRODUCTION");
}

#[test]
fn test_non_military_can_set_verbose_explicitly() {
    // When neither MILNET_MILITARY_DEPLOYMENT nor MILNET_PRODUCTION is set,
    // Verbose error level should be allowed.
    std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
    std::env::remove_var("MILNET_PRODUCTION");
    let elc = ErrorLevelConfig::new();
    elc.set_level(ErrorLevel::Verbose);
    assert_eq!(elc.level(), ErrorLevel::Verbose);
    assert!(elc.is_verbose());
    // Cleanup: restore to Warn
    elc.set_level(ErrorLevel::Warn);
}

#[test]
fn test_military_allows_explicit_warn() {
    // Setting Warn explicitly in military mode should succeed (it's already Warn).
    std::env::set_var("MILNET_MILITARY_DEPLOYMENT", "1");
    let elc = ErrorLevelConfig::new();
    elc.set_level(ErrorLevel::Warn);
    assert_eq!(elc.level(), ErrorLevel::Warn);
    std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
}

#[test]
fn test_error_level_from_u8_edge_cases() {
    // 0 -> Verbose, anything else -> Warn
    assert_eq!(ErrorLevel::from_u8(0), ErrorLevel::Verbose);
    assert_eq!(ErrorLevel::from_u8(1), ErrorLevel::Warn);
    assert_eq!(ErrorLevel::from_u8(2), ErrorLevel::Warn);
    assert_eq!(ErrorLevel::from_u8(u8::MAX), ErrorLevel::Warn);
}

#[test]
fn test_error_level_display() {
    assert_eq!(format!("{}", ErrorLevel::Verbose), "verbose");
    assert_eq!(format!("{}", ErrorLevel::Warn), "warn");
}

#[test]
fn test_backwards_compat_set_developer_mode_sets_verbose() {
    // set_developer_mode(true, ...) sets Verbose regardless of env.
    std::env::set_var("MILNET_MILITARY_DEPLOYMENT", "1");
    let elc = ErrorLevelConfig::new();
    elc.set_developer_mode(true, "irrelevant_proof");
    assert_eq!(elc.level(), ErrorLevel::Verbose, "developer mode must set Verbose");
    std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
}
