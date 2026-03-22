use common::config::SecurityConfig;

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
    assert_eq!(c.max_ratchet_epochs(), 960); // 28800/30
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
fn test_ratchet_lookahead_is_3() {
    let c = SecurityConfig::default();
    assert_eq!(c.ratchet_lookahead_epochs, 3);
}

#[test]
fn test_session_covers_many_ratchet_epochs() {
    let c = SecurityConfig::default();
    // Session lifetime should cover significantly more than lookahead epochs
    assert!(c.max_ratchet_epochs() > c.ratchet_lookahead_epochs * 10);
}
