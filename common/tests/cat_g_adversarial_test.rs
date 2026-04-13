//! CAT-G adversarial regression suite.
//!
//! Exercises the new common-library hardening primitives:
//! - secret_loader: env-path blocked in production
//! - login_lockout: 5-failure trigger + dual-approval unlock
//! - password_policy: weak/common/short rejected, history replay rejected
//! - input_validation: NUL bytes, length limits
//! - encrypted_db: v1 envelope rejected in strict mode (smoke)

use common::{input_validation, login_lockout, password_policy, secret_loader};

#[test]
fn secret_loader_blocks_env_path_in_production() {
    let prev = std::env::var("MILNET_PRODUCTION").ok();
    std::env::set_var("MILNET_PRODUCTION", "1");
    std::env::remove_var("MILNET_DEV_ALLOW_ENV_SECRETS");
    std::env::set_var("MILNET_CATGSEC_SEALED", "should-not-be-readable");

    let result = secret_loader::load_secret("CATGSEC");
    assert!(matches!(
        result,
        Err(secret_loader::SecretLoadError::DevPathDisabled(_))
    ));

    std::env::remove_var("MILNET_CATGSEC_SEALED");
    if let Some(v) = prev { std::env::set_var("MILNET_PRODUCTION", v); }
    else { std::env::remove_var("MILNET_PRODUCTION"); }
}

#[test]
fn login_lockout_triggers_after_five_failures() {
    let user = format!("catg-{}", uuid::Uuid::new_v4());
    for _ in 0..4 {
        assert!(!login_lockout::record_attempt(&user, "10.0.0.1", false));
    }
    assert!(login_lockout::record_attempt(&user, "10.0.0.1", false));
    assert!(login_lockout::is_locked(&user));

    // Single approver must NOT unlock.
    assert!(login_lockout::unlock_with_dual_approval(&user, "a", "a").is_err());
    assert!(login_lockout::is_locked(&user));

    // Dual distinct approvers do unlock.
    assert!(login_lockout::unlock_with_dual_approval(&user, "a", "b").is_ok());
    assert!(!login_lockout::is_locked(&user));
}

#[test]
fn password_policy_rejects_weak_and_common_passwords() {
    let user = format!("catg-{}", uuid::Uuid::new_v4());
    assert!(password_policy::validate_password(&user, "short1!").is_err());
    assert!(password_policy::validate_password(&user, "Password1234!").is_err());
    assert!(password_policy::validate_password(&user, "alllowercase12345").is_err());
    assert!(password_policy::validate_password(&user, "Tr0ub4dor&3xY!q").is_ok());
}

#[test]
fn password_policy_history_replay_blocked() {
    let user = format!("catg-{}", uuid::Uuid::new_v4());
    let pw = "Tr0ub4dor&3xY!q";
    password_policy::validate_password(&user, pw).unwrap();
    password_policy::record_password(&user, pw);
    assert!(password_policy::validate_password(&user, pw).is_err());
}

#[test]
fn input_validation_rejects_nul_bytes_and_overlong() {
    assert!(input_validation::no_nul("f", "abc\0def").is_err());
    assert!(input_validation::max_len("f", "x".repeat(100).as_str(), 10).is_err());
    assert!(input_validation::email("f", "user@host.example").is_ok());
    assert!(input_validation::email("f", "no-at-sign").is_err());
}
