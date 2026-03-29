//! Tests that production mode is ALWAYS active.
//!
//! There is only one mode: production. The `is_production()` function
//! unconditionally returns `true` regardless of feature flags or env vars.

#[test]
fn test_is_production_always_true() {
    assert!(
        common::sealed_keys::is_production(),
        "is_production() must ALWAYS return true — there is only production mode"
    );
}

#[test]
fn test_is_production_ignores_env_var() {
    // Even if MILNET_PRODUCTION is unset, is_production() must return true.
    std::env::remove_var("MILNET_PRODUCTION");
    assert!(
        common::sealed_keys::is_production(),
        "is_production() must return true regardless of env vars"
    );
}
