//! Tests that production mode is unconditionally active.

#[test]
fn test_is_production_always_true() {
    assert!(
        common::sealed_keys::is_production(),
        "is_production() must always return true"
    );
}

#[test]
fn test_is_production_ignores_milnet_production_env() {
    std::env::remove_var("MILNET_PRODUCTION");
    assert!(
        common::sealed_keys::is_production(),
        "is_production() must return true regardless of MILNET_PRODUCTION env var"
    );
}
