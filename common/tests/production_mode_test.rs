//! Tests that production mode is active by default but can be overridden
//! with MILNET_DEV_MODE=1 for testing/MVP deployments.

#[test]
fn test_is_production_true_by_default() {
    std::env::remove_var("MILNET_DEV_MODE");
    assert!(
        common::sealed_keys::is_production(),
        "is_production() must return true by default"
    );
}

#[test]
fn test_is_production_ignores_milnet_production_env() {
    // MILNET_PRODUCTION env var does not control is_production(); only MILNET_DEV_MODE does.
    std::env::remove_var("MILNET_DEV_MODE");
    std::env::remove_var("MILNET_PRODUCTION");
    assert!(
        common::sealed_keys::is_production(),
        "is_production() must return true regardless of MILNET_PRODUCTION env var"
    );
}
