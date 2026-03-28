//! Tests for compile-time production mode flag.

#[test]
fn test_is_production_returns_compile_time_value() {
    let result = common::sealed_keys::is_production();
    #[cfg(feature = "production")]
    assert!(result, "is_production() must return true when 'production' feature is enabled");
    #[cfg(not(feature = "production"))]
    assert!(!result, "is_production() must return false when 'production' feature is disabled");
}

#[test]
fn test_is_production_ignores_env_var() {
    std::env::set_var("MILNET_PRODUCTION", "1");
    let result = common::sealed_keys::is_production();
    #[cfg(not(feature = "production"))]
    assert!(!result, "env var must NOT override compile-time flag");
    std::env::remove_var("MILNET_PRODUCTION");
}
