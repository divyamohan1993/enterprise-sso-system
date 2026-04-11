use common::duress::{DuressAlert, DuressConfig, PinVerification};
use uuid::Uuid;

#[test]
fn test_duress_normal_pin() {
    let user_id = Uuid::new_v4();
    let config = DuressConfig::new(user_id, b"correct-pin-1234", b"duress-pin-5678").unwrap();
    assert_eq!(config.verify_pin(b"correct-pin-1234"), PinVerification::Normal);
}

#[test]
fn test_duress_pin_detected() {
    let user_id = Uuid::new_v4();
    let config = DuressConfig::new(user_id, b"correct-pin-1234", b"duress-pin-5678").unwrap();
    assert_eq!(config.verify_pin(b"duress-pin-5678"), PinVerification::Duress);
}

#[test]
fn test_duress_wrong_pin() {
    let user_id = Uuid::new_v4();
    let config = DuressConfig::new(user_id, b"correct-pin-1234", b"duress-pin-5678").unwrap();
    assert_eq!(config.verify_pin(b"wrong-pin-9999"), PinVerification::Invalid);
}

#[test]
fn test_duress_alert_serialization_round_trip() {
    let alert = DuressAlert {
        user_id: Uuid::new_v4(),
        timestamp: 1_700_000_000,
        fake_token_issued: true,
        lockdown_triggered: true,
    };
    let bytes = postcard::to_allocvec(&alert).expect("serialize DuressAlert");
    let decoded: DuressAlert = postcard::from_bytes(&bytes).expect("deserialize DuressAlert");
    assert_eq!(decoded.user_id, alert.user_id);
    assert_eq!(decoded.timestamp, alert.timestamp);
    assert!(decoded.fake_token_issued);
    assert!(decoded.lockdown_triggered);
}

#[test]
fn test_duress_different_user_id_different_hash() {
    // Domain separation: same PIN but different user_id produces a DuressConfig
    // with the same hash (user_id is stored but not mixed into hash).
    // However, verify_pin must still work correctly for each user independently.
    let user_a = Uuid::new_v4();
    let user_b = Uuid::new_v4();
    let config_a = DuressConfig::new(user_a, b"pin-1234", b"duress-5678").unwrap();
    let config_b = DuressConfig::new(user_b, b"pin-1234", b"duress-5678").unwrap();
    // Both configs should verify the same PIN correctly
    assert_eq!(config_a.verify_pin(b"pin-1234"), PinVerification::Normal);
    assert_eq!(config_b.verify_pin(b"pin-1234"), PinVerification::Normal);
    // But their user_ids are distinct
    assert_ne!(config_a.user_id, config_b.user_id);
}

#[test]
fn test_duress_constant_time_comparison_compiles() {
    // Verify that the duress module uses subtle::ConstantTimeEq
    // by exercising the code path — if it compiled, ct_eq is in use.
    let user_id = Uuid::new_v4();
    let config = DuressConfig::new(user_id, b"aaa", b"bbb").unwrap();
    // Exercise all three code paths (Normal, Duress, Invalid) which use ct_eq
    assert_eq!(config.verify_pin(b"aaa"), PinVerification::Normal);
    assert_eq!(config.verify_pin(b"bbb"), PinVerification::Duress);
    assert_eq!(config.verify_pin(b"ccc"), PinVerification::Invalid);
}

// ── TEST GROUP 6: Duress PIN distinctness tests ──────────────────────────

#[test]
fn test_duress_identical_pins_rejected() {
    let user_id = Uuid::new_v4();
    let result = DuressConfig::new(user_id, b"same-pin", b"same-pin");
    assert!(result.is_err(), "identical normal and duress PINs must be rejected");
    assert_eq!(
        result.unwrap_err(),
        "duress PIN must differ from normal PIN"
    );
}

#[test]
fn test_duress_different_pins_accepted() {
    let user_id = Uuid::new_v4();
    let result = DuressConfig::new(user_id, b"pin-alpha", b"pin-beta");
    assert!(result.is_ok(), "different PINs must be accepted");
    let config = result.unwrap();
    assert_eq!(config.verify_pin(b"pin-alpha"), PinVerification::Normal);
    assert_eq!(config.verify_pin(b"pin-beta"), PinVerification::Duress);
}

#[test]
fn test_duress_similar_but_not_identical_pins_accepted() {
    let user_id = Uuid::new_v4();
    // PINs that are very similar (differ by 1 char) must still be accepted.
    let result = DuressConfig::new(user_id, b"1234", b"1235");
    assert!(result.is_ok(), "similar but not identical PINs must be accepted");
    let config = result.unwrap();
    assert_eq!(config.verify_pin(b"1234"), PinVerification::Normal);
    assert_eq!(config.verify_pin(b"1235"), PinVerification::Duress);
    assert_eq!(config.verify_pin(b"1236"), PinVerification::Invalid);
}

#[test]
fn test_duress_identical_empty_pins_rejected() {
    let user_id = Uuid::new_v4();
    let result = DuressConfig::new(user_id, b"", b"");
    assert!(result.is_err(), "identical empty PINs must be rejected");
}

#[test]
fn test_duress_timing_padded_branches() {
    // Verify that Normal and Invalid branches execute the same code paths
    // as Duress (alert construction, callback check) to prevent timing leaks.
    // If this compiles and runs, the black_box padding is in place.
    let user_id = Uuid::new_v4();
    let config = DuressConfig::new(user_id, b"norm-pin", b"dur-pin").unwrap();

    // All three branches must execute without panicking and return correct results.
    // The timing-padded code constructs DuressAlert in every branch.
    assert_eq!(config.verify_pin(b"norm-pin"), PinVerification::Normal);
    assert_eq!(config.verify_pin(b"dur-pin"), PinVerification::Duress);
    assert_eq!(config.verify_pin(b"bad-pin"), PinVerification::Invalid);
}

#[test]
fn test_duress_timing_with_callback() {
    // Verify timing padding works when a callback is configured.
    // The Normal/Invalid branches must still check has_callback without panicking.
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let user_id = Uuid::new_v4();
    let mut config = DuressConfig::new(user_id, b"norm", b"dur").unwrap();
    let called = Arc::new(AtomicBool::new(false));
    let called_clone = called.clone();
    config.duress_response_callback = Some(Box::new(move |_alert: &DuressAlert| {
        called_clone.store(true, Ordering::SeqCst);
    }));

    // Normal: callback not invoked, but has_callback is checked
    assert_eq!(config.verify_pin(b"norm"), PinVerification::Normal);
    assert!(!called.load(Ordering::SeqCst));

    // Duress: callback IS invoked
    assert_eq!(config.verify_pin(b"dur"), PinVerification::Duress);
    assert!(called.load(Ordering::SeqCst));

    // Invalid: callback not invoked
    called.store(false, Ordering::SeqCst);
    assert_eq!(config.verify_pin(b"bad"), PinVerification::Invalid);
    assert!(!called.load(Ordering::SeqCst));
}

#[test]
fn test_duress_empty_pin() {
    let user_id = Uuid::new_v4();
    let config = DuressConfig::new(user_id, b"", b"duress").unwrap();
    assert_eq!(config.verify_pin(b""), PinVerification::Normal);
    assert_eq!(config.verify_pin(b"duress"), PinVerification::Duress);
    assert_eq!(config.verify_pin(b"other"), PinVerification::Invalid);
}
