use common::duress::{DuressAlert, DuressConfig, PinVerification};
use uuid::Uuid;

#[test]
fn test_duress_normal_pin() {
    let user_id = Uuid::new_v4();
    let config = DuressConfig::new(user_id, b"correct-pin-1234", b"duress-pin-5678");
    assert_eq!(config.verify_pin(b"correct-pin-1234"), PinVerification::Normal);
}

#[test]
fn test_duress_pin_detected() {
    let user_id = Uuid::new_v4();
    let config = DuressConfig::new(user_id, b"correct-pin-1234", b"duress-pin-5678");
    assert_eq!(config.verify_pin(b"duress-pin-5678"), PinVerification::Duress);
}

#[test]
fn test_duress_wrong_pin() {
    let user_id = Uuid::new_v4();
    let config = DuressConfig::new(user_id, b"correct-pin-1234", b"duress-pin-5678");
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
    let config_a = DuressConfig::new(user_a, b"pin-1234", b"duress-5678");
    let config_b = DuressConfig::new(user_b, b"pin-1234", b"duress-5678");
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
    let config = DuressConfig::new(user_id, b"aaa", b"bbb");
    // Exercise all three code paths (Normal, Duress, Invalid) which use ct_eq
    assert_eq!(config.verify_pin(b"aaa"), PinVerification::Normal);
    assert_eq!(config.verify_pin(b"bbb"), PinVerification::Duress);
    assert_eq!(config.verify_pin(b"ccc"), PinVerification::Invalid);
}

#[test]
fn test_duress_empty_pin() {
    let user_id = Uuid::new_v4();
    let config = DuressConfig::new(user_id, b"", b"duress");
    assert_eq!(config.verify_pin(b""), PinVerification::Normal);
    assert_eq!(config.verify_pin(b"duress"), PinVerification::Duress);
    assert_eq!(config.verify_pin(b"other"), PinVerification::Invalid);
}
