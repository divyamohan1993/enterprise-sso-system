use common::duress::{DuressConfig, PinVerification};
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
