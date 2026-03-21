use milnet_common::types::DeviceTier;
use milnet_risk::scoring::{RiskEngine, RiskLevel, RiskSignals};
use milnet_risk::tiers::{check_tier_access, DeviceEnrollment, DeviceRegistry};
use uuid::Uuid;

fn clean_signals() -> RiskSignals {
    RiskSignals {
        device_attestation_age_secs: 0.0,
        geo_velocity_kmh: 0.0,
        is_unusual_network: false,
        is_unusual_time: false,
        unusual_access_score: 0.0,
        recent_failed_attempts: 0,
    }
}

fn max_risk_signals() -> RiskSignals {
    RiskSignals {
        device_attestation_age_secs: 7200.0,
        geo_velocity_kmh: 2000.0,
        is_unusual_network: true,
        is_unusual_time: true,
        unusual_access_score: 1.0,
        recent_failed_attempts: 10,
    }
}

#[test]
fn zero_risk_signals_score_zero() {
    let engine = RiskEngine::new();
    let user = Uuid::new_v4();
    let score = engine.compute_score(&user, &clean_signals());
    assert!(
        (score - 0.0).abs() < f64::EPSILON,
        "expected 0.0, got {score}"
    );
}

#[test]
fn max_risk_signals_score_one() {
    let engine = RiskEngine::new();
    let user = Uuid::new_v4();
    let score = engine.compute_score(&user, &max_risk_signals());
    // 0.25 + 0.20 + 0.15 + 0.10 + 0.15 + 0.15 = 1.0
    assert!(
        (score - 1.0).abs() < f64::EPSILON,
        "expected 1.0, got {score}"
    );
}

#[test]
fn failed_attempts_increase_risk() {
    let engine = RiskEngine::new();
    let user = Uuid::new_v4();
    let mut signals = clean_signals();
    signals.recent_failed_attempts = 5;
    let score = engine.compute_score(&user, &signals);
    // 5/5 * 0.15 = 0.15
    assert!((score - 0.15).abs() < 0.001, "expected ~0.15, got {score}");
}

#[test]
fn impossible_travel_high_risk() {
    let engine = RiskEngine::new();
    let user = Uuid::new_v4();
    let mut signals = clean_signals();
    signals.geo_velocity_kmh = 2000.0;
    let score = engine.compute_score(&user, &signals);
    assert!((score - 0.20).abs() < 0.001, "expected ~0.20, got {score}");
}

#[test]
fn classify_levels() {
    let engine = RiskEngine::new();
    assert_eq!(engine.classify(0.0), RiskLevel::Normal);
    assert_eq!(engine.classify(0.29), RiskLevel::Normal);
    assert_eq!(engine.classify(0.3), RiskLevel::Elevated);
    assert_eq!(engine.classify(0.59), RiskLevel::Elevated);
    assert_eq!(engine.classify(0.6), RiskLevel::High);
    assert_eq!(engine.classify(0.79), RiskLevel::High);
    assert_eq!(engine.classify(0.8), RiskLevel::Critical);
    assert_eq!(engine.classify(1.0), RiskLevel::Critical);
}

#[test]
fn step_up_required_at_06() {
    let engine = RiskEngine::new();
    assert!(!engine.requires_step_up(0.59));
    assert!(engine.requires_step_up(0.6));
    assert!(engine.requires_step_up(0.9));
}

#[test]
fn termination_at_08() {
    let engine = RiskEngine::new();
    assert!(!engine.requires_termination(0.79));
    assert!(engine.requires_termination(0.8));
    assert!(engine.requires_termination(1.0));
}

#[test]
fn tier_sovereign_accesses_all() {
    assert!(check_tier_access(DeviceTier::Sovereign, DeviceTier::Sovereign).is_ok());
    assert!(check_tier_access(DeviceTier::Sovereign, DeviceTier::Operational).is_ok());
    assert!(check_tier_access(DeviceTier::Sovereign, DeviceTier::Sensor).is_ok());
    assert!(check_tier_access(DeviceTier::Sovereign, DeviceTier::Emergency).is_ok());
}

#[test]
fn tier_sensor_cannot_access_operational() {
    assert!(check_tier_access(DeviceTier::Sensor, DeviceTier::Operational).is_err());
}

#[test]
fn device_registry_enroll_and_lookup() {
    let mut registry = DeviceRegistry::new();
    let device_id = Uuid::new_v4();
    let enrolled_by = Uuid::new_v4();

    registry.enroll(DeviceEnrollment {
        device_id,
        tier: DeviceTier::Operational,
        attestation_hash: [0xAA; 32],
        enrolled_by,
        is_active: true,
    });

    let device = registry.lookup(&device_id).expect("device should exist");
    assert_eq!(device.tier, DeviceTier::Operational);
    assert!(device.is_active);
    assert_eq!(device.enrolled_by, enrolled_by);
}

#[test]
fn device_registry_revoke() {
    let mut registry = DeviceRegistry::new();
    let device_id = Uuid::new_v4();

    registry.enroll(DeviceEnrollment {
        device_id,
        tier: DeviceTier::Sensor,
        attestation_hash: [0xBB; 32],
        enrolled_by: Uuid::new_v4(),
        is_active: true,
    });

    assert!(registry.revoke(&device_id));
    let device = registry.lookup(&device_id).expect("device should exist");
    assert!(!device.is_active);

    // Revoking non-existent device returns false
    assert!(!registry.revoke(&Uuid::new_v4()));
}
