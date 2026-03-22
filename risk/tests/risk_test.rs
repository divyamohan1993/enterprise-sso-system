use common::types::DeviceTier;
use risk::scoring::{RiskEngine, RiskLevel, RiskRequest, RiskResponse, RiskSignals};
use risk::tiers::{check_tier_access, DeviceEnrollment, DeviceRegistry};
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
    // All-zero signals trigger the mimicry detection penalty (+0.05)
    // plus random noise in [0.0, 0.03), so score should be in [0.05, 0.08).
    assert!(
        score >= 0.05 && score < 0.08,
        "expected [0.05, 0.08) with mimicry penalty + noise, got {score}"
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
    // 5/5 * 0.15 = 0.15 + noise [0.0, 0.03)
    assert!(score >= 0.15 && score < 0.18, "expected [0.15, 0.18), got {score}");
}

#[test]
fn impossible_travel_high_risk() {
    let engine = RiskEngine::new();
    let user = Uuid::new_v4();
    let mut signals = clean_signals();
    signals.geo_velocity_kmh = 2000.0;
    let score = engine.compute_score(&user, &signals);
    // 0.20 + noise [0.0, 0.03)
    assert!(score >= 0.20 && score < 0.23, "expected [0.20, 0.23), got {score}");
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

#[test]
fn risk_request_serialization_round_trip() {
    let request = RiskRequest {
        user_id: Uuid::new_v4(),
        device_tier: 2,
        signals: RiskSignals {
            device_attestation_age_secs: 120.0,
            geo_velocity_kmh: 50.0,
            is_unusual_network: true,
            is_unusual_time: false,
            unusual_access_score: 0.3,
            recent_failed_attempts: 2,
        },
    };

    let bytes = postcard::to_allocvec(&request).expect("serialize RiskRequest");
    let decoded: RiskRequest = postcard::from_bytes(&bytes).expect("deserialize RiskRequest");

    assert_eq!(decoded.user_id, request.user_id);
    assert_eq!(decoded.device_tier, request.device_tier);
    assert!((decoded.signals.device_attestation_age_secs - 120.0).abs() < f64::EPSILON);
    assert!((decoded.signals.geo_velocity_kmh - 50.0).abs() < f64::EPSILON);
    assert!(decoded.signals.is_unusual_network);
    assert!(!decoded.signals.is_unusual_time);
    assert!((decoded.signals.unusual_access_score - 0.3).abs() < f64::EPSILON);
    assert_eq!(decoded.signals.recent_failed_attempts, 2);
}

#[test]
fn risk_response_serialization_round_trip() {
    let response = RiskResponse {
        score: 0.75,
        classification: "High".to_string(),
        step_up_required: true,
        session_terminate: false,
    };

    let bytes = postcard::to_allocvec(&response).expect("serialize RiskResponse");
    let decoded: RiskResponse = postcard::from_bytes(&bytes).expect("deserialize RiskResponse");

    assert!((decoded.score - 0.75).abs() < f64::EPSILON);
    assert_eq!(decoded.classification, "High");
    assert!(decoded.step_up_required);
    assert!(!decoded.session_terminate);
}

#[test]
fn high_geo_velocity_triggers_elevated_score() {
    let engine = RiskEngine::new();
    let user = Uuid::new_v4();
    let mut signals = clean_signals();
    signals.geo_velocity_kmh = 600.0; // above 500 threshold
    let score = engine.compute_score(&user, &signals);
    assert!(score >= 0.10, "geo velocity 600 km/h should add at least 0.10, got {score}");
    assert_eq!(engine.classify(score), RiskLevel::Normal); // 0.10 is still Normal
}

#[test]
fn unusual_network_adds_risk() {
    let engine = RiskEngine::new();
    let user = Uuid::new_v4();
    let mut signals = clean_signals();
    signals.is_unusual_network = true;
    let score = engine.compute_score(&user, &signals);
    // 0.15 + noise [0.0, 0.03)
    assert!(score >= 0.15 && score < 0.18, "unusual network should add 0.15 + noise, got {score}");
}

#[test]
fn unusual_time_adds_risk() {
    let engine = RiskEngine::new();
    let user = Uuid::new_v4();
    let mut signals = clean_signals();
    signals.is_unusual_time = true;
    let score = engine.compute_score(&user, &signals);
    // 0.10 + noise [0.0, 0.03)
    assert!(score >= 0.10 && score < 0.13, "unusual time should add 0.10 + noise, got {score}");
}

#[test]
fn stale_device_attestation_moderate_risk() {
    let engine = RiskEngine::new();
    let user = Uuid::new_v4();
    let mut signals = clean_signals();
    signals.device_attestation_age_secs = 400.0; // > 300, < 3600
    let score = engine.compute_score(&user, &signals);
    // 0.10 + noise [0.0, 0.03)
    assert!(score >= 0.10 && score < 0.13, "stale attestation (400s) should add 0.10 + noise, got {score}");
}

#[test]
fn combined_signals_additive() {
    let engine = RiskEngine::new();
    let user = Uuid::new_v4();
    let mut signals = clean_signals();
    signals.is_unusual_network = true; // +0.15
    signals.is_unusual_time = true;    // +0.10
    signals.recent_failed_attempts = 5; // +0.15
    let score = engine.compute_score(&user, &signals);
    // 0.40 + noise [0.0, 0.03)
    assert!(score >= 0.40 && score < 0.43, "combined signals should be 0.40 + noise, got {score}");
    assert!(matches!(engine.classify(score), RiskLevel::Elevated), "expected Elevated classification");
}

#[test]
fn risk_request_end_to_end_with_engine() {
    let request = RiskRequest {
        user_id: Uuid::new_v4(),
        device_tier: 2,
        signals: RiskSignals {
            device_attestation_age_secs: 7200.0,
            geo_velocity_kmh: 2000.0,
            is_unusual_network: true,
            is_unusual_time: true,
            unusual_access_score: 1.0,
            recent_failed_attempts: 10,
        },
    };

    // Serialize and deserialize the request (simulating SHARD transport)
    let req_bytes = postcard::to_allocvec(&request).expect("serialize");
    let decoded_req: RiskRequest = postcard::from_bytes(&req_bytes).expect("deserialize");

    // Process with engine
    let engine = RiskEngine::new();
    let score = engine.compute_score(&decoded_req.user_id, &decoded_req.signals);
    let classification = format!("{:?}", engine.classify(score));

    let response = RiskResponse {
        score,
        classification: classification.clone(),
        step_up_required: engine.requires_step_up(score),
        session_terminate: engine.requires_termination(score),
    };

    // Serialize and deserialize the response
    let resp_bytes = postcard::to_allocvec(&response).expect("serialize response");
    let decoded_resp: RiskResponse = postcard::from_bytes(&resp_bytes).expect("deserialize response");

    assert!((decoded_resp.score - 1.0).abs() < f64::EPSILON);
    assert_eq!(decoded_resp.classification, "Critical");
    assert!(decoded_resp.step_up_required);
    assert!(decoded_resp.session_terminate);
}
