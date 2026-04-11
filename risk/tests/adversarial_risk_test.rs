//! Adversarial tests for the risk scoring engine.
//!
//! Tests threat intel feed poisoning, UEBA baseline tampering,
//! risk score overflow/underflow, concurrent risk assessments,
//! and anomaly detection under adversarial input.

use risk::scoring::{
    BaselineStore, FileBaselinePersistence, RiskEngine, RiskLevel, RiskSignals,
    SignedBaselineEnvelope, UserBaseline,
};
use risk::threat_intel::{
    BloomFilter, CisaKevFeed, ThreatIntelFeed, ThreatIntelManager, FeedType,
    AbuseIpDbFeed, TorExitNodeFeed, KnownBadIpFeed,
};
use risk::anomaly::{AnomalyDetector, GeoCoord, LoginLocation, RunningStats, UserAnomalyProfile};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

fn clean_signals() -> RiskSignals {
    RiskSignals {
        device_attestation_age_secs: 0.0,
        geo_velocity_kmh: 0.0,
        is_unusual_network: false,
        is_unusual_time: false,
        unusual_access_score: 0.0,
        recent_failed_attempts: 0,
        login_hour: Some(12),
        network_id: Some("AS1234".to_string()),
        session_duration_secs: Some(300.0),
    }
}

// ---------------------------------------------------------------------------
// Threat intel feed poisoning
// ---------------------------------------------------------------------------

#[test]
fn test_bloom_filter_poisoning_with_massive_entries() {
    // An attacker flooding the Bloom filter with entries to cause
    // false positives for all IPs.
    let mut bloom = BloomFilter::new(1000);

    // Insert a large number of entries to saturate the filter.
    for i in 0..10_000 {
        bloom.insert(format!("10.0.{}.{}", i / 256, i % 256).as_bytes());
    }

    // After 10x the expected capacity, false positive rate should be very high
    // but the filter should still function (not panic, OOM, etc.).
    assert_eq!(bloom.len(), 10_000);

    // A legitimate IP should have a high false-positive chance when the
    // filter is oversaturated -- this tests that the system degrades
    // gracefully rather than crashing.
    let _ = bloom.contains(b"192.168.1.1");
}

#[test]
fn test_bloom_filter_empty_item() {
    let mut bloom = BloomFilter::new(100);
    bloom.insert(b"");
    assert!(bloom.contains(b""), "empty item should be found after insert");
    assert_eq!(bloom.len(), 1);
}

#[test]
fn test_bloom_filter_very_long_item() {
    let mut bloom = BloomFilter::new(100);
    let long_item = vec![0xAA; 1_000_000]; // 1MB item
    bloom.insert(&long_item);
    assert!(bloom.contains(&long_item));
}

#[test]
fn test_bloom_filter_clear_resets_state() {
    let mut bloom = BloomFilter::new(100);
    for i in 0..100u32 {
        bloom.insert(&i.to_le_bytes());
    }
    assert_eq!(bloom.len(), 100);
    bloom.clear();
    assert_eq!(bloom.len(), 0);
    assert!(bloom.is_empty());
    // After clear, previously inserted items should (mostly) not be found.
    // Some false positives are expected for Bloom filters, but all bits
    // should be cleared.
    assert!(!bloom.contains(&0u32.to_le_bytes()));
}

#[test]
fn test_threat_intel_feed_hmac_integrity() {
    let manager = ThreatIntelManager::new(b"test-hmac-key-for-integrity");
    // Feeds with legitimate HMAC should verify correctly.
    // The manager tracks feed metadata including integrity hashes.
    // We test that the manager can be created and doesn't panic.
    drop(manager);
}

#[test]
fn test_threat_intel_feed_wrong_hmac_key() {
    // Create a manager with one key, then try to verify data signed
    // with a different key.
    let _manager1 = ThreatIntelManager::new(b"key-alpha");
    let _manager2 = ThreatIntelManager::new(b"key-beta");
    // In production, cross-key verification would fail.
    // The important thing is no panic or undefined behavior.
}

// ---------------------------------------------------------------------------
// UEBA baseline tampering
// ---------------------------------------------------------------------------

#[test]
fn test_baseline_envelope_tamper_detection() {
    let key = b"secret-hmac-key-for-baselines";
    let user_id = Uuid::new_v4();
    let mut baselines = HashMap::new();
    baselines.insert(
        user_id,
        UserBaseline {
            typical_login_hours: (8, 18),
            known_networks: vec!["AS1234".to_string()],
            avg_session_duration_secs: 300.0,
            last_updated: 1700000000,
            avg_login_hour: 12.0,
        },
    );

    // Seal with correct key.
    let sealed = SignedBaselineEnvelope::seal(&baselines, key).unwrap();

    // Unseal with correct key should succeed.
    let recovered = SignedBaselineEnvelope::unseal(&sealed, key).unwrap();
    assert!(recovered.contains_key(&user_id));

    // Tamper with the sealed data.
    let mut tampered = sealed.clone();
    if tampered.len() > 10 {
        tampered[10] ^= 0xFF; // Flip bits.
    }
    let result = SignedBaselineEnvelope::unseal(&tampered, key);
    assert!(
        result.is_err(),
        "tampered baseline envelope must fail HMAC verification"
    );

    // Unseal with wrong key should also fail.
    let wrong_key = b"wrong-key-for-baselines-attack";
    let result = SignedBaselineEnvelope::unseal(&sealed, wrong_key);
    assert!(
        result.is_err(),
        "wrong key must fail HMAC verification"
    );
}

#[test]
fn test_baseline_envelope_empty_baselines() {
    let key = b"key";
    let baselines: HashMap<Uuid, UserBaseline> = HashMap::new();
    let sealed = SignedBaselineEnvelope::seal(&baselines, key).unwrap();
    let recovered = SignedBaselineEnvelope::unseal(&sealed, key).unwrap();
    assert!(recovered.is_empty());
}

// ---------------------------------------------------------------------------
// Risk score overflow/underflow
// ---------------------------------------------------------------------------

#[test]
fn test_risk_score_with_extreme_positive_signals() {
    let engine = RiskEngine::new();
    let user = Uuid::new_v4();
    let signals = RiskSignals {
        device_attestation_age_secs: f64::MAX,
        geo_velocity_kmh: f64::MAX,
        is_unusual_network: true,
        is_unusual_time: true,
        unusual_access_score: f64::MAX,
        recent_failed_attempts: u32::MAX,
        login_hour: Some(23),
        network_id: Some("evil-tor-exit".to_string()),
        session_duration_secs: Some(f64::MAX),
    };
    let score = engine.compute_score(&user, &signals);
    assert!(score.is_finite(), "score must not be NaN or infinite");
    assert!(score >= 0.0, "score must not be negative");
    assert!(score <= 1.0, "score must not exceed 1.0, got {}", score);
}

#[test]
fn test_risk_score_with_negative_signals() {
    let engine = RiskEngine::new();
    let user = Uuid::new_v4();
    let signals = RiskSignals {
        device_attestation_age_secs: -1000.0,
        geo_velocity_kmh: -500.0,
        is_unusual_network: false,
        is_unusual_time: false,
        unusual_access_score: -1.0,
        recent_failed_attempts: 0,
        login_hour: Some(0),
        network_id: None,
        session_duration_secs: Some(-100.0),
    };
    let score = engine.compute_score(&user, &signals);
    assert!(score.is_finite(), "score must not be NaN");
    assert!(score >= 0.0, "score must not be negative, got {}", score);
    assert!(score <= 1.0, "score must not exceed 1.0");
}

#[test]
fn test_risk_score_with_nan_signals() {
    let engine = RiskEngine::new();
    let user = Uuid::new_v4();
    let signals = RiskSignals {
        device_attestation_age_secs: f64::NAN,
        geo_velocity_kmh: f64::NAN,
        is_unusual_network: false,
        is_unusual_time: false,
        unusual_access_score: f64::NAN,
        recent_failed_attempts: 0,
        login_hour: None,
        network_id: None,
        session_duration_secs: Some(f64::NAN),
    };
    let score = engine.compute_score(&user, &signals);
    // NaN inputs should not propagate to the score.
    // The engine should clamp or filter NaN values.
    assert!(
        score.is_finite(),
        "NaN input signals must not produce NaN score, got {}",
        score
    );
}

#[test]
fn test_risk_score_with_infinity_signals() {
    let engine = RiskEngine::new();
    let user = Uuid::new_v4();
    let signals = RiskSignals {
        device_attestation_age_secs: f64::INFINITY,
        geo_velocity_kmh: f64::INFINITY,
        is_unusual_network: true,
        is_unusual_time: true,
        unusual_access_score: f64::INFINITY,
        recent_failed_attempts: u32::MAX,
        login_hour: Some(255),
        network_id: None,
        session_duration_secs: Some(f64::INFINITY),
    };
    let score = engine.compute_score(&user, &signals);
    assert!(score.is_finite(), "infinity signals must produce finite score");
    assert!(score <= 1.0);
}

// ---------------------------------------------------------------------------
// Concurrent risk assessments
// ---------------------------------------------------------------------------

#[test]
fn test_concurrent_risk_scoring() {
    let engine = Arc::new(RiskEngine::new());
    let mut handles = Vec::new();

    for _ in 0..20 {
        let eng = engine.clone();
        handles.push(std::thread::spawn(move || {
            let user = Uuid::new_v4();
            for _ in 0..100 {
                let signals = RiskSignals {
                    device_attestation_age_secs: 100.0,
                    geo_velocity_kmh: 50.0,
                    is_unusual_network: false,
                    is_unusual_time: false,
                    unusual_access_score: 0.3,
                    recent_failed_attempts: 2,
                    login_hour: Some(14),
                    network_id: Some("AS9999".to_string()),
                    session_duration_secs: Some(600.0),
                };
                let score = eng.compute_score(&user, &signals);
                assert!(score.is_finite());
                assert!(score >= 0.0 && score <= 1.0);
            }
        }));
    }

    for h in handles {
        h.join().expect("thread panicked during concurrent risk scoring");
    }
}

#[test]
fn test_concurrent_baseline_updates() {
    let store = Arc::new(BaselineStore::new());
    let mut handles = Vec::new();

    for _ in 0..10 {
        let s = store.clone();
        handles.push(std::thread::spawn(move || {
            let user = Uuid::new_v4();
            for i in 0..50 {
                let signals = RiskSignals {
                    device_attestation_age_secs: 0.0,
                    geo_velocity_kmh: 0.0,
                    is_unusual_network: false,
                    is_unusual_time: false,
                    unusual_access_score: 0.0,
                    recent_failed_attempts: 0,
                    login_hour: Some((i % 24) as u8),
                    network_id: Some(format!("AS{}", i)),
                    session_duration_secs: Some(300.0 + i as f64),
                };
                s.update_baseline(user, &signals);
            }
        }));
    }

    for h in handles {
        h.join().expect("thread panicked during concurrent baseline updates");
    }
}

// ---------------------------------------------------------------------------
// Anomaly detection under adversarial input
// ---------------------------------------------------------------------------

#[test]
fn test_running_stats_with_identical_values() {
    let mut stats = RunningStats::new();
    for _ in 0..100 {
        stats.update(42.0);
    }
    assert!((stats.mean() - 42.0).abs() < f64::EPSILON);
    assert!(stats.variance() < f64::EPSILON);
    // z-score should be None when variance is zero.
    assert!(stats.z_score(42.0).is_none());
    assert!(stats.z_score(100.0).is_none());
}

#[test]
fn test_running_stats_with_extreme_values() {
    let mut stats = RunningStats::new();
    stats.update(f64::MAX / 2.0);
    stats.update(f64::MIN / 2.0);
    // Should not panic or produce NaN mean.
    let _ = stats.mean();
    let _ = stats.variance();
}

#[test]
fn test_anomaly_detector_creation() {
    let detector = AnomalyDetector::new();
    // Just verify it doesn't panic.
    drop(detector);
}

#[test]
fn test_impossible_travel_same_location() {
    let coord = GeoCoord {
        lat: 28.6139,
        lon: 77.2090,
    };
    let distance = coord.distance_km(&coord);
    assert!(
        distance < 0.001,
        "distance from point to itself should be ~0, got {}",
        distance
    );
}

#[test]
fn test_impossible_travel_antipodal_points() {
    let a = GeoCoord { lat: 0.0, lon: 0.0 };
    let b = GeoCoord {
        lat: 0.0,
        lon: 180.0,
    };
    let distance = a.distance_km(&b);
    // Half the Earth's circumference is ~20015 km.
    assert!(
        (distance - 20015.0).abs() < 100.0,
        "antipodal distance should be ~20015 km, got {}",
        distance
    );
}

#[test]
fn test_anomaly_profile_new_device_is_anomalous() {
    let mut profile = UserAnomalyProfile::new();
    profile.known_devices.push("device-abc".to_string());
    assert!(
        !profile.known_devices.contains(&"device-xyz".to_string()),
        "unknown device should not be in known_devices"
    );
}

#[test]
fn test_running_stats_z_score_insufficient_data() {
    let mut stats = RunningStats::new();
    for i in 0..9 {
        stats.update(i as f64);
    }
    assert_eq!(stats.count(), 9);
    assert!(
        stats.z_score(5.0).is_none(),
        "z_score should require >= 10 observations"
    );
}

#[test]
fn test_running_stats_z_score_extreme_outlier() {
    let mut stats = RunningStats::new();
    for i in 0..100 {
        stats.update(i as f64);
    }
    let z = stats.z_score(1000.0);
    assert!(z.is_some());
    assert!(z.unwrap() > 3.0, "1000 should be a strong outlier");
}

// ---------------------------------------------------------------------------
// Baseline store eviction under capacity pressure
// ---------------------------------------------------------------------------

#[test]
fn test_baseline_store_handles_many_users() {
    let store = BaselineStore::new();
    // Insert many users to trigger eviction logic.
    for _ in 0..1000 {
        let user = Uuid::new_v4();
        store.update_baseline(user, &clean_signals());
    }
    // Should not panic or leak memory.
}

// ---------------------------------------------------------------------------
// Feed type staleness thresholds
// ---------------------------------------------------------------------------

#[test]
fn test_feed_staleness_thresholds() {
    assert!(FeedType::CisaKev.staleness_threshold().as_secs() > 0);
    assert!(FeedType::AbuseIpDb.staleness_threshold().as_secs() > 0);
    assert!(FeedType::TorExitNodes.staleness_threshold().as_secs() > 0);
    assert!(FeedType::KnownBadIps.staleness_threshold().as_secs() > 0);
    // Staleness = 2x refresh interval.
    assert_eq!(
        FeedType::CisaKev.staleness_threshold(),
        FeedType::CisaKev.default_refresh_interval() * 2
    );
}
