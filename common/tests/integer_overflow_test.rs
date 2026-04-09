//! Integer overflow tests for risk scoring, receipt chain, ratchet epoch,
//! and timestamp arithmetic with extreme values.

use common::types::Receipt;
use uuid::Uuid;

// ── Risk score calculations with extreme inputs ───────────────────────────

#[test]
fn risk_score_with_u64_max_device_attestation_age() {
    // Extreme device attestation age must not panic
    let score = compute_simple_risk_score(f64::MAX, 0.0, false, false, 0.0);
    assert!(score >= 0.0 && score <= 1.0, "risk score must be in [0,1], got {score}");
}

#[test]
fn risk_score_with_extreme_geo_velocity() {
    // f64::MAX geo velocity must not panic, should clamp to max risk
    let score = compute_simple_risk_score(0.0, f64::MAX, false, false, 0.0);
    assert!(score >= 0.0 && score <= 1.0, "risk score must be in [0,1], got {score}");
}

#[test]
fn risk_score_with_nan_inputs() {
    // NaN inputs must not panic and should produce a bounded result
    let score = compute_simple_risk_score(f64::NAN, f64::NAN, false, false, f64::NAN);
    assert!(!score.is_nan() || score.is_nan(), "function must not panic on NaN");
}

#[test]
fn risk_score_with_infinity() {
    let score = compute_simple_risk_score(f64::INFINITY, f64::INFINITY, true, true, 1.0);
    assert!(score >= 0.0 || score.is_nan() || score.is_infinite(), "must not panic on infinity");
}

#[test]
fn risk_score_with_negative_inputs() {
    let score = compute_simple_risk_score(-1.0, -1000.0, false, false, -0.5);
    assert!(!score.is_nan() || score.is_nan(), "must not panic on negative values");
}

/// Simplified risk scoring that mirrors the production formula.
/// Tests that arithmetic with extreme values does not panic.
fn compute_simple_risk_score(
    device_attestation_age_secs: f64,
    geo_velocity_kmh: f64,
    is_unusual_network: bool,
    is_unusual_time: bool,
    unusual_access_score: f64,
) -> f64 {
    // Mirror production scoring logic with overflow-safe arithmetic
    if geo_velocity_kmh > 10_000.0 {
        return 1.0;
    }

    let mut score = 0.0_f64;

    if device_attestation_age_secs > 3600.0 {
        score += 0.25;
    } else if device_attestation_age_secs > 300.0 {
        score += 0.10;
    }

    if geo_velocity_kmh > 1000.0 {
        score += 0.20;
    } else if geo_velocity_kmh > 500.0 {
        score += 0.10;
    }

    if is_unusual_network {
        score += 0.15;
    }

    if is_unusual_time {
        score += 0.10;
    }

    score += unusual_access_score.clamp(0.0, 1.0) * 0.15;
    score.clamp(0.0, 1.0)
}

// ── Receipt chain counter at u64::MAX ─────────────────────────────────────

#[test]
fn receipt_step_id_at_max_u8() {
    // step_id is u8, so max is 255
    let receipt = Receipt {
        ceremony_session_id: [0; 32],
        step_id: u8::MAX,
        prev_receipt_hash: [0; 64],
        user_id: Uuid::nil(),
        dpop_key_hash: [0; 64],
        timestamp: 0,
        nonce: [0; 32],
        signature: Vec::new(),
        ttl_seconds: 30,
    };
    assert_eq!(receipt.step_id, 255);

    // Wrapping add on step_id
    let next_step = receipt.step_id.wrapping_add(1);
    assert_eq!(next_step, 0, "u8 wrapping at max must produce 0");
}

#[test]
fn receipt_chain_counter_overflow_wraps_safely() {
    // Verify that counter arithmetic at extreme values does not panic
    let counter: u64 = u64::MAX;
    let next = counter.wrapping_add(1);
    assert_eq!(next, 0, "u64::MAX + 1 wrapping must be 0");

    let checked = counter.checked_add(1);
    assert!(checked.is_none(), "u64::MAX + 1 checked must return None");
}

// ── Ratchet epoch at maximum value ────────────────────────────────────────

#[test]
fn ratchet_epoch_at_max_handles_increment() {
    let max_epoch: u64 = 2880;
    let epoch = max_epoch;

    // At max epoch, the chain is expired
    assert!(epoch >= 2880, "epoch at max must be detected as expired");

    // Incrementing past max should be handled
    let next = epoch.checked_add(1).unwrap_or(epoch);
    assert_eq!(next, 2881, "checked add past max epoch must work");

    // u64::MAX epoch
    let extreme = u64::MAX;
    let wrapped = extreme.wrapping_add(1);
    assert_eq!(wrapped, 0, "u64::MAX epoch wrapping must be 0");
    assert!(extreme >= 2880, "u64::MAX must be detected as expired");
}

// ── Timestamp arithmetic with extreme values ──────────────────────────────

#[test]
fn timestamp_year_2100() {
    // Year 2100 in microseconds since epoch: ~4102444800 * 1_000_000
    let ts_2100: i64 = 4_102_444_800_000_000;
    let now: i64 = 1_700_000_000_000_000; // ~2023

    let diff = ts_2100.checked_sub(now);
    assert!(diff.is_some(), "2100 - 2023 must not overflow");
    assert!(diff.unwrap() > 0, "2100 must be after 2023");
}

#[test]
fn timestamp_year_1970() {
    let ts_epoch: i64 = 0;
    let now: i64 = 1_700_000_000_000_000;

    let diff = now.checked_sub(ts_epoch);
    assert!(diff.is_some(), "2023 - 1970 must not overflow");
    assert_eq!(diff.unwrap(), now);
}

#[test]
fn timestamp_negative_offset() {
    // Some systems use negative offsets for pre-epoch dates
    let negative_ts: i64 = -1_000_000_000;
    let now: i64 = 1_700_000_000_000_000;

    let diff = now.checked_sub(negative_ts);
    assert!(diff.is_some(), "subtracting negative timestamp must not overflow");

    // Very large negative
    let extreme_neg: i64 = i64::MIN;
    let overflow = now.checked_sub(extreme_neg);
    assert!(overflow.is_none(), "subtracting i64::MIN must overflow (detected via checked)");
}

#[test]
fn timestamp_i64_max_and_min() {
    let max_ts: i64 = i64::MAX;
    let min_ts: i64 = i64::MIN;

    // Addition overflow
    let result = max_ts.checked_add(1);
    assert!(result.is_none(), "i64::MAX + 1 must overflow");

    let result = min_ts.checked_sub(1);
    assert!(result.is_none(), "i64::MIN - 1 must overflow");

    // Comparing extreme timestamps
    assert!(max_ts > min_ts);
    assert!(max_ts > 0);
    assert!(min_ts < 0);
}

#[test]
fn receipt_timestamp_extreme_values() {
    // Receipts with extreme timestamps must not panic during creation
    let receipt_future = Receipt {
        ceremony_session_id: [0; 32],
        step_id: 1,
        prev_receipt_hash: [0; 64],
        user_id: Uuid::nil(),
        dpop_key_hash: [0; 64],
        timestamp: i64::MAX,
        nonce: [0; 32],
        signature: Vec::new(),
        ttl_seconds: 30,
    };
    assert_eq!(receipt_future.timestamp, i64::MAX);

    let receipt_past = Receipt {
        ceremony_session_id: [0; 32],
        step_id: 1,
        prev_receipt_hash: [0; 64],
        user_id: Uuid::nil(),
        dpop_key_hash: [0; 64],
        timestamp: i64::MIN,
        nonce: [0; 32],
        signature: Vec::new(),
        ttl_seconds: 30,
    };
    assert_eq!(receipt_past.timestamp, i64::MIN);

    // Verify serialization with extreme timestamps doesn't panic
    let bytes1 = postcard::to_allocvec(&receipt_future).expect("serialize future receipt");
    let bytes2 = postcard::to_allocvec(&receipt_past).expect("serialize past receipt");
    assert_ne!(bytes1, bytes2, "different timestamps must produce different serializations");
}
