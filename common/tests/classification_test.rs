//! Tests for the classification labels and MAC enforcement module.

use common::classification::*;

// ── Classification Ordering Tests ──────────────────────────────────────────

#[test]
fn sci_is_highest_classification() {
    assert!(ClassificationLevel::SCI > ClassificationLevel::TopSecret);
    assert!(ClassificationLevel::SCI > ClassificationLevel::Secret);
    assert!(ClassificationLevel::SCI > ClassificationLevel::Confidential);
    assert!(ClassificationLevel::SCI > ClassificationLevel::Unclassified);
}

#[test]
fn unclassified_is_lowest() {
    assert!(ClassificationLevel::Unclassified < ClassificationLevel::Confidential);
    assert!(ClassificationLevel::Unclassified < ClassificationLevel::Secret);
    assert!(ClassificationLevel::Unclassified < ClassificationLevel::TopSecret);
    assert!(ClassificationLevel::Unclassified < ClassificationLevel::SCI);
}

#[test]
fn equal_classification_is_equal() {
    assert_eq!(ClassificationLevel::Secret, ClassificationLevel::Secret);
}

// ── Simple Security Property (No Read Up) ──────────────────────────────────

#[test]
fn unclassified_cannot_access_secret_resource() {
    let decision = enforce_classification(
        ClassificationLevel::Unclassified,
        ClassificationLevel::Secret,
    );
    assert!(!decision.is_granted());
    match decision {
        ClassificationDecision::Denied { subject_level, resource_level } => {
            assert_eq!(subject_level, ClassificationLevel::Unclassified);
            assert_eq!(resource_level, ClassificationLevel::Secret);
        }
        other => panic!("expected Denied, got {:?}", other),
    }
}

#[test]
fn confidential_cannot_access_top_secret_resource() {
    let decision = enforce_classification(
        ClassificationLevel::Confidential,
        ClassificationLevel::TopSecret,
    );
    assert!(!decision.is_granted());
}

#[test]
fn secret_can_access_secret_resource() {
    let decision = enforce_classification(
        ClassificationLevel::Secret,
        ClassificationLevel::Secret,
    );
    assert!(decision.is_granted());
}

#[test]
fn top_secret_can_access_confidential_resource() {
    let decision = enforce_classification(
        ClassificationLevel::TopSecret,
        ClassificationLevel::Confidential,
    );
    assert!(decision.is_granted());
}

#[test]
fn sci_can_access_any_resource() {
    for level in [
        ClassificationLevel::Unclassified,
        ClassificationLevel::Confidential,
        ClassificationLevel::Secret,
        ClassificationLevel::TopSecret,
        ClassificationLevel::SCI,
    ] {
        let decision = enforce_classification(ClassificationLevel::SCI, level);
        assert!(decision.is_granted(), "SCI should access {:?}", level);
    }
}

// ── Star Property (No Write Down / No Downgrade) ───────────────────────────

#[test]
fn top_secret_data_cannot_flow_to_secret_session() {
    let decision = enforce_no_downgrade(
        ClassificationLevel::TopSecret,
        ClassificationLevel::Secret,
    );
    assert!(!decision.is_granted());
    assert!(matches!(decision, ClassificationDecision::DowngradePrevented { .. }));
}

#[test]
fn secret_data_cannot_flow_to_unclassified_session() {
    let decision = enforce_no_downgrade(
        ClassificationLevel::Secret,
        ClassificationLevel::Unclassified,
    );
    assert!(!decision.is_granted());
}

#[test]
fn data_can_flow_to_same_classification() {
    let decision = enforce_no_downgrade(
        ClassificationLevel::Secret,
        ClassificationLevel::Secret,
    );
    assert!(decision.is_granted());
}

#[test]
fn data_can_flow_to_higher_classification() {
    let decision = enforce_no_downgrade(
        ClassificationLevel::Confidential,
        ClassificationLevel::TopSecret,
    );
    assert!(decision.is_granted());
}

// ── from_u8 / as_u8 ────────────────────────────────────────────────────────

#[test]
fn from_u8_valid_values() {
    assert_eq!(ClassificationLevel::from_u8(0), Some(ClassificationLevel::Unclassified));
    assert_eq!(ClassificationLevel::from_u8(1), Some(ClassificationLevel::Confidential));
    assert_eq!(ClassificationLevel::from_u8(2), Some(ClassificationLevel::Secret));
    assert_eq!(ClassificationLevel::from_u8(3), Some(ClassificationLevel::TopSecret));
    assert_eq!(ClassificationLevel::from_u8(4), Some(ClassificationLevel::SCI));
}

#[test]
fn from_u8_invalid_value_returns_none() {
    assert!(ClassificationLevel::from_u8(5).is_none());
    assert!(ClassificationLevel::from_u8(255).is_none());
}

#[test]
fn as_u8_roundtrip() {
    for v in 0..=4 {
        let level = ClassificationLevel::from_u8(v).unwrap();
        assert_eq!(level.as_u8(), v);
    }
}

// ── Default Tier Mapping ────────────────────────────────────────────────────

#[test]
fn sovereign_tier_maps_to_top_secret() {
    assert_eq!(default_classification_for_tier(1), ClassificationLevel::TopSecret);
}

#[test]
fn operational_tier_maps_to_secret() {
    assert_eq!(default_classification_for_tier(2), ClassificationLevel::Secret);
}

#[test]
fn sensor_tier_maps_to_confidential() {
    assert_eq!(default_classification_for_tier(3), ClassificationLevel::Confidential);
}

#[test]
fn emergency_tier_maps_to_unclassified() {
    assert_eq!(default_classification_for_tier(4), ClassificationLevel::Unclassified);
}

#[test]
fn unknown_tier_maps_to_unclassified() {
    assert_eq!(default_classification_for_tier(0), ClassificationLevel::Unclassified);
    assert_eq!(default_classification_for_tier(99), ClassificationLevel::Unclassified);
}

// ── Display ─────────────────────────────────────────────────────────────────

#[test]
fn classification_labels_are_human_readable() {
    assert_eq!(ClassificationLevel::Unclassified.label(), "UNCLASSIFIED");
    assert_eq!(ClassificationLevel::Confidential.label(), "CONFIDENTIAL");
    assert_eq!(ClassificationLevel::Secret.label(), "SECRET");
    assert_eq!(ClassificationLevel::TopSecret.label(), "TOP SECRET");
    assert_eq!(ClassificationLevel::SCI.label(), "SCI");
}

// ── Serde Round-Trip ────────────────────────────────────────────────────────

#[test]
fn classification_serde_roundtrip() {
    for v in 0..=4 {
        let level = ClassificationLevel::from_u8(v).unwrap();
        let bytes = postcard::to_allocvec(&level).expect("serialize");
        let decoded: ClassificationLevel = postcard::from_bytes(&bytes).expect("deserialize");
        assert_eq!(decoded, level);
    }
}
