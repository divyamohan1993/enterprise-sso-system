//! Bell-LaPadula cross-domain guard tests.
//!
//! Verifies that the CrossDomainGuard enforces information flow control
//! per Bell-LaPadula (BLP) mandatory access control:
//!   - Simple security property (no read up)
//!   - Star property (no write down without declassification)
//!   - Default-deny policy
//!   - Classification hierarchy ordering

use common::classification::{
    enforce_classification, enforce_no_downgrade, ClassificationDecision, ClassificationLevel,
};
use common::cross_domain::*;
use uuid::Uuid;

fn make_domain(name: &str, level: ClassificationLevel) -> SecurityDomain {
    SecurityDomain {
        id: Uuid::new_v4(),
        name: name.to_string(),
        classification: level,
    }
}

fn make_rule(
    source: Uuid,
    target: Uuid,
    direction: FlowDirection,
    declass: bool,
    justification: &str,
) -> FlowRule {
    FlowRule {
        source_domain: source,
        target_domain: target,
        direction,
        declassification_authorized: declass,
        justification: justification.to_string(),
        authorized_by: Uuid::nil(),
        created_at: 0,
    }
}

// ── BLP Simple Security Property: No Read Up ──────────────────────────────

/// Security property: An Unclassified user MUST NOT read a Secret document.
/// Bell-LaPadula "no read up" — subject clearance < resource classification => DENY.
#[test]
fn blp_unclassified_user_cannot_read_secret_document() {
    let decision = enforce_classification(
        ClassificationLevel::Unclassified,
        ClassificationLevel::Secret,
    );
    assert!(
        !decision.is_granted(),
        "BLP violation: Unclassified subject must NOT read Secret resource"
    );
    match decision {
        ClassificationDecision::Denied {
            subject_level,
            resource_level,
        } => {
            assert_eq!(subject_level, ClassificationLevel::Unclassified);
            assert_eq!(resource_level, ClassificationLevel::Secret);
        }
        _ => panic!("Expected Denied decision"),
    }
}

/// Security property: A TopSecret user CAN read all lower classifications.
/// Bell-LaPadula "no read up" — subject clearance >= resource classification => GRANT.
#[test]
fn blp_top_secret_user_can_read_all_lower_classifications() {
    let ts = ClassificationLevel::TopSecret;
    assert!(enforce_classification(ts, ClassificationLevel::Unclassified).is_granted());
    assert!(enforce_classification(ts, ClassificationLevel::Confidential).is_granted());
    assert!(enforce_classification(ts, ClassificationLevel::Secret).is_granted());
    assert!(enforce_classification(ts, ClassificationLevel::TopSecret).is_granted());
    // TopSecret cannot read SCI
    assert!(!enforce_classification(ts, ClassificationLevel::SCI).is_granted());
}

/// Security property: SCI user has full access to everything.
/// SCI is the highest classification level and dominates all others.
#[test]
fn blp_sci_user_has_full_read_access() {
    let sci = ClassificationLevel::SCI;
    assert!(enforce_classification(sci, ClassificationLevel::Unclassified).is_granted());
    assert!(enforce_classification(sci, ClassificationLevel::Confidential).is_granted());
    assert!(enforce_classification(sci, ClassificationLevel::Secret).is_granted());
    assert!(enforce_classification(sci, ClassificationLevel::TopSecret).is_granted());
    assert!(enforce_classification(sci, ClassificationLevel::SCI).is_granted());
}

// ── BLP Star Property: No Write Down ──────────────────────────────────────

/// Security property: A Secret user MUST NOT write to Unclassified (no write-down).
/// Bell-LaPadula star property prevents data leakage from higher to lower levels.
#[test]
fn blp_star_property_secret_cannot_write_to_unclassified() {
    let decision = enforce_no_downgrade(
        ClassificationLevel::Secret,
        ClassificationLevel::Unclassified,
    );
    assert!(
        !decision.is_granted(),
        "BLP star property violation: Secret data must NOT flow to Unclassified"
    );
    match decision {
        ClassificationDecision::DowngradePrevented {
            source_level,
            target_level,
        } => {
            assert_eq!(source_level, ClassificationLevel::Secret);
            assert_eq!(target_level, ClassificationLevel::Unclassified);
        }
        _ => panic!("Expected DowngradePrevented decision"),
    }
}

/// Security property: Data transfer from Secret to TopSecret IS allowed.
/// Writing up (to a higher classification) is always permitted under BLP.
#[test]
fn blp_data_transfer_secret_to_top_secret_allowed() {
    let decision = enforce_no_downgrade(
        ClassificationLevel::Secret,
        ClassificationLevel::TopSecret,
    );
    assert!(
        decision.is_granted(),
        "Writing up from Secret to TopSecret must be allowed"
    );
}

/// Security property: Data transfer from TopSecret to Secret is DENIED.
/// This is a downgrade and requires explicit declassification.
#[test]
fn blp_data_transfer_top_secret_to_secret_denied() {
    let decision = enforce_no_downgrade(
        ClassificationLevel::TopSecret,
        ClassificationLevel::Secret,
    );
    assert!(
        !decision.is_granted(),
        "TopSecret to Secret is a downgrade and must be denied"
    );
}

// ── Modify Requires Both Read and Write ───────────────────────────────────

/// Security property: Modify operation requires BOTH read and write permissions.
/// A user must have sufficient clearance to read AND the star property must allow
/// the write. For equal classifications, both conditions are met.
#[test]
fn blp_modify_requires_both_read_and_write() {
    // Secret user modifying Secret resource: needs read (>=) AND write (<=)
    let can_read = enforce_classification(
        ClassificationLevel::Secret,
        ClassificationLevel::Secret,
    )
    .is_granted();
    let can_write = enforce_no_downgrade(
        ClassificationLevel::Secret,
        ClassificationLevel::Secret,
    )
    .is_granted();
    assert!(can_read && can_write, "Modify at same level must succeed");

    // TopSecret user modifying Secret resource: can read (TS >= S) but
    // cannot write down (star property: TS -> S is downgrade)
    let can_read = enforce_classification(
        ClassificationLevel::TopSecret,
        ClassificationLevel::Secret,
    )
    .is_granted();
    let can_write = enforce_no_downgrade(
        ClassificationLevel::TopSecret,
        ClassificationLevel::Secret,
    )
    .is_granted();
    assert!(can_read, "TopSecret can read Secret");
    assert!(!can_write, "TopSecret cannot write down to Secret (star property)");
    assert!(
        !(can_read && can_write),
        "Modify denied: read OK but write-down blocked by star property"
    );
}

// ── Classification Comparison Ordering ────────────────────────────────────

/// Security property: Classification levels follow strict total ordering.
/// SCI > TopSecret > Secret > Confidential > Unclassified
#[test]
fn classification_comparison_ordering_is_strict_total_order() {
    let levels = [
        ClassificationLevel::Unclassified,
        ClassificationLevel::Confidential,
        ClassificationLevel::Secret,
        ClassificationLevel::TopSecret,
        ClassificationLevel::SCI,
    ];

    // Each level is strictly greater than all previous levels
    for i in 1..levels.len() {
        for j in 0..i {
            assert!(
                levels[i] > levels[j],
                "{:?} must be > {:?}",
                levels[i],
                levels[j]
            );
        }
    }

    // Equal comparison
    for level in &levels {
        assert_eq!(level, level);
        assert!(level >= level);
        assert!(level <= level);
    }
}

/// Security property: Classification round-trip through u8 preserves ordering.
#[test]
fn classification_u8_roundtrip_preserves_ordering() {
    for v in 0..=4u8 {
        let level = ClassificationLevel::from_u8(v).expect("valid u8");
        assert_eq!(level.as_u8(), v);
    }
    // Out-of-range values are rejected
    assert!(ClassificationLevel::from_u8(5).is_none());
    assert!(ClassificationLevel::from_u8(255).is_none());
}

// ── Cross-Domain Guard: Declassification Policies ─────────────────────────

/// Security property: High-to-low transfer through the cross-domain guard
/// requires an explicit declassification authorization flag. Even with a
/// matching flow rule, the transfer is denied if declassification_authorized
/// is false.
#[test]
fn cross_domain_guard_declassification_requires_explicit_authorization() {
    let mut guard = CrossDomainGuard::new();

    let ts_domain = make_domain("JWICS", ClassificationLevel::TopSecret);
    let s_domain = make_domain("SIPRNet", ClassificationLevel::Secret);
    let u_domain = make_domain("NIPRNet", ClassificationLevel::Unclassified);
    let ts_id = ts_domain.id;
    let s_id = s_domain.id;
    let u_id = u_domain.id;
    guard.register_domain(ts_domain);
    guard.register_domain(s_domain);
    guard.register_domain(u_domain);

    // Rule WITHOUT declassification flag: TS -> Secret
    guard.add_flow_rule(make_rule(ts_id, s_id, FlowDirection::Unidirectional, false, "no declass"));
    assert!(
        !guard.validate_transfer(&ts_id, &s_id).allowed,
        "TS->S without declass flag must be denied"
    );

    // Rule WITH declassification flag: TS -> Unclassified
    guard.add_flow_rule(make_rule(ts_id, u_id, FlowDirection::Unidirectional, true, "authorized declass"));
    assert!(
        guard.validate_transfer(&ts_id, &u_id).allowed,
        "TS->U with declass flag must be allowed"
    );
}

/// Security property: A bidirectional rule between domains of DIFFERENT
/// classifications requires declassification authorization for the high-to-low
/// direction, but not for the low-to-high direction.
#[test]
fn cross_domain_bidirectional_asymmetric_classification() {
    let mut guard = CrossDomainGuard::new();

    let s_domain = make_domain("SIPRNet", ClassificationLevel::Secret);
    let ts_domain = make_domain("JWICS", ClassificationLevel::TopSecret);
    let s_id = s_domain.id;
    let ts_id = ts_domain.id;
    guard.register_domain(s_domain);
    guard.register_domain(ts_domain);

    // Bidirectional rule WITHOUT declassification
    guard.add_flow_rule(make_rule(
        s_id,
        ts_id,
        FlowDirection::Bidirectional,
        false,
        "bidirectional no-declass",
    ));

    // Secret -> TopSecret: allowed (low to high)
    assert!(
        guard.validate_transfer(&s_id, &ts_id).allowed,
        "Secret->TopSecret should be allowed (low to high)"
    );

    // TopSecret -> Secret: denied (high to low without declass)
    assert!(
        !guard.validate_transfer(&ts_id, &s_id).allowed,
        "TopSecret->Secret without declass must be denied even with bidirectional rule"
    );
}

/// Security property: Decision metadata contains correct classification levels
/// for audit trail integrity.
#[test]
fn cross_domain_decision_metadata_correctness() {
    let mut guard = CrossDomainGuard::new();

    let src = make_domain("SourceNet", ClassificationLevel::TopSecret);
    let tgt = make_domain("TargetNet", ClassificationLevel::Confidential);
    let src_id = src.id;
    let tgt_id = tgt.id;
    guard.register_domain(src);
    guard.register_domain(tgt);

    // No rule, default deny
    let decision = guard.validate_transfer(&src_id, &tgt_id);
    assert!(!decision.allowed);
    assert_eq!(decision.source_domain, "SourceNet");
    assert_eq!(decision.target_domain, "TargetNet");
    assert_eq!(decision.source_classification, ClassificationLevel::TopSecret);
    assert_eq!(decision.target_classification, ClassificationLevel::Confidential);
    assert!(decision.timestamp > 0, "decision must carry a timestamp for audit");
}
