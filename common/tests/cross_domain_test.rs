//! Tests for the cross-domain guard module.

use common::classification::ClassificationLevel;
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

// ── Default Deny ────────────────────────────────────────────────────────────

#[test]
fn default_deny_empty_guard() {
    let guard = CrossDomainGuard::new();
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    let decision = guard.validate_transfer(&a, &b);
    assert!(!decision.allowed, "empty guard must deny all transfers");
}

#[test]
fn default_deny_registered_domains_no_rule() {
    let mut guard = CrossDomainGuard::new();
    let a = make_domain("Alpha", ClassificationLevel::Secret);
    let b = make_domain("Bravo", ClassificationLevel::Secret);
    let a_id = a.id;
    let b_id = b.id;
    guard.register_domain(a);
    guard.register_domain(b);

    let decision = guard.validate_transfer(&a_id, &b_id);
    assert!(!decision.allowed, "no rule => default deny");
    assert!(decision.reason.contains("default deny"));
}

#[test]
fn unregistered_source_denied() {
    let mut guard = CrossDomainGuard::new();
    let b = make_domain("Bravo", ClassificationLevel::Secret);
    let b_id = b.id;
    guard.register_domain(b);

    let bogus = Uuid::new_v4();
    let decision = guard.validate_transfer(&bogus, &b_id);
    assert!(!decision.allowed);
    assert!(decision.reason.contains("source domain not registered"));
}

#[test]
fn unregistered_target_denied() {
    let mut guard = CrossDomainGuard::new();
    let a = make_domain("Alpha", ClassificationLevel::Secret);
    let a_id = a.id;
    guard.register_domain(a);

    let bogus = Uuid::new_v4();
    let decision = guard.validate_transfer(&a_id, &bogus);
    assert!(!decision.allowed);
    assert!(decision.reason.contains("target domain not registered"));
}

// ── Same Domain ─────────────────────────────────────────────────────────────

#[test]
fn same_domain_always_allowed() {
    let mut guard = CrossDomainGuard::new();
    let d = make_domain("JWICS", ClassificationLevel::TopSecret);
    let id = d.id;
    guard.register_domain(d);

    let decision = guard.validate_transfer(&id, &id);
    assert!(decision.allowed);
    assert!(decision.reason.contains("intra-domain"));
}

// ── Explicit Policy Allows Transfer ─────────────────────────────────────────

#[test]
fn explicit_rule_allows_same_level_transfer() {
    let mut guard = CrossDomainGuard::new();
    let a = make_domain("SIPRNet", ClassificationLevel::Secret);
    let b = make_domain("SIPRNet-B", ClassificationLevel::Secret);
    let a_id = a.id;
    let b_id = b.id;
    guard.register_domain(a);
    guard.register_domain(b);
    guard.add_flow_rule(make_rule(
        a_id,
        b_id,
        FlowDirection::Unidirectional,
        false,
        "operational",
    ));

    let decision = guard.validate_transfer(&a_id, &b_id);
    assert!(decision.allowed);
}

#[test]
fn low_to_high_transfer_allowed_with_rule() {
    let mut guard = CrossDomainGuard::new();
    let a = make_domain("NIPRNet", ClassificationLevel::Unclassified);
    let b = make_domain("JWICS", ClassificationLevel::TopSecret);
    let a_id = a.id;
    let b_id = b.id;
    guard.register_domain(a);
    guard.register_domain(b);
    guard.add_flow_rule(make_rule(
        a_id,
        b_id,
        FlowDirection::Unidirectional,
        false,
        "upload to classified",
    ));

    let decision = guard.validate_transfer(&a_id, &b_id);
    assert!(decision.allowed, "low-to-high should be allowed");
}

// ── Declassification ────────────────────────────────────────────────────────

#[test]
fn high_to_low_without_declass_flag_denied() {
    let mut guard = CrossDomainGuard::new();
    let a = make_domain("JWICS", ClassificationLevel::TopSecret);
    let b = make_domain("NIPRNet", ClassificationLevel::Unclassified);
    let a_id = a.id;
    let b_id = b.id;
    guard.register_domain(a);
    guard.register_domain(b);
    guard.add_flow_rule(make_rule(
        a_id,
        b_id,
        FlowDirection::Unidirectional,
        false, // No declassification authorization
        "test",
    ));

    let decision = guard.validate_transfer(&a_id, &b_id);
    assert!(!decision.allowed, "high-to-low without declass must be denied");
    assert!(decision.reason.contains("declassification"));
}

#[test]
fn high_to_low_with_declass_flag_allowed() {
    let mut guard = CrossDomainGuard::new();
    let a = make_domain("JWICS", ClassificationLevel::TopSecret);
    let b = make_domain("SIPRNet", ClassificationLevel::Secret);
    let a_id = a.id;
    let b_id = b.id;
    guard.register_domain(a);
    guard.register_domain(b);
    guard.add_flow_rule(make_rule(
        a_id,
        b_id,
        FlowDirection::Unidirectional,
        true, // Declassification authorized
        "authorized review board decision",
    ));

    let decision = guard.validate_transfer(&a_id, &b_id);
    assert!(decision.allowed, "high-to-low with declass should be allowed");
}

// ── Bidirectional Rules ─────────────────────────────────────────────────────

#[test]
fn bidirectional_rule_allows_both_directions() {
    let mut guard = CrossDomainGuard::new();
    let a = make_domain("Domain-A", ClassificationLevel::Secret);
    let b = make_domain("Domain-B", ClassificationLevel::Secret);
    let a_id = a.id;
    let b_id = b.id;
    guard.register_domain(a);
    guard.register_domain(b);
    guard.add_flow_rule(make_rule(
        a_id,
        b_id,
        FlowDirection::Bidirectional,
        false,
        "peer domains",
    ));

    assert!(guard.validate_transfer(&a_id, &b_id).allowed);
    assert!(guard.validate_transfer(&b_id, &a_id).allowed);
}

#[test]
fn unidirectional_rule_does_not_allow_reverse() {
    let mut guard = CrossDomainGuard::new();
    let a = make_domain("Domain-A", ClassificationLevel::Secret);
    let b = make_domain("Domain-B", ClassificationLevel::Secret);
    let a_id = a.id;
    let b_id = b.id;
    guard.register_domain(a);
    guard.register_domain(b);
    guard.add_flow_rule(make_rule(
        a_id,
        b_id,
        FlowDirection::Unidirectional,
        false,
        "one-way",
    ));

    assert!(guard.validate_transfer(&a_id, &b_id).allowed);
    assert!(!guard.validate_transfer(&b_id, &a_id).allowed, "reverse direction must be denied");
}

// ── Rule Removal ────────────────────────────────────────────────────────────

#[test]
fn removing_rule_revokes_access() {
    let mut guard = CrossDomainGuard::new();
    let a = make_domain("A", ClassificationLevel::Secret);
    let b = make_domain("B", ClassificationLevel::Secret);
    let a_id = a.id;
    let b_id = b.id;
    guard.register_domain(a);
    guard.register_domain(b);
    guard.add_flow_rule(make_rule(a_id, b_id, FlowDirection::Unidirectional, false, "test"));

    assert!(guard.validate_transfer(&a_id, &b_id).allowed);
    assert!(guard.remove_flow_rule(&a_id, &b_id));
    assert!(!guard.validate_transfer(&a_id, &b_id).allowed, "must be denied after rule removal");
}

#[test]
fn removing_nonexistent_rule_returns_false() {
    let mut guard = CrossDomainGuard::new();
    assert!(!guard.remove_flow_rule(&Uuid::new_v4(), &Uuid::new_v4()));
}

// ── Decision Audit Logging ──────────────────────────────────────────────────

#[test]
fn decision_contains_domain_names() {
    let mut guard = CrossDomainGuard::new();
    let a = make_domain("SourceNet", ClassificationLevel::Secret);
    let b = make_domain("TargetNet", ClassificationLevel::Secret);
    let a_id = a.id;
    let b_id = b.id;
    guard.register_domain(a);
    guard.register_domain(b);

    let decision = guard.validate_transfer(&a_id, &b_id);
    assert_eq!(decision.source_domain, "SourceNet");
    assert_eq!(decision.target_domain, "TargetNet");
    assert_eq!(decision.source_classification, ClassificationLevel::Secret);
    assert_eq!(decision.target_classification, ClassificationLevel::Secret);
    assert!(decision.timestamp > 0, "decision must have a timestamp");
}

// ── Domain and Rule Counts ──────────────────────────────────────────────────

#[test]
fn domain_and_rule_counts() {
    let mut guard = CrossDomainGuard::new();
    assert_eq!(guard.domain_count(), 0);
    assert_eq!(guard.rule_count(), 0);

    let a = make_domain("A", ClassificationLevel::Secret);
    let b = make_domain("B", ClassificationLevel::Secret);
    let a_id = a.id;
    let b_id = b.id;
    guard.register_domain(a);
    guard.register_domain(b);
    assert_eq!(guard.domain_count(), 2);

    guard.add_flow_rule(make_rule(a_id, b_id, FlowDirection::Unidirectional, false, "test"));
    assert_eq!(guard.rule_count(), 1);
}
