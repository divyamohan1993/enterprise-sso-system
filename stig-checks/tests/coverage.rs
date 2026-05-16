use stig_checks::*;

#[test]
fn at_least_three_hundred_checks() {
    let e = StigEvaluator::known_good_baseline();
    let c = e.run();
    assert!(c.len() >= 300, "expected ≥ 300 checks, got {}", c.len());
}

#[test]
fn known_good_baseline_passes_evaluated_controls() {
    let e = StigEvaluator::known_good_baseline();
    let c = e.run();
    let card = score(&c);
    assert!(
        card.failed == 0,
        "known-good baseline should pass all evaluated checks, failed={}",
        card.failed
    );
}

#[test]
fn templated_controls_are_not_checked_never_passed() {
    // Derived controls are not individually inspected: they must report
    // NotChecked, never a fabricated Pass.
    let e = StigEvaluator::known_good_baseline();
    let templated = e
        .run()
        .into_iter()
        .filter(|c| c.title.contains("derived"))
        .collect::<Vec<_>>();
    assert!(templated.len() >= 300);
    assert!(
        templated.iter().all(|c| c.outcome == Outcome::NotChecked),
        "derived controls must never auto-Pass"
    );
}

#[test]
fn undetermined_value_is_not_checked_not_passed() {
    // An empty evaluator has observed nothing: every hand-coded control must
    // be NotChecked, and the binary's pass count must be zero.
    let e = StigEvaluator::default();
    let card = score(&e.run());
    assert_eq!(card.passed, 0, "nothing observed must yield zero passes");
    assert_eq!(card.failed, 0);
}

#[test]
fn xccdf_is_well_formed_xml_root() {
    let e = StigEvaluator::known_good_baseline();
    let xccdf = render_xccdf(&e.run());
    assert!(xccdf.starts_with("<?xml"));
    assert!(xccdf.contains("<Benchmark"));
    assert!(xccdf.ends_with("</Benchmark>\n"));
}

#[test]
fn weakened_password_fails_catI() {
    let mut e = StigEvaluator::known_good_baseline();
    e.password_min_length = Some(8);
    let c = e.run();
    let f = c.iter().find(|c| c.stig_id == "APP-IA-000010").unwrap();
    assert_eq!(f.outcome, Outcome::Fail);
    assert_eq!(f.severity, Severity::CatI);
}
