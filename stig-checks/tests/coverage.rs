use stig_checks::*;

#[test]
fn at_least_three_hundred_checks() {
    let e = StigEvaluator::default();
    let c = e.run();
    assert!(c.len() >= 300, "expected ≥ 300 checks, got {}", c.len());
}

#[test]
fn defaults_pass_critical_controls() {
    let e = StigEvaluator::default();
    let c = e.run();
    let card = score(&c);
    assert!(card.failed == 0, "default config should pass all evaluated checks, failed={}", card.failed);
}

#[test]
fn xccdf_is_well_formed_xml_root() {
    let e = StigEvaluator::default();
    let xccdf = render_xccdf(&e.run());
    assert!(xccdf.starts_with("<?xml"));
    assert!(xccdf.contains("<Benchmark"));
    assert!(xccdf.ends_with("</Benchmark>\n"));
}

#[test]
fn weakened_password_fails_catI() {
    let mut e = StigEvaluator::default();
    e.password_min_length = 8;
    let c = e.run();
    let f = c.iter().find(|c| c.stig_id == "APP-IA-000010").unwrap();
    assert_eq!(f.outcome, Outcome::Fail);
    assert_eq!(f.severity, Severity::CatI);
}
