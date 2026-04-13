use stepup_mfa::*;

fn map() -> SensitivityMap {
    let mut m = SensitivityMap::default();
    m.add("POST", r"^/admin/.*", Sensitivity::Critical).unwrap();
    m.add("DELETE", r"^/api/.*", Sensitivity::High).unwrap();
    m.default = Some(Sensitivity::Low);
    m
}

#[test]
fn low_always_allowed() {
    assert_eq!(decide(&map(), "GET", "/health", None), Decision::Allow);
}

#[test]
fn critical_requires_fresh() {
    let d = decide(&map(), "POST", "/admin/users", Some(now_secs() - 3600));
    matches!(d, Decision::RequireFreshMfa { .. });
}

#[test]
fn fresh_mfa_within_window_allows() {
    assert_eq!(decide(&map(), "DELETE", "/api/x", Some(now_secs() - 60)), Decision::Allow);
}
