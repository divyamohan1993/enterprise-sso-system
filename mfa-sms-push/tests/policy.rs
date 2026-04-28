use mfa_sms_push::{RiskTierForSms, SmsPolicy, SmsPolicyContext};

fn ctx(hw: bool, risk: RiskTierForSms, ha: bool) -> SmsPolicyContext {
    SmsPolicyContext {
        has_hardware_factor: hw,
        risk,
        require_high_assurance: ha,
    }
}

#[test]
fn allows_normal_risk_no_hw_no_ha() {
    assert!(SmsPolicy::evaluate(ctx(false, RiskTierForSms::Normal, false)).allowed());
}

#[test]
fn denies_when_hardware_factor_enrolled() {
    assert!(!SmsPolicy::evaluate(ctx(true, RiskTierForSms::Normal, false)).allowed());
}

#[test]
fn denies_when_high_assurance_required() {
    assert!(!SmsPolicy::evaluate(ctx(false, RiskTierForSms::Normal, true)).allowed());
}

#[test]
fn denies_when_risk_above_normal() {
    for r in [
        RiskTierForSms::Elevated,
        RiskTierForSms::High,
        RiskTierForSms::Critical,
    ] {
        assert!(
            !SmsPolicy::evaluate(ctx(false, r, false)).allowed(),
            "SMS must be denied at risk tier {:?}",
            r
        );
    }
}

#[test]
fn denies_when_combination_of_factors() {
    assert!(!SmsPolicy::evaluate(ctx(true, RiskTierForSms::Elevated, true)).allowed());
}
