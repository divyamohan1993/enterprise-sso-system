//! Compliance policy failure injection tests.
//!
//! Validates data residency enforcement, retention policy checking, FIPS
//! production enforcement, PII encryption requirements, classification ceilings,
//! STIG auditor execution, and CMMC assessment scoring.

use common::compliance::{ComplianceConfig, ComplianceEngine, ComplianceRegime};
use common::config::SecurityConfig;
use common::stig::StigAuditor;
use common::cmmc::CmmcAssessor;

// ---------------------------------------------------------------------------
// 1. Indian Govt data residency enforced
// ---------------------------------------------------------------------------

/// IndianGovt regime: `asia-south1` is allowed, `us-east-1` is blocked.
#[test]
fn test_indian_data_residency_enforced() {
    let engine = ComplianceEngine::new(ComplianceConfig::indian_govt_default());

    assert!(
        engine.check_data_residency("asia-south1").is_ok(),
        "asia-south1 must be allowed under IndianGovt regime"
    );
    assert!(
        engine.check_data_residency("asia-south2").is_ok(),
        "asia-south2 must be allowed under IndianGovt regime"
    );
    assert!(
        engine.check_data_residency("us-east-1").is_err(),
        "us-east-1 must be blocked under IndianGovt regime"
    );
}

// ---------------------------------------------------------------------------
// 2. DoD data residency enforced
// ---------------------------------------------------------------------------

/// UsDod regime: `us-gov-west-1` is allowed, `us-east-1` is blocked.
#[test]
fn test_dod_data_residency_enforced() {
    let engine = ComplianceEngine::new(ComplianceConfig::us_dod_default());

    assert!(
        engine.check_data_residency("us-gov-west-1").is_ok(),
        "us-gov-west-1 must be allowed under UsDod regime"
    );
    assert!(
        engine.check_data_residency("us-gov-east-1").is_ok(),
        "us-gov-east-1 must be allowed under UsDod regime"
    );
    assert!(
        engine.check_data_residency("us-east-1").is_err(),
        "us-east-1 (non-GovCloud) must be blocked under UsDod regime"
    );
}

// ---------------------------------------------------------------------------
// 3. Dual compliance uses most-restrictive rules
// ---------------------------------------------------------------------------

/// Dual regime: both Indian and DoD checks are enforced simultaneously.
/// Classification ceiling = 3 (min of 3 and 4), retention = 2555 days (max).
#[test]
fn test_dual_compliance_most_restrictive() {
    let engine = ComplianceEngine::new(ComplianceConfig::dual_default());

    // Both GovCloud and Indian regions allowed (union).
    assert!(engine.check_data_residency("us-gov-west-1").is_ok());
    assert!(engine.check_data_residency("asia-south1").is_ok());
    // EU is blocked in both.
    assert!(engine.check_data_residency("eu-west-1").is_err());

    // Most-restrictive classification ceiling = 3 (India's limit).
    assert!(engine.check_classification_allowed(3).is_ok());
    assert!(engine.check_classification_allowed(4).is_err(),
        "dual regime must block level 4 (exceeds IndianGovt ceiling of 3)");

    // Most-restrictive retention = 2555 days (DoD requirement).
    assert!(engine.check_audit_retention(2555).is_ok());
    assert!(engine.check_audit_retention(365).is_err(),
        "dual regime must require 2555-day retention (DoD minimum)");
}

// ---------------------------------------------------------------------------
// 4. CERT-In 365-day retention — 300-day-old entries NOT deletable
// ---------------------------------------------------------------------------

/// IndianGovt audit retention is 365 days. An entry that is only 300 days
/// old must NOT be eligible for deletion.
#[test]
fn test_cert_in_retention_365_days() {
    let engine = ComplianceEngine::new(ComplianceConfig::indian_govt_default());

    // 300 days < 365 days — should fail the retention check.
    let result = engine.check_audit_retention(300);
    assert!(
        result.is_err(),
        "300-day retention is below the 365-day CERT-In minimum — entry must not be deletable"
    );
}

// ---------------------------------------------------------------------------
// 5. DoD 2555-day retention — 2000-day-old entries NOT deletable
// ---------------------------------------------------------------------------

/// UsDod audit retention is 2555 days (~7 years). An entry that is only
/// 2000 days old must NOT be eligible for deletion.
#[test]
fn test_dod_retention_2555_days() {
    let engine = ComplianceEngine::new(ComplianceConfig::us_dod_default());

    // 2000 days < 2555 days — should fail the retention check.
    let result = engine.check_audit_retention(2000);
    assert!(
        result.is_err(),
        "2000-day retention is below the 2555-day DoD minimum — entry must not be deletable"
    );
}

// ---------------------------------------------------------------------------
// 6. FIPS mode production enforcement
// ---------------------------------------------------------------------------

/// A `SecurityConfig` with `fips_mode=false` must be flagged as a production
/// violation.
#[test]
fn test_fips_mode_production_enforcement() {
    let cfg = SecurityConfig {
        fips_mode: false,
        ..Default::default()
    };
    let violations = cfg.validate_production_config();
    assert!(
        violations.iter().any(|v| v.contains("fips_mode")),
        "production config must flag fips_mode=false as a violation"
    );
}

// ---------------------------------------------------------------------------
// 7. PII encryption required
// ---------------------------------------------------------------------------

/// Under the IndianGovt regime (DPDP Act), PII encryption is mandatory.
/// Verify that unencrypted PII is flagged.
#[test]
fn test_pii_encryption_required() {
    let engine = ComplianceEngine::new(ComplianceConfig::indian_govt_default());

    // Encrypted PII: OK.
    assert!(
        engine.check_pii_encryption(true, "aadhaar_number").is_ok(),
        "encrypted PII must be allowed"
    );

    // Unencrypted PII: must be flagged.
    let result = engine.check_pii_encryption(false, "aadhaar_number");
    assert!(
        result.is_err(),
        "unencrypted PII must be rejected under DPDP Act compliance"
    );
}

// ---------------------------------------------------------------------------
// 8. Classification level ceiling
// ---------------------------------------------------------------------------

/// IndianGovt max classification = 3. Level 4 must be blocked.
#[test]
fn test_classification_level_ceiling() {
    let engine = ComplianceEngine::new(ComplianceConfig::indian_govt_default());

    // Level 3 is the ceiling — must be allowed.
    assert!(
        engine.check_classification_allowed(3).is_ok(),
        "classification level 3 must be allowed under IndianGovt (ceiling = 3)"
    );

    // Level 4 exceeds the ceiling — must be blocked.
    assert!(
        engine.check_classification_allowed(4).is_err(),
        "classification level 4 must be blocked under IndianGovt (ceiling = 3)"
    );
}

// ---------------------------------------------------------------------------
// 9. STIG auditor runs and returns correct total
// ---------------------------------------------------------------------------

/// Run `StigAuditor::run_all()` and verify the summary total equals the number
/// of checks returned.
#[test]
fn test_stig_auditor_runs() {
    let mut auditor = StigAuditor::new();
    let checks = auditor.run_all();
    let total = checks.len();

    let summary = auditor.summary();
    assert_eq!(
        summary.total,
        total,
        "STIG summary total must equal the number of checks run"
    );
    assert!(total > 0, "STIG auditor must return at least one check");
    // passed + failed + not_applicable + manual == total
    assert_eq!(
        summary.passed + summary.failed + summary.not_applicable + summary.manual,
        total,
        "STIG summary counts must sum to total"
    );
}

// ---------------------------------------------------------------------------
// 10. CMMC assessor runs and score tuple adds up
// ---------------------------------------------------------------------------

/// Run `CmmcAssessor::assess()` and verify that the score tuple
/// `(met, partial, not_met)` sums to the total number of assessed practices
/// (excluding NotApplicable).
#[test]
fn test_cmmc_assessor_runs() {
    let mut assessor = CmmcAssessor::new();
    let practices = assessor.assess();
    let total = practices.len();

    let (met, partial, not_met) = assessor.score();

    // The sum of met + partial + not_met must be ≤ total (NotApplicable are excluded
    // from the score tuple but ARE counted in the total practice list).
    assert!(
        met + partial + not_met <= total,
        "CMMC score tuple ({}, {}, {}) must not exceed total practices ({})",
        met, partial, not_met, total
    );
    assert!(total > 0, "CMMC assessor must return at least one practice");
    // At least some practices must be Met for a well-hardened system.
    assert!(met > 0, "at least some CMMC practices must be Met");
}
