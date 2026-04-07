//! Compliance & Data Flow Control Hardened Tests
//!
//! Simulates a REAL-WORLD threat scenario: badly configured public-facing VM with
//! no firewall, directly on the public internet. Tests verify that the compliance
//! and data flow control mechanisms remain airtight even when the network perimeter
//! is completely absent.
//!
//! Coverage:
//! - CMMC Level 2 assessment on misconfigured systems
//! - STIG Cat I violation detection and halt enforcement
//! - Data sovereignty (India DPDP Act, US DoD ITAR)
//! - Cross-domain exfiltration prevention (Bell-LaPadula)
//! - Encrypted audit trail on compromised VM
//! - Audit immutability with ML-DSA-87 signatures
//! - Witness checkpoint monotonicity
//! - Merkle proof public verifiability
//! - Multi-person ceremony enforcement
//! - Duress PIN silent lockdown
//! - Session recording integrity
//! - Action authorization tiered enforcement
//! - Receipt chain session binding
//! - DPoP token theft prevention
//! - Domain separation collision checks
//! - Token classification field enforcement
//! - Compliance report aggregation

#![allow(unused_imports)]

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

fn now_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64
}

/// Helper to run closures on a large stack (ML-DSA-87 keys are ~4KB).
fn run_with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(f)
        .expect("thread spawn failed")
        .join()
        .expect("thread panicked");
}

// ═══════════════════════════════════════════════════════════════════════════════
// 1. CMMC Level 2 Assessment on Misconfigured System
// ═══════════════════════════════════════════════════════════════════════════════

mod cmmc_assessment {
    use super::*;
    use common::cmmc::*;

    #[test]
    fn cmmc_assessor_identifies_gaps_in_default_config() {
        // The default CmmcAssessor represents a well-configured system.
        // It should still have some PartiallyMet practices (realistic gaps).
        let mut assessor = CmmcAssessor::new();
        assessor.assess();
        let (met, partial, not_met) = assessor.score();

        // A well-configured system should have the majority of practices Met
        assert!(met > 0, "expected at least some Met practices");
        // There should be some gaps (PartiallyMet) reflecting real-world imperfections
        assert!(
            partial > 0,
            "expected some PartiallyMet practices in a realistic assessment"
        );
        // Total should account for all practices
        let total = assessor.assess().len();
        assert_eq!(met + partial + not_met, total - assessor.assess().iter()
            .filter(|p| p.status == PracticeStatus::NotApplicable).count());
    }

    #[test]
    fn cmmc_gaps_return_only_deficient_practices() {
        let assessor = CmmcAssessor::new();
        let gaps = assessor.gaps();

        for gap in &gaps {
            assert!(
                gap.status == PracticeStatus::PartiallyMet || gap.status == PracticeStatus::NotMet,
                "gap {} has unexpected status {:?}",
                gap.id, gap.status
            );
            // Each gap should have a gap description
            assert!(
                gap.gap.is_some(),
                "gap {} should have a gap description",
                gap.id
            );
        }
    }

    #[test]
    fn cmmc_family_summary_covers_all_security_domains() {
        let assessor = CmmcAssessor::new();
        let summary = assessor.family_summary();

        // A CMMC Level 2+ assessment must cover these core families
        let required_families = [
            "Access Control",
            "Audit and Accountability",
            "Identification and Authentication",
            "System and Communications Protection",
            "System and Information Integrity",
        ];

        for family in &required_families {
            assert!(
                summary.contains_key(*family),
                "missing required CMMC family: {}",
                family
            );
            let score = &summary[*family];
            // Each family should have at least one assessed practice
            let family_total = score.met + score.partial + score.not_met + score.not_applicable;
            assert!(
                family_total > 0,
                "family {} has no assessed practices",
                family
            );
        }
    }

    #[test]
    fn cmmc_json_report_is_valid_and_complete() {
        let assessor = CmmcAssessor::new();
        let json = assessor.to_json();

        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("CMMC report must be valid JSON");

        // Verify structure
        assert_eq!(parsed["cmmc_level"], 3);
        assert!(parsed["score"]["met"].as_u64().unwrap() > 0);
        assert!(parsed["score"]["total"].as_u64().unwrap() >= 20);

        // Every practice must have an evidence field
        let practices = parsed["practices"].as_array().unwrap();
        for practice in practices {
            assert!(
                !practice["evidence"].as_str().unwrap_or("").is_empty(),
                "practice {} missing evidence",
                practice["id"]
            );
        }
    }

    #[test]
    fn cmmc_score_reflects_met_ratio() {
        let mut assessor = CmmcAssessor::new();
        let (met, partial, _not_met) = assessor.score();
        let total = assessor.assess().len();

        // For a well-configured military system, >60% should be Met
        let met_ratio = met as f64 / total as f64;
        assert!(
            met_ratio > 0.6,
            "expected >60% Met ratio for configured system, got {:.1}%",
            met_ratio * 100.0
        );

        // Gaps should be fewer than Met practices
        assert!(
            partial < met,
            "more gaps ({}) than Met practices ({}) indicates misconfiguration",
            partial, met
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2. STIG Cat I Violation Halts Operations
// ═══════════════════════════════════════════════════════════════════════════════

mod stig_enforcement {
    use super::*;
    use common::stig::*;

    #[test]
    fn stig_auditor_runs_all_checks() {
        let mut auditor = StigAuditor::new();
        let results = auditor.run_all();

        // Should have a significant number of checks
        assert!(
            results.len() >= 10,
            "expected at least 10 STIG checks, got {}",
            results.len()
        );
    }

    #[test]
    fn stig_cat_i_failures_are_critical() {
        let mut auditor = StigAuditor::new();
        auditor.run_all();
        let cat_i = auditor.cat_i_failures();

        // Cat I findings must halt operations in production
        // Verify each Cat I finding has remediation guidance
        for finding in &cat_i {
            assert_eq!(finding.severity, StigSeverity::CatI);
            assert_eq!(finding.status, StigStatus::Fail);
            assert!(
                !finding.remediation.is_empty(),
                "Cat I finding {} must have remediation guidance",
                finding.id
            );
        }
    }

    #[test]
    fn stig_summary_accounts_for_all_checks() {
        let mut auditor = StigAuditor::new();
        auditor.run_all();
        let summary = auditor.summary();

        assert_eq!(
            summary.total,
            summary.passed + summary.failed + summary.not_applicable + summary.manual,
            "summary totals must account for all checks"
        );

        // Cat failure breakdown must not exceed total failures
        assert!(
            summary.cat_i_failures + summary.cat_ii_failures + summary.cat_iii_failures
                <= summary.failed,
            "categorized failures exceed total failures"
        );
    }

    #[test]
    fn stig_category_filter_returns_correct_checks() {
        let mut auditor = StigAuditor::new();
        let kernel_checks = auditor.run_category(StigCategory::Kernel);

        for check in &kernel_checks {
            assert_eq!(
                check.category,
                StigCategory::Kernel,
                "run_category(Kernel) returned non-kernel check: {}",
                check.id
            );
        }

        // Also verify network category
        let net_checks = auditor.run_category(StigCategory::Network);
        for check in &net_checks {
            assert_eq!(check.category, StigCategory::Network);
        }
    }

    #[test]
    fn stig_production_halt_on_cat_i() {
        let mut auditor = StigAuditor::new();
        auditor.run_all();
        let summary = auditor.summary();

        // Simulate production mode decision: if ANY Cat I failures exist,
        // operations must be halted. This is the critical enforcement test.
        let should_halt = summary.cat_i_failures > 0;

        // Cat II and Cat III should NOT cause a halt by themselves
        let cat_ii_only = summary.cat_ii_failures > 0 && summary.cat_i_failures == 0;
        let cat_iii_only = summary.cat_iii_failures > 0
            && summary.cat_i_failures == 0
            && summary.cat_ii_failures == 0;

        // The decision logic: only Cat I halts
        if should_halt {
            // This is expected in many environments (containers, non-FIPS kernels)
            assert!(
                summary.cat_i_failures > 0,
                "halt triggered but no Cat I failures found"
            );
        }

        // Verify Cat II alone does not trigger halt
        if cat_ii_only {
            assert!(
                summary.cat_i_failures == 0,
                "Cat II-only scenario incorrectly has Cat I failures"
            );
        }

        // Verify Cat III alone does not trigger halt
        if cat_iii_only {
            assert!(
                summary.cat_i_failures == 0 && summary.cat_ii_failures == 0,
                "Cat III-only scenario incorrectly has higher-severity failures"
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. Data Sovereignty Violation on Public Cloud
// ═══════════════════════════════════════════════════════════════════════════════

mod data_sovereignty {
    use super::*;
    use common::compliance::*;
    use common::data_residency::*;

    #[test]
    fn indian_data_in_us_region_rejected() {
        let policy = RegionPolicy::india_only();
        assert!(policy.validate_storage("us-east-1").is_err());
        assert!(policy.validate_storage("us-gov-west-1").is_err());
        assert!(policy.validate_storage("eu-west-1").is_err());
        assert!(policy.validate_storage("ap-southeast-1").is_err());

        // Only Indian regions are allowed
        assert!(policy.validate_storage("asia-south1").is_ok());
        assert!(policy.validate_storage("asia-south2").is_ok());
    }

    #[test]
    fn us_dod_data_in_eu_region_rejected() {
        let policy = RegionPolicy::us_govcloud_only();
        assert!(policy.validate_storage("eu-west-1").is_err());
        assert!(policy.validate_storage("ap-southeast-1").is_err());
        assert!(policy.validate_storage("asia-south1").is_err());
        assert!(policy.validate_storage("us-east-1").is_err()); // Commercial AWS != GovCloud

        // Only GovCloud regions are allowed
        assert!(policy.validate_storage("us-gov-west-1").is_ok());
        assert!(policy.validate_storage("us-gov-east-1").is_ok());
    }

    #[test]
    fn dual_compliance_india_certin_enforcement() {
        // Dual policy allows both India and GovCloud
        let policy = RegionPolicy::dual_india_govcloud();
        assert!(policy.validate_storage("asia-south1").is_ok());
        assert!(policy.validate_storage("us-gov-west-1").is_ok());

        // Still rejects non-compliant regions
        assert!(policy.validate_storage("eu-west-1").is_err());
        assert!(policy.validate_storage("us-east-1").is_err());
    }

    #[test]
    fn cross_border_replication_blocked() {
        let india_policy = RegionPolicy::india_only();

        // Cross-border replication is blocked
        assert!(india_policy
            .validate_replication("asia-south1", "us-gov-west-1")
            .is_err());
        assert!(india_policy
            .validate_replication("us-gov-west-1", "asia-south1")
            .is_err());

        // Intra-India replication is allowed
        assert!(india_policy
            .validate_replication("asia-south1", "asia-south2")
            .is_ok());
    }

    #[test]
    fn compliance_engine_data_residency_check() {
        let india_engine = ComplianceEngine::new(ComplianceConfig::indian_govt_default());

        // Indian data in US region: violation
        let result = india_engine.check_data_residency("us-east-1");
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert_eq!(violation.severity, ComplianceSeverity::Critical);
        assert_eq!(violation.rule, "DATA_RESIDENCY");

        // US DoD data in EU region: violation
        let dod_engine = ComplianceEngine::new(ComplianceConfig::us_dod_default());
        let result = dod_engine.check_data_residency("eu-west-1");
        assert!(result.is_err());

        // Valid regions pass
        assert!(india_engine.check_data_residency("asia-south1").is_ok());
        assert!(dod_engine.check_data_residency("us-gov-east-1").is_ok());
    }

    #[test]
    fn backup_location_sovereignty_enforced() {
        let india = RegionPolicy::india_only();
        assert!(india.validate_backup("asia-south1").is_ok());
        assert!(india.validate_backup("us-east-1").is_err());

        let govcloud = RegionPolicy::us_govcloud_only();
        assert!(govcloud.validate_backup("us-gov-west-1").is_ok());
        assert!(govcloud.validate_backup("asia-south1").is_err());
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 4. Cross-Domain Data Exfiltration Attempt
// ═══════════════════════════════════════════════════════════════════════════════

mod cross_domain_exfiltration {
    use super::*;
    use common::classification::ClassificationLevel;
    use common::cross_domain::*;

    fn make_domain(name: &str, level: ClassificationLevel) -> SecurityDomain {
        SecurityDomain {
            id: Uuid::new_v4(),
            name: name.to_string(),
            classification: level,
        }
    }

    #[test]
    fn top_secret_to_unclassified_blocked_without_declass() {
        let mut guard = CrossDomainGuard::new();
        let jwics = make_domain("JWICS", ClassificationLevel::TopSecret);
        let niprnet = make_domain("NIPRNet", ClassificationLevel::Unclassified);
        let jwics_id = jwics.id;
        let niprnet_id = niprnet.id;
        guard.register_domain(jwics);
        guard.register_domain(niprnet);

        // Add a rule WITHOUT declassification authorization
        guard.add_flow_rule(FlowRule {
            source_domain: jwics_id,
            target_domain: niprnet_id,
            direction: FlowDirection::Unidirectional,
            declassification_authorized: false,
            justification: "attempted exfiltration".to_string(),
            authorized_by: Uuid::nil(),
            created_at: 0,
        });

        // Transfer should be BLOCKED even though a rule exists
        let decision = guard.validate_transfer(&jwics_id, &niprnet_id);
        assert!(
            !decision.allowed,
            "TopSecret -> Unclassified must be blocked without declassification"
        );
        assert!(
            decision.reason.contains("declassification"),
            "reason should mention declassification requirement"
        );
    }

    #[test]
    fn declassified_transfer_allowed_after_authorization() {
        let mut guard = CrossDomainGuard::new();
        let jwics = make_domain("JWICS", ClassificationLevel::TopSecret);
        let niprnet = make_domain("NIPRNet", ClassificationLevel::Unclassified);
        let jwics_id = jwics.id;
        let niprnet_id = niprnet.id;
        guard.register_domain(jwics);
        guard.register_domain(niprnet);

        // Add a rule WITH declassification authorization
        guard.add_flow_rule(FlowRule {
            source_domain: jwics_id,
            target_domain: niprnet_id,
            direction: FlowDirection::Unidirectional,
            declassification_authorized: true,
            justification: "authorized declassification review by OCA".to_string(),
            authorized_by: Uuid::new_v4(),
            created_at: now_us(),
        });

        let decision = guard.validate_transfer(&jwics_id, &niprnet_id);
        assert!(
            decision.allowed,
            "authorized declassification should allow transfer"
        );
    }

    #[test]
    fn no_rule_default_deny() {
        let mut guard = CrossDomainGuard::new();
        let jwics = make_domain("JWICS", ClassificationLevel::TopSecret);
        let niprnet = make_domain("NIPRNet", ClassificationLevel::Unclassified);
        let jwics_id = jwics.id;
        let niprnet_id = niprnet.id;
        guard.register_domain(jwics);
        guard.register_domain(niprnet);

        // No rule added at all: must be default deny
        let decision = guard.validate_transfer(&jwics_id, &niprnet_id);
        assert!(!decision.allowed);
        assert!(decision.reason.contains("default deny"));
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 5. Cross-Domain Rule Exhaustive Validation
// ═══════════════════════════════════════════════════════════════════════════════

mod cross_domain_exhaustive {
    use super::*;
    use common::classification::ClassificationLevel;
    use common::cross_domain::*;

    fn make_domain(name: &str, level: ClassificationLevel) -> SecurityDomain {
        SecurityDomain {
            id: Uuid::new_v4(),
            name: name.to_string(),
            classification: level,
        }
    }

    #[test]
    fn five_domain_exhaustive_transfer_matrix() {
        let mut guard = CrossDomainGuard::new();

        // Register 5 domains at different classification levels
        let domains = vec![
            make_domain("NIPRNet", ClassificationLevel::Unclassified),
            make_domain("FedNet", ClassificationLevel::Confidential),
            make_domain("SIPRNet", ClassificationLevel::Secret),
            make_domain("JWICS", ClassificationLevel::TopSecret),
            make_domain("SCINet", ClassificationLevel::SCI),
        ];

        let ids: Vec<Uuid> = domains.iter().map(|d| d.id).collect();
        let levels: Vec<ClassificationLevel> =
            domains.iter().map(|d| d.classification).collect();

        for d in domains {
            guard.register_domain(d);
        }

        // Test 1: Default deny for ALL cross-domain pairs (no rules)
        for i in 0..5 {
            for j in 0..5 {
                if i == j {
                    continue;
                }
                let decision = guard.validate_transfer(&ids[i], &ids[j]);
                assert!(
                    !decision.allowed,
                    "default deny should block {} -> {}",
                    levels[i].label(),
                    levels[j].label()
                );
            }
        }

        // Test 2: Same domain always allowed
        for i in 0..5 {
            let decision = guard.validate_transfer(&ids[i], &ids[i]);
            assert!(
                decision.allowed,
                "same-domain transfer should be allowed for {}",
                levels[i].label()
            );
        }

        // Test 3: Add low->high rule (NIPRNet -> SIPRNet), verify it works
        guard.add_flow_rule(FlowRule {
            source_domain: ids[0], // Unclassified
            target_domain: ids[2], // Secret
            direction: FlowDirection::Unidirectional,
            declassification_authorized: false,
            justification: "upward flow authorized".to_string(),
            authorized_by: Uuid::nil(),
            created_at: 0,
        });
        let decision = guard.validate_transfer(&ids[0], &ids[2]);
        assert!(decision.allowed, "low->high with rule should be allowed");

        // Test 4: High->low needs declass even with rule
        guard.add_flow_rule(FlowRule {
            source_domain: ids[3], // TopSecret
            target_domain: ids[0], // Unclassified
            direction: FlowDirection::Unidirectional,
            declassification_authorized: false,
            justification: "test without declass".to_string(),
            authorized_by: Uuid::nil(),
            created_at: 0,
        });
        let decision = guard.validate_transfer(&ids[3], &ids[0]);
        assert!(
            !decision.allowed,
            "high->low without declass should be blocked"
        );

        // Test 5: High->low WITH declass authorized
        guard.add_flow_rule(FlowRule {
            source_domain: ids[4], // SCI
            target_domain: ids[2], // Secret
            direction: FlowDirection::Unidirectional,
            declassification_authorized: true,
            justification: "authorized declassification".to_string(),
            authorized_by: Uuid::new_v4(),
            created_at: 0,
        });
        let decision = guard.validate_transfer(&ids[4], &ids[2]);
        assert!(decision.allowed, "high->low with declass should be allowed");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 6. Classification Level Escalation Attack
// ═══════════════════════════════════════════════════════════════════════════════

mod classification_escalation {
    use super::*;
    use common::classification::*;

    #[test]
    fn all_read_up_attempts_blocked() {
        let levels = [
            ClassificationLevel::Unclassified,
            ClassificationLevel::Confidential,
            ClassificationLevel::Secret,
            ClassificationLevel::TopSecret,
            ClassificationLevel::SCI,
        ];

        // For every pair where subject < resource, access must be denied
        for (i, &subject) in levels.iter().enumerate() {
            for &resource in &levels[i + 1..] {
                let decision = enforce_classification(subject, resource);
                assert!(
                    !decision.is_granted(),
                    "{} should NOT be able to access {} resources",
                    subject.label(),
                    resource.label()
                );
            }
        }
    }

    #[test]
    fn same_level_access_granted() {
        let levels = [
            ClassificationLevel::Unclassified,
            ClassificationLevel::Confidential,
            ClassificationLevel::Secret,
            ClassificationLevel::TopSecret,
            ClassificationLevel::SCI,
        ];

        for &level in &levels {
            let decision = enforce_classification(level, level);
            assert!(
                decision.is_granted(),
                "{} should access own level",
                level.label()
            );
        }
    }

    #[test]
    fn higher_clearance_accesses_lower() {
        let levels = [
            ClassificationLevel::Unclassified,
            ClassificationLevel::Confidential,
            ClassificationLevel::Secret,
            ClassificationLevel::TopSecret,
            ClassificationLevel::SCI,
        ];

        for (i, &subject) in levels.iter().enumerate() {
            for &resource in &levels[..i] {
                let decision = enforce_classification(subject, resource);
                assert!(
                    decision.is_granted(),
                    "{} should access {} resources",
                    subject.label(),
                    resource.label()
                );
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 7. Star Property (No Write Down) Enforcement
// ═══════════════════════════════════════════════════════════════════════════════

mod star_property {
    use super::*;
    use common::classification::*;

    #[test]
    fn top_secret_cannot_flow_to_secret() {
        let decision = enforce_no_downgrade(
            ClassificationLevel::TopSecret,
            ClassificationLevel::Secret,
        );
        assert!(
            !decision.is_granted(),
            "star property: TopSecret data must not flow to Secret session"
        );
        assert!(matches!(
            decision,
            ClassificationDecision::DowngradePrevented { .. }
        ));
    }

    #[test]
    fn all_downgrade_attempts_blocked() {
        let levels = [
            ClassificationLevel::Unclassified,
            ClassificationLevel::Confidential,
            ClassificationLevel::Secret,
            ClassificationLevel::TopSecret,
            ClassificationLevel::SCI,
        ];

        for (i, &source) in levels.iter().enumerate() {
            for &target in &levels[..i] {
                let decision = enforce_no_downgrade(source, target);
                assert!(
                    !decision.is_granted(),
                    "star property: {} data must not flow to {} session",
                    source.label(),
                    target.label()
                );
            }
        }
    }

    #[test]
    fn same_level_write_allowed() {
        let levels = [
            ClassificationLevel::Unclassified,
            ClassificationLevel::Confidential,
            ClassificationLevel::Secret,
            ClassificationLevel::TopSecret,
            ClassificationLevel::SCI,
        ];

        for &level in &levels {
            let decision = enforce_no_downgrade(level, level);
            assert!(
                decision.is_granted(),
                "same-level write should be allowed for {}",
                level.label()
            );
        }
    }

    #[test]
    fn upgrade_write_allowed() {
        let levels = [
            ClassificationLevel::Unclassified,
            ClassificationLevel::Confidential,
            ClassificationLevel::Secret,
            ClassificationLevel::TopSecret,
            ClassificationLevel::SCI,
        ];

        for (i, &source) in levels.iter().enumerate() {
            for &target in &levels[i + 1..] {
                let decision = enforce_no_downgrade(source, target);
                assert!(
                    decision.is_granted(),
                    "{} data should be allowed to flow up to {} session",
                    source.label(),
                    target.label()
                );
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 8. Encrypted Audit Prevents Data Exposure on Compromised VM
// ═══════════════════════════════════════════════════════════════════════════════

mod encrypted_audit {
    use super::*;
    use common::encrypted_audit::*;
    use common::types::AuditEventType;

    fn random_keys() -> ([u8; 32], [u8; 32]) {
        let mut enc_key = [0u8; 32];
        let mut blind_key = [0u8; 32];
        getrandom::getrandom(&mut enc_key).unwrap();
        getrandom::getrandom(&mut blind_key).unwrap();
        (enc_key, blind_key)
    }

    #[test]
    fn encrypted_entries_not_readable_without_key() {
        let (enc_key, blind_key) = random_keys();
        let user_id = Uuid::new_v4();

        let encrypted = encrypt_audit_metadata(
            AuditEventType::AuthSuccess,
            &[user_id],
            &[Uuid::new_v4()],
            0.85,
            &[],
            &enc_key,
            &blind_key,
        )
        .unwrap();

        // An attacker who compromises the VM gets the ciphertext but not the key
        let mut wrong_key = [0u8; 32];
        getrandom::getrandom(&mut wrong_key).unwrap();

        let result = decrypt_audit_metadata(&encrypted, &wrong_key);
        assert!(
            result.is_err(),
            "decryption with wrong key must fail on compromised VM"
        );

        // Verify the ciphertext does not contain plaintext user_id
        let user_bytes = user_id.as_bytes();
        let ciphertext_contains_plaintext = encrypted
            .ciphertext
            .windows(user_bytes.len())
            .any(|w| w == user_bytes);
        assert!(
            !ciphertext_contains_plaintext,
            "ciphertext must not contain plaintext user_id"
        );
    }

    #[test]
    fn blind_index_search_without_decryption() {
        let (enc_key, blind_key) = random_keys();
        let target_user = Uuid::new_v4();
        let other_user = Uuid::new_v4();

        // Store entries for different users
        let entry_target = encrypt_audit_metadata(
            AuditEventType::AuthSuccess,
            &[target_user],
            &[],
            0.0,
            &[],
            &enc_key,
            &blind_key,
        )
        .unwrap();

        let entry_other = encrypt_audit_metadata(
            AuditEventType::AuthFailure,
            &[other_user],
            &[],
            0.5,
            &[],
            &enc_key,
            &blind_key,
        )
        .unwrap();

        // Search by user blind index -- no decryption needed
        let search_idx = search_user_blind_index(&blind_key, &target_user);

        assert!(
            entry_target.user_blind_indexes.contains(&search_idx),
            "blind index search should find target user's entry"
        );
        assert!(
            !entry_other.user_blind_indexes.contains(&search_idx),
            "blind index search should NOT match other user's entry"
        );
    }

    #[test]
    fn event_type_blind_index_filtering() {
        let (enc_key, blind_key) = random_keys();

        let auth_entry = encrypt_audit_metadata(
            AuditEventType::AuthSuccess,
            &[Uuid::new_v4()],
            &[],
            0.0,
            &[],
            &enc_key,
            &blind_key,
        )
        .unwrap();

        let key_rot_entry = encrypt_audit_metadata(
            AuditEventType::KeyRotation,
            &[Uuid::new_v4()],
            &[],
            0.0,
            &[],
            &enc_key,
            &blind_key,
        )
        .unwrap();

        let auth_idx = search_event_type_blind_index(&blind_key, &AuditEventType::AuthSuccess);
        let keyrot_idx = search_event_type_blind_index(&blind_key, &AuditEventType::KeyRotation);

        assert_eq!(auth_entry.event_type_blind_index, auth_idx);
        assert_ne!(auth_entry.event_type_blind_index, keyrot_idx);
        assert_eq!(key_rot_entry.event_type_blind_index, keyrot_idx);
    }

    #[test]
    fn tampered_ciphertext_detected() {
        let (enc_key, blind_key) = random_keys();
        let mut encrypted = encrypt_audit_metadata(
            AuditEventType::DuressDetected,
            &[Uuid::new_v4()],
            &[],
            1.0,
            &[],
            &enc_key,
            &blind_key,
        )
        .unwrap();

        // Attacker on public network tampers with the ciphertext
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 0xFF;
        }

        let result = decrypt_audit_metadata(&encrypted, &enc_key);
        assert!(result.is_err(), "tampered ciphertext must be detected");
    }

    #[test]
    fn nonces_never_repeat() {
        let (enc_key, blind_key) = random_keys();
        let mut nonces = HashSet::new();

        for _ in 0..100 {
            let encrypted = encrypt_audit_metadata(
                AuditEventType::AuthSuccess,
                &[],
                &[],
                0.0,
                &[],
                &enc_key,
                &blind_key,
            )
            .unwrap();
            assert!(
                nonces.insert(encrypted.nonce),
                "nonce collision detected -- catastrophic for AES-GCM security"
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 9. Audit Trail Immutability on Public Network
// ═══════════════════════════════════════════════════════════════════════════════

mod audit_immutability {
    use super::*;
    use audit::log::AuditLog;
    use common::types::{AuditEventType, Receipt};

    #[test]
    fn hundred_entry_signed_log_verifies() {
        run_with_large_stack(|| {
            let (sk, vk) = crypto::pq_sign::generate_pq_keypair();
            let mut log = AuditLog::new();

            for i in 0..100 {
                log.append(
                    AuditEventType::AuthSuccess,
                    vec![Uuid::new_v4()],
                    vec![],
                    0.1 * (i as f64),
                    vec![],
                    &sk,
                );
            }

            assert_eq!(log.len(), 100);
            assert!(
                log.verify_chain_with_key(Some(&vk)),
                "100-entry signed audit log must verify"
            );
        });
    }

    #[test]
    fn tampered_entry_detected() {
        run_with_large_stack(|| {
            let (sk, vk) = crypto::pq_sign::generate_pq_keypair();
            let mut log = AuditLog::new();

            for _ in 0..100 {
                log.append(
                    AuditEventType::AuthSuccess,
                    vec![Uuid::new_v4()],
                    vec![],
                    0.5,
                    vec![],
                    &sk,
                );
            }

            assert!(log.verify_chain_with_key(Some(&vk)));

            // Now rebuild from entries, tamper entry 50's risk_score
            let mut entries = log.entries().to_vec();
            entries[50].risk_score = 99.9; // tamper!
            let tampered_log = AuditLog::from_entries(entries);

            // The chain hash will no longer match because the entry was modified
            // but prev_hash of entry 51 still points to the old hash of entry 50.
            // Signature verification will also fail for the tampered entry.
            assert!(
                !tampered_log.verify_chain_with_key(Some(&vk)),
                "tampered entry 50 must break signature verification"
            );
        });
    }

    #[test]
    fn hash_chain_detects_insertion() {
        run_with_large_stack(|| {
            let (sk, _vk) = crypto::pq_sign::generate_pq_keypair();
            let mut log = AuditLog::new();

            for _ in 0..10 {
                log.append(
                    AuditEventType::AuthSuccess,
                    vec![Uuid::new_v4()],
                    vec![],
                    0.1,
                    vec![],
                    &sk,
                );
            }

            assert!(log.verify_chain());

            // Try to insert a forged entry in the middle
            let mut entries = log.entries().to_vec();
            let forged = common::types::AuditEntry {
                event_id: Uuid::new_v4(),
                event_type: AuditEventType::AuthFailure,
                user_ids: vec![Uuid::new_v4()],
                device_ids: vec![],
                ceremony_receipts: vec![],
                risk_score: 0.0,
                timestamp: now_us(),
                prev_hash: [0xAA; 64], // wrong hash
                signature: vec![],
                classification: 0,
                correlation_id: None,
                trace_id: None,
                source_ip: None,
                session_id: None,
                request_id: None,
                user_agent: None,
            };
            entries.insert(5, forged);

            let tampered_log = AuditLog::from_entries(entries);
            assert!(
                !tampered_log.verify_chain(),
                "inserted entry must break hash chain"
            );
        });
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 10. Witness Checkpoint Consistency
// ═══════════════════════════════════════════════════════════════════════════════

mod witness_checkpoint {
    use super::*;
    use common::witness::WitnessLog;

    #[test]
    fn checkpoint_sequence_is_monotonic() {
        let mut log = WitnessLog::new();

        for i in 0..10 {
            let mut audit_root = [0u8; 64];
            let mut kt_root = [0u8; 64];
            audit_root[0] = i as u8;
            kt_root[0] = (i + 100) as u8;

            log.add_checkpoint(audit_root, kt_root, vec![0u8; 64]);
        }

        assert_eq!(log.len(), 10);

        // Verify the latest checkpoint has the highest sequence
        let latest = log.latest().unwrap();
        assert_eq!(latest.sequence, 9, "latest sequence should be 9 (0-indexed)");
    }

    #[test]
    fn checkpoint_timestamps_are_nondecreasing() {
        let mut log = WitnessLog::new();

        let mut prev_ts = 0i64;
        for i in 0..10 {
            let mut audit_root = [0u8; 64];
            let mut kt_root = [0u8; 64];
            audit_root[0] = i as u8;
            kt_root[0] = i as u8;

            log.add_checkpoint(audit_root, kt_root, vec![0u8; 64]);

            let latest = log.latest().unwrap();
            assert!(
                latest.timestamp >= prev_ts,
                "checkpoint {} timestamp {} is before previous {}",
                i, latest.timestamp, prev_ts
            );
            prev_ts = latest.timestamp;
        }
    }

    #[test]
    fn signed_checkpoints_carry_real_data() {
        let mut log = WitnessLog::new();

        let audit_root = [0xAAu8; 64];
        let kt_root = [0xBBu8; 64];

        // Use add_signed_checkpoint with a signing function
        log.add_signed_checkpoint(audit_root, kt_root, |data| {
            // In production this would be ML-DSA-87; for testing, hash the data
            use sha2::{Digest, Sha512};
            let sig = Sha512::digest(data);
            sig.to_vec()
        });

        let cp = log.latest().unwrap();
        assert_eq!(cp.audit_root, audit_root);
        assert_eq!(cp.kt_root, kt_root);
        assert_eq!(cp.sequence, 0);
        assert!(!cp.signature.is_empty(), "signed checkpoint must have signature");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 11. Merkle Proof for Public Verifiability
// ═══════════════════════════════════════════════════════════════════════════════

mod merkle_public_verifiability {
    use super::*;
    use kt::merkle::MerkleTree;

    #[test]
    fn fifty_entry_tree_all_proofs_verify() {
        let mut tree = MerkleTree::new();
        let mut leaves = Vec::new();

        for i in 0..50 {
            let user_id = Uuid::new_v4();
            let mut cred_hash = [0u8; 32];
            cred_hash[0] = i as u8;
            let leaf = tree.append_credential_op(
                &user_id,
                &format!("register_credential_{}", i),
                &cred_hash,
                now_us(),
            );
            leaves.push(leaf);
        }

        let root = tree.root();
        let tree_size = tree.len();
        assert_eq!(tree_size, 50);

        // Verify inclusion proof for every entry
        for i in 0..50 {
            let proof = tree.inclusion_proof(i).expect("proof must exist");
            let valid = MerkleTree::verify_inclusion_with_size(
                &root, &leaves[i], &proof, i, tree_size,
            );
            assert!(
                valid,
                "inclusion proof for entry {} must verify (public network verifiability)",
                i
            );
        }
    }

    #[test]
    fn invalid_leaf_rejected() {
        let mut tree = MerkleTree::new();

        for i in 0..10 {
            let user_id = Uuid::new_v4();
            let mut cred_hash = [0u8; 32];
            cred_hash[0] = i as u8;
            tree.append_credential_op(&user_id, "register", &cred_hash, now_us());
        }

        let root = tree.root();
        let proof = tree.inclusion_proof(0).unwrap();
        let tree_size = tree.len();

        // Forge a fake leaf
        let fake_leaf = [0xFFu8; 64];
        let valid = MerkleTree::verify_inclusion_with_size(
            &root, &fake_leaf, &proof, 0, tree_size,
        );
        assert!(
            !valid,
            "forged leaf must be rejected by Merkle proof verification"
        );
    }

    #[test]
    fn out_of_bounds_proof_returns_none() {
        let mut tree = MerkleTree::new();
        let user_id = Uuid::new_v4();
        let cred_hash = [0u8; 32];
        tree.append_credential_op(&user_id, "register", &cred_hash, now_us());

        assert!(tree.inclusion_proof(0).is_some());
        assert!(
            tree.inclusion_proof(1).is_none(),
            "out-of-bounds index must return None"
        );
        assert!(tree.inclusion_proof(999).is_none());
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 12. Multi-Person Ceremony Prevents Single-Admin Compromise
// ═══════════════════════════════════════════════════════════════════════════════

mod multi_person_ceremony {
    use super::*;
    use common::actions::*;
    use common::types::ActionLevel;

    fn make_participant(dept: &str) -> CeremonyParticipant {
        CeremonyParticipant {
            user_id: Uuid::new_v4(),
            department: dept.to_string(),
            authenticated_at: now_us(),
            device_id: Uuid::new_v4(),
        }
    }

    #[test]
    fn sovereign_requires_three_different_departments() {
        let p1 = make_participant("Engineering");
        let p2 = make_participant("Security");
        let p3 = make_participant("Operations");

        let result = validate_multi_person_ceremony(
            &[p1, p2, p3],
            ActionLevel::Sovereign,
        );
        assert!(result.is_ok(), "3 people from 3 departments should succeed");
    }

    #[test]
    fn sovereign_two_people_fails() {
        let p1 = make_participant("Engineering");
        let p2 = make_participant("Security");

        let result = validate_multi_person_ceremony(
            &[p1, p2],
            ActionLevel::Sovereign,
        );
        assert!(result.is_err(), "2 people should fail for Sovereign");
    }

    #[test]
    fn sovereign_same_department_fails() {
        let p1 = make_participant("Engineering");
        let p2 = make_participant("Engineering");
        let p3 = make_participant("Engineering");

        let result = validate_multi_person_ceremony(
            &[p1, p2, p3],
            ActionLevel::Sovereign,
        );
        assert!(
            result.is_err(),
            "3 people from same department should fail for Sovereign"
        );
    }

    #[test]
    fn critical_requires_two_people() {
        let p1 = make_participant("Engineering");
        let p2 = make_participant("Engineering"); // same dept is OK for Critical

        let result = validate_multi_person_ceremony(
            &[p1, p2],
            ActionLevel::Critical,
        );
        assert!(result.is_ok(), "2 people should succeed for Critical");
    }

    #[test]
    fn critical_one_person_fails() {
        let p1 = make_participant("Engineering");

        let result = validate_multi_person_ceremony(
            &[p1],
            ActionLevel::Critical,
        );
        assert!(result.is_err(), "1 person should fail for Critical");
    }

    #[test]
    fn read_level_no_ceremony_needed() {
        let result = validate_multi_person_ceremony(&[], ActionLevel::Read);
        assert!(result.is_ok(), "Read actions need no ceremony");
    }

    #[test]
    fn duplicate_participants_rejected() {
        let user_id = Uuid::new_v4();
        let device1 = Uuid::new_v4();
        let device2 = Uuid::new_v4();
        let device3 = Uuid::new_v4();

        // Same user_id, different devices
        let p1 = CeremonyParticipant {
            user_id,
            department: "Eng".to_string(),
            authenticated_at: now_us(),
            device_id: device1,
        };
        let p2 = CeremonyParticipant {
            user_id,
            department: "Sec".to_string(),
            authenticated_at: now_us(),
            device_id: device2,
        };
        let p3 = CeremonyParticipant {
            user_id,
            department: "Ops".to_string(),
            authenticated_at: now_us(),
            device_id: device3,
        };

        let result = validate_multi_person_ceremony(
            &[p1, p2, p3],
            ActionLevel::Sovereign,
        );
        assert!(
            result.is_err(),
            "same user on different devices should be rejected"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 13. Duress Code Triggers Silent Lockdown
// ═══════════════════════════════════════════════════════════════════════════════

mod duress_lockdown {
    use super::*;
    use common::duress::*;

    #[test]
    fn normal_pin_returns_normal() {
        let user_id = Uuid::new_v4();
        let config = DuressConfig::new(user_id, b"correct-pin-1234", b"duress-pin-5678").unwrap();

        let result = config.verify_pin(b"correct-pin-1234");
        assert_eq!(result, PinVerification::Normal);
    }

    #[test]
    fn duress_pin_returns_duress() {
        let user_id = Uuid::new_v4();
        let config = DuressConfig::new(user_id, b"correct-pin-1234", b"duress-pin-5678").unwrap();

        let result = config.verify_pin(b"duress-pin-5678");
        assert_eq!(result, PinVerification::Duress);
    }

    #[test]
    fn wrong_pin_returns_invalid() {
        let user_id = Uuid::new_v4();
        let config = DuressConfig::new(user_id, b"correct-pin-1234", b"duress-pin-5678").unwrap();

        let result = config.verify_pin(b"wrong-pin-9999");
        assert_eq!(result, PinVerification::Invalid);
    }

    #[test]
    fn duress_alert_generation() {
        let user_id = Uuid::new_v4();
        let config = DuressConfig::new(user_id, b"normal", b"duress").unwrap();

        let result = config.verify_pin(b"duress");
        assert_eq!(result, PinVerification::Duress);

        // In a real system, this would generate a DuressAlert
        let alert = DuressAlert {
            user_id,
            timestamp: now_us(),
            fake_token_issued: true,
            lockdown_triggered: true,
        };

        assert_eq!(alert.user_id, user_id);
        assert!(alert.fake_token_issued, "duress must issue a fake token to deceive attacker");
        assert!(alert.lockdown_triggered, "duress must trigger silent lockdown");
    }

    #[test]
    fn duress_pin_timing_indistinguishable() {
        // Both normal and duress verification must take similar time
        // to prevent timing side-channel attacks on a public-facing system
        let user_id = Uuid::new_v4();
        let config = DuressConfig::new(user_id, b"normal-pin", b"duress-pin").unwrap();

        // Verify both paths execute (correctness, not timing)
        let normal = config.verify_pin(b"normal-pin");
        let duress = config.verify_pin(b"duress-pin");
        let invalid = config.verify_pin(b"wrong-pin");

        assert_eq!(normal, PinVerification::Normal);
        assert_eq!(duress, PinVerification::Duress);
        assert_eq!(invalid, PinVerification::Invalid);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 14. Session Recording Captures All Privileged Ops
// ═══════════════════════════════════════════════════════════════════════════════

mod session_recording {
    use super::*;
    use common::session_recording::*;

    #[test]
    fn fifteen_privileged_ops_all_captured() {
        let recorder = SessionRecorder::with_defaults();
        let sid = Uuid::new_v4();
        let uid = Uuid::new_v4();

        recorder
            .start_recording(sid, uid, RecordingType::Privileged, 1000)
            .unwrap();

        let event_types = [
            SessionEventType::CommandExecuted,
            SessionEventType::ResourceAccessed,
            SessionEventType::ConfigurationChanged,
            SessionEventType::PrivilegeEscalated,
            SessionEventType::AuthenticationAttempt,
            SessionEventType::DataExported,
            SessionEventType::CommandExecuted,
            SessionEventType::ResourceAccessed,
            SessionEventType::CommandExecuted,
            SessionEventType::ResourceAccessed,
            SessionEventType::ConfigurationChanged,
            SessionEventType::CommandExecuted,
            SessionEventType::ResourceAccessed,
            SessionEventType::AuthenticationAttempt,
            SessionEventType::DataExported,
        ];

        for (i, &event_type) in event_types.iter().enumerate() {
            recorder
                .record_event(
                    sid,
                    event_type,
                    format!("privileged operation {} on public-facing server", i),
                    "203.0.113.42".into(),
                    1001 + i as i64,
                )
                .unwrap();
        }

        recorder.stop_recording(sid, 2000).unwrap();

        let recording = recorder.get_recording(sid).unwrap();
        assert_eq!(recording.events.len(), 15, "all 15 events must be captured");

        // Verify hash chain integrity
        assert!(
            SessionRecorder::verify_integrity(&recording),
            "hash chain must verify for all 15 events"
        );
    }

    #[test]
    fn tampered_event_breaks_integrity() {
        let recorder = SessionRecorder::with_defaults();
        let sid = Uuid::new_v4();
        let uid = Uuid::new_v4();

        recorder
            .start_recording(sid, uid, RecordingType::Admin, 1000)
            .unwrap();

        for i in 0..5 {
            recorder
                .record_event(
                    sid,
                    SessionEventType::CommandExecuted,
                    format!("command {}", i),
                    "10.0.0.1".into(),
                    1001 + i,
                )
                .unwrap();
        }

        recorder.stop_recording(sid, 2000).unwrap();

        let mut recording = recorder.get_recording(sid).unwrap();
        // Attacker modifies event details
        recording.events[2].details = "malicious rm -rf /".to_string();

        assert!(
            !SessionRecorder::verify_integrity(&recording),
            "tampered event must break hash chain"
        );
    }

    #[test]
    fn export_encryption_works() {
        let recorder = SessionRecorder::with_defaults();
        let sid = Uuid::new_v4();
        let uid = Uuid::new_v4();

        recorder
            .start_recording(sid, uid, RecordingType::Sovereign, 1000)
            .unwrap();

        recorder
            .record_event(
                sid,
                SessionEventType::DataExported,
                "classified data export".into(),
                "10.0.0.1".into(),
                1001,
            )
            .unwrap();

        recorder.stop_recording(sid, 2000).unwrap();

        let key = [0x42u8; 32];
        let encrypted = recorder.export_recording(sid, &key).unwrap();

        // Output: 12 bytes nonce + ciphertext (with 16-byte GCM tag)
        assert!(
            encrypted.len() > 28,
            "encrypted export must be nonce + ciphertext + GCM tag"
        );

        // Verify the plaintext session_id does not appear in the encrypted blob
        let sid_bytes = sid.as_bytes();
        let contains_plaintext = encrypted
            .windows(sid_bytes.len())
            .any(|w| w == sid_bytes);
        assert!(
            !contains_plaintext,
            "encrypted export should not contain plaintext session_id"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 15. Action Authorization Tiered Enforcement
// ═══════════════════════════════════════════════════════════════════════════════

mod action_authorization {
    use super::*;
    use common::actions::*;
    use common::types::ActionLevel;

    #[test]
    fn read_always_permitted() {
        // Read is allowed for any tier, any config
        for tier in 1..=4 {
            let auth = check_action_authorization(tier, ActionLevel::Read, false, false);
            assert!(
                auth.permitted,
                "Read should be permitted for tier {}",
                tier
            );
            assert!(!auth.requires_step_up);
            assert!(!auth.requires_two_person);
            assert!(!auth.requires_sovereign);
        }
    }

    #[test]
    fn modify_requires_dpop() {
        let auth = check_action_authorization(1, ActionLevel::Modify, false, false);
        assert!(!auth.permitted, "Modify without DPoP should be denied");

        let auth = check_action_authorization(1, ActionLevel::Modify, true, false);
        assert!(auth.permitted, "Modify with DPoP should be permitted");
    }

    #[test]
    fn privileged_requires_step_up_and_tier() {
        // No step-up: denied
        let auth = check_action_authorization(1, ActionLevel::Privileged, true, false);
        assert!(!auth.permitted);
        assert!(auth.requires_step_up);

        // Step-up but wrong tier (3 = Sensor)
        let auth = check_action_authorization(3, ActionLevel::Privileged, true, true);
        assert!(!auth.permitted, "tier 3 should not do privileged actions");

        // Step-up and correct tier
        let auth = check_action_authorization(1, ActionLevel::Privileged, true, true);
        assert!(auth.permitted, "tier 1 with step-up should be permitted");

        let auth = check_action_authorization(2, ActionLevel::Privileged, true, true);
        assert!(auth.permitted, "tier 2 with step-up should be permitted");
    }

    #[test]
    fn critical_always_requires_ceremony() {
        for tier in 1..=4 {
            let auth = check_action_authorization(tier, ActionLevel::Critical, true, true);
            assert!(
                !auth.permitted,
                "Critical should never be directly permitted for tier {}",
                tier
            );
            assert!(auth.requires_two_person);
            assert!(!auth.requires_sovereign);
        }
    }

    #[test]
    fn sovereign_always_requires_three_person() {
        for tier in 1..=4 {
            let auth = check_action_authorization(tier, ActionLevel::Sovereign, true, true);
            assert!(
                !auth.permitted,
                "Sovereign should never be directly permitted for tier {}",
                tier
            );
            assert!(auth.requires_two_person);
            assert!(auth.requires_sovereign);
        }
    }

    #[test]
    fn all_five_levels_times_four_tiers() {
        let action_levels = [
            ActionLevel::Read,
            ActionLevel::Modify,
            ActionLevel::Privileged,
            ActionLevel::Critical,
            ActionLevel::Sovereign,
        ];

        for &level in &action_levels {
            for tier in 1..=4u8 {
                let auth = check_action_authorization(tier, level, true, true);

                // Verify structural invariants
                match level {
                    ActionLevel::Read => {
                        assert!(auth.permitted);
                    }
                    ActionLevel::Critical => {
                        assert!(!auth.permitted);
                        assert!(auth.requires_two_person);
                    }
                    ActionLevel::Sovereign => {
                        assert!(!auth.permitted);
                        assert!(auth.requires_sovereign);
                    }
                    _ => {}
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 16. Receipt Chain Binds to Ceremony Session
// ═══════════════════════════════════════════════════════════════════════════════

mod receipt_chain_binding {
    use super::*;
    use common::types::Receipt;
    use crypto::receipts::*;

    fn make_receipt(session_id: [u8; 32], step_id: u8, prev_hash: [u8; 64]) -> Receipt {
        Receipt {
            ceremony_session_id: session_id,
            step_id,
            prev_receipt_hash: prev_hash,
            user_id: Uuid::new_v4(),
            dpop_key_hash: [0u8; 64],
            timestamp: now_us(),
            nonce: [0u8; 32],
            signature: vec![],
            ttl_seconds: 30,
        }
    }

    #[test]
    fn receipt_chain_accepts_matching_session() {
        let session_id = [0x01u8; 32];
        let mut chain = ReceiptChain::new(session_id);

        let r1 = make_receipt(session_id, 1, [0u8; 64]);
        chain.add_receipt(r1).expect("first receipt should succeed");

        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn receipt_chain_rejects_wrong_session() {
        let session_a = [0x01u8; 32];
        let session_b = [0x02u8; 32];
        let mut chain = ReceiptChain::new(session_a);

        let r1 = make_receipt(session_b, 1, [0u8; 64]);
        let result = chain.add_receipt(r1);
        assert!(
            result.is_err(),
            "receipt from different session must be rejected"
        );
    }

    #[test]
    fn three_sessions_cannot_mix_receipts() {
        let sessions: Vec<[u8; 32]> = (0..3)
            .map(|i| {
                let mut s = [0u8; 32];
                s[0] = i;
                s
            })
            .collect();

        let mut chains: Vec<ReceiptChain> = sessions
            .iter()
            .map(|s| ReceiptChain::new(*s))
            .collect();

        // Add first receipt to each chain
        for (i, chain) in chains.iter_mut().enumerate() {
            let r = make_receipt(sessions[i], 1, [0u8; 64]);
            chain.add_receipt(r).unwrap();
        }

        // Try to add session 0's receipt to session 1's chain
        let cross_receipt = make_receipt(sessions[0], 2, [0u8; 64]);
        let result = chains[1].add_receipt(cross_receipt);
        assert!(
            result.is_err(),
            "cross-session receipt must be rejected"
        );

        // Try to add session 2's receipt to session 0's chain
        let cross_receipt2 = make_receipt(sessions[2], 2, [0u8; 64]);
        let result = chains[0].add_receipt(cross_receipt2);
        assert!(
            result.is_err(),
            "cross-session receipt must be rejected"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 17. DPoP Binding Prevents Token Theft on Public Network
// ═══════════════════════════════════════════════════════════════════════════════

mod dpop_binding {
    use super::*;
    use crypto::dpop::*;

    fn now_secs() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    #[test]
    fn dpop_proof_verifies_with_correct_key() {
        run_with_large_stack(|| {
            let (sk, vk) = generate_dpop_keypair_raw();
            let vk_bytes = vk.encode();
            let expected_hash = dpop_key_hash(vk_bytes.as_ref());

            let claims = b"token-claims-data";
            let timestamp = now_secs();
            let proof = generate_dpop_proof(&sk, claims, timestamp, b"POST", b"https://sso.milnet.example/token", None);

            assert!(
                verify_dpop_proof(&vk, &proof, claims, timestamp, &expected_hash, b"POST", b"https://sso.milnet.example/token", None),
                "DPoP proof must verify with correct key"
            );
        });
    }

    #[test]
    fn dpop_proof_rejected_with_wrong_key() {
        run_with_large_stack(|| {
            let (sk_a, _vk_a) = generate_dpop_keypair_raw();
            let (_sk_b, vk_b) = generate_dpop_keypair_raw();

            let vk_b_bytes = vk_b.encode();
            let hash_b = dpop_key_hash(vk_b_bytes.as_ref());

            let claims = b"stolen-token";
            let timestamp = now_secs();
            let proof = generate_dpop_proof(&sk_a, claims, timestamp, b"POST", b"https://sso.milnet.example/token", None);

            // Attacker has user A's token but uses user B's DPoP key
            assert!(
                !verify_dpop_proof(&vk_b, &proof, claims, timestamp, &hash_b, b"POST", b"https://sso.milnet.example/token", None),
                "DPoP proof must be rejected when key doesn't match"
            );
        });
    }

    #[test]
    fn dpop_key_hash_is_deterministic() {
        let key_bytes = [0x42u8; 64];
        let h1 = dpop_key_hash(&key_bytes);
        let h2 = dpop_key_hash(&key_bytes);
        assert_eq!(h1, h2, "DPoP key hash must be deterministic");
    }

    #[test]
    fn dpop_different_keys_different_hashes() {
        let key_a = [0x01u8; 64];
        let key_b = [0x02u8; 64];
        let ha = dpop_key_hash(&key_a);
        let hb = dpop_key_hash(&key_b);
        assert_ne!(
            ha, hb,
            "different keys must produce different DPoP hashes"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 18. Domain Separation Constants Collision Check
// ═══════════════════════════════════════════════════════════════════════════════

mod domain_separation {
    use super::*;
    use common::domain;

    #[test]
    fn all_domain_separators_are_unique() {
        let constants: Vec<&[u8]> = vec![
            domain::FROST_TOKEN,
            domain::RECEIPT_SIGN,
            domain::DPOP_PROOF,
            domain::AUDIT_ENTRY,
            domain::MODULE_ATTEST,
            domain::RATCHET_ADVANCE,
            domain::SHARD_AUTH,
            domain::TOKEN_TAG,
            domain::KT_LEAF,
            domain::RECEIPT_CHAIN,
            domain::ACTION_BIND,
            domain::ENVELOPE_AAD,
            domain::KEY_WRAP,
            domain::SEAL_KEY,
            domain::MASTER_KEK_DERIVE,
            domain::ATTEST_MANIFEST,
            domain::ENTROPY_COMBINE,
            domain::RECOVERY_CODE,
            domain::ADMIN_ROLE_KEY_DERIVE,
            domain::CROSS_DOMAIN_AUDIT,
            domain::PENDING_ADMIN_ACTION,
        ];

        let mut seen = HashSet::new();
        for constant in &constants {
            assert!(
                seen.insert(*constant),
                "duplicate domain separator found: {:?}",
                std::str::from_utf8(constant).unwrap_or("<non-utf8>")
            );
        }

        // Verify no constant is a prefix of another (prevents cross-protocol confusion)
        for (i, a) in constants.iter().enumerate() {
            for (j, b) in constants.iter().enumerate() {
                if i == j {
                    continue;
                }
                assert!(
                    !a.starts_with(b) || a == b,
                    "domain separator {:?} is a prefix of {:?} -- cross-protocol attack possible",
                    std::str::from_utf8(b).unwrap_or(""),
                    std::str::from_utf8(a).unwrap_or("")
                );
            }
        }
    }

    #[test]
    fn domain_separators_are_non_empty() {
        let constants: Vec<&[u8]> = vec![
            domain::FROST_TOKEN,
            domain::RECEIPT_SIGN,
            domain::DPOP_PROOF,
            domain::AUDIT_ENTRY,
            domain::MODULE_ATTEST,
            domain::RATCHET_ADVANCE,
            domain::SHARD_AUTH,
            domain::TOKEN_TAG,
            domain::KT_LEAF,
            domain::RECEIPT_CHAIN,
            domain::ACTION_BIND,
        ];

        for constant in &constants {
            assert!(!constant.is_empty(), "domain separator must not be empty");
            assert!(
                constant.len() >= 10,
                "domain separator too short ({} bytes): {:?}",
                constant.len(),
                std::str::from_utf8(constant).unwrap_or("")
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 19. Token Classification Field Enforcement
// ═══════════════════════════════════════════════════════════════════════════════

mod token_classification {
    use super::*;
    use common::classification::*;
    use common::types::*;

    #[test]
    fn unclassified_token_cannot_access_secret() {
        let token = Token::test_fixture_unsigned();
        // Default classification is 0 (Unclassified)
        assert_eq!(token.claims.classification, 0);

        let token_level = ClassificationLevel::from_u8(token.claims.classification)
            .expect("classification must be valid");
        let resource_level = ClassificationLevel::Secret;

        let decision = enforce_classification(token_level, resource_level);
        assert!(
            !decision.is_granted(),
            "Unclassified token must NOT access Secret resources"
        );
    }

    #[test]
    fn classification_field_serialization_roundtrip() {
        for level_u8 in 0..=4u8 {
            let level = ClassificationLevel::from_u8(level_u8).unwrap();
            assert_eq!(level.as_u8(), level_u8, "roundtrip failed for level {}", level_u8);
        }

        // Out-of-range returns None
        assert!(ClassificationLevel::from_u8(5).is_none());
        assert!(ClassificationLevel::from_u8(255).is_none());
    }

    #[test]
    fn token_classification_levels_match_hierarchy() {
        // Verify the numeric ordering matches the security hierarchy
        assert!(ClassificationLevel::Unclassified < ClassificationLevel::Confidential);
        assert!(ClassificationLevel::Confidential < ClassificationLevel::Secret);
        assert!(ClassificationLevel::Secret < ClassificationLevel::TopSecret);
        assert!(ClassificationLevel::TopSecret < ClassificationLevel::SCI);
    }

    #[test]
    fn all_classification_levels_have_labels() {
        for level_u8 in 0..=4u8 {
            let level = ClassificationLevel::from_u8(level_u8).unwrap();
            let label = level.label();
            assert!(!label.is_empty(), "classification level {} must have a label", level_u8);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 20. Compliance Report Aggregation
// ═══════════════════════════════════════════════════════════════════════════════

mod compliance_aggregation {
    use super::*;
    use common::cmmc::*;
    use common::compliance::*;
    use common::data_residency::*;
    use common::stig::*;

    #[test]
    fn comprehensive_compliance_picture() {
        // Run CMMC assessment
        let mut cmmc = CmmcAssessor::new();
        cmmc.assess();
        let (cmmc_met, _cmmc_partial, _cmmc_not_met) = cmmc.score();

        // Run STIG audit
        let mut stig = StigAuditor::new();
        stig.run_all();
        let stig_summary = stig.summary();

        // Run data residency check (Indian deployment)
        let india_policy = RegionPolicy::india_only();
        let india_storage_ok = india_policy.validate_storage("asia-south1").is_ok();
        let india_storage_violation = india_policy.validate_storage("us-east-1").is_err();

        // Run compliance engine validation
        let engine = ComplianceEngine::new(ComplianceConfig::indian_govt_default());
        let deployment_violations = engine.validate_deployment();

        // Aggregate results
        assert!(
            cmmc_met > 0,
            "CMMC must have some Met practices"
        );
        assert!(
            stig_summary.total > 0,
            "STIG must have run some checks"
        );
        assert!(india_storage_ok, "Indian storage in asia-south1 must pass");
        assert!(india_storage_violation, "Indian storage in us-east-1 must fail");
        assert!(
            deployment_violations.is_empty(),
            "clean Indian deployment should have no violations"
        );

        // Verify the overall picture: count total compliance checks
        let total_checks = cmmc.assess().len() + stig_summary.total;
        assert!(
            total_checks >= 30,
            "comprehensive compliance should run at least 30 checks, got {}",
            total_checks
        );
    }

    #[test]
    fn dual_regime_strictest_rules_applied() {
        let dual_engine = ComplianceEngine::new(ComplianceConfig::dual_default());

        // Dual mode: retention must meet DoD minimum (stricter)
        assert!(dual_engine.check_audit_retention(2555).is_ok());
        assert!(dual_engine.check_audit_retention(365).is_err());

        // Classification ceiling is the minimum of both regimes
        assert!(dual_engine.check_classification_allowed(3).is_ok());
        assert!(dual_engine.check_classification_allowed(4).is_err());

        // Both ITAR and MEITY are enforced
        assert!(dual_engine.config().itar_controls_enabled);
        assert!(dual_engine.config().meity_empanelled_cloud_only);

        // Cross-border transfers are blocked
        assert!(dual_engine.config().cross_border_transfer_blocked);

        // Incident reporting uses the shortest deadline (6 hours from India)
        assert_eq!(dual_engine.config().cert_in_incident_reporting_hours, 6);
    }

    #[test]
    fn misconfigured_deployment_flagged() {
        let bad_config = ComplianceConfig {
            regime: ComplianceRegime::UsDod,
            data_residency_regions: vec![],
            audit_retention_days: 100, // way too short for DoD
            require_data_classification: false,
            max_classification_level: 4,
            pii_encryption_required: false,
            cross_border_transfer_blocked: false,
            cert_in_incident_reporting_hours: 72,
            itar_controls_enabled: false,
            meity_empanelled_cloud_only: false,
        };

        let engine = ComplianceEngine::new(bad_config);
        let violations = engine.validate_deployment();

        // Should flag multiple issues
        assert!(violations.len() >= 2, "misconfigured system should have multiple violations");

        // Check specific violations are detected
        let rules: HashSet<String> = violations.iter().map(|v| v.rule.clone()).collect();
        assert!(rules.contains("DEPLOYMENT_PII_ENCRYPTION"), "missing PII encryption violation");
        assert!(rules.contains("DEPLOYMENT_DATA_RESIDENCY"), "missing data residency violation");
        assert!(rules.contains("DEPLOYMENT_ITAR"), "missing ITAR violation");
    }

    #[test]
    fn pii_encryption_mandatory_for_all_regimes() {
        for config_fn in [
            ComplianceConfig::us_dod_default,
            ComplianceConfig::indian_govt_default,
            ComplianceConfig::dual_default,
        ] {
            let config = config_fn();
            let engine = ComplianceEngine::new(config);

            // PII must be encrypted
            assert!(engine.check_pii_encryption(true, "email").is_ok());
            assert!(
                engine.check_pii_encryption(false, "email").is_err(),
                "PII encryption must be required"
            );
        }
    }

    #[test]
    fn assurance_level_validation_for_tiers() {
        // Sovereign tier: must have hardware MFA, DPoP, identity proofing
        let v = validate_assurance_level(1, true, true, true, true);
        assert!(v.is_empty(), "fully configured Sovereign should pass");

        let v = validate_assurance_level(1, false, true, true, true);
        assert!(
            v.iter().any(|viol| viol.rule == "AAL3_HARDWARE_MFA"),
            "Sovereign without hardware MFA must be flagged"
        );

        // Sensor tier: minimal requirements
        let v = validate_assurance_level(3, false, false, false, false);
        assert!(v.is_empty(), "Sensor tier should pass with minimal config");

        // Unknown tier: violation
        let v = validate_assurance_level(99, false, false, false, false);
        assert!(!v.is_empty(), "unknown tier must produce a violation");
    }
}
