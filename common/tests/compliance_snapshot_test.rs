//! Snapshot tests for compliance evidence structures.
//!
//! Uses `insta` to capture and verify the output format of compliance reports
//! across CNSA 2.0, CMMC 2.0, STIG audit, and FedRAMP SSP evidence.
//! These snapshots serve as regression guards: any change to compliance output
//! format must be reviewed and explicitly approved.

// ── CNSA 2.0 compliance report format ────────────────────────────────────

#[test]
fn snapshot_cnsa2_compliance_constants() {
    use common::cnsa2;

    let report = serde_json::json!({
        "cnsa2_compliant": cnsa2::is_cnsa2_compliant(),
        "min_hash_output_bytes": cnsa2::MIN_HASH_OUTPUT_BYTES,
        "sha512_output_bytes": cnsa2::SHA512_OUTPUT_BYTES,
        "algorithms": {
            "hash": "SHA-512",
            "symmetric_encryption": "AES-256",
            "digital_signature": "ML-DSA-87 (FIPS 204)",
            "key_exchange": "ML-KEM-1024 (FIPS 203)",
            "key_derivation": "HKDF-SHA512",
        },
        "compliance_assertion": "All primary hash operations use SHA-512 (64 bytes >= 48 byte CNSA 2.0 minimum)",
    });

    insta::assert_yaml_snapshot!("cnsa2_compliance_report", report);
}

// ── CMMC 2.0 assessment output format ────────────────────────────────────

#[test]
fn snapshot_cmmc_assessment_output() {
    use common::cmmc::CmmcAssessor;

    let mut assessor = CmmcAssessor::new();
    let total_practices = assessor.assess().len();

    // Capture a summary structure instead of the full practice list
    // to keep snapshots manageable while still catching format changes.
    let (met, partial, not_met) = assessor.score();
    let gaps: Vec<_> = assessor
        .gaps()
        .iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id,
                "family": p.family,
                "title": p.title,
                "status": format!("{:?}", p.status),
                "gap": p.gap,
            })
        })
        .collect();

    let report = serde_json::json!({
        "assessment_type": "CMMC 2.0 Level 3",
        "framework": "NIST SP 800-171",
        "total_practices": total_practices,
        "score": {
            "met": met,
            "partially_met": partial,
            "not_met": not_met,
        },
        "gaps": gaps,
    });

    insta::assert_yaml_snapshot!("cmmc_assessment_output", report);
}

// ── STIG audit result format ─────────────────────────────────────────────

#[test]
fn snapshot_stig_audit_result() {
    use common::stig::StigAuditor;

    let mut auditor = StigAuditor::new();

    // Build a structured report for snapshotting.
    // Collect check data into owned Vec to release the mutable borrow.
    let check_summaries: Vec<_> = auditor
        .run_all()
        .iter()
        .map(|c| {
            serde_json::json!({
                "id": c.id,
                "title": c.title,
                "severity": format!("{:?}", c.severity),
                "category": format!("{:?}", c.category),
                "status": format!("{:?}", c.status),
            })
        })
        .collect();

    let summary = auditor.summary();

    let report = serde_json::json!({
        "audit_type": "DISA STIG / CIS Level 2",
        "summary": {
            "total": summary.total,
            "passed": summary.passed,
            "failed": summary.failed,
            "not_applicable": summary.not_applicable,
            "manual": summary.manual,
            "cat_i_failures": summary.cat_i_failures,
            "cat_ii_failures": summary.cat_ii_failures,
            "cat_iii_failures": summary.cat_iii_failures,
        },
        "checks": check_summaries,
    });

    insta::assert_yaml_snapshot!("stig_audit_result", report);
}

// ── FedRAMP evidence structure ───────────────────────────────────────────

#[test]
fn snapshot_fedramp_evidence_structure() {
    use common::fedramp_evidence::{
        ControlFamily, ControlImplementation, FedRampLevel, ImplementationStatus, SspGenerator,
    };

    let mut ssp = SspGenerator::new(
        "MILNET SSO System".to_string(),
        FedRampLevel::High,
    );

    // Register representative controls to test the output structure
    ssp.register_control(ControlImplementation {
        control_id: "IA-5(1)".to_string(),
        family: ControlFamily::IA,
        title: "Authenticator Management | Password-Based Authentication".to_string(),
        status: ImplementationStatus::Implemented,
        implementation_description: "OPAQUE aPAKE protocol eliminates server-side password storage.".to_string(),
        code_references: vec!["opaque/src/service.rs".to_string()],
        config_references: vec![],
        responsible_roles: vec!["ISSO".to_string()],
        last_assessed: Some("2026-03-26".to_string()),
    });

    ssp.register_control(ControlImplementation {
        control_id: "SC-13".to_string(),
        family: ControlFamily::SC,
        title: "Cryptographic Protection".to_string(),
        status: ImplementationStatus::Implemented,
        implementation_description: "CNSA 2.0 compliant: ML-DSA-87, ML-KEM-1024, AES-256, HKDF-SHA512.".to_string(),
        code_references: vec!["crypto/src/pq_sign.rs".to_string(), "crypto/src/xwing.rs".to_string()],
        config_references: vec![],
        responsible_roles: vec!["ISSM".to_string()],
        last_assessed: Some("2026-03-26".to_string()),
    });

    let stats = ssp.compliance_stats();
    let report_text = ssp.generate_ssp_report();

    // Snapshot the structural metadata (not the full report text, which is
    // environment-dependent for some fields)
    let evidence = serde_json::json!({
        "system_name": "MILNET SSO System",
        "impact_level": "High",
        "stats": {
            "total_controls": stats.total_controls,
            "implemented": stats.implemented,
            "partially_implemented": stats.partially_implemented,
            "planned": stats.planned,
            "not_applicable": stats.not_applicable,
            "open_poams": stats.open_poams,
            "evidence_count": stats.evidence_count,
        },
        "report_starts_with_header": report_text.starts_with("=== System Security Plan:"),
        "report_contains_summary": report_text.contains("Compliance Summary"),
        "report_contains_controls": report_text.contains("Control Implementations"),
    });

    insta::assert_yaml_snapshot!("fedramp_evidence_structure", evidence);
}
