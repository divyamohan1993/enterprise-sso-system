//! Compliance policy engine for US DoD and Indian Government regulatory regimes.
//!
//! Supports DISA STIG / ITAR (UsDod), CERT-In / DPDP Act / MEITY (IndianGovt),
//! and a dual-regime mode that enforces the union of both.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// NIST SP 800-63-3 Assurance Level Declarations
// ---------------------------------------------------------------------------

/// NIST SP 800-63-3 Identity Assurance Levels.
///
/// Defines the degree of confidence in identity proofing:
/// - **IAL1**: Self-asserted identity (no proofing required).
/// - **IAL2**: Remote or in-person proofing with evidence verification.
/// - **IAL3**: In-person proofing with physical document verification and biometrics.
///
/// # Tier Mapping
///
/// | DeviceTier   | IAL | Rationale                                    |
/// |-------------|-----|----------------------------------------------|
/// | Sovereign   | IAL3 | Command-level: requires in-person proofing  |
/// | Operational | IAL2 | Standard ops: remote proofing acceptable     |
/// | Sensor      | IAL1 | Device identity only, no human proofing      |
/// | Emergency   | IAL1 | Degraded mode, minimal proofing              |
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub enum IdentityAssuranceLevel {
    /// IAL1: Self-asserted identity
    Ial1,
    /// IAL2: Remote or in-person proofing
    Ial2,
    /// IAL3: In-person proofing with physical verification
    Ial3,
}

/// NIST SP 800-63-3 Authenticator Assurance Levels.
///
/// Defines the strength of the authentication process:
/// - **AAL1**: Single-factor authentication (password or TOTP alone).
/// - **AAL2**: Two-factor authentication; phishing-resistant optional.
/// - **AAL3**: Hardware-based multi-factor, phishing-resistant required (FIDO2/CAC).
///
/// # Tier Mapping
///
/// | DeviceTier   | AAL | Authentication Methods Required               |
/// |-------------|-----|------------------------------------------------|
/// | Sovereign   | AAL3 | FIDO2 + CAC/PIV hardware token (phishing-resistant) |
/// | Operational | AAL2 | OPAQUE + TOTP or FIDO2                         |
/// | Sensor      | AAL1 | Device certificate or single-factor            |
/// | Emergency   | AAL1 | Degraded authentication path                   |
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub enum AuthenticatorAssuranceLevel {
    /// AAL1: Single-factor authentication
    Aal1,
    /// AAL2: Two-factor authentication (phishing-resistant optional)
    Aal2,
    /// AAL3: Hardware-based multi-factor, phishing-resistant
    Aal3,
}

/// NIST SP 800-63-3 Federation Assurance Levels.
///
/// Defines the strength of federated identity assertions:
/// - **FAL1**: Bearer assertion (e.g., signed SAML or JWT).
/// - **FAL2**: Holder-of-key assertion (DPoP proof-of-possession).
/// - **FAL3**: Holder-of-key + direct presentation (no intermediary).
///
/// # Tier Mapping
///
/// | DeviceTier   | FAL | Assertion Type                                |
/// |-------------|-----|-----------------------------------------------|
/// | Sovereign   | FAL3 | Direct presentation with DPoP + mTLS         |
/// | Operational | FAL2 | DPoP holder-of-key assertion                  |
/// | Sensor      | FAL1 | Bearer assertion (signed JWT)                 |
/// | Emergency   | FAL1 | Bearer assertion (degraded mode)              |
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub enum FederationAssuranceLevel {
    /// FAL1: Bearer assertion
    Fal1,
    /// FAL2: Holder-of-key assertion
    Fal2,
    /// FAL3: Holder-of-key + direct presentation
    Fal3,
}

/// Combined NIST SP 800-63-3 assurance level binding for a given tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssuranceLevelBinding {
    pub ial: IdentityAssuranceLevel,
    pub aal: AuthenticatorAssuranceLevel,
    pub fal: FederationAssuranceLevel,
}

/// Map a `DeviceTier` numeric value to its required NIST SP 800-63-3 assurance levels.
///
/// Tier values follow `crate::types::DeviceTier`:
/// - 1 = Sovereign, 2 = Operational, 3 = Sensor, 4 = Emergency
///
/// Returns `None` for unrecognized tier values.
pub fn assurance_levels_for_tier(tier: u8) -> Option<AssuranceLevelBinding> {
    match tier {
        1 => Some(AssuranceLevelBinding {
            ial: IdentityAssuranceLevel::Ial3,
            aal: AuthenticatorAssuranceLevel::Aal3,
            fal: FederationAssuranceLevel::Fal3,
        }),
        2 => Some(AssuranceLevelBinding {
            ial: IdentityAssuranceLevel::Ial2,
            aal: AuthenticatorAssuranceLevel::Aal2,
            fal: FederationAssuranceLevel::Fal2,
        }),
        3 => Some(AssuranceLevelBinding {
            ial: IdentityAssuranceLevel::Ial1,
            aal: AuthenticatorAssuranceLevel::Aal1,
            fal: FederationAssuranceLevel::Fal1,
        }),
        4 => Some(AssuranceLevelBinding {
            ial: IdentityAssuranceLevel::Ial1,
            aal: AuthenticatorAssuranceLevel::Aal1,
            fal: FederationAssuranceLevel::Fal1,
        }),
        _ => None,
    }
}

/// Validate that a deployment's authentication configuration meets the declared
/// assurance level requirements.
///
/// # Parameters
/// - `tier`: The `DeviceTier` numeric value (1-4).
/// - `has_hardware_mfa`: Whether FIDO2/CAC hardware MFA is enforced.
/// - `has_two_factor`: Whether any two-factor authentication is enforced.
/// - `has_dpop`: Whether DPoP proof-of-possession is enforced on tokens.
/// - `has_identity_proofing`: Whether in-person or remote identity proofing is performed.
///
/// # Returns
/// A list of compliance violations (empty if fully compliant).
pub fn validate_assurance_level(
    tier: u8,
    has_hardware_mfa: bool,
    has_two_factor: bool,
    has_dpop: bool,
    has_identity_proofing: bool,
) -> Vec<ComplianceViolation> {
    let mut violations = Vec::new();

    let binding = match assurance_levels_for_tier(tier) {
        Some(b) => b,
        None => {
            violations.push(ComplianceViolation::new(
                "ASSURANCE_LEVEL",
                format!("Unknown device tier: {}", tier),
                ComplianceSeverity::Critical,
            ));
            return violations;
        }
    };

    // AAL validation
    match binding.aal {
        AuthenticatorAssuranceLevel::Aal3 => {
            if !has_hardware_mfa {
                violations.push(ComplianceViolation::new(
                    "AAL3_HARDWARE_MFA",
                    "AAL3 requires hardware-based phishing-resistant MFA (FIDO2/CAC) but it is not enforced".to_string(),
                    ComplianceSeverity::Critical,
                ));
            }
        }
        AuthenticatorAssuranceLevel::Aal2 => {
            if !has_two_factor {
                violations.push(ComplianceViolation::new(
                    "AAL2_TWO_FACTOR",
                    "AAL2 requires two-factor authentication but it is not enforced".to_string(),
                    ComplianceSeverity::High,
                ));
            }
        }
        AuthenticatorAssuranceLevel::Aal1 => {
            // AAL1: single-factor is sufficient; no additional check needed.
        }
    }

    // FAL validation
    match binding.fal {
        FederationAssuranceLevel::Fal3 | FederationAssuranceLevel::Fal2 => {
            if !has_dpop {
                violations.push(ComplianceViolation::new(
                    "FAL_HOLDER_OF_KEY",
                    format!(
                        "{:?} requires DPoP holder-of-key assertions but DPoP is not enforced",
                        binding.fal
                    ),
                    ComplianceSeverity::High,
                ));
            }
        }
        FederationAssuranceLevel::Fal1 => {}
    }

    // IAL validation
    match binding.ial {
        IdentityAssuranceLevel::Ial3 | IdentityAssuranceLevel::Ial2 => {
            if !has_identity_proofing {
                violations.push(ComplianceViolation::new(
                    "IAL_IDENTITY_PROOFING",
                    format!(
                        "{:?} requires identity proofing but it is not configured",
                        binding.ial
                    ),
                    ComplianceSeverity::High,
                ));
            }
        }
        IdentityAssuranceLevel::Ial1 => {}
    }

    violations
}

// ---------------------------------------------------------------------------
// Regulatory Compliance
// ---------------------------------------------------------------------------

/// Regulatory compliance regime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ComplianceRegime {
    UsDod,
    IndianGovt,
    Dual,
}

/// Full compliance configuration for a deployment.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ComplianceConfig {
    pub regime: ComplianceRegime,
    pub data_residency_regions: Vec<String>,
    pub audit_retention_days: u64,
    pub require_data_classification: bool,
    pub max_classification_level: u8,
    pub pii_encryption_required: bool,
    pub cross_border_transfer_blocked: bool,
    pub cert_in_incident_reporting_hours: u64,
    pub itar_controls_enabled: bool,
    pub meity_empanelled_cloud_only: bool,
}

impl ComplianceConfig {
    /// Default configuration for US DoD (DISA STIG / ITAR).
    pub fn us_dod_default() -> Self {
        Self {
            regime: ComplianceRegime::UsDod,
            data_residency_regions: vec![
                "us-gov-west-1".to_string(),
                "us-gov-east-1".to_string(),
            ],
            audit_retention_days: 2555, // ~7 years
            require_data_classification: true,
            max_classification_level: 4,
            pii_encryption_required: true,
            cross_border_transfer_blocked: true,
            cert_in_incident_reporting_hours: 72, // NIST default
            itar_controls_enabled: true,
            meity_empanelled_cloud_only: false,
        }
    }

    /// Default configuration for Indian Government (CERT-In / DPDP Act / MEITY).
    pub fn indian_govt_default() -> Self {
        Self {
            regime: ComplianceRegime::IndianGovt,
            data_residency_regions: vec![
                "asia-south1".to_string(),
                "asia-south2".to_string(),
            ],
            audit_retention_days: 365,
            require_data_classification: true,
            max_classification_level: 3,
            pii_encryption_required: true,
            cross_border_transfer_blocked: true,
            cert_in_incident_reporting_hours: 6,
            itar_controls_enabled: false,
            meity_empanelled_cloud_only: true,
        }
    }

    /// Dual regime: merges both, uses the most restrictive values.
    pub fn dual_default() -> Self {
        let dod = Self::us_dod_default();
        let india = Self::indian_govt_default();

        // Merge allowed regions (union)
        let mut regions = dod.data_residency_regions.clone();
        for r in &india.data_residency_regions {
            if !regions.contains(r) {
                regions.push(r.clone());
            }
        }

        // Most restrictive: minimum of classification levels
        let max_classification_level =
            dod.max_classification_level.min(india.max_classification_level);

        // Most restrictive: maximum retention
        let audit_retention_days = dod.audit_retention_days.max(india.audit_retention_days);

        // Most restrictive: minimum incident reporting window
        let cert_in_incident_reporting_hours = dod
            .cert_in_incident_reporting_hours
            .min(india.cert_in_incident_reporting_hours);

        Self {
            regime: ComplianceRegime::Dual,
            data_residency_regions: regions,
            audit_retention_days,
            require_data_classification: true,
            max_classification_level,
            pii_encryption_required: true,
            cross_border_transfer_blocked: true,
            cert_in_incident_reporting_hours,
            itar_controls_enabled: true,
            meity_empanelled_cloud_only: true,
        }
    }
}

/// A recorded compliance violation.
#[derive(Debug, Clone)]
pub struct ComplianceViolation {
    pub timestamp: i64,
    pub rule: String,
    pub detail: String,
    pub severity: ComplianceSeverity,
    pub auto_remediated: bool,
}

impl ComplianceViolation {
    fn new(rule: impl Into<String>, detail: impl Into<String>, severity: ComplianceSeverity) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as i64)
            .unwrap_or(0);
        Self {
            timestamp,
            rule: rule.into(),
            detail: detail.into(),
            severity,
            auto_remediated: false,
        }
    }
}

/// Severity levels for compliance violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplianceSeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// The runtime compliance policy engine.
pub struct ComplianceEngine {
    config: ComplianceConfig,
    violations: Vec<ComplianceViolation>,
}

impl ComplianceEngine {
    /// Create a new engine with the given configuration.
    pub fn new(config: ComplianceConfig) -> Self {
        Self {
            config,
            violations: Vec::new(),
        }
    }

    /// Access the underlying configuration.
    pub fn config(&self) -> &ComplianceConfig {
        &self.config
    }

    /// Verify that `target_region` is in the allowed data residency list.
    pub fn check_data_residency(&self, target_region: &str) -> Result<(), ComplianceViolation> {
        let allowed = &self.config.data_residency_regions;
        if allowed.iter().any(|r| r == target_region) {
            Ok(())
        } else {
            Err(ComplianceViolation::new(
                "DATA_RESIDENCY",
                format!(
                    "Region '{}' is not in the allowed list for {:?}: {:?}",
                    target_region, self.config.regime, allowed
                ),
                ComplianceSeverity::Critical,
            ))
        }
    }

    /// Verify that PII is encrypted when required.
    pub fn check_pii_encryption(
        &self,
        is_encrypted: bool,
        field_name: &str,
    ) -> Result<(), ComplianceViolation> {
        if self.config.pii_encryption_required && !is_encrypted {
            return Err(ComplianceViolation::new(
                "PII_ENCRYPTION",
                format!(
                    "PII field '{}' is not encrypted; encryption is required under {:?}",
                    field_name, self.config.regime
                ),
                ComplianceSeverity::Critical,
            ));
        }
        Ok(())
    }

    /// Verify that the configured retention period meets the minimum.
    pub fn check_audit_retention(
        &self,
        current_retention_days: u64,
    ) -> Result<(), ComplianceViolation> {
        let required = self.config.audit_retention_days;
        if current_retention_days < required {
            return Err(ComplianceViolation::new(
                "AUDIT_RETENTION",
                format!(
                    "Audit retention {} days is below the minimum {} days required under {:?}",
                    current_retention_days, required, self.config.regime
                ),
                ComplianceSeverity::High,
            ));
        }
        Ok(())
    }

    /// Verify that the classification level does not exceed the ceiling.
    pub fn check_classification_allowed(&self, level: u8) -> Result<(), ComplianceViolation> {
        let ceiling = self.config.max_classification_level;
        if level > ceiling {
            return Err(ComplianceViolation::new(
                "CLASSIFICATION_CEILING",
                format!(
                    "Classification level {} exceeds maximum {} under {:?}",
                    level, ceiling, self.config.regime
                ),
                ComplianceSeverity::Critical,
            ));
        }
        Ok(())
    }

    /// Verify that a cross-border data transfer is permitted.
    ///
    /// Returns `Ok(())` if both regions are in the same allowed set,
    /// or if cross-border transfers are not blocked.
    pub fn check_cross_border(
        &self,
        source_region: &str,
        dest_region: &str,
    ) -> Result<(), ComplianceViolation> {
        if !self.config.cross_border_transfer_blocked {
            return Ok(());
        }
        let allowed = &self.config.data_residency_regions;
        let src_ok = allowed.iter().any(|r| r == source_region);
        let dst_ok = allowed.iter().any(|r| r == dest_region);
        if !src_ok || !dst_ok {
            return Err(ComplianceViolation::new(
                "CROSS_BORDER_TRANSFER",
                format!(
                    "Transfer from '{}' to '{}' violates cross-border restriction under {:?}. \
                     Allowed regions: {:?}",
                    source_region, dest_region, self.config.regime, allowed
                ),
                ComplianceSeverity::Critical,
            ));
        }
        Ok(())
    }

    /// Calculate the CERT-In reporting deadline for an incident.
    ///
    /// Returns the deadline as a Unix microsecond timestamp, or a violation
    /// if the deadline has already passed.
    ///
    /// `incident_time_us` is the incident timestamp in microseconds since epoch.
    pub fn check_incident_reporting_deadline(
        &self,
        incident_time_us: i64,
    ) -> Result<i64, ComplianceViolation> {
        let hours = self.config.cert_in_incident_reporting_hours;
        let deadline_us = incident_time_us + (hours as i64) * 3_600_000_000;
        let now_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as i64)
            .unwrap_or(0);

        if now_us > deadline_us {
            Err(ComplianceViolation::new(
                "INCIDENT_REPORTING_DEADLINE",
                format!(
                    "Incident reporting deadline of {} hours under {:?} has passed \
                     (deadline was at {} us, now {})",
                    hours, self.config.regime, deadline_us, now_us
                ),
                ComplianceSeverity::Critical,
            ))
        } else {
            Ok(deadline_us)
        }
    }

    /// Run all deployment-level checks and return every violation found.
    ///
    /// This validates the configuration itself rather than individual data items.
    pub fn validate_deployment(&self) -> Vec<ComplianceViolation> {
        let mut violations = Vec::new();

        // Retention check: the configured retention must meet regime minimum
        if let Err(v) = self.check_audit_retention(self.config.audit_retention_days) {
            violations.push(v);
        }

        // PII encryption must be enabled
        if !self.config.pii_encryption_required {
            violations.push(ComplianceViolation::new(
                "DEPLOYMENT_PII_ENCRYPTION",
                format!(
                    "PII encryption is not required in this deployment config (regime: {:?})",
                    self.config.regime
                ),
                ComplianceSeverity::Critical,
            ));
        }

        // At least one allowed region must be configured
        if self.config.data_residency_regions.is_empty() {
            violations.push(ComplianceViolation::new(
                "DEPLOYMENT_DATA_RESIDENCY",
                "No allowed data residency regions are configured".to_string(),
                ComplianceSeverity::Critical,
            ));
        }

        // ITAR check for DoD / Dual
        if matches!(
            self.config.regime,
            ComplianceRegime::UsDod | ComplianceRegime::Dual
        ) && !self.config.itar_controls_enabled
        {
            violations.push(ComplianceViolation::new(
                "DEPLOYMENT_ITAR",
                format!(
                    "ITAR controls must be enabled under {:?} but are disabled",
                    self.config.regime
                ),
                ComplianceSeverity::Critical,
            ));
        }

        // MEITY check for India / Dual
        if matches!(
            self.config.regime,
            ComplianceRegime::IndianGovt | ComplianceRegime::Dual
        ) && !self.config.meity_empanelled_cloud_only
        {
            violations.push(ComplianceViolation::new(
                "DEPLOYMENT_MEITY",
                format!(
                    "MEITY empanelled cloud restriction must be enabled under {:?}",
                    self.config.regime
                ),
                ComplianceSeverity::High,
            ));
        }

        violations
    }

    /// Record a violation into the engine's audit log.
    pub fn record_violation(&mut self, v: ComplianceViolation) {
        self.violations.push(v);
    }

    /// Return a summary of violation counts grouped by rule name.
    pub fn violation_summary(&self) -> HashMap<String, usize> {
        let mut map = HashMap::new();
        for v in &self.violations {
            *map.entry(v.rule.clone()).or_insert(0) += 1;
        }
        map
    }
}

// ---------------------------------------------------------------------------
// Unified Compliance Dashboard
// ---------------------------------------------------------------------------

/// Aggregated compliance dashboard across all frameworks.
#[derive(Debug)]
pub struct ComplianceDashboard {
    /// FIPS 140-3 CMVP validation percentage.
    pub fips_percentage: f64,
    /// CNSA 2.0 Level 5 status (true = all checks pass).
    pub cnsa2_passed: bool,
    /// CMMC compliance percentage (against 110 practices).
    pub cmmc_percentage: f64,
    /// CMMC practices assessed / total.
    pub cmmc_assessed: usize,
    /// Common Criteria SFR coverage (0.0 to 1.0).
    pub cc_sfr_coverage: f64,
    /// FedRAMP controls mapped.
    pub fedramp_controls_mapped: usize,
    /// SOC 2 evidence items collected.
    pub soc2_evidence_count: usize,
    /// STIG check pass rate (0.0 to 1.0).
    pub stig_pass_rate: f64,
    /// Overall readiness assessment.
    pub overall_assessment: String,
}

/// Generate a unified compliance dashboard aggregating all framework scores.
///
/// Runs at startup and logs results to SIEM.
pub fn compliance_dashboard() -> ComplianceDashboard {
    // FIPS
    let fips_summary = crate::fips_validation::fips_compliance_summary();
    let fips_pct = fips_summary.compliance_percentage;

    // CNSA 2.0 (don't call enforce which might exit in military mode)
    let cnsa2_passed = crate::cnsa2::is_cnsa2_compliant();

    // CMMC
    let cmmc = crate::cmmc::CmmcAssessor::new();
    let cmmc_pct = cmmc.compliance_percentage();
    let (met, partial, not_met) = cmmc.score();
    let cmmc_assessed = met + partial + not_met;

    // Common Criteria
    let cc = crate::common_criteria::SecurityTarget::milnet_default();
    let cc_sfr = cc.sfr_implementation_coverage();

    // FedRAMP
    let mut fedramp = crate::fedramp_evidence::SspGenerator::new(
        "MILNET SSO".to_string(),
        crate::fedramp_evidence::FedRampLevel::High,
    );
    fedramp.auto_populate_from_code();
    let fedramp_count = fedramp.controls.len();

    // STIG
    let mut stig = crate::stig::StigAuditor::new();
    stig.run_all();
    let stig_summary = stig.summary();
    let stig_pass = if stig_summary.total > 0 {
        stig_summary.passed as f64 / stig_summary.total as f64
    } else {
        0.0
    };

    let overall = if fips_pct >= 100.0 && cnsa2_passed && cmmc_pct >= 80.0 && cc_sfr >= 0.9 {
        "FULLY COMPLIANT: All frameworks at or above threshold.".to_string()
    } else if fips_pct >= 50.0 || cmmc_pct >= 30.0 {
        format!(
            "PARTIALLY COMPLIANT: FIPS {:.0}%, CMMC {:.0}%, CC SFR {:.0}%. Gaps remain.",
            fips_pct, cmmc_pct, cc_sfr * 100.0
        )
    } else {
        format!(
            "NOT COMPLIANT: FIPS {:.0}%, CMMC {:.0}%, CC SFR {:.0}%. Significant gaps.",
            fips_pct, cmmc_pct, cc_sfr * 100.0
        )
    };

    tracing::info!(
        "SIEM:COMPLIANCE-DASHBOARD FIPS={:.0}% CNSA2={} CMMC={:.0}% CC_SFR={:.0}% \
         FedRAMP_controls={} STIG_pass={:.0}% SOC2=pending assessment={}",
        fips_pct,
        if cnsa2_passed { "PASS" } else { "FAIL" },
        cmmc_pct,
        cc_sfr * 100.0,
        fedramp_count,
        stig_pass * 100.0,
        if overall.starts_with("FULLY") { "COMPLIANT" } else { "GAPS" }
    );

    ComplianceDashboard {
        fips_percentage: fips_pct,
        cnsa2_passed,
        cmmc_percentage: cmmc_pct,
        cmmc_assessed,
        cc_sfr_coverage: cc_sfr,
        fedramp_controls_mapped: fedramp_count,
        soc2_evidence_count: 0, // populated when auto_populate is called
        stig_pass_rate: stig_pass,
        overall_assessment: overall,
    }
}

/// Run all compliance checks at startup and log results to SIEM.
pub fn run_compliance_startup_checks() {
    // FIPS startup check
    crate::fips_validation::fips_startup_check();

    // Generate dashboard
    let dashboard = compliance_dashboard();

    tracing::info!(
        "SIEM:COMPLIANCE-STARTUP Overall: {}",
        dashboard.overall_assessment
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn india_engine() -> ComplianceEngine {
        ComplianceEngine::new(ComplianceConfig::indian_govt_default())
    }

    fn dod_engine() -> ComplianceEngine {
        ComplianceEngine::new(ComplianceConfig::us_dod_default())
    }

    fn dual_engine() -> ComplianceEngine {
        ComplianceEngine::new(ComplianceConfig::dual_default())
    }

    #[test]
    fn test_compliance_india_data_residency() {
        let engine = india_engine();
        assert!(engine.check_data_residency("asia-south1").is_ok());
        assert!(engine.check_data_residency("asia-south2").is_ok());
        assert!(engine.check_data_residency("us-east-1").is_err());
        assert!(engine.check_data_residency("us-gov-west-1").is_err());
    }

    #[test]
    fn test_compliance_india_audit_retention_365() {
        let engine = india_engine();
        assert!(engine.check_audit_retention(365).is_ok());
        assert!(engine.check_audit_retention(400).is_ok());
        assert!(engine.check_audit_retention(364).is_err());
        assert!(engine.check_audit_retention(0).is_err());
    }

    #[test]
    fn test_compliance_dod_audit_retention_2555() {
        let engine = dod_engine();
        assert!(engine.check_audit_retention(2555).is_ok());
        assert!(engine.check_audit_retention(3000).is_ok());
        assert!(engine.check_audit_retention(2554).is_err());
        assert!(engine.check_audit_retention(365).is_err());
    }

    #[test]
    fn test_compliance_cross_border_blocked() {
        let engine = india_engine();
        // Both in allowed: OK
        assert!(engine.check_cross_border("asia-south1", "asia-south2").is_ok());
        // Destination outside: blocked
        assert!(engine.check_cross_border("asia-south1", "us-east-1").is_err());
        // Source outside: blocked
        assert!(engine.check_cross_border("eu-west-1", "asia-south1").is_err());
    }

    #[test]
    fn test_compliance_pii_encryption_enforced() {
        let engine = india_engine();
        assert!(engine.check_pii_encryption(true, "email").is_ok());
        let violation = engine.check_pii_encryption(false, "email");
        assert!(violation.is_err());
        let v = violation.unwrap_err();
        assert_eq!(v.rule, "PII_ENCRYPTION");
        assert_eq!(v.severity, ComplianceSeverity::Critical);
    }

    #[test]
    fn test_compliance_classification_ceiling() {
        let engine = india_engine(); // max_classification_level = 3
        assert!(engine.check_classification_allowed(0).is_ok());
        assert!(engine.check_classification_allowed(3).is_ok());
        assert!(engine.check_classification_allowed(4).is_err());

        let dod = dod_engine(); // max_classification_level = 4
        assert!(dod.check_classification_allowed(4).is_ok());
        assert!(dod.check_classification_allowed(5).is_err());
    }

    #[test]
    fn test_compliance_cert_in_incident_deadline() {
        let engine = india_engine(); // cert_in = 6 hours
        // Incident that happened 10 hours in the future from now (deadline not passed)
        let future_incident = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as i64)
            .unwrap_or(0)
            + 10 * 3_600_000_000_i64;
        let result = engine.check_incident_reporting_deadline(future_incident);
        assert!(result.is_ok(), "future incident should have deadline in future");

        // Incident that happened 10 hours ago — deadline (6h) has passed
        let old_incident = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as i64)
            .unwrap_or(0)
            - 10 * 3_600_000_000_i64;
        let result = engine.check_incident_reporting_deadline(old_incident);
        assert!(result.is_err(), "old incident should be past deadline");
    }

    #[test]
    fn test_compliance_dual_mode() {
        let engine = dual_engine();
        // Both GovCloud and India regions are allowed in dual mode
        assert!(engine.check_data_residency("us-gov-west-1").is_ok());
        assert!(engine.check_data_residency("asia-south1").is_ok());
        // EU is blocked in both
        assert!(engine.check_data_residency("eu-west-1").is_err());

        // Retention must meet DoD minimum (2555) — the stricter one
        assert!(engine.check_audit_retention(2555).is_ok());
        assert!(engine.check_audit_retention(365).is_err());

        // ITAR and MEITY are both enabled
        assert!(engine.config().itar_controls_enabled);
        assert!(engine.config().meity_empanelled_cloud_only);

        // Classification ceiling is the minimum of both regimes (3)
        assert!(engine.check_classification_allowed(3).is_ok());
        assert!(engine.check_classification_allowed(4).is_err());
    }

    #[test]
    fn test_compliance_startup_validation() {
        // Valid DoD config should produce no violations
        let engine = dod_engine();
        let violations = engine.validate_deployment();
        assert!(
            violations.is_empty(),
            "clean DoD config should have no violations: {:?}",
            violations.iter().map(|v| &v.detail).collect::<Vec<_>>()
        );

        // Valid India config should produce no violations
        let engine = india_engine();
        let violations = engine.validate_deployment();
        assert!(
            violations.is_empty(),
            "clean India config should have no violations: {:?}",
            violations.iter().map(|v| &v.detail).collect::<Vec<_>>()
        );

        // Misconfigured: PII not required + no regions
        let bad_config = ComplianceConfig {
            regime: ComplianceRegime::UsDod,
            data_residency_regions: vec![],
            audit_retention_days: 2555,
            require_data_classification: true,
            max_classification_level: 4,
            pii_encryption_required: false,
            cross_border_transfer_blocked: true,
            cert_in_incident_reporting_hours: 72,
            itar_controls_enabled: false,
            meity_empanelled_cloud_only: false,
        };
        let engine = ComplianceEngine::new(bad_config);
        let violations = engine.validate_deployment();
        // Should have: PII not required, no regions, ITAR not enabled
        assert!(
            violations.len() >= 2,
            "expected at least 2 violations, got {:?}",
            violations.iter().map(|v| &v.rule).collect::<Vec<_>>()
        );
        assert!(violations.iter().any(|v| v.rule == "DEPLOYMENT_PII_ENCRYPTION"));
        assert!(violations.iter().any(|v| v.rule == "DEPLOYMENT_DATA_RESIDENCY"));
    }

    // ── NIST SP 800-63-3 Assurance Level Tests ──

    #[test]
    fn test_assurance_levels_sovereign_tier() {
        let binding = assurance_levels_for_tier(1).expect("tier 1 must be valid");
        assert_eq!(binding.ial, IdentityAssuranceLevel::Ial3);
        assert_eq!(binding.aal, AuthenticatorAssuranceLevel::Aal3);
        assert_eq!(binding.fal, FederationAssuranceLevel::Fal3);
    }

    #[test]
    fn test_assurance_levels_operational_tier() {
        let binding = assurance_levels_for_tier(2).expect("tier 2 must be valid");
        assert_eq!(binding.ial, IdentityAssuranceLevel::Ial2);
        assert_eq!(binding.aal, AuthenticatorAssuranceLevel::Aal2);
        assert_eq!(binding.fal, FederationAssuranceLevel::Fal2);
    }

    #[test]
    fn test_assurance_levels_sensor_tier() {
        let binding = assurance_levels_for_tier(3).expect("tier 3 must be valid");
        assert_eq!(binding.ial, IdentityAssuranceLevel::Ial1);
        assert_eq!(binding.aal, AuthenticatorAssuranceLevel::Aal1);
        assert_eq!(binding.fal, FederationAssuranceLevel::Fal1);
    }

    #[test]
    fn test_assurance_levels_emergency_tier() {
        let binding = assurance_levels_for_tier(4).expect("tier 4 must be valid");
        assert_eq!(binding.ial, IdentityAssuranceLevel::Ial1);
        assert_eq!(binding.aal, AuthenticatorAssuranceLevel::Aal1);
        assert_eq!(binding.fal, FederationAssuranceLevel::Fal1);
    }

    #[test]
    fn test_assurance_levels_unknown_tier() {
        assert!(assurance_levels_for_tier(0).is_none());
        assert!(assurance_levels_for_tier(5).is_none());
        assert!(assurance_levels_for_tier(255).is_none());
    }

    #[test]
    fn test_validate_assurance_sovereign_fully_compliant() {
        let violations = validate_assurance_level(1, true, true, true, true);
        assert!(violations.is_empty(), "fully configured Sovereign should have no violations");
    }

    #[test]
    fn test_validate_assurance_sovereign_missing_hardware_mfa() {
        let violations = validate_assurance_level(1, false, true, true, true);
        assert!(violations.iter().any(|v| v.rule == "AAL3_HARDWARE_MFA"));
    }

    #[test]
    fn test_validate_assurance_operational_missing_two_factor() {
        let violations = validate_assurance_level(2, false, false, true, true);
        assert!(violations.iter().any(|v| v.rule == "AAL2_TWO_FACTOR"));
    }

    #[test]
    fn test_validate_assurance_operational_missing_dpop() {
        let violations = validate_assurance_level(2, false, true, false, true);
        assert!(violations.iter().any(|v| v.rule == "FAL_HOLDER_OF_KEY"));
    }

    #[test]
    fn test_validate_assurance_sensor_minimal_ok() {
        // Sensor tier (AAL1/FAL1/IAL1) requires nothing special
        let violations = validate_assurance_level(3, false, false, false, false);
        assert!(violations.is_empty(), "Sensor tier should pass with minimal config");
    }

    #[test]
    fn test_validate_assurance_unknown_tier_violation() {
        let violations = validate_assurance_level(99, false, false, false, false);
        assert!(violations.iter().any(|v| v.rule == "ASSURANCE_LEVEL"));
    }

    #[test]
    fn test_compliance_dashboard() {
        std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
        let dashboard = compliance_dashboard();
        // FIPS should be 0% (no CMVP validation)
        assert!(dashboard.fips_percentage < 1.0);
        // CMMC should be < 50% (not all 110 practices met)
        assert!(dashboard.cmmc_percentage < 50.0);
        // CC SFR coverage < 100% (some unimplemented)
        assert!(dashboard.cc_sfr_coverage < 1.0);
        // FedRAMP should have >= 40 controls
        assert!(dashboard.fedramp_controls_mapped >= 40);
        // Overall should say NOT COMPLIANT or PARTIALLY COMPLIANT
        assert!(
            !dashboard.overall_assessment.starts_with("FULLY"),
            "should not be fully compliant with no FIPS validation"
        );
    }

    #[test]
    fn test_compliance_startup_checks_run() {
        std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
        // Just verify it doesn't panic
        run_compliance_startup_checks();
    }
}
