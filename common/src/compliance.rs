//! Compliance policy engine for US DoD and Indian Government regulatory regimes.
//!
//! Supports DISA STIG / ITAR (UsDod), CERT-In / DPDP Act / MEITY (IndianGovt),
//! and a dual-regime mode that enforces the union of both.

use std::collections::HashMap;

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
}
