//! Data residency validation for India (CERT-In / DPDP Act) and US GovCloud (DoD).
//!
//! Provides region policies that enforce where data may be stored, replicated, and backed up.

use std::collections::HashSet;

/// GCP regions approved for Indian government data.
pub const INDIA_REGIONS: &[&str] = &["asia-south1", "asia-south2"];

/// AWS GovCloud regions approved for US DoD data.
pub const GOVCLOUD_REGIONS: &[&str] = &["us-gov-west-1", "us-gov-east-1"];

/// Cloud provider used by a deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudProvider {
    Gcp,
    AwsGovCloud,
    OnPremises,
}

/// Enforces data residency constraints for storage, replication, and backups.
pub struct RegionPolicy {
    allowed_regions: HashSet<String>,
    /// ISO-3166-1 alpha-2 country codes permitted for data operations.
    #[allow(dead_code)]
    allowed_countries: HashSet<String>,
    cloud_provider: CloudProvider,
}

impl RegionPolicy {
    /// Policy that restricts data to Indian regions only (GCP asia-south*).
    pub fn india_only() -> Self {
        let allowed_regions: HashSet<String> =
            INDIA_REGIONS.iter().map(|s| s.to_string()).collect();
        let mut allowed_countries = HashSet::new();
        allowed_countries.insert("IN".to_string());
        Self {
            allowed_regions,
            allowed_countries,
            cloud_provider: CloudProvider::Gcp,
        }
    }

    /// Policy that restricts data to US GovCloud regions only (AWS).
    pub fn us_govcloud_only() -> Self {
        let allowed_regions: HashSet<String> =
            GOVCLOUD_REGIONS.iter().map(|s| s.to_string()).collect();
        let mut allowed_countries = HashSet::new();
        allowed_countries.insert("US".to_string());
        Self {
            allowed_regions,
            allowed_countries,
            cloud_provider: CloudProvider::AwsGovCloud,
        }
    }

    /// Dual policy: data may reside in either India or US GovCloud regions.
    pub fn dual_india_govcloud() -> Self {
        let allowed_regions: HashSet<String> = INDIA_REGIONS
            .iter()
            .chain(GOVCLOUD_REGIONS.iter())
            .map(|s| s.to_string())
            .collect();
        let mut allowed_countries = HashSet::new();
        allowed_countries.insert("IN".to_string());
        allowed_countries.insert("US".to_string());
        Self {
            allowed_regions,
            allowed_countries,
            cloud_provider: CloudProvider::OnPremises,
        }
    }

    /// Validate that a storage operation targets an allowed region.
    pub fn validate_storage(&self, region: &str) -> Result<(), String> {
        if self.allowed_regions.contains(region) {
            Ok(())
        } else {
            Err(format!(
                "Storage region '{}' is not in the allowed set: {:?}",
                region,
                self.allowed_regions_sorted()
            ))
        }
    }

    /// Validate that both source and destination of a replication are allowed.
    pub fn validate_replication(&self, source: &str, dest: &str) -> Result<(), String> {
        self.validate_storage(source).map_err(|e| {
            format!("Replication source rejected: {e}")
        })?;
        self.validate_storage(dest).map_err(|e| {
            format!("Replication destination rejected: {e}")
        })?;
        Ok(())
    }

    /// Validate that a backup location is within allowed regions.
    pub fn validate_backup(&self, location: &str) -> Result<(), String> {
        if self.allowed_regions.contains(location) {
            Ok(())
        } else {
            Err(format!(
                "Backup location '{}' is not in the allowed set: {:?}",
                location,
                self.allowed_regions_sorted()
            ))
        }
    }

    /// Return the set of allowed regions.
    pub fn allowed_regions(&self) -> &HashSet<String> {
        &self.allowed_regions
    }

    /// Return the cloud provider for this policy.
    pub fn cloud_provider(&self) -> CloudProvider {
        self.cloud_provider
    }

    /// Sorted list of allowed regions for deterministic error messages.
    fn allowed_regions_sorted(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.allowed_regions.iter().map(|s| s.as_str()).collect();
        v.sort_unstable();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_region_policy_india() {
        let policy = RegionPolicy::india_only();

        // Valid Indian regions
        assert!(policy.validate_storage("asia-south1").is_ok());
        assert!(policy.validate_storage("asia-south2").is_ok());

        // Non-Indian regions rejected
        assert!(policy.validate_storage("us-gov-west-1").is_err());
        assert!(policy.validate_storage("us-east-1").is_err());
        assert!(policy.validate_storage("eu-west-1").is_err());

        // Backup validation
        assert!(policy.validate_backup("asia-south1").is_ok());
        assert!(policy.validate_backup("us-gov-west-1").is_err());

        // Provider
        assert_eq!(policy.cloud_provider(), CloudProvider::Gcp);

        // Allowed regions contains exactly the India regions
        for r in INDIA_REGIONS {
            assert!(policy.allowed_regions().contains(*r));
        }
        for r in GOVCLOUD_REGIONS {
            assert!(!policy.allowed_regions().contains(*r));
        }
    }

    #[test]
    fn test_region_policy_govcloud() {
        let policy = RegionPolicy::us_govcloud_only();

        // Valid GovCloud regions
        assert!(policy.validate_storage("us-gov-west-1").is_ok());
        assert!(policy.validate_storage("us-gov-east-1").is_ok());

        // Indian regions rejected
        assert!(policy.validate_storage("asia-south1").is_err());
        assert!(policy.validate_storage("us-east-1").is_err());

        // Provider
        assert_eq!(policy.cloud_provider(), CloudProvider::AwsGovCloud);

        for r in GOVCLOUD_REGIONS {
            assert!(policy.allowed_regions().contains(*r));
        }
        for r in INDIA_REGIONS {
            assert!(!policy.allowed_regions().contains(*r));
        }
    }

    #[test]
    fn test_replication_india_internal() {
        let policy = RegionPolicy::india_only();
        // Replication within India is allowed
        assert!(policy.validate_replication("asia-south1", "asia-south2").is_ok());
        assert!(policy.validate_replication("asia-south2", "asia-south1").is_ok());
        // Same-region replication also allowed
        assert!(policy.validate_replication("asia-south1", "asia-south1").is_ok());
    }

    #[test]
    fn test_replication_india_cross_border() {
        let policy = RegionPolicy::india_only();
        // Cross-border replication is rejected
        assert!(policy.validate_replication("asia-south1", "us-gov-west-1").is_err());
        assert!(policy.validate_replication("us-gov-west-1", "asia-south1").is_err());
        assert!(policy.validate_replication("asia-south1", "eu-west-1").is_err());
    }
}
