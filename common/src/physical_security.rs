//! Physical security and SCIF (Sensitive Compartmented Information Facility)
//! integration.
//!
//! Provides access control policy enforcement for physical security zones,
//! including SCIF facilities, TEMPEST/EMSEC compliance tracking, and
//! two-person integrity (TPI) enforcement.
//!
//! Integrates with the classification module to map zone clearance
//! requirements to the `ClassificationLevel` hierarchy.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from physical security operations.
#[derive(Debug)]
pub enum PhysicalSecurityError {
    /// Access denied — insufficient clearance.
    AccessDenied(String),
    /// Two-person integrity violation.
    TpiViolation(String),
    /// Zone not found.
    ZoneNotFound(String),
    /// TEMPEST compliance failure.
    TempestNonCompliant(String),
    /// Logging error.
    LogError(String),
}

impl std::fmt::Display for PhysicalSecurityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AccessDenied(s) => write!(f, "access denied: {}", s),
            Self::TpiViolation(s) => write!(f, "TPI violation: {}", s),
            Self::ZoneNotFound(s) => write!(f, "zone not found: {}", s),
            Self::TempestNonCompliant(s) => write!(f, "TEMPEST non-compliant: {}", s),
            Self::LogError(s) => write!(f, "log error: {}", s),
        }
    }
}

impl std::error::Error for PhysicalSecurityError {}

// ---------------------------------------------------------------------------
// Access control types
// ---------------------------------------------------------------------------

/// Physical access control mechanism for a zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessControlType {
    /// Mantrap / airlock entry.
    ManTrap,
    /// Cipher lock (combination pushbutton).
    CipherLock,
    /// Biometric scanner (fingerprint, iris, etc.).
    Biometric,
    /// Common Access Card (CAC) / PIV card reader.
    CacReader,
    /// Combination of multiple methods.
    Combination,
}

// ---------------------------------------------------------------------------
// TEMPEST classification
// ---------------------------------------------------------------------------

/// TEMPEST/EMSEC emission security classification level.
///
/// Per CNSSAM TEMPEST/01-13 and SDIP-27:
/// - Level A (NATO SDIP-27 Level A): Full TEMPEST shielding.
/// - Level B (NATO SDIP-27 Level B): Reduced emanation standard.
/// - Level C (NATO SDIP-27 Level C): Tactical protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TempestClass {
    /// NATO SDIP-27 Level A — full laboratory-level TEMPEST protection.
    A,
    /// NATO SDIP-27 Level B — reduced emanation standard for fixed facilities.
    B,
    /// NATO SDIP-27 Level C — tactical / field-level TEMPEST protection.
    C,
}

impl std::fmt::Display for TempestClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::A => write!(f, "TEMPEST Level A (SDIP-27 Level A)"),
            Self::B => write!(f, "TEMPEST Level B (SDIP-27 Level B)"),
            Self::C => write!(f, "TEMPEST Level C (SDIP-27 Level C)"),
        }
    }
}

// ---------------------------------------------------------------------------
// SCIF zone
// ---------------------------------------------------------------------------

/// A Sensitive Compartmented Information Facility (SCIF) zone.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScifZone {
    /// Unique zone identifier.
    pub zone_id: String,
    /// Human-readable zone name.
    pub zone_name: String,
    /// Classification level (maps to ClassificationLevel u8 encoding).
    /// 0 = Unclassified, 1 = Confidential, 2 = Secret, 3 = TopSecret, 4 = SCI.
    pub classification_level: u8,
    /// Physical access control mechanism.
    pub access_control_type: AccessControlType,
    /// Minimum clearance level required for unescorted access (same u8 encoding).
    pub required_clearance: u8,
    /// Whether two-person integrity (TPI) is enforced in this zone.
    pub two_person_integrity: bool,
    /// Whether the zone has TEMPEST/EMSEC shielding.
    pub tempest_rated: bool,
}

// ---------------------------------------------------------------------------
// Physical access log
// ---------------------------------------------------------------------------

/// A physical access log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhysicalAccessLog {
    /// Unique entry identifier.
    pub entry_id: String,
    /// User who entered the zone.
    pub user_id: String,
    /// Zone that was entered.
    pub zone_id: String,
    /// Entry timestamp (Unix seconds).
    pub entry_time: u64,
    /// Exit timestamp (Unix seconds), 0 if still inside.
    pub exit_time: u64,
    /// Escort user ID (empty if unescorted).
    pub escort_id: String,
    /// Access method used.
    pub method: AccessControlType,
}

// ---------------------------------------------------------------------------
// TEMPEST compliance
// ---------------------------------------------------------------------------

/// TEMPEST/EMSEC compliance status for a zone.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TempestCompliance {
    /// Zone this compliance record applies to.
    pub zone_id: String,
    /// TEMPEST emission class rating.
    pub emission_class: TempestClass,
    /// Last TEMPEST inspection date (Unix timestamp).
    pub last_inspection_date: u64,
    /// Next scheduled inspection date (Unix timestamp).
    pub next_inspection_date: u64,
    /// Whether RF shielding has been verified.
    pub shielding_verified: bool,
}

impl TempestCompliance {
    /// Check whether the zone is currently TEMPEST-compliant.
    ///
    /// A zone is compliant if:
    /// - Shielding has been verified
    /// - The next inspection date has not passed
    pub fn is_compliant(&self) -> bool {
        if !self.shielding_verified {
            return false;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now < self.next_inspection_date
    }

    /// Calculate days until the next TEMPEST inspection.
    ///
    /// Returns 0 if the inspection is overdue.
    pub fn days_until_next_inspection(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now >= self.next_inspection_date {
            0
        } else {
            (self.next_inspection_date - now) / 86400
        }
    }
}

// ---------------------------------------------------------------------------
// Physical access policy
// ---------------------------------------------------------------------------

/// Physical access policy engine for SCIF zones.
pub struct PhysicalAccessPolicy {
    /// Defined security zones.
    pub zones: Vec<ScifZone>,
    /// Access log entries.
    access_log: Vec<PhysicalAccessLog>,
    /// TEMPEST compliance records keyed by zone_id.
    tempest_records: Vec<TempestCompliance>,
    /// Log entry counter for generating unique IDs.
    log_counter: u64,
}

impl PhysicalAccessPolicy {
    /// Create a new policy with the given zones.
    pub fn new(zones: Vec<ScifZone>) -> Self {
        Self {
            zones,
            access_log: Vec::new(),
            tempest_records: Vec::new(),
            log_counter: 0,
        }
    }

    /// Add a TEMPEST compliance record for a zone.
    pub fn add_tempest_record(&mut self, record: TempestCompliance) {
        self.tempest_records.push(record);
    }

    /// Check whether a user with the given clearance level can access a zone.
    ///
    /// Returns `Ok(())` if access is permitted, or an error describing why not.
    pub fn can_access(
        &self,
        user_clearance: u8,
        zone_id: &str,
    ) -> Result<(), PhysicalSecurityError> {
        let zone = self.find_zone(zone_id)?;

        if user_clearance < zone.required_clearance {
            return Err(PhysicalSecurityError::AccessDenied(format!(
                "user clearance {} < zone '{}' requirement {}",
                user_clearance, zone.zone_name, zone.required_clearance
            )));
        }

        Ok(())
    }

    /// Determine whether a visitor requires an escort for a given zone.
    ///
    /// Visitors (clearance 0) always require escorts in classified zones.
    /// Personnel with clearance below the zone requirement need escorts.
    pub fn require_escort(
        &self,
        visitor_clearance: u8,
        zone_id: &str,
    ) -> Result<bool, PhysicalSecurityError> {
        let zone = self.find_zone(zone_id)?;

        // Visitors or under-cleared personnel need escorts.
        if visitor_clearance < zone.required_clearance {
            return Ok(true);
        }

        // In SCI zones, even cleared personnel may need escort if they
        // lack the specific compartment access.
        if zone.classification_level >= 4 {
            // SCI — always require escort unless fully read-in.
            // For this implementation, clearance == requirement means read-in.
            return Ok(visitor_clearance < zone.classification_level);
        }

        Ok(false)
    }

    /// Log a physical access entry.
    pub fn log_entry(
        &mut self,
        user_id: &str,
        zone_id: &str,
        timestamp: u64,
    ) -> Result<PhysicalAccessLog, PhysicalSecurityError> {
        // Verify zone exists and capture needed fields before mutable borrow.
        let zone = self.find_zone(zone_id)?;
        let access_method = zone.access_control_type;
        let zone_name = zone.zone_name.clone();

        self.log_counter += 1;
        let entry = PhysicalAccessLog {
            entry_id: format!("PAL-{:08}", self.log_counter),
            user_id: user_id.to_string(),
            zone_id: zone_id.to_string(),
            entry_time: timestamp,
            exit_time: 0,
            escort_id: String::new(),
            method: access_method,
        };

        tracing::info!(
            entry_id = %entry.entry_id,
            user_id = %entry.user_id,
            zone_id = %entry.zone_id,
            zone_name = %zone_name,
            entry_time = entry.entry_time,
            "physical access logged"
        );

        self.access_log.push(entry.clone());
        Ok(entry)
    }

    /// Enforce two-person integrity (TPI) for a zone.
    ///
    /// TPI requires at least two authorized persons to be present in
    /// the zone simultaneously. Returns an error if fewer than 2 users
    /// are provided.
    pub fn verify_two_person_integrity(
        &self,
        zone_id: &str,
        users: &[String],
    ) -> Result<(), PhysicalSecurityError> {
        let zone = self.find_zone(zone_id)?;

        if !zone.two_person_integrity {
            // TPI not required for this zone.
            return Ok(());
        }

        if users.len() < 2 {
            return Err(PhysicalSecurityError::TpiViolation(format!(
                "zone '{}' requires two-person integrity but only {} user(s) present",
                zone.zone_name,
                users.len()
            )));
        }

        // Verify all users are distinct.
        let mut unique = std::collections::HashSet::new();
        for u in users {
            unique.insert(u.as_str());
        }
        if unique.len() < 2 {
            return Err(PhysicalSecurityError::TpiViolation(
                "two-person integrity requires two distinct individuals".into(),
            ));
        }

        Ok(())
    }

    /// Check TEMPEST/EMSEC compliance for a zone.
    pub fn check_tempest_compliance(
        &self,
        zone_id: &str,
    ) -> Result<TempestCompliance, PhysicalSecurityError> {
        let zone = self.find_zone(zone_id)?;

        if !zone.tempest_rated {
            return Err(PhysicalSecurityError::TempestNonCompliant(format!(
                "zone '{}' is not TEMPEST-rated",
                zone.zone_name
            )));
        }

        // Find compliance record.
        let record = self
            .tempest_records
            .iter()
            .find(|r| r.zone_id == zone_id)
            .cloned()
            .ok_or_else(|| {
                PhysicalSecurityError::TempestNonCompliant(format!(
                    "no TEMPEST compliance record for zone '{}'",
                    zone_id
                ))
            })?;

        if !record.is_compliant() {
            return Err(PhysicalSecurityError::TempestNonCompliant(format!(
                "zone '{}' TEMPEST inspection overdue or shielding unverified",
                zone.zone_name
            )));
        }

        Ok(record)
    }

    /// Return all access log entries for a zone.
    pub fn get_zone_access_log(&self, zone_id: &str) -> Vec<&PhysicalAccessLog> {
        self.access_log
            .iter()
            .filter(|e| e.zone_id == zone_id)
            .collect()
    }

    /// Return all access log entries for a user.
    pub fn get_user_access_log(&self, user_id: &str) -> Vec<&PhysicalAccessLog> {
        self.access_log
            .iter()
            .filter(|e| e.user_id == user_id)
            .collect()
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn find_zone(&self, zone_id: &str) -> Result<&ScifZone, PhysicalSecurityError> {
        self.zones
            .iter()
            .find(|z| z.zone_id == zone_id)
            .ok_or_else(|| {
                PhysicalSecurityError::ZoneNotFound(format!("zone '{}' not found", zone_id))
            })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_zones() -> Vec<ScifZone> {
        vec![
            ScifZone {
                zone_id: "LOBBY".into(),
                zone_name: "Building Lobby".into(),
                classification_level: 0,
                access_control_type: AccessControlType::CacReader,
                required_clearance: 0,
                two_person_integrity: false,
                tempest_rated: false,
            },
            ScifZone {
                zone_id: "SCIF-A".into(),
                zone_name: "SCIF Alpha".into(),
                classification_level: 3, // TopSecret
                access_control_type: AccessControlType::ManTrap,
                required_clearance: 3,
                two_person_integrity: true,
                tempest_rated: true,
            },
            ScifZone {
                zone_id: "SCI-VAULT".into(),
                zone_name: "SCI Vault".into(),
                classification_level: 4, // SCI
                access_control_type: AccessControlType::Combination,
                required_clearance: 4,
                two_person_integrity: true,
                tempest_rated: true,
            },
            ScifZone {
                zone_id: "SERVER-ROOM".into(),
                zone_name: "Server Room".into(),
                classification_level: 2, // Secret
                access_control_type: AccessControlType::Biometric,
                required_clearance: 2,
                two_person_integrity: false,
                tempest_rated: true,
            },
        ]
    }

    #[test]
    fn access_granted_with_sufficient_clearance() {
        let policy = PhysicalAccessPolicy::new(test_zones());
        assert!(policy.can_access(3, "SCIF-A").is_ok());
        assert!(policy.can_access(4, "SCIF-A").is_ok()); // Over-cleared is OK.
    }

    #[test]
    fn access_denied_with_insufficient_clearance() {
        let policy = PhysicalAccessPolicy::new(test_zones());
        assert!(policy.can_access(2, "SCIF-A").is_err());
        assert!(policy.can_access(0, "SCI-VAULT").is_err());
    }

    #[test]
    fn visitor_requires_escort_in_classified_zone() {
        let policy = PhysicalAccessPolicy::new(test_zones());
        assert!(policy.require_escort(0, "SCIF-A").unwrap());
        assert!(policy.require_escort(2, "SCIF-A").unwrap());
    }

    #[test]
    fn cleared_person_no_escort_at_level() {
        let policy = PhysicalAccessPolicy::new(test_zones());
        assert!(!policy.require_escort(3, "SCIF-A").unwrap());
    }

    #[test]
    fn lobby_no_escort_needed() {
        let policy = PhysicalAccessPolicy::new(test_zones());
        assert!(!policy.require_escort(0, "LOBBY").unwrap());
    }

    #[test]
    fn tpi_enforced_in_scif() {
        let policy = PhysicalAccessPolicy::new(test_zones());
        let one_user = vec!["alice".into()];
        let two_users = vec!["alice".into(), "bob".into()];

        assert!(policy
            .verify_two_person_integrity("SCIF-A", &one_user)
            .is_err());
        assert!(policy
            .verify_two_person_integrity("SCIF-A", &two_users)
            .is_ok());
    }

    #[test]
    fn tpi_rejects_duplicate_users() {
        let policy = PhysicalAccessPolicy::new(test_zones());
        let same_user = vec!["alice".into(), "alice".into()];
        assert!(policy
            .verify_two_person_integrity("SCIF-A", &same_user)
            .is_err());
    }

    #[test]
    fn tpi_not_required_in_lobby() {
        let policy = PhysicalAccessPolicy::new(test_zones());
        let one_user = vec!["alice".into()];
        assert!(policy
            .verify_two_person_integrity("LOBBY", &one_user)
            .is_ok());
    }

    #[test]
    fn access_log_records_entry() {
        let mut policy = PhysicalAccessPolicy::new(test_zones());
        let entry = policy.log_entry("alice", "LOBBY", 1700000000).unwrap();
        assert_eq!(entry.user_id, "alice");
        assert_eq!(entry.zone_id, "LOBBY");
        assert_eq!(entry.entry_time, 1700000000);
        assert_eq!(policy.get_zone_access_log("LOBBY").len(), 1);
        assert_eq!(policy.get_user_access_log("alice").len(), 1);
    }

    #[test]
    fn tempest_compliant_zone() {
        let mut policy = PhysicalAccessPolicy::new(test_zones());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        policy.add_tempest_record(TempestCompliance {
            zone_id: "SCIF-A".into(),
            emission_class: TempestClass::A,
            last_inspection_date: now - 86400,
            next_inspection_date: now + 86400 * 180, // 6 months out.
            shielding_verified: true,
        });
        let compliance = policy.check_tempest_compliance("SCIF-A").unwrap();
        assert!(compliance.is_compliant());
        assert!(compliance.days_until_next_inspection() > 0);
    }

    #[test]
    fn tempest_non_compliant_unverified_shielding() {
        let record = TempestCompliance {
            zone_id: "test".into(),
            emission_class: TempestClass::B,
            last_inspection_date: 1700000000,
            next_inspection_date: u64::MAX,
            shielding_verified: false,
        };
        assert!(!record.is_compliant());
    }

    #[test]
    fn tempest_non_compliant_overdue() {
        let record = TempestCompliance {
            zone_id: "test".into(),
            emission_class: TempestClass::A,
            last_inspection_date: 1600000000,
            next_inspection_date: 1600100000, // In the past.
            shielding_verified: true,
        };
        assert!(!record.is_compliant());
        assert_eq!(record.days_until_next_inspection(), 0);
    }

    #[test]
    fn non_tempest_zone_returns_error() {
        let policy = PhysicalAccessPolicy::new(test_zones());
        assert!(policy.check_tempest_compliance("LOBBY").is_err());
    }

    #[test]
    fn unknown_zone_returns_error() {
        let policy = PhysicalAccessPolicy::new(test_zones());
        assert!(policy.can_access(4, "NONEXISTENT").is_err());
    }
}
