//! Classification labels and Mandatory Access Control (MAC) enforcement.
//!
//! Implements MIL-STD classification levels from Unclassified through SCI.
//! Enforces the simple security property (no read up) and star property
//! (no write down) per Bell-LaPadula model.
//!
//! # Classification Hierarchy
//! ```text
//!   SCI > TopSecret > Secret > Confidential > Unclassified
//! ```
//!
//! All classification decisions are audit-logged. Downgrade attempts are
//! rejected with explicit error messages.

use serde::{Deserialize, Serialize};

/// Security classification level per MIL-STD hierarchy.
///
/// Numeric ordering: higher value = higher classification.
/// Implements `Ord` so that comparisons like `token.classification >= resource.required`
/// work naturally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ClassificationLevel {
    /// Unclassified — no access restrictions.
    Unclassified = 0,
    /// Confidential — lowest classified level.
    Confidential = 1,
    /// Secret — mid-level classification.
    Secret = 2,
    /// Top Secret — high-level classification.
    TopSecret = 3,
    /// Sensitive Compartmented Information — highest classification.
    SCI = 4,
}

impl ClassificationLevel {
    /// Convert from raw u8. Returns `None` for out-of-range values.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Unclassified),
            1 => Some(Self::Confidential),
            2 => Some(Self::Secret),
            3 => Some(Self::TopSecret),
            4 => Some(Self::SCI),
            _ => None,
        }
    }

    /// Return the numeric level for serialization into token claims.
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Human-readable label for audit logs.
    pub fn label(self) -> &'static str {
        match self {
            Self::Unclassified => "UNCLASSIFIED",
            Self::Confidential => "CONFIDENTIAL",
            Self::Secret => "SECRET",
            Self::TopSecret => "TOP SECRET",
            Self::SCI => "SCI",
        }
    }
}

impl std::fmt::Display for ClassificationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

impl Default for ClassificationLevel {
    fn default() -> Self {
        Self::Unclassified
    }
}

/// Classified resource with both a classification level and SCI compartment tags.
///
/// While `ClassificationLevel` provides vertical access control (Unclassified through SCI),
/// compartments provide horizontal access control within the same level. A user must hold
/// ALL required compartments to access a compartmented resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifiedResource {
    /// The vertical classification level.
    pub level: ClassificationLevel,
    /// SCI compartment tags (e.g., "TK", "SI", "HCS", "GAMMA").
    /// Empty means no compartment restrictions beyond the classification level.
    pub compartments: Vec<String>,
}

impl ClassifiedResource {
    pub fn new(level: ClassificationLevel) -> Self {
        Self {
            level,
            compartments: Vec::new(),
        }
    }

    pub fn with_compartments(level: ClassificationLevel, compartments: Vec<String>) -> Self {
        Self { level, compartments }
    }
}

/// Check whether a user has access to all required compartments.
///
/// Returns `true` if `user_compartments` is a superset of `resource_compartments`.
/// An empty `resource_compartments` always returns `true` (no compartment restriction).
pub fn check_compartment_access(
    user_compartments: &[String],
    resource_compartments: &[String],
) -> bool {
    resource_compartments.iter().all(|rc| user_compartments.contains(rc))
}

/// Result of a classification enforcement check.
#[derive(Debug, Clone)]
pub enum ClassificationDecision {
    /// Access granted: subject classification meets or exceeds resource requirement.
    Granted,
    /// Access denied: subject classification is below the resource requirement.
    Denied {
        subject_level: ClassificationLevel,
        resource_level: ClassificationLevel,
    },
    /// Downgrade prevented: attempted to flow data from higher to lower classification.
    DowngradePrevented {
        source_level: ClassificationLevel,
        target_level: ClassificationLevel,
    },
}

impl ClassificationDecision {
    /// Returns `true` if access was granted.
    pub fn is_granted(&self) -> bool {
        matches!(self, Self::Granted)
    }
}

/// Check whether a subject with `subject_level` may access a resource
/// requiring `resource_level` (simple security property / "no read up").
///
/// Access is granted only if `subject_level >= resource_level`.
pub fn enforce_classification(
    subject_level: ClassificationLevel,
    resource_level: ClassificationLevel,
) -> ClassificationDecision {
    if subject_level >= resource_level {
        ClassificationDecision::Granted
    } else {
        ClassificationDecision::Denied {
            subject_level,
            resource_level,
        }
    }
}

/// Check whether data at `source_level` may flow to a session at `target_level`
/// (star property / "no write down").
///
/// Data may only flow to a target at the same or higher classification.
/// Downgrade requires an explicit declassification policy (handled separately
/// by the cross-domain guard).
pub fn enforce_no_downgrade(
    source_level: ClassificationLevel,
    target_level: ClassificationLevel,
) -> ClassificationDecision {
    if target_level >= source_level {
        ClassificationDecision::Granted
    } else {
        ClassificationDecision::DowngradePrevented {
            source_level,
            target_level,
        }
    }
}

/// Map a device tier (1-4) to a default classification level.
///
/// This provides a baseline mapping; specific deployments may override.
/// - Tier 1 (Sovereign) -> TopSecret
/// - Tier 2 (Operational) -> Secret
/// - Tier 3 (Sensor) -> Confidential
/// - Tier 4 (Emergency) -> Unclassified
pub fn default_classification_for_tier(tier: u8) -> ClassificationLevel {
    match tier {
        1 => ClassificationLevel::TopSecret,
        2 => ClassificationLevel::Secret,
        3 => ClassificationLevel::Confidential,
        4 => ClassificationLevel::Unclassified,
        _ => ClassificationLevel::Unclassified,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_ordering() {
        assert!(ClassificationLevel::SCI > ClassificationLevel::TopSecret);
        assert!(ClassificationLevel::TopSecret > ClassificationLevel::Secret);
        assert!(ClassificationLevel::Secret > ClassificationLevel::Confidential);
        assert!(ClassificationLevel::Confidential > ClassificationLevel::Unclassified);
    }

    #[test]
    fn enforce_classification_grants_equal() {
        let decision = enforce_classification(
            ClassificationLevel::Secret,
            ClassificationLevel::Secret,
        );
        assert!(decision.is_granted());
    }

    #[test]
    fn enforce_classification_grants_higher() {
        let decision = enforce_classification(
            ClassificationLevel::TopSecret,
            ClassificationLevel::Secret,
        );
        assert!(decision.is_granted());
    }

    #[test]
    fn enforce_classification_denies_lower() {
        let decision = enforce_classification(
            ClassificationLevel::Confidential,
            ClassificationLevel::Secret,
        );
        assert!(!decision.is_granted());
    }

    #[test]
    fn enforce_no_downgrade_allows_equal() {
        let decision = enforce_no_downgrade(
            ClassificationLevel::Secret,
            ClassificationLevel::Secret,
        );
        assert!(decision.is_granted());
    }

    #[test]
    fn enforce_no_downgrade_allows_upgrade() {
        let decision = enforce_no_downgrade(
            ClassificationLevel::Secret,
            ClassificationLevel::TopSecret,
        );
        assert!(decision.is_granted());
    }

    #[test]
    fn enforce_no_downgrade_prevents_downgrade() {
        let decision = enforce_no_downgrade(
            ClassificationLevel::TopSecret,
            ClassificationLevel::Secret,
        );
        assert!(!decision.is_granted());
        assert!(matches!(decision, ClassificationDecision::DowngradePrevented { .. }));
    }

    #[test]
    fn from_u8_roundtrip() {
        for v in 0..=4 {
            let level = ClassificationLevel::from_u8(v).unwrap();
            assert_eq!(level.as_u8(), v);
        }
        assert!(ClassificationLevel::from_u8(5).is_none());
    }

    #[test]
    fn default_tier_mapping() {
        assert_eq!(default_classification_for_tier(1), ClassificationLevel::TopSecret);
        assert_eq!(default_classification_for_tier(2), ClassificationLevel::Secret);
        assert_eq!(default_classification_for_tier(3), ClassificationLevel::Confidential);
        assert_eq!(default_classification_for_tier(4), ClassificationLevel::Unclassified);
        assert_eq!(default_classification_for_tier(0), ClassificationLevel::Unclassified);
    }
}
