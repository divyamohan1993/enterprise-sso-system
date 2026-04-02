//! Cross-Domain Guard — enforces information flow control between security domains.
//!
//! Implements a default-deny policy: every cross-domain data transfer must be
//! explicitly allowed by a configured flow rule. Transfers from a higher
//! classification domain to a lower one require an explicit declassification
//! policy entry.
//!
//! All cross-domain decisions (grant or deny) are audit-logged.

use crate::classification::ClassificationLevel;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// A security domain with a name and classification level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityDomain {
    /// Unique identifier for the domain.
    pub id: Uuid,
    /// Human-readable domain name (e.g., "JWICS", "SIPRNet", "NIPRNet").
    pub name: String,
    /// Classification level of this domain.
    pub classification: ClassificationLevel,
}

/// Direction of a cross-domain flow rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowDirection {
    /// Data flows from source domain to target domain.
    Unidirectional,
    /// Data may flow in both directions between the domains.
    Bidirectional,
}

/// A policy rule authorizing data flow between two domains.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowRule {
    /// Source domain ID.
    pub source_domain: Uuid,
    /// Target domain ID.
    pub target_domain: Uuid,
    /// Flow direction.
    pub direction: FlowDirection,
    /// If true, this rule explicitly authorizes high-to-low declassification.
    /// Without this flag, flows from higher to lower classification are blocked
    /// even if a rule exists.
    pub declassification_authorized: bool,
    /// Human-readable justification for this flow rule (audit trail).
    pub justification: String,
    /// Authorizing officer ID — who approved this rule.
    pub authorized_by: Uuid,
    /// Timestamp when this rule was created (epoch seconds).
    pub created_at: i64,
}

/// Result of a cross-domain transfer decision.
#[derive(Debug, Clone, Serialize)]
pub struct CrossDomainDecision {
    /// Whether the transfer was allowed.
    pub allowed: bool,
    /// Source domain name.
    pub source_domain: String,
    /// Target domain name.
    pub target_domain: String,
    /// Source domain classification.
    pub source_classification: ClassificationLevel,
    /// Target domain classification.
    pub target_classification: ClassificationLevel,
    /// Reason for the decision.
    pub reason: String,
    /// Timestamp of the decision (epoch seconds).
    pub timestamp: i64,
}

/// The Cross-Domain Guard enforces flow control between security domains.
///
/// Default policy is DENY: only explicitly configured flow rules permit
/// cross-domain transfers.
pub struct CrossDomainGuard {
    /// Registered security domains.
    domains: HashMap<Uuid, SecurityDomain>,
    /// Flow rules indexed by (source_domain_id, target_domain_id).
    rules: HashMap<(Uuid, Uuid), FlowRule>,
}

impl CrossDomainGuard {
    /// Create a new guard with no domains or rules (default-deny).
    pub fn new() -> Self {
        Self {
            domains: HashMap::new(),
            rules: HashMap::new(),
        }
    }

    /// Register a security domain.
    pub fn register_domain(&mut self, domain: SecurityDomain) {
        self.domains.insert(domain.id, domain);
    }

    /// Add a flow rule authorizing data transfer between domains.
    pub fn add_flow_rule(&mut self, rule: FlowRule) {
        crate::siem::SecurityEvent::admin_data_access(
            &format!(
                "flow_rule_added: source={}, target={}, direction={:?}, declass={}, authorized_by={}, justification={}",
                rule.source_domain, rule.target_domain, rule.direction,
                rule.declassification_authorized, rule.authorized_by, rule.justification,
            ),
        );
        self.rules
            .insert((rule.source_domain, rule.target_domain), rule);
    }

    /// Remove a flow rule.
    pub fn remove_flow_rule(&mut self, source: &Uuid, target: &Uuid, authorized_by: Uuid) -> bool {
        let removed = self.rules.remove(&(*source, *target)).is_some();
        if removed {
            crate::siem::SecurityEvent::admin_data_access(
                &format!(
                    "flow_rule_removed: source={}, target={}, authorized_by={}",
                    source, target, authorized_by,
                ),
            );
        }
        removed
    }

    /// Return the number of registered domains.
    pub fn domain_count(&self) -> usize {
        self.domains.len()
    }

    /// Return the number of active flow rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Validate a cross-domain data transfer.
    ///
    /// Checks:
    /// 1. Both domains must be registered.
    /// 2. A flow rule must exist for the (source, target) pair.
    /// 3. If the flow is from higher to lower classification, the rule must
    ///    have `declassification_authorized = true`.
    /// 4. Bidirectional rules are checked in both directions.
    ///
    /// Returns a `CrossDomainDecision` that MUST be audit-logged by the caller.
    pub fn validate_transfer(
        &self,
        source_domain_id: &Uuid,
        target_domain_id: &Uuid,
    ) -> CrossDomainDecision {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // Same domain: always allowed
        if source_domain_id == target_domain_id {
            let domain_name = self
                .domains
                .get(source_domain_id)
                .map(|d| d.name.clone())
                .unwrap_or_else(|| "unknown".to_string());
            let classification = self
                .domains
                .get(source_domain_id)
                .map(|d| d.classification)
                .unwrap_or(ClassificationLevel::Unclassified);
            return CrossDomainDecision {
                allowed: true,
                source_domain: domain_name.clone(),
                target_domain: domain_name,
                source_classification: classification,
                target_classification: classification,
                reason: "intra-domain transfer".to_string(),
                timestamp: now,
            };
        }

        // Look up domains
        let source = match self.domains.get(source_domain_id) {
            Some(d) => d,
            None => {
                return CrossDomainDecision {
                    allowed: false,
                    source_domain: format!("{}", source_domain_id),
                    target_domain: format!("{}", target_domain_id),
                    source_classification: ClassificationLevel::Unclassified,
                    target_classification: ClassificationLevel::Unclassified,
                    reason: "source domain not registered".to_string(),
                    timestamp: now,
                };
            }
        };
        let target = match self.domains.get(target_domain_id) {
            Some(d) => d,
            None => {
                return CrossDomainDecision {
                    allowed: false,
                    source_domain: source.name.clone(),
                    target_domain: format!("{}", target_domain_id),
                    source_classification: source.classification,
                    target_classification: ClassificationLevel::Unclassified,
                    reason: "target domain not registered".to_string(),
                    timestamp: now,
                };
            }
        };

        // Look up flow rule: check direct rule first, then reverse (bidirectional)
        let rule = self
            .rules
            .get(&(*source_domain_id, *target_domain_id))
            .or_else(|| {
                // Check if there is a bidirectional rule in the reverse direction
                self.rules
                    .get(&(*target_domain_id, *source_domain_id))
                    .filter(|r| r.direction == FlowDirection::Bidirectional)
            });

        let rule = match rule {
            Some(r) => r,
            None => {
                // DEFAULT DENY: no rule found
                tracing::warn!(
                    "cross-domain transfer DENIED (default-deny): {} ({}) -> {} ({})",
                    source.name,
                    source.classification.label(),
                    target.name,
                    target.classification.label(),
                );
                return CrossDomainDecision {
                    allowed: false,
                    source_domain: source.name.clone(),
                    target_domain: target.name.clone(),
                    source_classification: source.classification,
                    target_classification: target.classification,
                    reason: "no flow rule exists — default deny".to_string(),
                    timestamp: now,
                };
            }
        };

        // Check declassification requirement: high -> low needs explicit authorization
        if source.classification > target.classification && !rule.declassification_authorized {
            tracing::warn!(
                "cross-domain transfer DENIED (declassification not authorized): \
                 {} ({}) -> {} ({})",
                source.name,
                source.classification.label(),
                target.name,
                target.classification.label(),
            );
            return CrossDomainDecision {
                allowed: false,
                source_domain: source.name.clone(),
                target_domain: target.name.clone(),
                source_classification: source.classification,
                target_classification: target.classification,
                reason: format!(
                    "flow from {} to {} requires declassification authorization",
                    source.classification.label(),
                    target.classification.label(),
                ),
                timestamp: now,
            };
        }

        tracing::info!(
            "cross-domain transfer ALLOWED: {} ({}) -> {} ({}), justification: {}",
            source.name,
            source.classification.label(),
            target.name,
            target.classification.label(),
            rule.justification,
        );

        CrossDomainDecision {
            allowed: true,
            source_domain: source.name.clone(),
            target_domain: target.name.clone(),
            source_classification: source.classification,
            target_classification: target.classification,
            reason: format!("allowed by flow rule: {}", rule.justification),
            timestamp: now,
        }
    }
}

impl Default for CrossDomainGuard {
    fn default() -> Self {
        Self::new()
    }
}

// ── Bell-LaPadula Mandatory Access Control ─────────────────────────────────
//
// The Bell-LaPadula (BLP) model provides formal mandatory access control
// enforcement for multi-level security (MLS) systems as required by
// DISA STIG and CMMC Level 3 for DoD classified environments.
//
// Properties enforced:
// - Simple Security Property (ss-property): No read up — a subject cannot
//   read data at a classification level above their clearance.
// - *-Property (Star Property): No write down — a subject cannot write data
//   to a classification level below their clearance (prevents information
//   leakage to lower classification levels).
// - Strong Tranquility: Classification levels do not change during an
//   operation (enforced by using immutable classification arguments).

/// Bell-LaPadula mandatory access control guard.
///
/// Enforces the Simple Security Property and (optionally) the *-Property
/// for all access decisions. When `strict_mode` is enabled, both properties
/// are enforced; when disabled, only the Simple Security Property (no read up)
/// is enforced.
///
/// All access decisions are audit-logged via `tracing` for SIEM integration.
pub struct BellLaPadulaGuard {
    /// If true, enforce both Simple Security and *-Property (Star Property).
    /// If false, only enforce Simple Security Property (no read up).
    strict_mode: bool,
}

impl BellLaPadulaGuard {
    /// Create a new Bell-LaPadula guard.
    ///
    /// - `strict_mode = true`: Enforces both ss-property AND *-property.
    ///   This is the REQUIRED setting for DoD classified environments.
    /// - `strict_mode = false`: Enforces only ss-property (no read up).
    ///   Suitable for environments where the star property is managed
    ///   by other controls (e.g., application-level write policies).
    pub fn new(strict_mode: bool) -> Result<Self, String> {
        if !strict_mode {
            crate::siem::SecurityEvent::crypto_failure(
                "CRITICAL: BellLaPadulaGuard created with strict_mode=false. \
                 *-property (no write-down) is DISABLED. This violates DISA STIG \
                 and CMMC Level 3 requirements for DoD classified environments.",
            );
            if std::env::var("MILNET_MILITARY_DEPLOYMENT").is_ok() {
                return Err(
                    "BLP non-strict mode rejected: MILNET_MILITARY_DEPLOYMENT is active. \
                     *-property enforcement is mandatory in military deployments.".into()
                );
            }
        }
        Ok(Self { strict_mode })
    }

    /// Check if a subject can READ a resource (Simple Security Property).
    ///
    /// The subject's clearance level must be greater than or equal to the
    /// resource's classification level. A TOP SECRET cleared subject can
    /// read SECRET documents, but a SECRET cleared subject cannot read
    /// TOP SECRET documents.
    ///
    /// All decisions are audit-logged.
    pub fn can_read(
        &self,
        subject_clearance: ClassificationLevel,
        resource_classification: ClassificationLevel,
    ) -> bool {
        let allowed = subject_clearance >= resource_classification;
        if allowed {
            tracing::debug!(
                "BLP READ GRANTED: subject clearance {} >= resource classification {}",
                subject_clearance.label(),
                resource_classification.label(),
            );
        } else {
            tracing::warn!(
                "BLP READ DENIED (ss-property): subject clearance {} < resource classification {}",
                subject_clearance.label(),
                resource_classification.label(),
            );
        }
        allowed
    }

    /// Check if a subject can WRITE to a resource (*-Property / Star Property).
    ///
    /// In strict mode, the subject's clearance level must be less than or
    /// equal to the resource's classification level (no write-down). This
    /// prevents a TOP SECRET cleared subject from writing classified data
    /// into an UNCLASSIFIED resource, which would leak information.
    ///
    /// In non-strict mode, writes are always permitted (the star property
    /// is not enforced).
    ///
    /// All decisions are audit-logged.
    pub fn can_write(
        &self,
        subject_clearance: ClassificationLevel,
        resource_classification: ClassificationLevel,
    ) -> bool {
        if self.strict_mode {
            let allowed = subject_clearance <= resource_classification;
            if allowed {
                tracing::debug!(
                    "BLP WRITE GRANTED: subject clearance {} <= resource classification {}",
                    subject_clearance.label(),
                    resource_classification.label(),
                );
            } else {
                tracing::warn!(
                    "BLP WRITE DENIED (*-property): subject clearance {} > resource classification {} (no write-down)",
                    subject_clearance.label(),
                    resource_classification.label(),
                );
            }
            allowed
        } else {
            tracing::debug!(
                "BLP WRITE GRANTED (non-strict): *-property not enforced, subject={}, resource={}",
                subject_clearance.label(),
                resource_classification.label(),
            );
            true
        }
    }

    /// Combined read-write check for modify operations.
    ///
    /// A modify operation requires both read access (to see existing data)
    /// and write access (to change it). In strict mode, this means the
    /// subject's clearance must EQUAL the resource's classification
    /// (since can_read requires >= and can_write requires <=).
    ///
    /// All decisions are audit-logged.
    pub fn can_modify(
        &self,
        subject_clearance: ClassificationLevel,
        resource_classification: ClassificationLevel,
    ) -> bool {
        let read_ok = self.can_read(subject_clearance, resource_classification);
        let write_ok = self.can_write(subject_clearance, resource_classification);
        let allowed = read_ok && write_ok;
        if !allowed {
            tracing::warn!(
                "BLP MODIFY DENIED: subject clearance {}, resource classification {} (read={}, write={})",
                subject_clearance.label(),
                resource_classification.label(),
                read_ok,
                write_ok,
            );
        }
        allowed
    }

    /// Validate a data transfer between classification levels.
    ///
    /// Enforces all three checks:
    /// 1. Subject must be able to read the source (ss-property).
    /// 2. Subject must be able to write to the destination (*-property, if strict).
    /// 3. Data cannot flow downward: source classification must be <= destination
    ///    classification (information flow control).
    ///
    /// All decisions are audit-logged.
    pub fn validate_transfer(
        &self,
        source_classification: ClassificationLevel,
        destination_classification: ClassificationLevel,
        subject_clearance: ClassificationLevel,
    ) -> Result<(), String> {
        // Subject must be able to read source
        if !self.can_read(subject_clearance, source_classification) {
            let msg = format!(
                "Access denied: insufficient clearance ({}) to read source ({})",
                subject_clearance.label(),
                source_classification.label(),
            );
            tracing::warn!("BLP TRANSFER DENIED: {}", msg);
            return Err("Access denied: insufficient clearance to read source".into());
        }

        // Subject must be able to write to destination
        if !self.can_write(subject_clearance, destination_classification) {
            let msg = format!(
                "Access denied: *-property violation — clearance {} cannot write to {} (no write-down)",
                subject_clearance.label(),
                destination_classification.label(),
            );
            tracing::warn!("BLP TRANSFER DENIED: {}", msg);
            return Err("Access denied: star property violation (no write-down)".into());
        }

        // Data cannot flow downward (information flow control)
        if source_classification > destination_classification {
            let msg = format!(
                "Transfer denied: data at {} cannot flow to lower classification {}",
                source_classification.label(),
                destination_classification.label(),
            );
            tracing::warn!("BLP TRANSFER DENIED: {}", msg);
            return Err("Transfer denied: data cannot flow to lower classification".into());
        }

        tracing::info!(
            "BLP TRANSFER GRANTED: {} -> {}, subject clearance {}",
            source_classification.label(),
            destination_classification.label(),
            subject_clearance.label(),
        );
        Ok(())
    }

    /// Returns whether strict mode (*-property enforcement) is enabled.
    pub fn is_strict(&self) -> bool {
        self.strict_mode
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_domain(name: &str, level: ClassificationLevel) -> SecurityDomain {
        SecurityDomain {
            id: Uuid::new_v4(),
            name: name.to_string(),
            classification: level,
        }
    }

    #[test]
    fn default_deny_no_rules() {
        let guard = CrossDomainGuard::new();
        let src = Uuid::new_v4();
        let tgt = Uuid::new_v4();
        let decision = guard.validate_transfer(&src, &tgt);
        assert!(!decision.allowed);
        assert!(decision.reason.contains("not registered"));
    }

    #[test]
    fn same_domain_always_allowed() {
        let mut guard = CrossDomainGuard::new();
        let domain = make_domain("JWICS", ClassificationLevel::TopSecret);
        let id = domain.id;
        guard.register_domain(domain);
        let decision = guard.validate_transfer(&id, &id);
        assert!(decision.allowed);
    }

    #[test]
    fn explicit_rule_allows_transfer() {
        let mut guard = CrossDomainGuard::new();
        let src = make_domain("SIPRNet", ClassificationLevel::Secret);
        let tgt = make_domain("JWICS", ClassificationLevel::TopSecret);
        let src_id = src.id;
        let tgt_id = tgt.id;
        guard.register_domain(src);
        guard.register_domain(tgt);
        guard.add_flow_rule(FlowRule {
            source_domain: src_id,
            target_domain: tgt_id,
            direction: FlowDirection::Unidirectional,
            declassification_authorized: false,
            justification: "operational necessity".to_string(),
            authorized_by: Uuid::nil(),
            created_at: 0,
        });
        let decision = guard.validate_transfer(&src_id, &tgt_id);
        assert!(decision.allowed);
    }

    #[test]
    fn high_to_low_without_declass_denied() {
        let mut guard = CrossDomainGuard::new();
        let src = make_domain("JWICS", ClassificationLevel::TopSecret);
        let tgt = make_domain("NIPRNet", ClassificationLevel::Unclassified);
        let src_id = src.id;
        let tgt_id = tgt.id;
        guard.register_domain(src);
        guard.register_domain(tgt);
        guard.add_flow_rule(FlowRule {
            source_domain: src_id,
            target_domain: tgt_id,
            direction: FlowDirection::Unidirectional,
            declassification_authorized: false,
            justification: "test".to_string(),
            authorized_by: Uuid::nil(),
            created_at: 0,
        });
        let decision = guard.validate_transfer(&src_id, &tgt_id);
        assert!(!decision.allowed);
        assert!(decision.reason.contains("declassification"));
    }

    #[test]
    fn high_to_low_with_declass_allowed() {
        let mut guard = CrossDomainGuard::new();
        let src = make_domain("JWICS", ClassificationLevel::TopSecret);
        let tgt = make_domain("SIPRNet", ClassificationLevel::Secret);
        let src_id = src.id;
        let tgt_id = tgt.id;
        guard.register_domain(src);
        guard.register_domain(tgt);
        guard.add_flow_rule(FlowRule {
            source_domain: src_id,
            target_domain: tgt_id,
            direction: FlowDirection::Unidirectional,
            declassification_authorized: true,
            justification: "authorized declassification review".to_string(),
            authorized_by: Uuid::nil(),
            created_at: 0,
        });
        let decision = guard.validate_transfer(&src_id, &tgt_id);
        assert!(decision.allowed);
    }

    #[test]
    fn bidirectional_rule_works_both_ways() {
        let mut guard = CrossDomainGuard::new();
        let a = make_domain("DomainA", ClassificationLevel::Secret);
        let b = make_domain("DomainB", ClassificationLevel::Secret);
        let a_id = a.id;
        let b_id = b.id;
        guard.register_domain(a);
        guard.register_domain(b);
        guard.add_flow_rule(FlowRule {
            source_domain: a_id,
            target_domain: b_id,
            direction: FlowDirection::Bidirectional,
            declassification_authorized: false,
            justification: "peer domains".to_string(),
            authorized_by: Uuid::nil(),
            created_at: 0,
        });
        assert!(guard.validate_transfer(&a_id, &b_id).allowed);
        assert!(guard.validate_transfer(&b_id, &a_id).allowed);
    }

    #[test]
    fn no_rule_between_registered_domains_denied() {
        let mut guard = CrossDomainGuard::new();
        let src = make_domain("Alpha", ClassificationLevel::Confidential);
        let tgt = make_domain("Bravo", ClassificationLevel::Confidential);
        let src_id = src.id;
        let tgt_id = tgt.id;
        guard.register_domain(src);
        guard.register_domain(tgt);
        let decision = guard.validate_transfer(&src_id, &tgt_id);
        assert!(!decision.allowed);
        assert!(decision.reason.contains("default deny"));
    }

    // ── Bell-LaPadula Tests ────────────────────────────────────────────

    #[test]
    fn blp_read_up_denied() {
        let guard = BellLaPadulaGuard::new(true).unwrap();
        // SECRET subject cannot read TOP SECRET resource
        assert!(!guard.can_read(ClassificationLevel::Secret, ClassificationLevel::TopSecret));
    }

    #[test]
    fn blp_read_same_level_allowed() {
        let guard = BellLaPadulaGuard::new(true).unwrap();
        assert!(guard.can_read(ClassificationLevel::Secret, ClassificationLevel::Secret));
    }

    #[test]
    fn blp_read_down_allowed() {
        let guard = BellLaPadulaGuard::new(true).unwrap();
        // TOP SECRET subject can read SECRET resource
        assert!(guard.can_read(ClassificationLevel::TopSecret, ClassificationLevel::Secret));
    }

    #[test]
    fn blp_write_down_denied_strict() {
        let guard = BellLaPadulaGuard::new(true).unwrap();
        // TOP SECRET subject cannot write to SECRET resource (no write-down)
        assert!(!guard.can_write(ClassificationLevel::TopSecret, ClassificationLevel::Secret));
    }

    #[test]
    fn blp_write_up_allowed_strict() {
        let guard = BellLaPadulaGuard::new(true).unwrap();
        // SECRET subject can write to TOP SECRET resource
        assert!(guard.can_write(ClassificationLevel::Secret, ClassificationLevel::TopSecret));
    }

    #[test]
    fn blp_write_down_allowed_nonstrict() {
        let guard = BellLaPadulaGuard::new(false).unwrap();
        // Non-strict mode: write-down is allowed
        assert!(guard.can_write(ClassificationLevel::TopSecret, ClassificationLevel::Secret));
    }

    #[test]
    fn blp_modify_requires_exact_level_in_strict() {
        let guard = BellLaPadulaGuard::new(true).unwrap();
        // Modify requires read (>=) AND write (<=), so only exact match works
        assert!(guard.can_modify(ClassificationLevel::Secret, ClassificationLevel::Secret));
        assert!(!guard.can_modify(ClassificationLevel::TopSecret, ClassificationLevel::Secret));
        assert!(!guard.can_modify(ClassificationLevel::Secret, ClassificationLevel::TopSecret));
    }

    #[test]
    fn blp_transfer_upward_allowed() {
        let guard = BellLaPadulaGuard::new(true).unwrap();
        // Transfer from SECRET to TOP SECRET by a TOP SECRET cleared subject
        // Read source (TS >= S): OK. Write dest (TS <= TS): OK. Flow (S <= TS): OK.
        assert!(guard.validate_transfer(
            ClassificationLevel::Secret,
            ClassificationLevel::TopSecret,
            ClassificationLevel::TopSecret,
        ).is_ok());
    }

    #[test]
    fn blp_transfer_downward_denied() {
        let guard = BellLaPadulaGuard::new(true).unwrap();
        // Transfer from TOP SECRET to SECRET: data flow downward denied
        assert!(guard.validate_transfer(
            ClassificationLevel::TopSecret,
            ClassificationLevel::Secret,
            ClassificationLevel::TopSecret,
        ).is_err());
    }

    #[test]
    fn blp_transfer_insufficient_clearance() {
        let guard = BellLaPadulaGuard::new(true).unwrap();
        // SECRET subject cannot read TOP SECRET source
        let result = guard.validate_transfer(
            ClassificationLevel::TopSecret,
            ClassificationLevel::TopSecret,
            ClassificationLevel::Secret,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("insufficient clearance"));
    }

    // ── Original CrossDomainGuard Tests ──────────────────────────────

    #[test]
    fn remove_flow_rule() {
        let mut guard = CrossDomainGuard::new();
        let src = make_domain("Src", ClassificationLevel::Secret);
        let tgt = make_domain("Tgt", ClassificationLevel::Secret);
        let src_id = src.id;
        let tgt_id = tgt.id;
        guard.register_domain(src);
        guard.register_domain(tgt);
        guard.add_flow_rule(FlowRule {
            source_domain: src_id,
            target_domain: tgt_id,
            direction: FlowDirection::Unidirectional,
            declassification_authorized: false,
            justification: "test".to_string(),
            authorized_by: Uuid::nil(),
            created_at: 0,
        });
        assert!(guard.validate_transfer(&src_id, &tgt_id).allowed);
        assert!(guard.remove_flow_rule(&src_id, &tgt_id, Uuid::nil()));
        assert!(!guard.validate_transfer(&src_id, &tgt_id).allowed);
    }
}
