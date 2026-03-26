//! Conditional Access Policy Engine for the MILNET SSO system.
//!
//! Evaluates ordered policy rules against an access request context to produce
//! a structured policy decision. Supports rich condition types (IP range,
//! geolocation, time window, device tier, risk score, classification level,
//! user attributes, authentication strength) with `And`/`Or`/`Not` logical
//! composition.
//!
//! Evaluation is **first-match-wins** with an explicit **default-deny** when no
//! rule matches. Every evaluation produces a [`PolicyDecision`] containing the
//! action taken and a human-readable reason suitable for audit logging.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use crate::classification::ClassificationLevel;
use crate::types::DeviceTier;

// ── Policy Actions ──────────────────────────────────────────────────────

/// Action to take when a policy rule matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyAction {
    /// Grant access unconditionally.
    Allow,
    /// Deny access unconditionally.
    Deny,
    /// Require multi-factor authentication before granting access.
    RequireMFA,
    /// Require step-up re-authentication (e.g. CAC/PIV re-tap).
    RequireStepUp,
    /// Require out-of-band approval from a designated authority.
    RequireApproval,
    /// Hard block — session is terminated and the attempt is flagged.
    Block,
}

// ── Condition Types ─────────────────────────────────────────────────────

/// Day of week (Monday = 0 through Sunday = 6, matching `chrono` convention).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DayOfWeek {
    Monday = 0,
    Tuesday = 1,
    Wednesday = 2,
    Thursday = 3,
    Friday = 4,
    Saturday = 5,
    Sunday = 6,
}

/// A CIDR network specification for IP range matching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CidrRange {
    /// Network address (e.g. 10.0.0.0, fd00::1).
    pub network: IpAddr,
    /// Prefix length (0-32 for IPv4, 0-128 for IPv6).
    pub prefix_len: u8,
}

impl CidrRange {
    /// Create a new CIDR range.
    pub fn new(network: IpAddr, prefix_len: u8) -> Self {
        Self {
            network,
            prefix_len,
        }
    }

    /// Parse a CIDR string like "10.0.0.0/8" or "fd00::/64".
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.splitn(2, '/').collect();
        if parts.len() != 2 {
            return None;
        }
        let network: IpAddr = parts[0].parse().ok()?;
        let prefix_len: u8 = parts[1].parse().ok()?;
        let max_prefix = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max_prefix {
            return None;
        }
        Some(Self {
            network,
            prefix_len,
        })
    }

    /// Check whether `addr` falls within this CIDR range.
    pub fn contains(&self, addr: &IpAddr) -> bool {
        match (self.network, addr) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let net_bits = u32::from(net);
                let ip_bits = u32::from(*ip);
                let mask = u32::MAX.checked_shl(32 - self.prefix_len as u32).unwrap_or(0);
                (net_bits & mask) == (ip_bits & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let net_bits = u128::from(net);
                let ip_bits = u128::from(*ip);
                let mask = u128::MAX.checked_shl(128 - self.prefix_len as u32).unwrap_or(0);
                (net_bits & mask) == (ip_bits & mask)
            }
            // IPv4 vs IPv6 mismatch — never matches
            _ => false,
        }
    }
}

/// UTC time window restriction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindow {
    /// Start hour (inclusive), 0-23 UTC.
    pub start_hour: u8,
    /// End hour (exclusive), 0-23 UTC. If `end_hour < start_hour`, the
    /// window wraps around midnight (e.g. 22..06 means 22:00-05:59).
    pub end_hour: u8,
    /// Allowed days of week. Empty means all days are allowed.
    pub allowed_days: Vec<DayOfWeek>,
}

impl TimeWindow {
    /// Check whether a given hour and day fall within this window.
    pub fn contains(&self, hour: u8, day: DayOfWeek) -> bool {
        // Check day restriction
        if !self.allowed_days.is_empty() && !self.allowed_days.contains(&day) {
            return false;
        }
        // Check hour restriction
        if self.start_hour <= self.end_hour {
            // Normal range: e.g. 08..18
            hour >= self.start_hour && hour < self.end_hour
        } else {
            // Wraps midnight: e.g. 22..06 means 22,23,0,1,2,3,4,5
            hour >= self.start_hour || hour < self.end_hour
        }
    }
}

/// Risk score thresholds for conditional access decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskThresholds {
    /// Allow if score is strictly below this value.
    pub allow_below: f64,
    /// Challenge (MFA/step-up) if score is at or above this value.
    pub challenge_above: f64,
    /// Block if score is at or above this value.
    pub block_above: f64,
}

/// Authentication strength tiers (higher = stronger).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum AuthStrength {
    /// Password-only authentication.
    PasswordOnly = 0,
    /// Password + TOTP or similar software token.
    MultiFactor = 1,
    /// Hardware token (FIDO2/WebAuthn).
    HardwareToken = 2,
    /// CAC/PIV smart card.
    SmartCard = 3,
    /// Biometric + hardware token.
    BiometricHardware = 4,
}

/// A single condition that can be evaluated against an [`AccessContext`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Condition {
    /// Match if the source IP falls within any of the given CIDR ranges.
    IpRange(Vec<CidrRange>),
    /// Match if the country code is in the allowlist (or NOT in the blocklist).
    GeoLocation {
        /// If non-empty, access is allowed only from these countries.
        allowlist: Vec<String>,
        /// If non-empty, access is denied from these countries.
        blocklist: Vec<String>,
    },
    /// Match if the current time falls within the specified window.
    TimeWindow(TimeWindow),
    /// Match if the device tier meets or exceeds (numerically <=) the minimum.
    DeviceTier(DeviceTier),
    /// Match based on risk score thresholds.
    RiskScore(RiskThresholds),
    /// Match if the subject's classification level meets or exceeds the minimum.
    ClassificationLevel(ClassificationLevel),
    /// Match if the user possesses the required attribute (group or department).
    UserAttribute {
        /// Attribute key (e.g. "group", "department").
        key: String,
        /// Required value(s) — matches if the user has any of these.
        values: Vec<String>,
    },
    /// Match if the session's authentication strength meets or exceeds the minimum.
    AuthenticationStrength(AuthStrength),
    /// Logical AND — all sub-conditions must match.
    And(Vec<Condition>),
    /// Logical OR — at least one sub-condition must match.
    Or(Vec<Condition>),
    /// Logical NOT — the sub-condition must NOT match.
    Not(Box<Condition>),
}

// ── Access Context ──────────────────────────────────────────────────────

/// Context provided for each access request evaluation.
///
/// All fields are optional to support partial evaluation (a condition that
/// references a missing field evaluates to `false`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessContext {
    /// Source IP address of the request.
    pub source_ip: Option<IpAddr>,
    /// ISO 3166-1 alpha-2 country code derived from GeoIP lookup.
    pub country_code: Option<String>,
    /// Current hour in UTC (0-23).
    pub current_hour: Option<u8>,
    /// Current day of week.
    pub current_day: Option<DayOfWeek>,
    /// Device tier of the requesting device.
    pub device_tier: Option<DeviceTier>,
    /// Computed risk score (0.0 - 1.0).
    pub risk_score: Option<f64>,
    /// Subject's classification clearance level.
    pub classification: Option<ClassificationLevel>,
    /// User attributes as key-value pairs (e.g. groups, department).
    pub user_attributes: std::collections::HashMap<String, Vec<String>>,
    /// Authentication strength of the current session.
    pub auth_strength: Option<AuthStrength>,
}

impl Default for AccessContext {
    fn default() -> Self {
        Self {
            source_ip: None,
            country_code: None,
            current_hour: None,
            current_day: None,
            device_tier: None,
            risk_score: None,
            classification: None,
            user_attributes: std::collections::HashMap::new(),
            auth_strength: None,
        }
    }
}

// ── Condition Evaluation ────────────────────────────────────────────────

/// Evaluate a single condition against the given context.
///
/// Returns `true` if the condition matches. Conditions that reference a
/// context field that is `None` evaluate to `false` (fail-closed).
pub fn evaluate_condition(condition: &Condition, ctx: &AccessContext) -> bool {
    match condition {
        Condition::IpRange(ranges) => {
            let Some(ref ip) = ctx.source_ip else {
                return false;
            };
            ranges.iter().any(|r| r.contains(ip))
        }
        Condition::GeoLocation {
            allowlist,
            blocklist,
        } => {
            let Some(ref country) = ctx.country_code else {
                return false;
            };
            let country_upper = country.to_uppercase();
            // If blocklist is non-empty and country is on it, fail
            if !blocklist.is_empty()
                && blocklist.iter().any(|b| b.to_uppercase() == country_upper)
            {
                return false;
            }
            // If allowlist is non-empty, country must be on it
            if !allowlist.is_empty() {
                return allowlist.iter().any(|a| a.to_uppercase() == country_upper);
            }
            // No allowlist and not on blocklist — pass
            true
        }
        Condition::TimeWindow(tw) => {
            let Some(hour) = ctx.current_hour else {
                return false;
            };
            let day = ctx.current_day.unwrap_or(DayOfWeek::Monday);
            tw.contains(hour, day)
        }
        Condition::DeviceTier(min_tier) => {
            let Some(device_tier) = ctx.device_tier else {
                return false;
            };
            // Lower numeric tier = higher privilege (Sovereign=1 is best).
            // "Meets or exceeds" means device_tier <= min_tier numerically.
            (device_tier as u8) <= (*min_tier as u8)
        }
        Condition::RiskScore(thresholds) => {
            let Some(score) = ctx.risk_score else {
                return false;
            };
            // This condition matches when the score is within acceptable range.
            // The caller uses RiskScore to define "acceptable"; the condition
            // returns true when the score is below the allow threshold.
            score < thresholds.allow_below
        }
        Condition::ClassificationLevel(min_level) => {
            let Some(level) = ctx.classification else {
                return false;
            };
            level >= *min_level
        }
        Condition::UserAttribute { key, values } => {
            let Some(user_vals) = ctx.user_attributes.get(key) else {
                return false;
            };
            values.iter().any(|v| user_vals.contains(v))
        }
        Condition::AuthenticationStrength(min_strength) => {
            let Some(strength) = ctx.auth_strength else {
                return false;
            };
            strength >= *min_strength
        }
        Condition::And(conditions) => {
            if conditions.is_empty() {
                return true; // vacuous truth
            }
            conditions.iter().all(|c| evaluate_condition(c, ctx))
        }
        Condition::Or(conditions) => {
            if conditions.is_empty() {
                return false; // no conditions to satisfy
            }
            conditions.iter().any(|c| evaluate_condition(c, ctx))
        }
        Condition::Not(inner) => !evaluate_condition(inner, ctx),
    }
}

// ── Policy Rule & Engine ────────────────────────────────────────────────

/// A named policy rule consisting of a condition and an action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Human-readable name for audit logging.
    pub name: String,
    /// Optional description of the rule's purpose.
    pub description: Option<String>,
    /// Condition that must evaluate to `true` for this rule to match.
    pub condition: Condition,
    /// Action to take when the rule matches.
    pub action: PolicyAction,
    /// Whether the rule is currently enabled.
    pub enabled: bool,
}

/// Structured result of a policy evaluation, suitable for audit logging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// The action determined by evaluation.
    pub action: PolicyAction,
    /// Name of the rule that matched, or `"default-deny"` if none matched.
    pub matched_rule: String,
    /// Human-readable reason explaining why this decision was made.
    pub reason: String,
    /// Number of rules evaluated before a match was found.
    pub rules_evaluated: usize,
}

/// The conditional access policy engine.
///
/// Holds an ordered list of [`PolicyRule`]s and evaluates them in order
/// against an [`AccessContext`]. The first matching rule wins. If no rule
/// matches, the engine returns a default-deny decision.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    /// Ordered list of policy rules. First match wins.
    pub rules: Vec<PolicyRule>,
}

impl PolicyEngine {
    /// Create a new engine with the given ordered rules.
    pub fn new(rules: Vec<PolicyRule>) -> Self {
        Self { rules }
    }

    /// Create an empty engine (default-deny on every request).
    pub fn empty() -> Self {
        Self { rules: Vec::new() }
    }

    /// Evaluate the policy rules against the given access context.
    ///
    /// Iterates through enabled rules in order. The first rule whose
    /// condition evaluates to `true` determines the decision. If no rule
    /// matches, returns a default-deny decision.
    pub fn evaluate(&self, ctx: &AccessContext) -> PolicyDecision {
        let mut rules_evaluated = 0;

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            rules_evaluated += 1;

            if evaluate_condition(&rule.condition, ctx) {
                return PolicyDecision {
                    action: rule.action.clone(),
                    matched_rule: rule.name.clone(),
                    reason: format!(
                        "Rule '{}' matched: {}",
                        rule.name,
                        rule.description
                            .as_deref()
                            .unwrap_or("no description")
                    ),
                    rules_evaluated,
                };
            }
        }

        // Default deny — no rule matched
        PolicyDecision {
            action: PolicyAction::Deny,
            matched_rule: "default-deny".to_string(),
            reason: format!(
                "No policy rule matched after evaluating {} rules; access denied by default",
                rules_evaluated
            ),
            rules_evaluated,
        }
    }

    /// Evaluate and additionally return risk-based challenge/block overrides.
    ///
    /// If the base policy allows access but the risk score exceeds challenge
    /// or block thresholds, the decision is escalated accordingly. This
    /// provides defense-in-depth: even an explicit Allow rule can be
    /// overridden by extreme risk.
    pub fn evaluate_with_risk_override(
        &self,
        ctx: &AccessContext,
        thresholds: &RiskThresholds,
    ) -> PolicyDecision {
        let mut decision = self.evaluate(ctx);

        // Only escalate Allow decisions — Deny/Block should not be weakened.
        if decision.action == PolicyAction::Allow {
            if let Some(score) = ctx.risk_score {
                if score >= thresholds.block_above {
                    decision.action = PolicyAction::Block;
                    decision.reason = format!(
                        "{} [OVERRIDDEN: risk score {:.2} >= block threshold {:.2}]",
                        decision.reason, score, thresholds.block_above
                    );
                } else if score >= thresholds.challenge_above {
                    decision.action = PolicyAction::RequireStepUp;
                    decision.reason = format!(
                        "{} [ESCALATED: risk score {:.2} >= challenge threshold {:.2}]",
                        decision.reason, score, thresholds.challenge_above
                    );
                }
            }
        }

        decision
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::empty()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn allow_all_rule(name: &str) -> PolicyRule {
        PolicyRule {
            name: name.to_string(),
            description: Some("Allow everything".to_string()),
            condition: Condition::And(vec![]), // vacuous truth
            action: PolicyAction::Allow,
            enabled: true,
        }
    }

    fn deny_all_rule(name: &str) -> PolicyRule {
        PolicyRule {
            name: name.to_string(),
            description: Some("Deny everything".to_string()),
            condition: Condition::And(vec![]), // vacuous truth
            action: PolicyAction::Deny,
            enabled: true,
        }
    }

    fn base_context() -> AccessContext {
        AccessContext {
            source_ip: Some("10.0.1.50".parse().unwrap()),
            country_code: Some("US".to_string()),
            current_hour: Some(10),
            current_day: Some(DayOfWeek::Wednesday),
            device_tier: Some(DeviceTier::Operational),
            risk_score: Some(0.1),
            classification: Some(ClassificationLevel::Secret),
            user_attributes: {
                let mut m = HashMap::new();
                m.insert("group".to_string(), vec!["analysts".to_string(), "ops".to_string()]);
                m.insert("department".to_string(), vec!["intel".to_string()]);
                m
            },
            auth_strength: Some(AuthStrength::SmartCard),
        }
    }

    // ── CIDR parsing and matching ───────────────────────────────────────

    #[test]
    fn cidr_parse_and_contains_ipv4() {
        let cidr = CidrRange::parse("10.0.0.0/8").unwrap();
        assert!(cidr.contains(&"10.255.255.255".parse().unwrap()));
        assert!(cidr.contains(&"10.0.0.1".parse().unwrap()));
        assert!(!cidr.contains(&"11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn cidr_parse_and_contains_ipv6() {
        let cidr = CidrRange::parse("fd00::/16").unwrap();
        assert!(cidr.contains(&"fd00::1".parse().unwrap()));
        assert!(cidr.contains(&"fd00:abcd::1".parse().unwrap()));
        assert!(!cidr.contains(&"fe80::1".parse().unwrap()));
    }

    #[test]
    fn cidr_v4_v6_mismatch() {
        let cidr = CidrRange::parse("10.0.0.0/8").unwrap();
        assert!(!cidr.contains(&"fd00::1".parse().unwrap()));
    }

    #[test]
    fn cidr_parse_invalid() {
        assert!(CidrRange::parse("not-a-cidr").is_none());
        assert!(CidrRange::parse("10.0.0.0/33").is_none());
        assert!(CidrRange::parse("10.0.0.0").is_none());
    }

    // ── Single condition evaluation ─────────────────────────────────────

    #[test]
    fn condition_ip_range_match() {
        let ctx = base_context();
        let cond = Condition::IpRange(vec![CidrRange::parse("10.0.0.0/8").unwrap()]);
        assert!(evaluate_condition(&cond, &ctx));
    }

    #[test]
    fn condition_ip_range_no_match() {
        let ctx = base_context();
        let cond = Condition::IpRange(vec![CidrRange::parse("192.168.0.0/16").unwrap()]);
        assert!(!evaluate_condition(&cond, &ctx));
    }

    #[test]
    fn condition_ip_range_missing_ip() {
        let mut ctx = base_context();
        ctx.source_ip = None;
        let cond = Condition::IpRange(vec![CidrRange::parse("10.0.0.0/8").unwrap()]);
        assert!(!evaluate_condition(&cond, &ctx));
    }

    #[test]
    fn condition_geolocation_allowlist() {
        let ctx = base_context();
        let cond = Condition::GeoLocation {
            allowlist: vec!["US".to_string(), "GB".to_string()],
            blocklist: vec![],
        };
        assert!(evaluate_condition(&cond, &ctx));

        let cond_denied = Condition::GeoLocation {
            allowlist: vec!["GB".to_string()],
            blocklist: vec![],
        };
        assert!(!evaluate_condition(&cond_denied, &ctx));
    }

    #[test]
    fn condition_geolocation_blocklist() {
        let ctx = base_context();
        let cond = Condition::GeoLocation {
            allowlist: vec![],
            blocklist: vec!["RU".to_string(), "CN".to_string()],
        };
        assert!(evaluate_condition(&cond, &ctx));

        let cond_blocked = Condition::GeoLocation {
            allowlist: vec![],
            blocklist: vec!["US".to_string()],
        };
        assert!(!evaluate_condition(&cond_blocked, &ctx));
    }

    #[test]
    fn condition_geolocation_case_insensitive() {
        let ctx = base_context(); // country_code = "US"
        let cond = Condition::GeoLocation {
            allowlist: vec!["us".to_string()],
            blocklist: vec![],
        };
        assert!(evaluate_condition(&cond, &ctx));
    }

    #[test]
    fn condition_time_window_normal() {
        let ctx = base_context(); // hour=10, day=Wednesday
        let cond = Condition::TimeWindow(TimeWindow {
            start_hour: 8,
            end_hour: 18,
            allowed_days: vec![
                DayOfWeek::Monday,
                DayOfWeek::Tuesday,
                DayOfWeek::Wednesday,
                DayOfWeek::Thursday,
                DayOfWeek::Friday,
            ],
        });
        assert!(evaluate_condition(&cond, &ctx));
    }

    #[test]
    fn condition_time_window_outside_hours() {
        let mut ctx = base_context();
        ctx.current_hour = Some(20); // outside 08-18
        let cond = Condition::TimeWindow(TimeWindow {
            start_hour: 8,
            end_hour: 18,
            allowed_days: vec![],
        });
        assert!(!evaluate_condition(&cond, &ctx));
    }

    #[test]
    fn condition_time_window_wraps_midnight() {
        let mut ctx = base_context();
        ctx.current_hour = Some(23);
        let cond = Condition::TimeWindow(TimeWindow {
            start_hour: 22,
            end_hour: 6,
            allowed_days: vec![],
        });
        assert!(evaluate_condition(&cond, &ctx));

        ctx.current_hour = Some(3);
        assert!(evaluate_condition(&cond, &ctx));

        ctx.current_hour = Some(10);
        assert!(!evaluate_condition(&cond, &ctx));
    }

    #[test]
    fn condition_time_window_wrong_day() {
        let mut ctx = base_context();
        ctx.current_day = Some(DayOfWeek::Saturday);
        let cond = Condition::TimeWindow(TimeWindow {
            start_hour: 0,
            end_hour: 24, // This wraps: start > end is false, so 0..24 never matches via < 24 check
            allowed_days: vec![DayOfWeek::Monday, DayOfWeek::Tuesday],
        });
        assert!(!evaluate_condition(&cond, &ctx));
    }

    #[test]
    fn condition_device_tier() {
        let ctx = base_context(); // Operational (2)
        // Require Operational (2) or better
        let cond = Condition::DeviceTier(DeviceTier::Operational);
        assert!(evaluate_condition(&cond, &ctx));

        // Require Sovereign (1) — Operational (2) does not meet it
        let cond_strict = Condition::DeviceTier(DeviceTier::Sovereign);
        assert!(!evaluate_condition(&cond_strict, &ctx));

        // Require Sensor (3) — Operational (2) exceeds it
        let cond_lax = Condition::DeviceTier(DeviceTier::Sensor);
        assert!(evaluate_condition(&cond_lax, &ctx));
    }

    #[test]
    fn condition_risk_score() {
        let ctx = base_context(); // risk_score = 0.1
        let cond = Condition::RiskScore(RiskThresholds {
            allow_below: 0.3,
            challenge_above: 0.6,
            block_above: 0.8,
        });
        assert!(evaluate_condition(&cond, &ctx)); // 0.1 < 0.3

        let mut high_risk_ctx = base_context();
        high_risk_ctx.risk_score = Some(0.5);
        assert!(!evaluate_condition(&cond, &high_risk_ctx)); // 0.5 >= 0.3
    }

    #[test]
    fn condition_classification_level() {
        let ctx = base_context(); // Secret
        let cond = Condition::ClassificationLevel(ClassificationLevel::Secret);
        assert!(evaluate_condition(&cond, &ctx));

        let cond_higher = Condition::ClassificationLevel(ClassificationLevel::TopSecret);
        assert!(!evaluate_condition(&cond_higher, &ctx));

        let cond_lower = Condition::ClassificationLevel(ClassificationLevel::Confidential);
        assert!(evaluate_condition(&cond_lower, &ctx));
    }

    #[test]
    fn condition_user_attribute() {
        let ctx = base_context();
        let cond = Condition::UserAttribute {
            key: "group".to_string(),
            values: vec!["analysts".to_string()],
        };
        assert!(evaluate_condition(&cond, &ctx));

        let cond_missing = Condition::UserAttribute {
            key: "group".to_string(),
            values: vec!["admins".to_string()],
        };
        assert!(!evaluate_condition(&cond_missing, &ctx));

        let cond_no_key = Condition::UserAttribute {
            key: "role".to_string(),
            values: vec!["anything".to_string()],
        };
        assert!(!evaluate_condition(&cond_no_key, &ctx));
    }

    #[test]
    fn condition_auth_strength() {
        let ctx = base_context(); // SmartCard (3)
        let cond = Condition::AuthenticationStrength(AuthStrength::SmartCard);
        assert!(evaluate_condition(&cond, &ctx));

        let cond_lower = Condition::AuthenticationStrength(AuthStrength::MultiFactor);
        assert!(evaluate_condition(&cond_lower, &ctx));

        let cond_higher = Condition::AuthenticationStrength(AuthStrength::BiometricHardware);
        assert!(!evaluate_condition(&cond_higher, &ctx));
    }

    // ── Logical composition ─────────────────────────────────────────────

    #[test]
    fn condition_and_composition() {
        let ctx = base_context();
        let cond = Condition::And(vec![
            Condition::IpRange(vec![CidrRange::parse("10.0.0.0/8").unwrap()]),
            Condition::GeoLocation {
                allowlist: vec!["US".to_string()],
                blocklist: vec![],
            },
        ]);
        assert!(evaluate_condition(&cond, &ctx));

        // Fail one sub-condition
        let cond_fail = Condition::And(vec![
            Condition::IpRange(vec![CidrRange::parse("10.0.0.0/8").unwrap()]),
            Condition::GeoLocation {
                allowlist: vec!["GB".to_string()],
                blocklist: vec![],
            },
        ]);
        assert!(!evaluate_condition(&cond_fail, &ctx));
    }

    #[test]
    fn condition_or_composition() {
        let ctx = base_context();
        let cond = Condition::Or(vec![
            Condition::IpRange(vec![CidrRange::parse("192.168.0.0/16").unwrap()]),
            Condition::GeoLocation {
                allowlist: vec!["US".to_string()],
                blocklist: vec![],
            },
        ]);
        assert!(evaluate_condition(&cond, &ctx)); // second matches

        let cond_none = Condition::Or(vec![
            Condition::IpRange(vec![CidrRange::parse("192.168.0.0/16").unwrap()]),
            Condition::GeoLocation {
                allowlist: vec!["GB".to_string()],
                blocklist: vec![],
            },
        ]);
        assert!(!evaluate_condition(&cond_none, &ctx));
    }

    #[test]
    fn condition_not_composition() {
        let ctx = base_context();
        let cond = Condition::Not(Box::new(Condition::GeoLocation {
            allowlist: vec![],
            blocklist: vec!["RU".to_string()],
        }));
        // GeoLocation(blocklist=RU) evaluates to true (US not blocked), so NOT => false
        assert!(!evaluate_condition(&cond, &ctx));

        let cond2 = Condition::Not(Box::new(Condition::GeoLocation {
            allowlist: vec!["GB".to_string()],
            blocklist: vec![],
        }));
        // GeoLocation(allowlist=GB) evaluates to false (US not in allowlist), so NOT => true
        assert!(evaluate_condition(&cond2, &ctx));
    }

    #[test]
    fn condition_empty_and_is_true() {
        let ctx = base_context();
        assert!(evaluate_condition(&Condition::And(vec![]), &ctx));
    }

    #[test]
    fn condition_empty_or_is_false() {
        let ctx = base_context();
        assert!(!evaluate_condition(&Condition::Or(vec![]), &ctx));
    }

    // ── Policy engine: first-match-wins ─────────────────────────────────

    #[test]
    fn policy_first_match_wins() {
        let engine = PolicyEngine::new(vec![
            deny_all_rule("deny-first"),
            allow_all_rule("allow-second"),
        ]);
        let decision = engine.evaluate(&base_context());
        assert_eq!(decision.action, PolicyAction::Deny);
        assert_eq!(decision.matched_rule, "deny-first");
        assert_eq!(decision.rules_evaluated, 1);
    }

    #[test]
    fn policy_skips_non_matching_rules() {
        let engine = PolicyEngine::new(vec![
            PolicyRule {
                name: "only-gb".to_string(),
                description: Some("Only allow GB".to_string()),
                condition: Condition::GeoLocation {
                    allowlist: vec!["GB".to_string()],
                    blocklist: vec![],
                },
                action: PolicyAction::Allow,
                enabled: true,
            },
            allow_all_rule("fallback-allow"),
        ]);
        let decision = engine.evaluate(&base_context());
        assert_eq!(decision.matched_rule, "fallback-allow");
        assert_eq!(decision.rules_evaluated, 2);
    }

    #[test]
    fn policy_default_deny_when_no_match() {
        let engine = PolicyEngine::new(vec![PolicyRule {
            name: "only-gb".to_string(),
            description: None,
            condition: Condition::GeoLocation {
                allowlist: vec!["GB".to_string()],
                blocklist: vec![],
            },
            action: PolicyAction::Allow,
            enabled: true,
        }]);
        let decision = engine.evaluate(&base_context());
        assert_eq!(decision.action, PolicyAction::Deny);
        assert_eq!(decision.matched_rule, "default-deny");
    }

    #[test]
    fn policy_empty_engine_default_deny() {
        let engine = PolicyEngine::empty();
        let decision = engine.evaluate(&base_context());
        assert_eq!(decision.action, PolicyAction::Deny);
        assert_eq!(decision.matched_rule, "default-deny");
        assert_eq!(decision.rules_evaluated, 0);
    }

    #[test]
    fn policy_disabled_rules_skipped() {
        let engine = PolicyEngine::new(vec![
            PolicyRule {
                name: "disabled-allow".to_string(),
                description: None,
                condition: Condition::And(vec![]),
                action: PolicyAction::Allow,
                enabled: false,
            },
            deny_all_rule("active-deny"),
        ]);
        let decision = engine.evaluate(&base_context());
        assert_eq!(decision.action, PolicyAction::Deny);
        assert_eq!(decision.matched_rule, "active-deny");
        // Only the active rule was evaluated
        assert_eq!(decision.rules_evaluated, 1);
    }

    // ── Risk override ───────────────────────────────────────────────────

    #[test]
    fn policy_risk_override_escalates_allow_to_step_up() {
        let engine = PolicyEngine::new(vec![allow_all_rule("allow")]);
        let mut ctx = base_context();
        ctx.risk_score = Some(0.65);
        let thresholds = RiskThresholds {
            allow_below: 0.3,
            challenge_above: 0.6,
            block_above: 0.8,
        };
        let decision = engine.evaluate_with_risk_override(&ctx, &thresholds);
        assert_eq!(decision.action, PolicyAction::RequireStepUp);
        assert!(decision.reason.contains("ESCALATED"));
    }

    #[test]
    fn policy_risk_override_escalates_allow_to_block() {
        let engine = PolicyEngine::new(vec![allow_all_rule("allow")]);
        let mut ctx = base_context();
        ctx.risk_score = Some(0.9);
        let thresholds = RiskThresholds {
            allow_below: 0.3,
            challenge_above: 0.6,
            block_above: 0.8,
        };
        let decision = engine.evaluate_with_risk_override(&ctx, &thresholds);
        assert_eq!(decision.action, PolicyAction::Block);
        assert!(decision.reason.contains("OVERRIDDEN"));
    }

    #[test]
    fn policy_risk_override_does_not_weaken_deny() {
        let engine = PolicyEngine::new(vec![deny_all_rule("deny")]);
        let ctx = base_context(); // risk_score = 0.1 (low)
        let thresholds = RiskThresholds {
            allow_below: 0.3,
            challenge_above: 0.6,
            block_above: 0.8,
        };
        let decision = engine.evaluate_with_risk_override(&ctx, &thresholds);
        assert_eq!(decision.action, PolicyAction::Deny);
    }

    // ── Complex scenario ────────────────────────────────────────────────

    #[test]
    fn policy_complex_mil_scenario() {
        // Scenario: Allow Secret-cleared analysts on the internal network during
        // business hours with SmartCard auth; require MFA for Sensor-tier devices;
        // block everything else.
        let engine = PolicyEngine::new(vec![
            // Rule 1: Block adversary nations
            PolicyRule {
                name: "block-adversary-nations".to_string(),
                description: Some("Block access from adversary nations".to_string()),
                condition: Condition::GeoLocation {
                    allowlist: vec![],
                    blocklist: vec!["RU".to_string(), "CN".to_string(), "KP".to_string(), "IR".to_string()],
                },
                // This condition returns false when country IS on blocklist,
                // so we negate it: NOT(geo passes) = geo fails = country blocked
                action: PolicyAction::Block,
                enabled: false, // We use the Not wrapper below instead
            },
            PolicyRule {
                name: "block-adversary-nations".to_string(),
                description: Some("Block access from adversary nations".to_string()),
                condition: Condition::Not(Box::new(Condition::GeoLocation {
                    allowlist: vec![],
                    blocklist: vec!["RU".to_string(), "CN".to_string(), "KP".to_string(), "IR".to_string()],
                })),
                action: PolicyAction::Block,
                enabled: true,
            },
            // Rule 2: Allow analysts on internal net during business hours
            PolicyRule {
                name: "allow-analysts-internal".to_string(),
                description: Some("Cleared analysts on MILNET during hours".to_string()),
                condition: Condition::And(vec![
                    Condition::IpRange(vec![CidrRange::parse("10.0.0.0/8").unwrap()]),
                    Condition::ClassificationLevel(ClassificationLevel::Secret),
                    Condition::AuthenticationStrength(AuthStrength::SmartCard),
                    Condition::UserAttribute {
                        key: "group".to_string(),
                        values: vec!["analysts".to_string()],
                    },
                    Condition::TimeWindow(TimeWindow {
                        start_hour: 6,
                        end_hour: 22,
                        allowed_days: vec![],
                    }),
                ]),
                action: PolicyAction::Allow,
                enabled: true,
            },
            // Rule 3: Require MFA for sensor-tier devices
            PolicyRule {
                name: "mfa-sensor-tier".to_string(),
                description: Some("Require MFA for Sensor-tier devices".to_string()),
                condition: Condition::And(vec![
                    Condition::DeviceTier(DeviceTier::Emergency),
                    Condition::Not(Box::new(Condition::DeviceTier(DeviceTier::Operational))),
                ]),
                action: PolicyAction::RequireMFA,
                enabled: true,
            },
        ]);

        // Test: US analyst on internal net, Secret clearance, SmartCard, 10am Wed
        let ctx = base_context();
        let decision = engine.evaluate(&ctx);
        assert_eq!(decision.action, PolicyAction::Allow);
        assert_eq!(decision.matched_rule, "allow-analysts-internal");
    }

    // ── Missing context fields (fail-closed) ────────────────────────────

    #[test]
    fn condition_missing_context_fails_closed() {
        let ctx = AccessContext::default(); // everything is None
        // All individual conditions should return false
        assert!(!evaluate_condition(
            &Condition::IpRange(vec![CidrRange::parse("0.0.0.0/0").unwrap()]),
            &ctx
        ));
        assert!(!evaluate_condition(
            &Condition::GeoLocation {
                allowlist: vec!["US".to_string()],
                blocklist: vec![],
            },
            &ctx
        ));
        assert!(!evaluate_condition(
            &Condition::TimeWindow(TimeWindow {
                start_hour: 0,
                end_hour: 24,
                allowed_days: vec![],
            }),
            &ctx
        ));
        assert!(!evaluate_condition(
            &Condition::DeviceTier(DeviceTier::Emergency),
            &ctx
        ));
        assert!(!evaluate_condition(
            &Condition::RiskScore(RiskThresholds {
                allow_below: 1.0,
                challenge_above: 0.6,
                block_above: 0.8,
            }),
            &ctx
        ));
        assert!(!evaluate_condition(
            &Condition::ClassificationLevel(ClassificationLevel::Unclassified),
            &ctx
        ));
        assert!(!evaluate_condition(
            &Condition::AuthenticationStrength(AuthStrength::PasswordOnly),
            &ctx
        ));
    }

    // ── PolicyDecision reason contains rule name ────────────────────────

    #[test]
    fn policy_decision_contains_reason() {
        let engine = PolicyEngine::new(vec![PolicyRule {
            name: "test-rule".to_string(),
            description: Some("A test rule".to_string()),
            condition: Condition::And(vec![]),
            action: PolicyAction::RequireApproval,
            enabled: true,
        }]);
        let decision = engine.evaluate(&base_context());
        assert_eq!(decision.action, PolicyAction::RequireApproval);
        assert!(decision.reason.contains("test-rule"));
        assert!(decision.reason.contains("A test rule"));
    }
}
