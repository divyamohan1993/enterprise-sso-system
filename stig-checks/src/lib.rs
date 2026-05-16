//! DISA STIG V5R3 application-layer check module (J16).
//!
//! Implements the APP-* control family: session timeout, idle lockout,
//! password policy, failed-login lockout, FIPS crypto, audit logging,
//! error sanitization, secure defaults, concurrent session limits, and
//! privilege escalation controls. Produces an XCCDF 1.2 report.
//!
//! 300+ checks are generated via parameterised templates rather than being
//! hand-written one-by-one, because most of the V5R3 application family
//! consists of small variations on a fixed set of control axes.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fmt::Write;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity { CatI, CatII, CatIII }

impl Severity {
    pub fn xccdf(self) -> &'static str {
        match self { Severity::CatI => "high", Severity::CatII => "medium", Severity::CatIII => "low" }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome { Pass, Fail, NotApplicable, NotChecked }

impl Outcome {
    pub fn xccdf(self) -> &'static str {
        match self {
            Outcome::Pass => "pass",
            Outcome::Fail => "fail",
            Outcome::NotApplicable => "notapplicable",
            Outcome::NotChecked => "notchecked",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Check {
    pub stig_id: String,
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub control_family: String,
    pub fix_text: String,
    pub outcome: Outcome,
    pub evidence: String,
}

/// A STIG evaluator over the real posture of an `authsrv` deployment.
///
/// Every field is `Option`: `Some(_)` means the value was actually observed
/// from the running configuration, `None` means it could not be determined on
/// this host. An undetermined value yields `Outcome::NotChecked`, never a
/// fabricated `Pass` — a STIG attestation must not assert compliance for a
/// control it never inspected.
#[derive(Debug, Clone, Default)]
pub struct StigEvaluator {
    pub session_timeout_secs: Option<u64>,
    pub idle_lockout_secs: Option<u64>,
    pub password_min_length: Option<usize>,
    pub password_history: Option<usize>,
    pub failed_login_lockout: Option<usize>,
    pub fips_enabled: Option<bool>,
    pub audit_logging_enabled: Option<bool>,
    pub concurrent_session_limit: Option<usize>,
    pub error_messages_sanitized: Option<bool>,
    pub privilege_separation: Option<bool>,
}

/// Parse a `u64` policy value from an environment variable, or `None` if the
/// variable is unset or not a valid number. Returning `None` (rather than a
/// default) is what keeps an undetermined control honest.
fn env_u64(key: &str) -> Option<u64> {
    std::env::var(key).ok().and_then(|v| v.trim().parse().ok())
}

fn env_usize(key: &str) -> Option<usize> {
    std::env::var(key).ok().and_then(|v| v.trim().parse().ok())
}

/// Parse a boolean policy flag (`1`/`true`/`yes`/`on` vs `0`/`false`/`no`/`off`,
/// case-insensitive). Anything else, or an unset variable, yields `None`.
fn env_bool(key: &str) -> Option<bool> {
    match std::env::var(key).ok()?.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

impl StigEvaluator {
    /// Inspect the real host posture of the `authsrv` deployment.
    ///
    /// Configuration is read from the process environment (`.env`, the
    /// project's own config mechanism) and, where available, the filesystem.
    /// On Linux STIG targets `fips_enabled` is additionally cross-checked
    /// against `/proc/sys/crypto/fips_enabled`. Any value that cannot be
    /// observed stays `None`, so its control reports `NotChecked` instead of
    /// a false `Pass`.
    pub fn from_system() -> Self {
        // FIPS: prefer the kernel's authoritative flag when present, else the
        // application-level env override. The kernel file wins if both exist.
        let fips_kernel = std::fs::read_to_string("/proc/sys/crypto/fips_enabled")
            .ok()
            .map(|s| s.trim() == "1");
        let fips_enabled = fips_kernel.or_else(|| env_bool("STIG_FIPS_ENABLED"));

        Self {
            session_timeout_secs: env_u64("STIG_SESSION_TIMEOUT_SECS"),
            idle_lockout_secs: env_u64("STIG_IDLE_LOCKOUT_SECS"),
            password_min_length: env_usize("STIG_PASSWORD_MIN_LENGTH"),
            password_history: env_usize("STIG_PASSWORD_HISTORY"),
            failed_login_lockout: env_usize("STIG_FAILED_LOGIN_LOCKOUT"),
            fips_enabled,
            audit_logging_enabled: env_bool("STIG_AUDIT_LOGGING_ENABLED"),
            concurrent_session_limit: env_usize("STIG_CONCURRENT_SESSION_LIMIT"),
            error_messages_sanitized: env_bool("STIG_ERROR_MESSAGES_SANITIZED"),
            privilege_separation: env_bool("STIG_PRIVILEGE_SEPARATION"),
        }
    }

    /// A fully-populated, known-good baseline used for unit testing the
    /// scoring and rendering paths. This is NOT a system inspection: the
    /// production binary must use [`StigEvaluator::from_system`].
    pub fn known_good_baseline() -> Self {
        Self {
            session_timeout_secs: Some(900),
            idle_lockout_secs: Some(600),
            password_min_length: Some(15),
            password_history: Some(10),
            failed_login_lockout: Some(3),
            fips_enabled: Some(true),
            audit_logging_enabled: Some(true),
            concurrent_session_limit: Some(3),
            error_messages_sanitized: Some(true),
            privilege_separation: Some(true),
        }
    }
}

const FAMILIES: &[(&str, &str)] = &[
    ("APP-AC", "Access Control"),
    ("APP-AU", "Audit and Accountability"),
    ("APP-IA", "Identification and Authentication"),
    ("APP-CM", "Configuration Management"),
    ("APP-SC", "System and Communications Protection"),
    ("APP-SI", "System and Information Integrity"),
];

/// Render an observed `Option<T>` policy value for the evidence string.
fn evidence_opt<T: std::fmt::Display>(key: &str, v: &Option<T>) -> String {
    match v {
        Some(x) => format!("{key}={x}"),
        None => format!("{key}=<not observed>"),
    }
}

impl StigEvaluator {
    pub fn run(&self) -> Vec<Check> {
        let mut out = Vec::with_capacity(320);

        // Core hand-coded controls (the load-bearing ones). Each predicate is
        // an `Option<bool>`: `None` when the underlying value was never
        // observed, which yields `NotChecked` rather than a fabricated result.
        out.push(self.check(
            "APP-AC-000010", "session-timeout",
            "The application must terminate user sessions after 15 minutes",
            Severity::CatII, "APP-AC",
            self.session_timeout_secs.map(|v| (1..=900).contains(&v)),
            evidence_opt("session_timeout_secs", &self.session_timeout_secs),
            "Set session timeout to a value between 1 and 900 seconds.",
        ));
        out.push(self.check(
            "APP-AC-000020", "idle-lockout",
            "The application must lock the session after 10 minutes of inactivity",
            Severity::CatII, "APP-AC",
            self.idle_lockout_secs.map(|v| (1..=600).contains(&v)),
            evidence_opt("idle_lockout_secs", &self.idle_lockout_secs),
            "Set idle lockout to a value between 1 and 600 seconds.",
        ));
        out.push(self.check(
            "APP-AC-000030", "concurrent-sessions",
            "The application must limit concurrent sessions per user",
            Severity::CatII, "APP-AC",
            self.concurrent_session_limit.map(|v| (1..=10).contains(&v)),
            evidence_opt("concurrent_session_limit", &self.concurrent_session_limit),
            "Configure concurrent session limit between 1 and 10.",
        ));
        out.push(self.check(
            "APP-IA-000010", "password-length",
            "Passwords must be ≥ 15 characters",
            Severity::CatI, "APP-IA",
            self.password_min_length.map(|v| v >= 15),
            evidence_opt("password_min_length", &self.password_min_length),
            "Set MinPasswordLength to ≥ 15.",
        ));
        out.push(self.check(
            "APP-IA-000020", "password-history",
            "Password history must enforce 10 prior passwords",
            Severity::CatII, "APP-IA",
            self.password_history.map(|v| v >= 10),
            evidence_opt("password_history", &self.password_history),
            "Set PasswordHistory ≥ 10.",
        ));
        out.push(self.check(
            "APP-IA-000030", "failed-login-lockout",
            "Account must lock after 3 failed authentication attempts",
            Severity::CatII, "APP-IA",
            self.failed_login_lockout.map(|v| (1..=3).contains(&v)),
            evidence_opt("failed_login_lockout", &self.failed_login_lockout),
            "Set FailedLoginThreshold to 3.",
        ));
        out.push(self.check(
            "APP-SC-000010", "fips-mode",
            "Application must operate in FIPS 140-3 mode",
            Severity::CatI, "APP-SC",
            self.fips_enabled,
            evidence_opt("fips_enabled", &self.fips_enabled),
            "Enable FIPS mode and load only validated providers.",
        ));
        out.push(self.check(
            "APP-AU-000010", "audit-logging",
            "Audit logging of security-relevant events must be enabled",
            Severity::CatI, "APP-AU",
            self.audit_logging_enabled,
            evidence_opt("audit_logging_enabled", &self.audit_logging_enabled),
            "Enable common::audit_bridge.",
        ));
        out.push(self.check(
            "APP-SI-000010", "error-sanitization",
            "Error messages exposed to users must be sanitised",
            Severity::CatII, "APP-SI",
            self.error_messages_sanitized,
            evidence_opt("error_messages_sanitized", &self.error_messages_sanitized),
            "Disable developer mode in production.",
        ));
        out.push(self.check(
            "APP-CM-000010", "privilege-separation",
            "Application components must run with least privilege",
            Severity::CatII, "APP-CM",
            self.privilege_separation,
            evidence_opt("privilege_separation", &self.privilege_separation),
            "Run components under dedicated UIDs and capability sets.",
        ));

        // Templated coverage to reach the 300+ check goal: 50 numbered
        // controls per family. These derived controls are NOT individually
        // inspected by this tool, so their outcome is always `NotChecked`.
        // Emitting `Pass` here would be a positive XCCDF compliance assertion
        // for a requirement that was never evaluated — a false-pass. They are
        // reported so the benchmark's coverage gap is explicit, not hidden.
        for (fam_prefix, fam_name) in FAMILIES {
            for n in 0..50 {
                let id = format!("{}-{:06}", fam_prefix, 100 + n);
                out.push(Check {
                    stig_id: id.clone(),
                    rule_id: format!("rule_{}", id.to_lowercase()),
                    title: format!("{fam_name} control {n} (derived, not individually inspected)"),
                    severity: Severity::CatIII,
                    control_family: fam_prefix.to_string(),
                    fix_text: format!(
                        "Evaluate this {fam_prefix} control directly; it is not \
                         covered by an automated probe in this benchmark version."
                    ),
                    outcome: Outcome::NotChecked,
                    evidence: "no automated probe implemented for this control".to_string(),
                });
            }
        }
        out
    }

    /// Build a check from an `Option<bool>` predicate: `Some(true)` -> `Pass`,
    /// `Some(false)` -> `Fail`, `None` -> `NotChecked` (value never observed).
    fn check(
        &self,
        id: &str,
        rule: &str,
        title: &str,
        sev: Severity,
        family: &str,
        ok: Option<bool>,
        evidence: String,
        fix: &str,
    ) -> Check {
        let outcome = match ok {
            Some(true) => Outcome::Pass,
            Some(false) => Outcome::Fail,
            None => Outcome::NotChecked,
        };
        Check {
            stig_id: id.into(),
            rule_id: rule.into(),
            title: title.into(),
            severity: sev,
            control_family: family.into(),
            fix_text: fix.into(),
            outcome,
            evidence,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ScoreCard {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub not_applicable: usize,
    pub not_checked: usize,
    /// Pass rate over *evaluated* controls only (`passed / (passed + failed)`).
    pub score_pct: f32,
    /// Fraction of all controls that were actually evaluated. A high
    /// `score_pct` with a low `coverage_pct` means most controls were never
    /// inspected — the two MUST be read together to avoid a false-pass.
    pub coverage_pct: f32,
}

pub fn score(checks: &[Check]) -> ScoreCard {
    let total = checks.len();
    let passed = checks.iter().filter(|c| c.outcome == Outcome::Pass).count();
    let failed = checks.iter().filter(|c| c.outcome == Outcome::Fail).count();
    let na = checks.iter().filter(|c| c.outcome == Outcome::NotApplicable).count();
    let nc = checks.iter().filter(|c| c.outcome == Outcome::NotChecked).count();
    let evaluated = (passed + failed) as f32;
    let score_pct = if evaluated > 0.0 { (passed as f32 / evaluated) * 100.0 } else { 0.0 };
    let coverage_pct = if total > 0 {
        (evaluated / total as f32) * 100.0
    } else {
        0.0
    };
    ScoreCard { total, passed, failed, not_applicable: na, not_checked: nc, score_pct, coverage_pct }
}

pub fn render_xccdf(checks: &[Check]) -> String {
    let mut s = String::new();
    s.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    s.push_str("<Benchmark xmlns=\"http://checklists.nist.gov/xccdf/1.2\" id=\"xccdf_milnet_benchmark_app_v5r3\">\n");
    s.push_str("  <title>MILNET Application STIG V5R3</title>\n");
    s.push_str("  <version>5.3</version>\n");
    for c in checks {
        // XCCDF 1.2 requires Rule ids of the form
        // `xccdf_<reverse-dns>_rule_<name>`; STIG Viewer / SCAP scanners
        // reject anything else.
        let rule_id = format!("xccdf_one.dmj.milnet_rule_{}", c.rule_id);
        let _ = write!(
            s,
            "  <Rule id=\"{}\" severity=\"{}\">\n    <title>{}</title>\n    <fixtext>{}</fixtext>\n    <result>{}</result>\n    <check-content>{}</check-content>\n  </Rule>\n",
            xml_escape(&rule_id),
            c.severity.xccdf(),
            xml_escape(&c.title),
            xml_escape(&c.fix_text),
            c.outcome.xccdf(),
            xml_escape(&c.evidence),
        );
    }
    s.push_str("</Benchmark>\n");
    s
}

/// Escape a string for inclusion in XML 1.0 text or attribute content.
///
/// Escapes the five predefined entities (`& < > " '`) and numeric-escapes the
/// C0 control characters that XML 1.0 forbids, except the legal whitespace
/// `\t \n \r`. Control characters in evidence strings would otherwise produce
/// a document that downstream scanners reject as not well-formed.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' | '\n' | '\r' => out.push(c),
            c if (c as u32) < 0x20 => {
                // Illegal in XML 1.0; drop rather than emit an invalid doc.
                out.push('\u{FFFD}');
            }
            c => out.push(c),
        }
    }
    out
}
