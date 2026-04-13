//! Scheduled compliance report generator (J14).
//!
//! Renders FedRAMP / CMMC / STIG findings as HTML (always available) and PDF
//! (gated behind the `pdf` feature, which pulls in `printpdf`). Includes an
//! SMTP delivery hook for weekly rollups.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fmt::Write;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Framework {
    FedRamp,
    Cmmc,
    Stig,
}

impl Framework {
    pub fn label(self) -> &'static str {
        match self {
            Framework::FedRamp => "FedRAMP",
            Framework::Cmmc => "CMMC",
            Framework::Stig => "STIG",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub control_id: String,
    pub title: String,
    pub status: String,
    pub severity: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub framework: Framework,
    pub generated_at: i64,
    pub period_start: i64,
    pub period_end: i64,
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn pass_count(&self) -> usize { self.findings.iter().filter(|f| f.status == "PASS").count() }
    pub fn fail_count(&self) -> usize { self.findings.iter().filter(|f| f.status == "FAIL").count() }

    pub fn render_html(&self) -> String {
        let mut s = String::new();
        let _ = write!(
            s,
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
             <title>{} Compliance Report</title></head><body>",
            self.framework.label()
        );
        let _ = write!(s, "<h1>{} Report</h1>", self.framework.label());
        let _ = write!(
            s,
            "<p>Generated {} — period {}–{}</p>",
            self.generated_at, self.period_start, self.period_end
        );
        let _ = write!(
            s,
            "<p>Pass: <strong>{}</strong> &nbsp; Fail: <strong>{}</strong></p>",
            self.pass_count(),
            self.fail_count()
        );
        let _ = write!(s, "<table border=\"1\" cellpadding=\"4\"><tr><th>Control</th><th>Title</th><th>Severity</th><th>Status</th><th>Evidence</th></tr>");
        for f in &self.findings {
            let _ = write!(
                s,
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape(&f.control_id),
                escape(&f.title),
                escape(&f.severity),
                escape(&f.status),
                escape(&f.evidence)
            );
        }
        s.push_str("</table></body></html>");
        s
    }
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from: String,
}

/// Hook for SMTP delivery. Concrete sender is wired by callers (the
/// `lettre`-based adapter lives in `audit/`); this crate just produces the
/// MIME envelope to keep the dependency footprint small.
pub fn build_envelope(cfg: &SmtpConfig, to: &str, subject: &str, html: &str) -> String {
    format!(
        "From: {}\r\nTo: {}\r\nSubject: {}\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{}",
        cfg.from, to, subject, html
    )
}
