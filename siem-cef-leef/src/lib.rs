//! ArcSight CEF and QRadar LEEF formatters (J13).
//!
//! - CEF v0: `CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension`
//!   per ArcSight CEF Implementation Standard (Rev 25, 2017).
//! - LEEF v2: `LEEF:2.0|Vendor|Product|Version|EventID|DelimiterChar|Extension`
//!   per IBM QRadar LEEF Reference Guide.
//!
//! Both formatters escape the special characters required by their respective
//! specs so events parse correctly downstream.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub vendor: String,
    pub product: String,
    pub version: String,
    pub event_id: String,
    pub name: String,
    /// 0..10 (CEF) — LEEF treats severity as a free key in the extension map.
    pub severity: u8,
    pub extensions: BTreeMap<String, String>,
}

/// Reason a `SecurityEvent` could not be formatted. Returned rather than
/// silently coercing, so a call-site bug (e.g. a CVSS score or HTTP status
/// mis-assigned to `severity`) surfaces instead of being mapped to "highest".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatError {
    /// CEF severity must be 0..=10; the contained value is out of range.
    SeverityOutOfRange(u8),
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FormatError::SeverityOutOfRange(v) => {
                write!(f, "CEF severity {v} out of range (expected 0..=10)")
            }
        }
    }
}

impl std::error::Error for FormatError {}

/// Escape a CEF header field per ArcSight CEF Implementation Standard
/// (Rev 25, §3.4): `\`, `|`, and the line terminators `\n`/`\r`. Without the
/// newline escapes an attacker-controlled value (username, User-Agent, SP
/// entityID) could terminate the record and inject a forged event.
fn cef_escape_header(s: &str) -> String {
    s.replace('\\', r"\\")
        .replace('|', r"\|")
        .replace('\n', r"\n")
        .replace('\r', r"\r")
}

/// Escape a CEF extension value per §3.4: `\`, `=`, `\n`, `\r`.
fn cef_escape_ext_value(s: &str) -> String {
    s.replace('\\', r"\\")
        .replace('=', r"\=")
        .replace('\n', r"\n")
        .replace('\r', r"\r")
}

/// Sanitise an extension key for the SIEM trust boundary.
///
/// CEF/LEEF keys must be `[A-Za-z0-9_]+`; any other byte (`=`, space, tab,
/// `\n`, `\r`) lets a caller-influenced key smuggle additional pairs or forge
/// a record. Disallowed characters are replaced with `_` so the key can never
/// break out of its field.
fn sanitize_ext_key(k: &str) -> String {
    let cleaned: String = k
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect();
    if cleaned.is_empty() {
        "_".to_string()
    } else {
        cleaned
    }
}

pub fn format_cef(ev: &SecurityEvent) -> Result<String, FormatError> {
    // Validate rather than silently clamp: a severity above 10 is a call-site
    // bug (CVSS, HTTP status, etc.) and must not be coerced to "highest".
    if ev.severity > 10 {
        return Err(FormatError::SeverityOutOfRange(ev.severity));
    }
    let mut ext = String::new();
    for (k, v) in &ev.extensions {
        if !ext.is_empty() { ext.push(' '); }
        ext.push_str(&sanitize_ext_key(k));
        ext.push('=');
        ext.push_str(&cef_escape_ext_value(v));
    }
    Ok(format!(
        "CEF:0|{}|{}|{}|{}|{}|{}|{}",
        cef_escape_header(&ev.vendor),
        cef_escape_header(&ev.product),
        cef_escape_header(&ev.version),
        cef_escape_header(&ev.event_id),
        cef_escape_header(&ev.name),
        ev.severity,
        ext
    ))
}

/// Escape a LEEF header or extension value per the IBM QRadar LEEF Reference
/// Guide ("Character encoding"): `\` and the field delimiter are backslash-
/// escaped, and the line terminators `\n`/`\r` are emitted as the literal
/// sequences `\n`/`\r`. Escaping newlines is mandatory in both headers and
/// values; without it any attacker-controlled string can terminate the LEEF
/// record and inject a forged event.
fn leef_escape(s: &str, delim: char) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            '\\' => out.push_str(r"\\"),
            _ if c == delim => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

pub fn format_leef(ev: &SecurityEvent) -> String {
    let delim = '\t';
    let mut ext = String::new();
    let mut first = true;
    // Track whether the caller already supplied a `sev` key (after key
    // sanitisation), so the auto-appended severity does not produce a
    // duplicate `sev=` pair that downstream parsers handle inconsistently.
    let mut caller_set_sev = false;
    for (k, v) in &ev.extensions {
        let key = sanitize_ext_key(k);
        if key == "sev" { caller_set_sev = true; }
        if !first { ext.push(delim); }
        first = false;
        ext.push_str(&key);
        ext.push('=');
        ext.push_str(&leef_escape(v, delim));
    }
    // Only emit the event's own severity when the caller has not already
    // provided one; their explicit value takes precedence.
    if !caller_set_sev {
        if !first { ext.push(delim); }
        ext.push_str("sev=");
        ext.push_str(&ev.severity.to_string());
    }

    format!(
        "LEEF:2.0|{}|{}|{}|{}|^|{}",
        leef_escape(&ev.vendor, '|'),
        leef_escape(&ev.product, '|'),
        leef_escape(&ev.version, '|'),
        leef_escape(&ev.event_id, '|'),
        ext
    )
}
