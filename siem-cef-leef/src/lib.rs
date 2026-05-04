//! ArcSight CEF and QRadar LEEF formatters (J13).
//!
//! - CEF v0: `CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension`
//!   per ArcSight CEF Implementation Standard (Rev 25, 2017).
//! - LEEF v2: `LEEF:2.0|Vendor|Product|Version|EventID|DelimiterChar|Extension`
//!   per IBM QRadar LEEF Reference Guide.
//!
//! X-L hardening: every header field, extension key, and extension value is
//! escaped against the full set of separator and line-terminator codepoints
//! the SIEM specs require. Extension keys are validated against
//! `[A-Za-z0-9_]+` on insertion so a single attacker-controlled value can
//! never end the current record and forge a fully-formed audit event.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Unconditional escape: `\\` `|` CR LF U+0085 (NEL) U+2028 (LINE SEP)
/// U+2029 (PARA SEP). Applied to header fields and to every extension key
/// AND value at emit time. The pipe is escaped because the CEF/LEEF header
/// uses `|` as a field separator; missing it lets a value forge new fields.
fn escape_siem(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str(r"\\"),
            '|' => out.push_str(r"\|"),
            '\r' => out.push_str(r"\r"),
            '\n' => out.push_str(r"\n"),
            '\u{0085}' => out.push_str("\\u0085"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            other => out.push(other),
        }
    }
    out
}

/// CEF extension VALUE escape: header escapes plus `=` (the in-extension
/// field separator). Keys go through `escape_siem` only — they must not
/// contain `=` at all (validated on insertion).
fn escape_cef_ext_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str(r"\\"),
            '=' => out.push_str(r"\="),
            '|' => out.push_str(r"\|"),
            '\r' => out.push_str(r"\r"),
            '\n' => out.push_str(r"\n"),
            '\u{0085}' => out.push_str("\\u0085"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            other => out.push(other),
        }
    }
    out
}

/// LEEF VALUE escape: same as CEF extension value plus the configured
/// LEEF delimiter (`\t` by default). The delimiter must always be escaped
/// or a single attacker-controlled value can split the line into multiple
/// `key=value` pairs.
fn escape_leef_value(s: &str, delim: char) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str(r"\\"),
            '|' => out.push_str(r"\|"),
            '\r' => out.push_str(r"\r"),
            '\n' => out.push_str(r"\n"),
            '\u{0085}' => out.push_str("\\u0085"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if c == delim => {
                out.push('\\');
                out.push(c);
            }
            other => out.push(other),
        }
    }
    out
}

/// X-L: extension key validation. CEF requires keys match `[A-Za-z0-9_]+`;
/// rejecting at insertion time means a downstream renamer / refactor cannot
/// silently move attacker-influenced data into a key position.
fn is_valid_ext_key(k: &str) -> bool {
    !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Errors raised by `ExtensionMap::insert` and `format_*`. `InvalidExtensionKey`
/// is a hard rejection — callers MUST sanitise their keys at the source.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FormatError {
    #[error("invalid CEF/LEEF extension key {0:?} (must match [A-Za-z0-9_]+)")]
    InvalidExtensionKey(String),
    #[error("severity {0} out of range (CEF: 0..=10)")]
    SeverityOutOfRange(u8),
}

/// Wrapper around `BTreeMap<String, String>` that validates keys on
/// insertion. Storing keys in a wrapper instead of a raw map prevents the
/// "one rename away" footgun the reviewer flagged.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExtensionMap(BTreeMap<String, String>);

impl ExtensionMap {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Insert a `(key, value)` pair. Returns `Err(InvalidExtensionKey)` if
    /// the key violates the CEF key grammar.
    pub fn insert(
        &mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), FormatError> {
        let key = key.into();
        if !is_valid_ext_key(&key) {
            return Err(FormatError::InvalidExtensionKey(key));
        }
        self.0.insert(key, value.into());
        Ok(())
    }

    /// Iterate `(key, value)` pairs in sorted key order.
    pub fn iter(&self) -> std::collections::btree_map::Iter<'_, String, String> {
        self.0.iter()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn contains_key(&self, k: &str) -> bool {
        self.0.contains_key(k)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub vendor: String,
    pub product: String,
    pub version: String,
    pub event_id: String,
    pub name: String,
    /// 0..=10 (CEF). Higher values yield a `SeverityOutOfRange` at format
    /// time so a buggy caller (e.g. one that funnels a CVSS or HTTP status)
    /// gets a loud error instead of silent saturation to "10".
    pub severity: u8,
    pub extensions: ExtensionMap,
}

pub fn format_cef(ev: &SecurityEvent) -> Result<String, FormatError> {
    if ev.severity > 10 {
        return Err(FormatError::SeverityOutOfRange(ev.severity));
    }
    let mut ext = String::new();
    for (k, v) in ev.extensions.iter() {
        // Defensive: keys can only be inserted via ExtensionMap::insert which
        // already validates. Re-check on emit so a future field added that
        // bypasses the wrapper still cannot inject.
        if !is_valid_ext_key(k) {
            return Err(FormatError::InvalidExtensionKey(k.clone()));
        }
        if !ext.is_empty() {
            ext.push(' ');
        }
        ext.push_str(k);
        ext.push('=');
        ext.push_str(&escape_cef_ext_value(v));
    }
    Ok(format!(
        "CEF:0|{}|{}|{}|{}|{}|{}|{}",
        escape_siem(&ev.vendor),
        escape_siem(&ev.product),
        escape_siem(&ev.version),
        escape_siem(&ev.event_id),
        escape_siem(&ev.name),
        ev.severity,
        ext
    ))
}

pub fn format_leef(ev: &SecurityEvent) -> Result<String, FormatError> {
    if ev.severity > 10 {
        return Err(FormatError::SeverityOutOfRange(ev.severity));
    }
    let delim = '\t';
    let mut ext = String::new();
    let mut first = true;
    let caller_set_sev = ev.extensions.contains_key("sev");
    for (k, v) in ev.extensions.iter() {
        if !is_valid_ext_key(k) {
            return Err(FormatError::InvalidExtensionKey(k.clone()));
        }
        if !first {
            ext.push(delim);
        }
        first = false;
        ext.push_str(k);
        ext.push('=');
        ext.push_str(&escape_leef_value(v, delim));
    }
    if !caller_set_sev {
        if !first {
            ext.push(delim);
        }
        ext.push_str("sev=");
        ext.push_str(&ev.severity.to_string());
    }

    Ok(format!(
        "LEEF:2.0|{}|{}|{}|{}|^|{}",
        escape_siem(&ev.vendor),
        escape_siem(&ev.product),
        escape_siem(&ev.version),
        escape_siem(&ev.event_id),
        ext
    ))
}
