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

fn cef_escape_header(s: &str) -> String {
    s.replace('\\', r"\\").replace('|', r"\|")
}

fn cef_escape_ext_value(s: &str) -> String {
    s.replace('\\', r"\\").replace('=', r"\=").replace('\n', r"\n").replace('\r', r"\r")
}

pub fn format_cef(ev: &SecurityEvent) -> String {
    let mut ext = String::new();
    for (k, v) in &ev.extensions {
        if !ext.is_empty() { ext.push(' '); }
        ext.push_str(k);
        ext.push('=');
        ext.push_str(&cef_escape_ext_value(v));
    }
    format!(
        "CEF:0|{}|{}|{}|{}|{}|{}|{}",
        cef_escape_header(&ev.vendor),
        cef_escape_header(&ev.product),
        cef_escape_header(&ev.version),
        cef_escape_header(&ev.event_id),
        cef_escape_header(&ev.name),
        ev.severity.min(10),
        ext
    )
}

fn leef_escape(s: &str, delim: char) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '\\' || c == delim { out.push('\\'); }
        out.push(c);
    }
    out
}

pub fn format_leef(ev: &SecurityEvent) -> String {
    let delim = '\t';
    let mut ext = String::new();
    let mut first = true;
    for (k, v) in &ev.extensions {
        if !first { ext.push(delim); }
        first = false;
        ext.push_str(k);
        ext.push('=');
        ext.push_str(&leef_escape(v, delim));
    }
    if !first { ext.push(delim); }
    ext.push_str("sev=");
    ext.push_str(&ev.severity.to_string());

    format!(
        "LEEF:2.0|{}|{}|{}|{}|^|{}",
        leef_escape(&ev.vendor, '|'),
        leef_escape(&ev.product, '|'),
        leef_escape(&ev.version, '|'),
        leef_escape(&ev.event_id, '|'),
        ext
    )
}
