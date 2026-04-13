//! SAML Service Provider consumer (J7).
//!
//! Parses base64-encoded SAML 2.0 Response messages, performs structural
//! validation, extracts attributes, and rejects assertions that lack a
//! signature or whose conditions are violated. Signature *verification* is
//! delegated to a pluggable verifier so the crate can run unit tests without
//! pulling in the full xmlsec stack on every build.
#![forbid(unsafe_code)]

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SamlError {
    #[error("base64: {0}")]
    Base64(String),
    #[error("xml: {0}")]
    Xml(String),
    #[error("missing signature — unsigned assertions are forbidden")]
    UnsignedRejected,
    #[error("audience mismatch: got {0}, expected {1}")]
    AudienceMismatch(String, String),
    #[error("not on or after expired ({0} <= now {1})")]
    Expired(i64, i64),
    #[error("verifier rejected signature")]
    SignatureInvalid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAssertion {
    pub issuer: String,
    pub subject: String,
    pub audience: String,
    pub not_on_or_after: i64,
    pub attributes: HashMap<String, Vec<String>>,
    pub has_signature: bool,
}

pub trait SignatureVerifier: Send + Sync {
    fn verify(&self, xml: &[u8]) -> Result<(), SamlError>;
}

/// A verifier that always accepts — for tests only. Wire a real xmlsec-backed
/// verifier in production.
pub struct AlwaysAcceptVerifier;
impl SignatureVerifier for AlwaysAcceptVerifier {
    fn verify(&self, _: &[u8]) -> Result<(), SamlError> {
        Ok(())
    }
}

pub fn parse_response_b64(b64: &str) -> Result<Vec<u8>, SamlError> {
    STANDARD.decode(b64.trim()).map_err(|e| SamlError::Base64(e.to_string()))
}

/// Extract an assertion from a SAML Response XML byte slice.
/// Implementation note: uses `quick-xml` element scanning (not full schema
/// parsing) — sufficient for the attribute extraction needs of an SP.
pub fn extract_assertion(xml: &[u8]) -> Result<SamlAssertion, SamlError> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    let mut issuer = String::new();
    let mut subject = String::new();
    let mut audience = String::new();
    let mut not_on_or_after = 0i64;
    let mut attrs: HashMap<String, Vec<String>> = HashMap::new();
    let mut has_signature = false;
    let mut current_attr: Option<String> = None;
    let mut state = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let local = name.rsplit(':').next().unwrap_or("").to_string();
                state = local.clone();
                if local == "Signature" {
                    has_signature = true;
                }
                if local == "Attribute" {
                    for a in e.attributes().flatten() {
                        let key = String::from_utf8_lossy(a.key.as_ref()).to_string();
                        if key.ends_with("Name") {
                            current_attr = Some(String::from_utf8_lossy(&a.value).to_string());
                        }
                    }
                }
                if local == "Conditions" {
                    for a in e.attributes().flatten() {
                        if a.key.as_ref() == b"NotOnOrAfter" {
                            let s = String::from_utf8_lossy(&a.value).to_string();
                            not_on_or_after = parse_iso(&s);
                        }
                    }
                }
            }
            Ok(Event::Text(t)) => {
                let txt = t.unescape().map_err(|e| SamlError::Xml(e.to_string()))?.to_string();
                match state.as_str() {
                    "Issuer" if issuer.is_empty() => issuer = txt,
                    "NameID" if subject.is_empty() => subject = txt,
                    "Audience" if audience.is_empty() => audience = txt,
                    "AttributeValue" => {
                        if let Some(name) = &current_attr {
                            attrs.entry(name.clone()).or_default().push(txt);
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::End(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let local = name.rsplit(':').next().unwrap_or("");
                if local == "Attribute" {
                    current_attr = None;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(SamlError::Xml(e.to_string())),
            _ => {}
        }
        buf.clear();
    }

    Ok(SamlAssertion {
        issuer,
        subject,
        audience,
        not_on_or_after,
        attributes: attrs,
        has_signature,
    })
}

fn parse_iso(s: &str) -> i64 {
    // Best-effort RFC3339 → epoch. Avoids pulling chrono.
    // Accepts YYYY-MM-DDTHH:MM:SSZ
    let parts: Vec<&str> = s.trim_end_matches('Z').split(['-', 'T', ':']).collect();
    if parts.len() < 6 {
        return 0;
    }
    let y: i64 = parts[0].parse().unwrap_or(0);
    let mo: i64 = parts[1].parse().unwrap_or(0);
    let d: i64 = parts[2].parse().unwrap_or(0);
    let h: i64 = parts[3].parse().unwrap_or(0);
    let mi: i64 = parts[4].parse().unwrap_or(0);
    let se: i64 = parts[5].split('.').next().unwrap_or("0").parse().unwrap_or(0);
    let days_from_year = (y - 1970) * 365 + ((y - 1969) / 4);
    let mdays = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut day_of_year = 0i64;
    for i in 0..(mo - 1) as usize {
        day_of_year += mdays[i];
    }
    day_of_year += d - 1;
    (days_from_year + day_of_year) * 86400 + h * 3600 + mi * 60 + se
}

pub fn validate(
    assertion: &SamlAssertion,
    expected_audience: &str,
    now: i64,
    verifier: &dyn SignatureVerifier,
    raw_xml: &[u8],
) -> Result<(), SamlError> {
    if !assertion.has_signature {
        return Err(SamlError::UnsignedRejected);
    }
    if assertion.audience != expected_audience {
        return Err(SamlError::AudienceMismatch(
            assertion.audience.clone(),
            expected_audience.to_string(),
        ));
    }
    if assertion.not_on_or_after != 0 && assertion.not_on_or_after <= now {
        return Err(SamlError::Expired(assertion.not_on_or_after, now));
    }
    verifier.verify(raw_xml)?;
    Ok(())
}
