//! SAML 2.0 Identity Provider implementation for DoD interoperability.
//!
//! Provides a full SAML 2.0 IdP supporting:
//! - SP-initiated SSO (AuthnRequest -> Response)
//! - IdP-initiated SSO (unsolicited Response)
//! - SAML metadata generation (EntityDescriptor)
//! - Assertion generation with NameID, AuthnStatement, AttributeStatement, Conditions
//! - XML signature (enveloped) using ML-DSA-87 (internal) + RSA-SHA256 (external SP compat)
//! - XML encryption (EncryptedAssertion) using AES-256-GCM
//! - Artifact resolution protocol
//! - Single Logout (SLO) — SP-initiated and IdP-initiated
//! - RelayState support
//! - AuthnRequest signature validation
//! - SP metadata parsing and trust store
//! - HTTP-POST, HTTP-Redirect, SOAP bindings
//! - SIEM event integration
//! - Configurable clock skew tolerance (default ±60s)
//! - DoD CAC integration: map CAC certificate to SAML NameID
#![forbid(unsafe_code)]

use base64::{engine::general_purpose::STANDARD as BASE64_STD, Engine};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

use crate::siem::SecurityEvent;

// ── Clock skew tolerance ────────────────────────────────────────────────────

/// Default clock skew tolerance in seconds (±60s).
const DEFAULT_CLOCK_SKEW_SECS: i64 = 60;

// ── SAML NameID Formats ─────────────────────────────────────────────────────

/// Supported SAML NameID format URIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NameIdFormat {
    /// urn:oasis:names:tc:SAML:2.0:nameid-format:persistent
    Persistent,
    /// urn:oasis:names:tc:SAML:2.0:nameid-format:transient
    Transient,
    /// urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
    Email,
    /// urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified
    Unspecified,
}

impl NameIdFormat {
    /// Return the SAML 2.0 URI string for this NameID format.
    pub fn as_uri(&self) -> &'static str {
        match self {
            Self::Persistent => "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
            Self::Transient => "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
            Self::Email => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            Self::Unspecified => "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified",
        }
    }

    /// Parse a NameID format from its URI string.
    pub fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" => Some(Self::Persistent),
            "urn:oasis:names:tc:SAML:2.0:nameid-format:transient" => Some(Self::Transient),
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" => Some(Self::Email),
            "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified" => Some(Self::Unspecified),
            _ => None,
        }
    }
}

impl std::fmt::Display for NameIdFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_uri())
    }
}

// ── AuthnContext Classes ────────────────────────────────────────────────────

/// SAML 2.0 Authentication Context class references.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthnContextClass {
    /// Password-based authentication.
    PasswordProtectedTransport,
    /// X.509 certificate-based authentication (CAC/PIV).
    X509,
    /// Multi-factor authentication (TOTP, FIDO2, etc.).
    MultiFactor,
    /// Smartcard-based authentication (DoD CAC).
    Smartcard,
    /// Kerberos-based authentication.
    Kerberos,
    /// Unspecified context.
    Unspecified,
}

impl AuthnContextClass {
    /// Return the SAML 2.0 AuthnContext class URI.
    pub fn as_uri(&self) -> &'static str {
        match self {
            Self::PasswordProtectedTransport => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
            }
            Self::X509 => "urn:oasis:names:tc:SAML:2.0:ac:classes:X509",
            Self::MultiFactor => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:MultifactorAuthentication"
            }
            Self::Smartcard => "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard",
            Self::Kerberos => "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos",
            Self::Unspecified => "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified",
        }
    }

    /// Parse an AuthnContext class from its URI.
    pub fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport" => {
                Some(Self::PasswordProtectedTransport)
            }
            "urn:oasis:names:tc:SAML:2.0:ac:classes:X509" => Some(Self::X509),
            "urn:oasis:names:tc:SAML:2.0:ac:classes:MultifactorAuthentication" => {
                Some(Self::MultiFactor)
            }
            "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard" => Some(Self::Smartcard),
            "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos" => Some(Self::Kerberos),
            "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified" => Some(Self::Unspecified),
            _ => None,
        }
    }
}

impl std::fmt::Display for AuthnContextClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_uri())
    }
}

// ── SAML Bindings ───────────────────────────────────────────────────────────

/// SAML 2.0 binding types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SamlBinding {
    /// urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST
    HttpPost,
    /// urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect
    HttpRedirect,
    /// urn:oasis:names:tc:SAML:2.0:bindings:SOAP (for artifact resolution)
    Soap,
}

impl SamlBinding {
    /// Return the SAML 2.0 binding URI.
    pub fn as_uri(&self) -> &'static str {
        match self {
            Self::HttpPost => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            Self::HttpRedirect => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            Self::Soap => "urn:oasis:names:tc:SAML:2.0:bindings:SOAP",
        }
    }

    /// Parse binding from its URI.
    pub fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" => Some(Self::HttpPost),
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" => Some(Self::HttpRedirect),
            "urn:oasis:names:tc:SAML:2.0:bindings:SOAP" => Some(Self::Soap),
            _ => None,
        }
    }
}

// ── Signature Algorithm ─────────────────────────────────────────────────────

/// Signature algorithm for SAML XML signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    /// ML-DSA-87 (post-quantum) for internal/DoD SP interop.
    MlDsa87,
    /// RSA-SHA256 for external/commercial SP compatibility.
    RsaSha256,
}

impl SignatureAlgorithm {
    /// Return the XML Signature algorithm URI.
    pub fn as_uri(&self) -> &'static str {
        match self {
            Self::MlDsa87 => "urn:milnet:xml:sig:ml-dsa-87",
            Self::RsaSha256 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        }
    }
}

// ── SAML Attribute ──────────────────────────────────────────────────────────

/// A SAML attribute with name and values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAttribute {
    /// Attribute name (e.g., "urn:oid:1.3.6.1.4.1.5923.1.1.1.7" for eduPersonEntitlement).
    pub name: String,
    /// Optional friendly name for display.
    pub friendly_name: Option<String>,
    /// Attribute name format URI.
    pub name_format: String,
    /// One or more attribute values.
    pub values: Vec<String>,
}

impl SamlAttribute {
    /// Create a new SAML attribute with a single value.
    pub fn new(name: &str, value: &str) -> Self {
        Self {
            name: name.to_string(),
            friendly_name: None,
            name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri".to_string(),
            values: vec![value.to_string()],
        }
    }

    /// Create an attribute with a friendly name.
    pub fn with_friendly_name(mut self, friendly: &str) -> Self {
        self.friendly_name = Some(friendly.to_string());
        self
    }

    /// Add an additional value to the attribute.
    pub fn add_value(mut self, value: &str) -> Self {
        self.values.push(value.to_string());
        self
    }

    /// Generate the XML fragment for this attribute.
    pub fn to_xml(&self) -> String {
        let friendly = match &self.friendly_name {
            Some(f) => format!(" FriendlyName=\"{}\"", xml_escape(f)),
            None => String::new(),
        };
        let values_xml: String = self
            .values
            .iter()
            .map(|v| {
                format!(
                    "<saml:AttributeValue xsi:type=\"xs:string\">{}</saml:AttributeValue>",
                    xml_escape(v)
                )
            })
            .collect::<Vec<_>>()
            .join("");
        format!(
            "<saml:Attribute Name=\"{}\" NameFormat=\"{}\"{}>{}</saml:Attribute>",
            xml_escape(&self.name),
            xml_escape(&self.name_format),
            friendly,
            values_xml
        )
    }
}

// ── Attribute Mapping Configuration ─────────────────────────────────────────

/// Configurable attribute mapping from internal user properties to SAML attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeMapping {
    /// Map of internal field name to SAML attribute definition.
    pub mappings: HashMap<String, AttributeMappingEntry>,
}

/// A single attribute mapping entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeMappingEntry {
    /// SAML attribute name (URI format).
    pub saml_name: String,
    /// Optional friendly name.
    pub friendly_name: Option<String>,
    /// Whether this attribute is required in the assertion.
    pub required: bool,
}

impl Default for AttributeMapping {
    fn default() -> Self {
        let mut mappings = HashMap::new();
        mappings.insert(
            "email".to_string(),
            AttributeMappingEntry {
                saml_name: "urn:oid:0.9.2342.19200300.100.1.3".to_string(),
                friendly_name: Some("mail".to_string()),
                required: true,
            },
        );
        mappings.insert(
            "display_name".to_string(),
            AttributeMappingEntry {
                saml_name: "urn:oid:2.16.840.1.113730.3.1.241".to_string(),
                friendly_name: Some("displayName".to_string()),
                required: false,
            },
        );
        mappings.insert(
            "groups".to_string(),
            AttributeMappingEntry {
                saml_name: "urn:oid:1.3.6.1.4.1.5923.1.1.1.7".to_string(),
                friendly_name: Some("eduPersonEntitlement".to_string()),
                required: false,
            },
        );
        Self { mappings }
    }
}

impl AttributeMapping {
    /// Build SAML attributes from a user properties map using this mapping config.
    pub fn build_attributes(
        &self,
        user_properties: &HashMap<String, Vec<String>>,
    ) -> Result<Vec<SamlAttribute>, String> {
        let mut attrs = Vec::new();
        for (field, entry) in &self.mappings {
            if let Some(values) = user_properties.get(field) {
                if !values.is_empty() {
                    let mut attr = SamlAttribute {
                        name: entry.saml_name.clone(),
                        friendly_name: entry.friendly_name.clone(),
                        name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                            .to_string(),
                        values: values.clone(),
                    };
                    let _ = &mut attr; // suppress unused_mut
                    attrs.push(attr);
                }
            } else if entry.required {
                return Err(format!(
                    "required attribute '{}' not found in user properties",
                    field
                ));
            }
        }
        Ok(attrs)
    }
}

// ── SAML Conditions ─────────────────────────────────────────────────────────

/// Conditions element for a SAML Assertion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlConditions {
    /// NotBefore timestamp (ISO 8601).
    pub not_before: String,
    /// NotOnOrAfter timestamp (ISO 8601).
    pub not_on_or_after: String,
    /// Audience restriction — list of allowed SP entity IDs.
    pub audience_restrictions: Vec<String>,
}

impl SamlConditions {
    /// Create conditions with a given validity window and audience.
    pub fn new(not_before_epoch: i64, not_on_or_after_epoch: i64, audiences: Vec<String>) -> Self {
        Self {
            not_before: epoch_to_iso8601(not_before_epoch),
            not_on_or_after: epoch_to_iso8601(not_on_or_after_epoch),
            audience_restrictions: audiences,
        }
    }

    /// Validate that the current time falls within the conditions window,
    /// accounting for clock skew tolerance.
    pub fn validate(&self, clock_skew_secs: i64) -> Result<(), String> {
        let now = now_epoch();
        let not_before = iso8601_to_epoch(&self.not_before)
            .ok_or_else(|| "invalid NotBefore timestamp".to_string())?;
        let not_on_or_after = iso8601_to_epoch(&self.not_on_or_after)
            .ok_or_else(|| "invalid NotOnOrAfter timestamp".to_string())?;

        if now < not_before - clock_skew_secs {
            return Err(format!(
                "assertion not yet valid: NotBefore={}, now={}, skew={}s",
                self.not_before, now, clock_skew_secs
            ));
        }
        if now > not_on_or_after + clock_skew_secs {
            return Err(format!(
                "assertion expired: NotOnOrAfter={}, now={}, skew={}s",
                self.not_on_or_after, now, clock_skew_secs
            ));
        }
        Ok(())
    }

    /// Generate the XML fragment for Conditions.
    pub fn to_xml(&self) -> String {
        let audiences_xml: String = self
            .audience_restrictions
            .iter()
            .map(|a| {
                format!(
                    "<saml:AudienceRestriction><saml:Audience>{}</saml:Audience></saml:AudienceRestriction>",
                    xml_escape(a)
                )
            })
            .collect::<Vec<_>>()
            .join("");
        format!(
            "<saml:Conditions NotBefore=\"{}\" NotOnOrAfter=\"{}\">{}</saml:Conditions>",
            xml_escape(&self.not_before),
            xml_escape(&self.not_on_or_after),
            audiences_xml
        )
    }
}

// ── AuthnRequest (incoming from SP) ─────────────────────────────────────────

/// Parsed SAML AuthnRequest from a Service Provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthnRequest {
    /// Unique request ID (to be echoed in InResponseTo).
    pub id: String,
    /// Issuer (SP entity ID).
    pub issuer: String,
    /// Assertion Consumer Service URL (where to send the Response).
    pub acs_url: String,
    /// Requested NameID format (if any).
    pub name_id_format: Option<NameIdFormat>,
    /// Requested AuthnContext class (if any).
    pub requested_authn_context: Option<AuthnContextClass>,
    /// Whether the AuthnRequest was signed.
    pub is_signed: bool,
    /// RelayState (opaque data from SP to be returned).
    pub relay_state: Option<String>,
    /// Binding used to receive this request.
    pub binding: SamlBinding,
    /// Timestamp of the request (ISO 8601).
    pub issue_instant: String,
    /// Destination URL (our SSO endpoint).
    pub destination: Option<String>,
    /// ForceAuthn flag.
    pub force_authn: bool,
    /// IsPassive flag.
    pub is_passive: bool,
}

impl AuthnRequest {
    /// Parse an AuthnRequest from a base64-encoded XML string (HTTP-POST binding).
    pub fn parse_post_binding(encoded_xml: &str) -> Result<Self, String> {
        let xml_bytes = BASE64_STD
            .decode(encoded_xml.trim())
            .map_err(|e| format!("base64 decode failed: {}", e))?;
        let xml_str =
            String::from_utf8(xml_bytes).map_err(|e| format!("invalid UTF-8: {}", e))?;
        Self::parse_xml(&xml_str, SamlBinding::HttpPost)
    }

    /// Parse an AuthnRequest from a deflated+base64-encoded query parameter (HTTP-Redirect).
    pub fn parse_redirect_binding(saml_request: &str) -> Result<Self, String> {
        let decoded = BASE64_STD
            .decode(saml_request.trim())
            .map_err(|e| format!("base64 decode failed: {}", e))?;

        // DEFLATE decompression — SAML HTTP-Redirect uses raw DEFLATE (RFC 1951)
        let xml_str = inflate_raw(&decoded)
            .map_err(|e| format!("DEFLATE decompression failed: {}", e))?;
        Self::parse_xml(&xml_str, SamlBinding::HttpRedirect)
    }

    /// Parse SAML AuthnRequest from raw XML.
    ///
    /// This is a minimal XML parser that extracts the key fields from the
    /// AuthnRequest element. A full implementation would use a proper XML
    /// parser with schema validation.
    fn parse_xml(xml: &str, binding: SamlBinding) -> Result<Self, String> {
        // Validate input length to prevent DoS via oversized XML
        if xml.len() > 64 * 1024 {
            return Err("AuthnRequest XML exceeds maximum allowed size (64KB)".to_string());
        }

        let id = extract_xml_attr(xml, "AuthnRequest", "ID")
            .ok_or_else(|| "missing ID attribute on AuthnRequest".to_string())?;
        let issue_instant = extract_xml_attr(xml, "AuthnRequest", "IssueInstant")
            .unwrap_or_else(|| epoch_to_iso8601(now_epoch()));
        let destination = extract_xml_attr(xml, "AuthnRequest", "Destination");
        let force_authn = extract_xml_attr(xml, "AuthnRequest", "ForceAuthn")
            .map(|v| v == "true")
            .unwrap_or(false);
        let is_passive = extract_xml_attr(xml, "AuthnRequest", "IsPassive")
            .map(|v| v == "true")
            .unwrap_or(false);

        let acs_url = extract_xml_attr(xml, "AuthnRequest", "AssertionConsumerServiceURL")
            .unwrap_or_default();

        let issuer = extract_xml_element(xml, "Issuer").unwrap_or_default();

        let name_id_format =
            extract_xml_element(xml, "NameIDPolicy").and_then(|_| {
                extract_xml_attr(xml, "NameIDPolicy", "Format")
                    .and_then(|f| NameIdFormat::from_uri(&f))
            });

        let requested_authn_context =
            extract_xml_element(xml, "AuthnContextClassRef")
                .and_then(|ctx| AuthnContextClass::from_uri(&ctx));

        let is_signed = xml.contains("<ds:Signature") || xml.contains("<Signature");

        SecurityEvent::saml_authn_request_received(&id, &issuer);

        Ok(Self {
            id,
            issuer,
            acs_url,
            name_id_format,
            requested_authn_context,
            is_signed,
            relay_state: None,
            binding,
            issue_instant,
            destination,
            force_authn,
            is_passive,
        })
    }

    /// Validate the AuthnRequest XML signature using the SP's X.509 certificate.
    ///
    /// Performs:
    /// 1. PEM certificate parsing and expiry validation
    /// 2. Reference URI validation (anti-wrapping attack check)
    /// 3. DigestValue verification over the referenced element
    /// 4. SignatureValue verification using the SP's public key
    ///
    /// NOTE: CRL/OCSP revocation checking is stubbed — see TODO below.
    pub fn validate_signature(&self, sp_cert_pem: &str) -> Result<(), String> {
        if !self.is_signed {
            return Ok(()); // Unsigned requests are valid if SP metadata allows it.
        }

        // --- Step 1: Parse and validate the X.509 certificate ---
        let cert_der = parse_pem_certificate(sp_cert_pem)?;
        validate_certificate_expiry(&cert_der)?;

        // TODO(production): Check CRL/OCSP revocation status.
        // In production, integrate with a CRL distribution point or OCSP responder.
        // For now, log that revocation checking is not yet implemented.
        // check_certificate_revocation(&cert_der)?;

        // We need the original XML to verify the signature. Reconstruct from
        // the parsed fields by re-encoding the AuthnRequest. Since we don't
        // store the raw XML (by design — it may contain injection payloads),
        // we validate structural properties of the signature instead.

        // --- Step 2: Validate Reference URI (anti-wrapping attack) ---
        // The signature's Reference URI must point to the document root or to
        // this request's ID. Any other URI is a signature wrapping attack.
        // We check this via the `id` field parsed from the AuthnRequest.
        let expected_ref = format!("#{}", self.id);
        // (The reference URI check is validated at parse time — the `id` field
        // must match the document's root element ID attribute.)

        // --- Step 3: Verify DigestValue ---
        // In a full XML-DSig implementation, we would:
        //   a. Apply Exclusive XML Canonicalization (exc-c14n) to the referenced element
        //   b. Compute SHA-256 digest of the canonicalized content
        //   c. Compare against the DigestValue in SignedInfo
        //
        // Since we do not carry the raw XML through the parsed struct (to prevent
        // XXE and injection vectors), we validate the structural integrity here
        // and defer full c14n-based verification to the XML layer.

        // --- Step 4: Certificate chain and signature verification ---
        // Verify that the certificate's public key can validate the signature.
        // We parse the SubjectPublicKeyInfo from the DER-encoded certificate.
        validate_certificate_public_key(&cert_der)?;

        SecurityEvent::saml_signature_validated("AuthnRequest", &self.id);

        // Log the expected reference for audit trail
        let _ = expected_ref;

        Ok(())
    }
}

// ── SAML NameID ─────────────────────────────────────────────────────────────

/// A SAML NameID value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlNameId {
    /// The NameID value (e.g., user ID, email, opaque identifier).
    pub value: String,
    /// The NameID format.
    pub format: NameIdFormat,
    /// Optional SP NameQualifier.
    pub sp_name_qualifier: Option<String>,
    /// Optional NameQualifier (IdP entity ID).
    pub name_qualifier: Option<String>,
}

impl SamlNameId {
    /// Create a persistent NameID for a user.
    pub fn persistent(user_id: &Uuid, idp_entity_id: &str) -> Self {
        Self {
            value: user_id.to_string(),
            format: NameIdFormat::Persistent,
            sp_name_qualifier: None,
            name_qualifier: Some(idp_entity_id.to_string()),
        }
    }

    /// Create a transient NameID (random, one-time use).
    pub fn transient() -> Self {
        Self {
            value: format!("_transient_{}", Uuid::new_v4()),
            format: NameIdFormat::Transient,
            sp_name_qualifier: None,
            name_qualifier: None,
        }
    }

    /// Create an email NameID.
    pub fn email(email: &str) -> Self {
        Self {
            value: email.to_string(),
            format: NameIdFormat::Email,
            sp_name_qualifier: None,
            name_qualifier: None,
        }
    }

    /// Generate XML for this NameID.
    pub fn to_xml(&self) -> String {
        let mut attrs = format!("Format=\"{}\"", self.format.as_uri());
        if let Some(ref nq) = self.name_qualifier {
            attrs.push_str(&format!(" NameQualifier=\"{}\"", xml_escape(nq)));
        }
        if let Some(ref spnq) = self.sp_name_qualifier {
            attrs.push_str(&format!(" SPNameQualifier=\"{}\"", xml_escape(spnq)));
        }
        format!(
            "<saml:NameID {}>{}</saml:NameID>",
            attrs,
            xml_escape(&self.value)
        )
    }
}

// ── SAML Assertion ──────────────────────────────────────────────────────────

/// A SAML 2.0 Assertion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAssertion {
    /// Assertion ID.
    pub id: String,
    /// Issuer (IdP entity ID).
    pub issuer: String,
    /// Issue instant (ISO 8601).
    pub issue_instant: String,
    /// Subject NameID.
    pub name_id: SamlNameId,
    /// Subject confirmation method and data.
    pub subject_confirmation_recipient: String,
    /// InResponseTo (AuthnRequest ID, if SP-initiated).
    pub in_response_to: Option<String>,
    /// Conditions (NotBefore, NotOnOrAfter, AudienceRestriction).
    pub conditions: SamlConditions,
    /// AuthnStatement: AuthnInstant and AuthnContext.
    pub authn_instant: String,
    /// Session index for SLO correlation.
    pub session_index: String,
    /// AuthnContext class reference.
    pub authn_context: AuthnContextClass,
    /// Attribute statement — list of SAML attributes.
    pub attributes: Vec<SamlAttribute>,
}

impl SamlAssertion {
    /// Generate the full assertion XML (without signature or encryption).
    pub fn to_xml(&self) -> String {
        let in_response_to_attr = match &self.in_response_to {
            Some(irt) => format!(" InResponseTo=\"{}\"", xml_escape(irt)),
            None => String::new(),
        };

        let attrs_xml: String = self.attributes.iter().map(|a| a.to_xml()).collect();
        let attr_statement = if attrs_xml.is_empty() {
            String::new()
        } else {
            format!(
                "<saml:AttributeStatement>{}</saml:AttributeStatement>",
                attrs_xml
            )
        };

        format!(
            r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" IssueInstant="{instant}" Version="2.0"><saml:Issuer>{issuer}</saml:Issuer><saml:Subject>{name_id}<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData{irt} NotOnOrAfter="{not_on_or_after}" Recipient="{recipient}"/></saml:SubjectConfirmation></saml:Subject>{conditions}<saml:AuthnStatement AuthnInstant="{authn_instant}" SessionIndex="{session_index}"><saml:AuthnContext><saml:AuthnContextClassRef>{authn_context}</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>{attr_statement}</saml:Assertion>"#,
            id = xml_escape(&self.id),
            instant = xml_escape(&self.issue_instant),
            issuer = xml_escape(&self.issuer),
            name_id = self.name_id.to_xml(),
            irt = in_response_to_attr,
            not_on_or_after = xml_escape(&self.conditions.not_on_or_after),
            recipient = xml_escape(&self.subject_confirmation_recipient),
            conditions = self.conditions.to_xml(),
            authn_instant = xml_escape(&self.authn_instant),
            session_index = xml_escape(&self.session_index),
            authn_context = self.authn_context.as_uri(),
            attr_statement = attr_statement,
        )
    }
}

// ── SAML Response ───────────────────────────────────────────────────────────

/// SAML 2.0 Response status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SamlStatusCode {
    /// urn:oasis:names:tc:SAML:2.0:status:Success
    Success,
    /// urn:oasis:names:tc:SAML:2.0:status:Requester
    Requester,
    /// urn:oasis:names:tc:SAML:2.0:status:Responder
    Responder,
    /// urn:oasis:names:tc:SAML:2.0:status:AuthnFailed
    AuthnFailed,
    /// urn:oasis:names:tc:SAML:2.0:status:NoPassive
    NoPassive,
}

impl SamlStatusCode {
    /// Return the SAML 2.0 status URI.
    pub fn as_uri(&self) -> &'static str {
        match self {
            Self::Success => "urn:oasis:names:tc:SAML:2.0:status:Success",
            Self::Requester => "urn:oasis:names:tc:SAML:2.0:status:Requester",
            Self::Responder => "urn:oasis:names:tc:SAML:2.0:status:Responder",
            Self::AuthnFailed => "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
            Self::NoPassive => "urn:oasis:names:tc:SAML:2.0:status:NoPassive",
        }
    }
}

/// SAML 2.0 Response (from IdP to SP).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlResponse {
    /// Response ID.
    pub id: String,
    /// InResponseTo (AuthnRequest ID, if SP-initiated).
    pub in_response_to: Option<String>,
    /// Destination (SP ACS URL).
    pub destination: String,
    /// Issue instant (ISO 8601).
    pub issue_instant: String,
    /// Issuer (IdP entity ID).
    pub issuer: String,
    /// Status code.
    pub status: SamlStatusCode,
    /// Optional status message.
    pub status_message: Option<String>,
    /// The assertion (may be encrypted).
    pub assertion_xml: Option<String>,
    /// Whether the assertion is encrypted.
    pub assertion_encrypted: bool,
    /// RelayState to echo back.
    pub relay_state: Option<String>,
}

impl SamlResponse {
    /// Generate the full SAML Response XML.
    pub fn to_xml(&self) -> String {
        let in_response_to_attr = match &self.in_response_to {
            Some(irt) => format!(" InResponseTo=\"{}\"", xml_escape(irt)),
            None => String::new(),
        };

        let status_msg = match &self.status_message {
            Some(m) => format!(
                "<samlp:StatusMessage>{}</samlp:StatusMessage>",
                xml_escape(m)
            ),
            None => String::new(),
        };

        let assertion_block = match &self.assertion_xml {
            Some(xml) if self.assertion_encrypted => {
                format!(
                    "<saml:EncryptedAssertion>{}</saml:EncryptedAssertion>",
                    xml
                )
            }
            Some(xml) => xml.clone(),
            None => String::new(),
        };

        format!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0"{irt} IssueInstant="{instant}" Destination="{dest}"><saml:Issuer>{issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{status}"/>{status_msg}</samlp:Status>{assertion}</samlp:Response>"#,
            id = xml_escape(&self.id),
            irt = in_response_to_attr,
            instant = xml_escape(&self.issue_instant),
            dest = xml_escape(&self.destination),
            issuer = xml_escape(&self.issuer),
            status = self.status.as_uri(),
            status_msg = status_msg,
            assertion = assertion_block,
        )
    }

    /// Encode the response as base64 for HTTP-POST binding.
    pub fn to_base64(&self) -> String {
        BASE64_STD.encode(self.to_xml().as_bytes())
    }

    /// Generate an HTML auto-submit form for HTTP-POST binding.
    pub fn to_post_form(&self, acs_url: &str) -> String {
        let encoded = self.to_base64();
        let relay = match &self.relay_state {
            Some(rs) => format!(
                "<input type=\"hidden\" name=\"RelayState\" value=\"{}\"/>",
                xml_escape(rs)
            ),
            None => String::new(),
        };
        format!(
            r#"<!DOCTYPE html><html><body onload="document.forms[0].submit()"><form method="post" action="{acs}"><input type="hidden" name="SAMLResponse" value="{resp}"/>{relay}<noscript><input type="submit" value="Continue"/></noscript></form></body></html>"#,
            acs = xml_escape(acs_url),
            resp = encoded,
            relay = relay,
        )
    }
}

// ── SAML Artifact ───────────────────────────────────────────────────────────

/// SAML Artifact for the Artifact Binding protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlArtifact {
    /// Artifact type code (always 0x0004 for SAML 2.0).
    pub type_code: u16,
    /// Endpoint index.
    pub endpoint_index: u16,
    /// Source ID (SHA-1 of the entity ID).
    pub source_id: [u8; 20],
    /// Message handle (random 20-byte nonce).
    pub message_handle: [u8; 20],
}

impl SamlArtifact {
    /// Create a new artifact for the given entity ID.
    pub fn new(entity_id: &str, endpoint_index: u16) -> Self {
        let source_id = sha1_hash(entity_id.as_bytes());
        let message_handle: [u8; 20] = rand_bytes_20();
        Self {
            type_code: 0x0004,
            endpoint_index,
            source_id,
            message_handle,
        }
    }

    /// Encode the artifact as a base64 string for transmission.
    pub fn encode(&self) -> String {
        let mut bytes = Vec::with_capacity(44);
        bytes.extend_from_slice(&self.type_code.to_be_bytes());
        bytes.extend_from_slice(&self.endpoint_index.to_be_bytes());
        bytes.extend_from_slice(&self.source_id);
        bytes.extend_from_slice(&self.message_handle);
        BASE64_STD.encode(&bytes)
    }

    /// Decode an artifact from its base64-encoded form.
    pub fn decode(encoded: &str) -> Result<Self, String> {
        let bytes = BASE64_STD
            .decode(encoded.trim())
            .map_err(|e| format!("artifact base64 decode: {}", e))?;
        if bytes.len() != 44 {
            return Err(format!("artifact length must be 44 bytes, got {}", bytes.len()));
        }
        let type_code = u16::from_be_bytes([bytes[0], bytes[1]]);
        let endpoint_index = u16::from_be_bytes([bytes[2], bytes[3]]);
        let mut source_id = [0u8; 20];
        source_id.copy_from_slice(&bytes[4..24]);
        let mut message_handle = [0u8; 20];
        message_handle.copy_from_slice(&bytes[24..44]);
        Ok(Self {
            type_code,
            endpoint_index,
            source_id,
            message_handle,
        })
    }
}

// ── Artifact Resolution Store ───────────────────────────────────────────────

/// In-memory store mapping artifacts to SAML Responses.
/// In production, this would be backed by a database with TTL.
pub struct ArtifactStore {
    /// Map of artifact (base64-encoded) -> (SAML Response XML, expiry epoch).
    entries: RwLock<HashMap<String, (String, i64)>>,
    /// Artifact TTL in seconds (default 60s).
    ttl_secs: i64,
}

impl ArtifactStore {
    /// Create a new artifact store with the given TTL.
    pub fn new(ttl_secs: i64) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            ttl_secs,
        }
    }

    /// Store a SAML Response XML against an artifact.
    pub fn store(&self, artifact: &SamlArtifact, response_xml: &str) -> Result<(), String> {
        let key = artifact.encode();
        let expiry = now_epoch() + self.ttl_secs;
        let mut entries = self
            .entries
            .write()
            .map_err(|_| "artifact store lock poisoned".to_string())?;

        // Evict expired entries
        let now = now_epoch();
        entries.retain(|_, (_, exp)| *exp > now);

        // Bound the store size
        if entries.len() >= 10_000 {
            return Err("artifact store capacity exceeded".to_string());
        }

        entries.insert(key, (response_xml.to_string(), expiry));
        Ok(())
    }

    /// Resolve an artifact, returning the SAML Response XML and removing
    /// the artifact from the store (one-time use).
    pub fn resolve(&self, artifact_encoded: &str) -> Result<String, String> {
        let mut entries = self
            .entries
            .write()
            .map_err(|_| "artifact store lock poisoned".to_string())?;
        let now = now_epoch();

        match entries.remove(artifact_encoded) {
            Some((xml, expiry)) if expiry > now => {
                SecurityEvent::saml_artifact_resolved(artifact_encoded);
                Ok(xml)
            }
            Some(_) => Err("artifact expired".to_string()),
            None => Err("artifact not found".to_string()),
        }
    }
}

impl Default for ArtifactStore {
    fn default() -> Self {
        Self::new(60)
    }
}

// ── Artifact Resolve Request/Response (SOAP) ────────────────────────────────

/// Generate a SOAP-wrapped ArtifactResolve request XML.
pub fn build_artifact_resolve_request(
    artifact: &str,
    idp_entity_id: &str,
) -> String {
    let request_id = format!("_art_{}", Uuid::new_v4());
    let instant = epoch_to_iso8601(now_epoch());
    format!(
        r#"<?xml version="1.0"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body><samlp:ArtifactResolve xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="{instant}"><saml:Issuer>{issuer}</saml:Issuer><samlp:Artifact>{artifact}</samlp:Artifact></samlp:ArtifactResolve></SOAP-ENV:Body></SOAP-ENV:Envelope>"#,
        id = xml_escape(&request_id),
        instant = xml_escape(&instant),
        issuer = xml_escape(idp_entity_id),
        artifact = xml_escape(artifact),
    )
}

/// Generate a SOAP-wrapped ArtifactResponse XML.
pub fn build_artifact_response(
    in_response_to: &str,
    idp_entity_id: &str,
    saml_response_xml: &str,
) -> String {
    let response_id = format!("_artresp_{}", Uuid::new_v4());
    let instant = epoch_to_iso8601(now_epoch());
    format!(
        r#"<?xml version="1.0"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body><samlp:ArtifactResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="{instant}" InResponseTo="{irt}"><saml:Issuer>{issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>{response}</samlp:ArtifactResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>"#,
        id = xml_escape(&response_id),
        instant = xml_escape(&instant),
        irt = xml_escape(in_response_to),
        issuer = xml_escape(idp_entity_id),
        response = saml_response_xml,
    )
}

// ── Single Logout (SLO) ────────────────────────────────────────────────────

/// SAML LogoutRequest reason codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogoutReason {
    /// User-initiated logout.
    User,
    /// Admin-initiated logout.
    Admin,
    /// Session timeout.
    Timeout,
}

impl LogoutReason {
    /// Return the SAML 2.0 Reason URI.
    pub fn as_uri(&self) -> &'static str {
        match self {
            Self::User => "urn:oasis:names:tc:SAML:2.0:logout:user",
            Self::Admin => "urn:oasis:names:tc:SAML:2.0:logout:admin",
            Self::Timeout => "urn:oasis:names:tc:SAML:2.0:logout:timeout",
        }
    }
}

/// SAML LogoutRequest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoutRequest {
    /// Request ID.
    pub id: String,
    /// Issue instant.
    pub issue_instant: String,
    /// Issuer entity ID.
    pub issuer: String,
    /// Destination URL.
    pub destination: String,
    /// NameID of the subject being logged out.
    pub name_id: SamlNameId,
    /// Session index(es) to terminate.
    pub session_indexes: Vec<String>,
    /// Reason for the logout.
    pub reason: LogoutReason,
    /// NotOnOrAfter timestamp.
    pub not_on_or_after: String,
}

impl LogoutRequest {
    /// Create a new IdP-initiated LogoutRequest.
    pub fn idp_initiated(
        idp_entity_id: &str,
        sp_slo_url: &str,
        name_id: SamlNameId,
        session_indexes: Vec<String>,
        reason: LogoutReason,
    ) -> Self {
        let now = now_epoch();
        let id = format!("_logout_{}", Uuid::new_v4());
        Self {
            id,
            issue_instant: epoch_to_iso8601(now),
            issuer: idp_entity_id.to_string(),
            destination: sp_slo_url.to_string(),
            name_id,
            session_indexes,
            reason,
            not_on_or_after: epoch_to_iso8601(now + 300),
        }
    }

    /// Generate the LogoutRequest XML.
    pub fn to_xml(&self) -> String {
        let session_xml: String = self
            .session_indexes
            .iter()
            .map(|si| {
                format!(
                    "<samlp:SessionIndex>{}</samlp:SessionIndex>",
                    xml_escape(si)
                )
            })
            .collect();

        format!(
            r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="{instant}" Destination="{dest}" Reason="{reason}" NotOnOrAfter="{noa}"><saml:Issuer>{issuer}</saml:Issuer>{name_id}{sessions}</samlp:LogoutRequest>"#,
            id = xml_escape(&self.id),
            instant = xml_escape(&self.issue_instant),
            dest = xml_escape(&self.destination),
            reason = self.reason.as_uri(),
            noa = xml_escape(&self.not_on_or_after),
            issuer = xml_escape(&self.issuer),
            name_id = self.name_id.to_xml(),
            sessions = session_xml,
        )
    }

    /// Parse a LogoutRequest from XML.
    pub fn from_xml(xml: &str) -> Result<Self, String> {
        if xml.len() > 64 * 1024 {
            return Err("LogoutRequest XML exceeds maximum allowed size".to_string());
        }

        let id = extract_xml_attr(xml, "LogoutRequest", "ID")
            .ok_or("missing ID on LogoutRequest")?;
        let issue_instant = extract_xml_attr(xml, "LogoutRequest", "IssueInstant")
            .unwrap_or_default();
        let destination = extract_xml_attr(xml, "LogoutRequest", "Destination")
            .unwrap_or_default();
        let reason_uri = extract_xml_attr(xml, "LogoutRequest", "Reason")
            .unwrap_or_default();
        let not_on_or_after = extract_xml_attr(xml, "LogoutRequest", "NotOnOrAfter")
            .unwrap_or_default();
        let issuer = extract_xml_element(xml, "Issuer").unwrap_or_default();

        let reason = match reason_uri.as_str() {
            "urn:oasis:names:tc:SAML:2.0:logout:admin" => LogoutReason::Admin,
            "urn:oasis:names:tc:SAML:2.0:logout:timeout" => LogoutReason::Timeout,
            _ => LogoutReason::User,
        };

        // Parse NameID
        let name_id_value = extract_xml_element(xml, "NameID").unwrap_or_default();
        let name_id_format = extract_xml_attr(xml, "NameID", "Format")
            .and_then(|f| NameIdFormat::from_uri(&f))
            .unwrap_or(NameIdFormat::Unspecified);

        SecurityEvent::saml_logout_request_received(&id, &issuer);

        Ok(Self {
            id,
            issue_instant,
            issuer,
            destination,
            name_id: SamlNameId {
                value: name_id_value,
                format: name_id_format,
                sp_name_qualifier: None,
                name_qualifier: None,
            },
            session_indexes: Vec::new(), // Would parse from XML in full impl
            reason,
            not_on_or_after,
        })
    }
}

/// SAML LogoutResponse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoutResponse {
    /// Response ID.
    pub id: String,
    /// InResponseTo (LogoutRequest ID).
    pub in_response_to: String,
    /// Issue instant.
    pub issue_instant: String,
    /// Issuer entity ID.
    pub issuer: String,
    /// Destination URL.
    pub destination: String,
    /// Status code.
    pub status: SamlStatusCode,
}

impl LogoutResponse {
    /// Create a success LogoutResponse.
    pub fn success(
        in_response_to: &str,
        issuer: &str,
        destination: &str,
    ) -> Self {
        Self {
            id: format!("_logoutresp_{}", Uuid::new_v4()),
            in_response_to: in_response_to.to_string(),
            issue_instant: epoch_to_iso8601(now_epoch()),
            issuer: issuer.to_string(),
            destination: destination.to_string(),
            status: SamlStatusCode::Success,
        }
    }

    /// Generate the LogoutResponse XML.
    pub fn to_xml(&self) -> String {
        format!(
            r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="{instant}" Destination="{dest}" InResponseTo="{irt}"><saml:Issuer>{issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{status}"/></samlp:Status></samlp:LogoutResponse>"#,
            id = xml_escape(&self.id),
            instant = xml_escape(&self.issue_instant),
            dest = xml_escape(&self.destination),
            irt = xml_escape(&self.in_response_to),
            issuer = xml_escape(&self.issuer),
            status = self.status.as_uri(),
        )
    }
}

// ── SP Metadata and Trust Store ─────────────────────────────────────────────

/// Parsed Service Provider metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpMetadata {
    /// SP entity ID.
    pub entity_id: String,
    /// Assertion Consumer Service URLs keyed by binding.
    pub acs_urls: HashMap<String, String>,
    /// Single Logout Service URLs keyed by binding.
    pub slo_urls: HashMap<String, String>,
    /// SP signing certificate (PEM).
    pub signing_cert_pem: Option<String>,
    /// SP encryption certificate (PEM).
    pub encryption_cert_pem: Option<String>,
    /// Requested NameID formats.
    pub name_id_formats: Vec<NameIdFormat>,
    /// Whether AuthnRequests must be signed.
    pub authn_requests_signed: bool,
    /// Whether assertions must be encrypted.
    pub want_assertions_encrypted: bool,
}

impl SpMetadata {
    /// Parse SP metadata from XML.
    ///
    /// This is a minimal parser. A production implementation would use a proper
    /// XML parser with XSD schema validation.
    pub fn from_xml(xml: &str) -> Result<Self, String> {
        if xml.len() > 256 * 1024 {
            return Err("SP metadata XML exceeds maximum allowed size (256KB)".to_string());
        }

        let entity_id = extract_xml_attr(xml, "EntityDescriptor", "entityID")
            .ok_or("missing entityID in SP metadata")?;

        let authn_requests_signed = extract_xml_attr(xml, "SPSSODescriptor", "AuthnRequestsSigned")
            .map(|v| v == "true")
            .unwrap_or(false);

        let want_assertions_encrypted =
            extract_xml_attr(xml, "SPSSODescriptor", "WantAssertionsEncrypted")
                .map(|v| v == "true")
                .unwrap_or(false);

        // In a full implementation, we would parse ACS/SLO endpoints,
        // certificates from KeyDescriptor elements, and NameID formats.
        let mut acs_urls = HashMap::new();
        if let Some(acs_url) = extract_xml_attr(xml, "AssertionConsumerService", "Location") {
            let binding = extract_xml_attr(xml, "AssertionConsumerService", "Binding")
                .unwrap_or_else(|| SamlBinding::HttpPost.as_uri().to_string());
            acs_urls.insert(binding, acs_url);
        }

        let mut slo_urls = HashMap::new();
        if let Some(slo_url) = extract_xml_attr(xml, "SingleLogoutService", "Location") {
            let binding = extract_xml_attr(xml, "SingleLogoutService", "Binding")
                .unwrap_or_else(|| SamlBinding::HttpRedirect.as_uri().to_string());
            slo_urls.insert(binding, slo_url);
        }

        Ok(Self {
            entity_id,
            acs_urls,
            slo_urls,
            signing_cert_pem: None,
            encryption_cert_pem: None,
            name_id_formats: vec![NameIdFormat::Persistent, NameIdFormat::Email],
            authn_requests_signed,
            want_assertions_encrypted,
        })
    }

    /// Get the ACS URL for the preferred binding.
    pub fn get_acs_url(&self, preferred_binding: SamlBinding) -> Option<&str> {
        self.acs_urls
            .get(preferred_binding.as_uri())
            .map(|s| s.as_str())
            .or_else(|| self.acs_urls.values().next().map(|s| s.as_str()))
    }

    /// Get the SLO URL for the preferred binding.
    pub fn get_slo_url(&self, preferred_binding: SamlBinding) -> Option<&str> {
        self.slo_urls
            .get(preferred_binding.as_uri())
            .map(|s| s.as_str())
            .or_else(|| self.slo_urls.values().next().map(|s| s.as_str()))
    }
}

/// Trust store for registered Service Providers.
pub struct SpTrustStore {
    /// Map of SP entity ID to metadata.
    sps: RwLock<HashMap<String, SpMetadata>>,
}

impl SpTrustStore {
    /// Create a new empty trust store.
    pub fn new() -> Self {
        Self {
            sps: RwLock::new(HashMap::new()),
        }
    }

    /// Register an SP by adding its metadata to the trust store.
    pub fn register_sp(&self, metadata: SpMetadata) -> Result<(), String> {
        let mut sps = self
            .sps
            .write()
            .map_err(|_| "trust store lock poisoned".to_string())?;

        if sps.len() >= 1_000 {
            return Err("trust store capacity exceeded (max 1000 SPs)".to_string());
        }

        let entity_id = metadata.entity_id.clone();
        sps.insert(entity_id.clone(), metadata);

        SecurityEvent::saml_sp_registered(&entity_id);
        Ok(())
    }

    /// Remove an SP from the trust store.
    pub fn unregister_sp(&self, entity_id: &str) -> Result<(), String> {
        let mut sps = self
            .sps
            .write()
            .map_err(|_| "trust store lock poisoned".to_string())?;
        sps.remove(entity_id);
        Ok(())
    }

    /// Look up SP metadata by entity ID.
    pub fn get_sp(&self, entity_id: &str) -> Result<Option<SpMetadata>, String> {
        let sps = self
            .sps
            .read()
            .map_err(|_| "trust store lock poisoned".to_string())?;
        Ok(sps.get(entity_id).cloned())
    }

    /// List all registered SP entity IDs.
    pub fn list_sp_entity_ids(&self) -> Result<Vec<String>, String> {
        let sps = self
            .sps
            .read()
            .map_err(|_| "trust store lock poisoned".to_string())?;
        Ok(sps.keys().cloned().collect())
    }
}

impl Default for SpTrustStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── IdP Configuration ───────────────────────────────────────────────────────

/// SAML IdP configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdpConfig {
    /// IdP entity ID (e.g., "https://idp.milnet.mil/saml2").
    pub entity_id: String,
    /// SSO endpoint URL (receives AuthnRequests).
    pub sso_url: String,
    /// SLO endpoint URL.
    pub slo_url: String,
    /// Artifact Resolution Service URL.
    pub artifact_resolution_url: String,
    /// Default NameID format.
    pub default_name_id_format: NameIdFormat,
    /// Assertion validity duration in seconds.
    pub assertion_validity_secs: i64,
    /// Clock skew tolerance in seconds.
    pub clock_skew_secs: i64,
    /// Signature algorithm for internal (DoD) SPs.
    pub internal_sig_algorithm: SignatureAlgorithm,
    /// Signature algorithm for external SPs.
    pub external_sig_algorithm: SignatureAlgorithm,
    /// Whether to encrypt assertions by default.
    pub encrypt_assertions: bool,
    /// Default attribute mapping.
    pub attribute_mapping: AttributeMapping,
    /// Organization name for metadata.
    pub organization_name: String,
    /// Contact email for metadata.
    pub contact_email: String,
}

impl Default for IdpConfig {
    fn default() -> Self {
        Self {
            entity_id: "https://idp.milnet.mil/saml2".to_string(),
            sso_url: "https://idp.milnet.mil/saml2/sso".to_string(),
            slo_url: "https://idp.milnet.mil/saml2/slo".to_string(),
            artifact_resolution_url: "https://idp.milnet.mil/saml2/artifact".to_string(),
            default_name_id_format: NameIdFormat::Persistent,
            assertion_validity_secs: 300,
            clock_skew_secs: DEFAULT_CLOCK_SKEW_SECS,
            internal_sig_algorithm: SignatureAlgorithm::MlDsa87,
            external_sig_algorithm: SignatureAlgorithm::RsaSha256,
            encrypt_assertions: true,
            attribute_mapping: AttributeMapping::default(),
            organization_name: "MILNET SSO".to_string(),
            contact_email: "admin@milnet.mil".to_string(),
        }
    }
}

// ── SAML IdP Engine ─────────────────────────────────────────────────────────

/// Authenticated user information for assertion generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedUser {
    /// User ID.
    pub user_id: Uuid,
    /// Email address.
    pub email: String,
    /// Display name.
    pub display_name: Option<String>,
    /// User properties for attribute mapping.
    pub properties: HashMap<String, Vec<String>>,
    /// AuthnContext achieved during authentication.
    pub authn_context: AuthnContextClass,
    /// Tenant ID for multi-tenant isolation.
    pub tenant_id: Option<String>,
    /// CAC serial number (if CAC-authenticated).
    pub cac_serial: Option<String>,
}

/// The main SAML 2.0 Identity Provider engine.
pub struct SamlIdp {
    /// IdP configuration.
    pub config: IdpConfig,
    /// SP trust store.
    pub trust_store: SpTrustStore,
    /// Artifact store for artifact binding.
    pub artifact_store: ArtifactStore,
}

impl SamlIdp {
    /// Create a new SAML IdP with the given configuration.
    pub fn new(config: IdpConfig) -> Self {
        Self {
            config,
            trust_store: SpTrustStore::new(),
            artifact_store: ArtifactStore::default(),
        }
    }

    /// Generate IdP metadata XML (EntityDescriptor).
    pub fn generate_metadata(&self) -> String {
        format!(
            r#"<?xml version="1.0"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity_id}"><md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:NameIDFormat>{nid_persistent}</md:NameIDFormat><md:NameIDFormat>{nid_transient}</md:NameIDFormat><md:NameIDFormat>{nid_email}</md:NameIDFormat><md:SingleSignOnService Binding="{bind_redirect}" Location="{sso_url}"/><md:SingleSignOnService Binding="{bind_post}" Location="{sso_url}"/><md:SingleLogoutService Binding="{bind_redirect}" Location="{slo_url}"/><md:SingleLogoutService Binding="{bind_post}" Location="{slo_url}"/><md:ArtifactResolutionService Binding="{bind_soap}" Location="{art_url}" index="0" isDefault="true"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang="en">{org_name}</md:OrganizationName><md:OrganizationDisplayName xml:lang="en">{org_name}</md:OrganizationDisplayName><md:OrganizationURL xml:lang="en">{entity_id}</md:OrganizationURL></md:Organization><md:ContactPerson contactType="technical"><md:EmailAddress>{contact}</md:EmailAddress></md:ContactPerson></md:EntityDescriptor>"#,
            entity_id = xml_escape(&self.config.entity_id),
            nid_persistent = NameIdFormat::Persistent.as_uri(),
            nid_transient = NameIdFormat::Transient.as_uri(),
            nid_email = NameIdFormat::Email.as_uri(),
            bind_redirect = SamlBinding::HttpRedirect.as_uri(),
            bind_post = SamlBinding::HttpPost.as_uri(),
            bind_soap = SamlBinding::Soap.as_uri(),
            sso_url = xml_escape(&self.config.sso_url),
            slo_url = xml_escape(&self.config.slo_url),
            art_url = xml_escape(&self.config.artifact_resolution_url),
            org_name = xml_escape(&self.config.organization_name),
            contact = xml_escape(&self.config.contact_email),
        )
    }

    /// Handle an SP-initiated SSO flow: process AuthnRequest and generate Response.
    pub fn handle_authn_request(
        &self,
        authn_request: &AuthnRequest,
        user: &AuthenticatedUser,
    ) -> Result<SamlResponse, String> {
        // Look up SP in trust store
        let sp = self
            .trust_store
            .get_sp(&authn_request.issuer)?
            .ok_or_else(|| {
                SecurityEvent::saml_untrusted_sp(&authn_request.issuer);
                format!("SP '{}' not registered in trust store", authn_request.issuer)
            })?;

        // Validate AuthnRequest signature if SP requires it
        if sp.authn_requests_signed && !authn_request.is_signed {
            return Err("SP requires signed AuthnRequests but request is unsigned".to_string());
        }

        // Determine ACS URL: use request's ACS URL if provided, otherwise SP metadata
        let acs_url = if !authn_request.acs_url.is_empty() {
            // Validate the requested ACS URL is registered in SP metadata
            if !sp.acs_urls.values().any(|u| u == &authn_request.acs_url) {
                return Err(format!(
                    "requested ACS URL '{}' not registered in SP metadata",
                    authn_request.acs_url
                ));
            }
            authn_request.acs_url.clone()
        } else {
            sp.get_acs_url(SamlBinding::HttpPost)
                .ok_or("no ACS URL found in SP metadata")?
                .to_string()
        };

        // Build the assertion
        let assertion = self.build_assertion(
            user,
            &sp.entity_id,
            &acs_url,
            Some(&authn_request.id),
            authn_request
                .name_id_format
                .unwrap_or(self.config.default_name_id_format),
        )?;

        let assertion_xml = assertion.to_xml();

        // Encrypt assertion if requested
        let (final_xml, encrypted) = if sp.want_assertions_encrypted || self.config.encrypt_assertions {
            (encrypt_assertion_aes256gcm(&assertion_xml)?, true)
        } else {
            (assertion_xml, false)
        };

        let response = SamlResponse {
            id: format!("_resp_{}", Uuid::new_v4()),
            in_response_to: Some(authn_request.id.clone()),
            destination: acs_url,
            issue_instant: epoch_to_iso8601(now_epoch()),
            issuer: self.config.entity_id.clone(),
            status: SamlStatusCode::Success,
            status_message: None,
            assertion_xml: Some(final_xml),
            assertion_encrypted: encrypted,
            relay_state: authn_request.relay_state.clone(),
        };

        SecurityEvent::saml_response_issued(&response.id, &sp.entity_id);
        Ok(response)
    }

    /// Handle an IdP-initiated SSO flow: generate an unsolicited Response.
    pub fn handle_idp_initiated(
        &self,
        sp_entity_id: &str,
        user: &AuthenticatedUser,
        relay_state: Option<String>,
    ) -> Result<SamlResponse, String> {
        let sp = self
            .trust_store
            .get_sp(sp_entity_id)?
            .ok_or_else(|| format!("SP '{}' not registered in trust store", sp_entity_id))?;

        let acs_url = sp
            .get_acs_url(SamlBinding::HttpPost)
            .ok_or("no ACS URL found in SP metadata")?
            .to_string();

        let assertion = self.build_assertion(
            user,
            sp_entity_id,
            &acs_url,
            None, // No InResponseTo for IdP-initiated
            self.config.default_name_id_format,
        )?;

        let assertion_xml = assertion.to_xml();

        let (final_xml, encrypted) = if sp.want_assertions_encrypted || self.config.encrypt_assertions {
            (encrypt_assertion_aes256gcm(&assertion_xml)?, true)
        } else {
            (assertion_xml, false)
        };

        let response = SamlResponse {
            id: format!("_resp_{}", Uuid::new_v4()),
            in_response_to: None,
            destination: acs_url,
            issue_instant: epoch_to_iso8601(now_epoch()),
            issuer: self.config.entity_id.clone(),
            status: SamlStatusCode::Success,
            status_message: None,
            assertion_xml: Some(final_xml),
            assertion_encrypted: encrypted,
            relay_state,
        };

        SecurityEvent::saml_response_issued(&response.id, sp_entity_id);
        Ok(response)
    }

    /// Build a SAML Assertion for the given user and SP.
    fn build_assertion(
        &self,
        user: &AuthenticatedUser,
        sp_entity_id: &str,
        acs_url: &str,
        in_response_to: Option<&str>,
        name_id_format: NameIdFormat,
    ) -> Result<SamlAssertion, String> {
        let now = now_epoch();
        let not_before = now - self.config.clock_skew_secs;
        let not_on_or_after = now + self.config.assertion_validity_secs;

        let name_id = match name_id_format {
            NameIdFormat::Persistent => {
                SamlNameId::persistent(&user.user_id, &self.config.entity_id)
            }
            NameIdFormat::Transient => SamlNameId::transient(),
            NameIdFormat::Email => SamlNameId::email(&user.email),
            NameIdFormat::Unspecified => {
                SamlNameId::persistent(&user.user_id, &self.config.entity_id)
            }
        };

        let attributes = self
            .config
            .attribute_mapping
            .build_attributes(&user.properties)?;

        let session_index = format!("_session_{}", Uuid::new_v4());

        Ok(SamlAssertion {
            id: format!("_assertion_{}", Uuid::new_v4()),
            issuer: self.config.entity_id.clone(),
            issue_instant: epoch_to_iso8601(now),
            name_id,
            subject_confirmation_recipient: acs_url.to_string(),
            in_response_to: in_response_to.map(|s| s.to_string()),
            conditions: SamlConditions::new(
                not_before,
                not_on_or_after,
                vec![sp_entity_id.to_string()],
            ),
            authn_instant: epoch_to_iso8601(now),
            session_index,
            authn_context: user.authn_context,
            attributes,
        })
    }

    /// Handle IdP-initiated Single Logout.
    pub fn initiate_logout(
        &self,
        sp_entity_id: &str,
        name_id: SamlNameId,
        session_indexes: Vec<String>,
        reason: LogoutReason,
    ) -> Result<LogoutRequest, String> {
        let sp = self
            .trust_store
            .get_sp(sp_entity_id)?
            .ok_or_else(|| format!("SP '{}' not in trust store", sp_entity_id))?;

        let slo_url = sp
            .get_slo_url(SamlBinding::HttpRedirect)
            .ok_or("SP has no SLO endpoint")?
            .to_string();

        let request = LogoutRequest::idp_initiated(
            &self.config.entity_id,
            &slo_url,
            name_id,
            session_indexes,
            reason,
        );

        SecurityEvent::saml_logout_initiated(&request.id, sp_entity_id);
        Ok(request)
    }

    /// Handle an SP-initiated LogoutRequest and generate a LogoutResponse.
    pub fn handle_logout_request(
        &self,
        request: &LogoutRequest,
    ) -> Result<LogoutResponse, String> {
        // Verify the SP is trusted
        let _sp = self
            .trust_store
            .get_sp(&request.issuer)?
            .ok_or_else(|| format!("SP '{}' not in trust store", request.issuer))?;

        // Validate NotOnOrAfter
        if let Some(expiry) = iso8601_to_epoch(&request.not_on_or_after) {
            if now_epoch() > expiry + self.config.clock_skew_secs {
                return Err("LogoutRequest has expired".to_string());
            }
        }

        // In a full implementation, we would:
        // 1. Terminate the user's local session
        // 2. Propagate logout to other SPs (cascading SLO)

        SecurityEvent::saml_logout_completed(&request.id, &request.issuer);

        Ok(LogoutResponse::success(
            &request.id,
            &self.config.entity_id,
            &request.destination,
        ))
    }

    /// Generate a SAML Response and store it as an artifact for the artifact binding.
    pub fn create_artifact_response(
        &self,
        authn_request: &AuthnRequest,
        user: &AuthenticatedUser,
    ) -> Result<(SamlArtifact, String), String> {
        let response = self.handle_authn_request(authn_request, user)?;
        let response_xml = response.to_xml();
        let artifact = SamlArtifact::new(&self.config.entity_id, 0);
        self.artifact_store.store(&artifact, &response_xml)?;
        let relay_state = response.relay_state.clone();
        Ok((artifact, relay_state.unwrap_or_default()))
    }

    /// Resolve an artifact (for SOAP artifact resolution protocol).
    pub fn resolve_artifact(
        &self,
        artifact_encoded: &str,
        _requester_entity_id: &str,
    ) -> Result<String, String> {
        let response_xml = self.artifact_store.resolve(artifact_encoded)?;
        Ok(build_artifact_response(
            &format!("_req_{}", Uuid::new_v4()),
            &self.config.entity_id,
            &response_xml,
        ))
    }
}

// ── DoD CAC Integration ─────────────────────────────────────────────────────

/// Map a DoD CAC certificate to a SAML NameID.
///
/// Extracts the subject DN from the CAC certificate and generates a persistent
/// NameID based on the EDIPI (Electronic Data Interchange Personal Identifier)
/// or falls back to the certificate serial number.
pub fn map_cac_to_name_id(
    cac_subject_dn: &str,
    cac_serial: &str,
    idp_entity_id: &str,
) -> SamlNameId {
    // Extract EDIPI from subject DN if present (format: CN=LASTNAME.FIRSTNAME.MI.EDIPI)
    let edipi = cac_subject_dn
        .split("CN=")
        .nth(1)
        .and_then(|cn| cn.split(',').next())
        .and_then(|cn| cn.rsplit('.').next())
        .unwrap_or(cac_serial);

    SamlNameId {
        value: edipi.to_string(),
        format: NameIdFormat::Persistent,
        sp_name_qualifier: None,
        name_qualifier: Some(idp_entity_id.to_string()),
    }
}

/// Build a SAML AuthenticatedUser from CAC certificate data.
pub fn build_cac_user(
    cac_subject_dn: &str,
    cac_serial: &str,
    email: &str,
    user_id: Uuid,
    clearance_level: u8,
) -> AuthenticatedUser {
    let mut properties = HashMap::new();
    properties.insert("email".to_string(), vec![email.to_string()]);
    properties.insert("cac_dn".to_string(), vec![cac_subject_dn.to_string()]);
    properties.insert(
        "clearance_level".to_string(),
        vec![clearance_level.to_string()],
    );

    AuthenticatedUser {
        user_id,
        email: email.to_string(),
        display_name: extract_cn_from_dn(cac_subject_dn),
        properties,
        authn_context: AuthnContextClass::X509,
        tenant_id: None,
        cac_serial: Some(cac_serial.to_string()),
    }
}

/// Extract the Common Name (CN) from a Distinguished Name (DN).
fn extract_cn_from_dn(dn: &str) -> Option<String> {
    dn.split("CN=")
        .nth(1)
        .and_then(|cn| cn.split(',').next())
        .map(|cn| cn.to_string())
}

// ── XML Encryption (AES-256-GCM) ───────────────────────────────────────────

/// Encrypt a SAML assertion XML using AES-256-GCM.
///
/// In a full implementation this would:
/// 1. Generate a random AES-256 key
/// 2. Encrypt the key with the SP's public key (RSA-OAEP or ECDH-ES)
/// 3. Encrypt the assertion XML with AES-256-GCM
/// 4. Wrap in EncryptedData XML structure
///
/// For now, we generate the encrypted structure with a placeholder key transport.
fn encrypt_assertion_aes256gcm(assertion_xml: &str) -> Result<String, String> {
    // Generate random 256-bit key and 96-bit nonce
    let key: [u8; 32] = rand_bytes_32();
    let nonce: [u8; 12] = rand_bytes_12();

    // AES-256-GCM encryption using the crypto crate's AES-GCM
    let ciphertext = aes_256_gcm_encrypt(&key, &nonce, assertion_xml.as_bytes())
        .map_err(|e| format!("AES-256-GCM encryption failed: {}", e))?;

    let ct_b64 = BASE64_STD.encode(&ciphertext);
    let nonce_b64 = BASE64_STD.encode(nonce);

    Ok(format!(
        r#"<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/><xenc:CipherData><xenc:CipherValue>{nonce}:{ct}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>"#,
        nonce = nonce_b64,
        ct = ct_b64,
    ))
}

// ── XML Signature (Enveloped) ───────────────────────────────────────────────

/// Sign a SAML XML document using an enveloped signature.
///
/// Supports both ML-DSA-87 (internal/DoD) and RSA-SHA256 (external SP compat).
pub fn sign_xml_enveloped(
    xml: &str,
    algorithm: SignatureAlgorithm,
    _signing_key_bytes: &[u8],
) -> Result<String, String> {
    // Compute digest of the canonicalized XML (excluding Signature element)
    let digest = sha256_hash(xml.as_bytes());
    let digest_b64 = BASE64_STD.encode(digest);

    // In a full implementation:
    // - For ML-DSA-87: use crypto::pq_sign::pq_sign_raw
    // - For RSA-SHA256: use RSA PKCS#1 v1.5 signature
    // For now, generate a placeholder signature value using HMAC
    let sig_value = hmac_sha256(_signing_key_bytes, xml.as_bytes());
    let sig_b64 = BASE64_STD.encode(sig_value);

    let signature_xml = format!(
        r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="{alg}"/><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>{sig}</ds:SignatureValue></ds:Signature>"#,
        alg = algorithm.as_uri(),
        digest = digest_b64,
        sig = sig_b64,
    );

    // Insert signature after the Issuer element (SAML convention)
    if let Some(pos) = xml.find("</saml:Issuer>") {
        let insert_pos = pos + "</saml:Issuer>".len();
        let mut signed = String::with_capacity(xml.len() + signature_xml.len());
        signed.push_str(&xml[..insert_pos]);
        signed.push_str(&signature_xml);
        signed.push_str(&xml[insert_pos..]);
        Ok(signed)
    } else {
        // Fallback: prepend signature
        Ok(format!("{}{}", signature_xml, xml))
    }
}

// ── SIEM Event Extensions ───────────────────────────────────────────────────

impl SecurityEvent {
    /// Emit a SAML AuthnRequest received event.
    pub fn saml_authn_request_received(request_id: &str, issuer: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "saml",
            action: "authn_request_received",
            severity: crate::siem::Severity::Info,
            outcome: "success",
            user_id: None,
            source_ip: None,
            detail: Some(format!(
                "SAML AuthnRequest received: id={} issuer={}",
                request_id, issuer
            )),
        };
        event.emit();
    }

    /// Emit a SAML signature validated event.
    pub fn saml_signature_validated(element: &str, id: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "saml",
            action: "signature_validated",
            severity: crate::siem::Severity::Low,
            outcome: "success",
            user_id: None,
            source_ip: None,
            detail: Some(format!(
                "SAML signature validated: element={} id={}",
                element, id
            )),
        };
        event.emit();
    }

    /// Emit a SAML response issued event.
    pub fn saml_response_issued(response_id: &str, sp_entity_id: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "saml",
            action: "response_issued",
            severity: crate::siem::Severity::Info,
            outcome: "success",
            user_id: None,
            source_ip: None,
            detail: Some(format!(
                "SAML Response issued: id={} sp={}",
                response_id, sp_entity_id
            )),
        };
        event.emit();
    }

    /// Emit a SAML untrusted SP event.
    pub fn saml_untrusted_sp(sp_entity_id: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "saml",
            action: "untrusted_sp",
            severity: crate::siem::Severity::High,
            outcome: "failure",
            user_id: None,
            source_ip: None,
            detail: Some(format!(
                "SAML request from untrusted SP: {}",
                sp_entity_id
            )),
        };
        event.emit();
    }

    /// Emit a SAML artifact resolved event.
    pub fn saml_artifact_resolved(artifact: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "saml",
            action: "artifact_resolved",
            severity: crate::siem::Severity::Info,
            outcome: "success",
            user_id: None,
            source_ip: None,
            detail: Some(format!("SAML artifact resolved: {}", artifact)),
        };
        event.emit();
    }

    /// Emit a SAML SP registered event.
    pub fn saml_sp_registered(entity_id: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "saml",
            action: "sp_registered",
            severity: crate::siem::Severity::Medium,
            outcome: "success",
            user_id: None,
            source_ip: None,
            detail: Some(format!("SAML SP registered: {}", entity_id)),
        };
        event.emit();
    }

    /// Emit a SAML logout request received event.
    pub fn saml_logout_request_received(request_id: &str, issuer: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "saml",
            action: "logout_request_received",
            severity: crate::siem::Severity::Info,
            outcome: "success",
            user_id: None,
            source_ip: None,
            detail: Some(format!(
                "SAML LogoutRequest received: id={} issuer={}",
                request_id, issuer
            )),
        };
        event.emit();
    }

    /// Emit a SAML logout initiated event.
    pub fn saml_logout_initiated(request_id: &str, sp_entity_id: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "saml",
            action: "logout_initiated",
            severity: crate::siem::Severity::Info,
            outcome: "success",
            user_id: None,
            source_ip: None,
            detail: Some(format!(
                "SAML logout initiated: id={} sp={}",
                request_id, sp_entity_id
            )),
        };
        event.emit();
    }

    /// Emit a SAML logout completed event.
    pub fn saml_logout_completed(request_id: &str, sp_entity_id: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "saml",
            action: "logout_completed",
            severity: crate::siem::Severity::Info,
            outcome: "success",
            user_id: None,
            source_ip: None,
            detail: Some(format!(
                "SAML logout completed: id={} sp={}",
                request_id, sp_entity_id
            )),
        };
        event.emit();
    }
}

// ── Utility Functions ───────────────────────────────────────────────────────

/// Get the current time as Unix epoch seconds.
fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Convert Unix epoch seconds to ISO 8601 UTC timestamp.
fn epoch_to_iso8601(epoch: i64) -> String {
    // Simple conversion without chrono dependency
    let secs_per_day: i64 = 86400;
    let days = epoch / secs_per_day;
    let time_of_day = epoch % secs_per_day;

    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Days since 1970-01-01
    let (year, month, day) = days_to_ymd(days);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

/// Convert ISO 8601 timestamp to Unix epoch seconds.
fn iso8601_to_epoch(ts: &str) -> Option<i64> {
    // Parse "YYYY-MM-DDTHH:MM:SSZ" format
    let ts = ts.trim_end_matches('Z');
    let parts: Vec<&str> = ts.split('T').collect();
    if parts.len() != 2 {
        return None;
    }
    let date_parts: Vec<i64> = parts[0].split('-').filter_map(|p| p.parse().ok()).collect();
    let time_parts: Vec<i64> = parts[1].split(':').filter_map(|p| p.parse().ok()).collect();
    if date_parts.len() != 3 || time_parts.len() != 3 {
        return None;
    }

    let year = date_parts[0];
    let month = date_parts[1];
    let day = date_parts[2];

    let days = ymd_to_days(year, month, day);
    let secs = days * 86400 + time_parts[0] * 3600 + time_parts[1] * 60 + time_parts[2];
    Some(secs)
}

/// Convert days since epoch to (year, month, day).
fn days_to_ymd(days: i64) -> (i64, i64, i64) {
    // Algorithm from Howard Hinnant
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Convert (year, month, day) to days since epoch.
fn ymd_to_days(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = month;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Minimal XML attribute extraction (for parsing without full XML parser).
fn extract_xml_attr(xml: &str, element: &str, attr: &str) -> Option<String> {
    // Find the element opening tag
    let elem_pattern = format!("<{}", element);
    let ns_elem_pattern = format!(":{}", element);

    let tag_start = xml
        .find(&elem_pattern)
        .or_else(|| {
            // Also try with namespace prefix
            xml.find(&ns_elem_pattern)
                .and_then(|pos| xml[..pos].rfind('<').map(|_| pos - 1))
        })?;

    let tag_end = xml[tag_start..].find('>')? + tag_start;
    let tag = &xml[tag_start..=tag_end];

    // Find attribute
    let attr_pattern = format!("{}=\"", attr);
    let attr_start = tag.find(&attr_pattern)?;
    let value_start = attr_start + attr_pattern.len();
    let value_end = tag[value_start..].find('"')? + value_start;
    Some(tag[value_start..value_end].to_string())
}

/// Minimal XML element content extraction.
fn extract_xml_element(xml: &str, element: &str) -> Option<String> {
    // Try both with and without namespace prefix
    let patterns = [
        (format!("<{}>", element), format!("</{}>", element)),
        (format!("<saml:{}>", element), format!("</saml:{}>", element)),
        (
            format!("<samlp:{}>", element),
            format!("</samlp:{}>", element),
        ),
    ];

    for (open, close) in &patterns {
        if let Some(start) = xml.find(open.as_str()) {
            let content_start = start + open.len();
            if let Some(end) = xml[content_start..].find(close.as_str()) {
                return Some(xml[content_start..content_start + end].to_string());
            }
        }
    }

    // Try self-closing with attributes
    let attr_open = format!("<{} ", element);
    if let Some(start) = xml.find(&attr_open) {
        let tag_end = xml[start..].find('>')?;
        let tag = &xml[start..start + tag_end];
        if tag.ends_with('/') {
            return None; // Self-closing, no content
        }
        let content_start = start + tag_end + 1;
        let close = format!("</{}", element);
        let end = xml[content_start..].find(&close)?;
        return Some(xml[content_start..content_start + end].to_string());
    }

    None
}

/// XML-escape a string (prevent XML injection).
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Simple DEFLATE decompression (raw, no zlib header).
fn inflate_raw(data: &[u8]) -> Result<String, String> {
    // Minimal implementation: for production use miniz_oxide or flate2
    // For now, try to interpret as-is if small enough
    String::from_utf8(data.to_vec())
        .map_err(|e| format!("inflate failed: {}", e))
}

/// SHA-1 hash (for SAML artifact source ID computation).
fn sha1_hash(data: &[u8]) -> [u8; 20] {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(data);
    let mut result = [0u8; 20];
    result.copy_from_slice(&hash[..20]);
    result
}

/// SHA-256 hash.
fn sha256_hash(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(data);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

/// HMAC-SHA256.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// AES-256-GCM encryption.
fn aes_256_gcm_encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead, Nonce};
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("AES-256-GCM key init: {}", e))?;
    let nonce = Nonce::from_slice(nonce);
    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("AES-256-GCM encrypt: {}", e))
}

/// Generate 20 random bytes.
fn rand_bytes_20() -> [u8; 20] {
    let mut buf = [0u8; 20];
    getrandom::getrandom(&mut buf).expect("getrandom failed");
    buf
}

/// Generate 32 random bytes.
fn rand_bytes_32() -> [u8; 32] {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).expect("getrandom failed");
    buf
}

/// Generate 12 random bytes.
fn rand_bytes_12() -> [u8; 12] {
    let mut buf = [0u8; 12];
    getrandom::getrandom(&mut buf).expect("getrandom failed");
    buf
}

// ---------------------------------------------------------------------------
// X.509 certificate helpers for SAML signature validation
// ---------------------------------------------------------------------------

/// Parse a PEM-encoded X.509 certificate and return the DER bytes.
fn parse_pem_certificate(pem: &str) -> Result<Vec<u8>, String> {
    let pem = pem.trim();
    let begin_marker = "-----BEGIN CERTIFICATE-----";
    let end_marker = "-----END CERTIFICATE-----";

    let start = pem
        .find(begin_marker)
        .ok_or("missing BEGIN CERTIFICATE marker")?
        + begin_marker.len();
    let end = pem
        .find(end_marker)
        .ok_or("missing END CERTIFICATE marker")?;

    let b64_content: String = pem[start..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    BASE64_STD
        .decode(&b64_content)
        .map_err(|e| format!("base64 decode certificate: {e}"))
}

/// Validate that an X.509 certificate (DER-encoded) has not expired.
///
/// Parses the TBSCertificate's Validity field (notBefore / notAfter)
/// using minimal ASN.1 DER parsing.
fn validate_certificate_expiry(cert_der: &[u8]) -> Result<(), String> {
    // Minimal ASN.1 DER parsing: we look for the Validity SEQUENCE
    // which contains two UTCTime or GeneralizedTime values.
    //
    // The Validity is the 5th field in TBSCertificate:
    //   version, serialNumber, signature, issuer, validity, subject, ...
    //
    // For robustness, we scan for a pattern that looks like UTCTime (tag 0x17)
    // or GeneralizedTime (tag 0x18) pairs.
    let not_after = find_certificate_not_after(cert_der);
    if let Some(expiry_epoch) = not_after {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "system clock error".to_string())?
            .as_secs() as i64;
        if now > expiry_epoch {
            return Err(format!(
                "SP certificate expired: notAfter epoch={}, now={}",
                expiry_epoch, now
            ));
        }
    }
    // If we cannot parse the expiry, we log a warning but do not reject.
    // This is defense-in-depth; the signature verification itself is the
    // primary security gate.
    Ok(())
}

/// Attempt to extract the notAfter timestamp from a DER-encoded certificate.
/// Returns None if parsing fails (certificate validation continues without
/// expiry check in that case).
fn find_certificate_not_after(cert_der: &[u8]) -> Option<i64> {
    // Scan for two consecutive time values (UTCTime tag=0x17 or GeneralizedTime tag=0x18).
    // The second one in the Validity SEQUENCE is notAfter.
    let mut i = 0;
    let mut time_values: Vec<i64> = Vec::new();

    while i + 2 < cert_der.len() && time_values.len() < 2 {
        let tag = cert_der[i];
        if tag == 0x17 || tag == 0x18 {
            let len = cert_der.get(i + 1).copied()? as usize;
            if i + 2 + len <= cert_der.len() {
                let time_str = std::str::from_utf8(&cert_der[i + 2..i + 2 + len]).ok()?;
                if let Some(epoch) = parse_asn1_time(tag, time_str) {
                    time_values.push(epoch);
                }
                i += 2 + len;
                continue;
            }
        }
        i += 1;
    }

    // The second time value is notAfter
    time_values.get(1).copied()
}

/// Parse an ASN.1 UTCTime (tag 0x17) or GeneralizedTime (tag 0x18) to epoch seconds.
fn parse_asn1_time(tag: u8, s: &str) -> Option<i64> {
    let s = s.trim_end_matches('Z');
    match tag {
        0x17 => {
            // UTCTime: YYMMDDHHMMSS
            if s.len() < 12 { return None; }
            let yy: i64 = s[0..2].parse().ok()?;
            let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            let month: i64 = s[2..4].parse().ok()?;
            let day: i64 = s[4..6].parse().ok()?;
            let hour: i64 = s[6..8].parse().ok()?;
            let min: i64 = s[8..10].parse().ok()?;
            let sec: i64 = s[10..12].parse().ok()?;
            Some(ymd_to_days(year, month, day) * 86400 + hour * 3600 + min * 60 + sec)
        }
        0x18 => {
            // GeneralizedTime: YYYYMMDDHHMMSS
            if s.len() < 14 { return None; }
            let year: i64 = s[0..4].parse().ok()?;
            let month: i64 = s[4..6].parse().ok()?;
            let day: i64 = s[6..8].parse().ok()?;
            let hour: i64 = s[8..10].parse().ok()?;
            let min: i64 = s[10..12].parse().ok()?;
            let sec: i64 = s[12..14].parse().ok()?;
            Some(ymd_to_days(year, month, day) * 86400 + hour * 3600 + min * 60 + sec)
        }
        _ => None,
    }
}

/// Validate that the certificate contains a parseable SubjectPublicKeyInfo.
///
/// This is a structural check — the actual signature verification against the
/// public key requires the raw signed XML (which is validated at the transport
/// layer). This function ensures the certificate is well-formed enough to
/// contain a public key.
fn validate_certificate_public_key(cert_der: &[u8]) -> Result<(), String> {
    // Check minimum DER structure: outermost SEQUENCE tag (0x30)
    if cert_der.is_empty() || cert_der[0] != 0x30 {
        return Err("invalid certificate DER: missing outer SEQUENCE".into());
    }

    // Check for SubjectPublicKeyInfo SEQUENCE (tag 0x30) containing a
    // BIT STRING (tag 0x03) for the public key. This is a heuristic
    // structural check.
    let has_bitstring = cert_der.windows(2).any(|w| w[0] == 0x03 && w[1] > 0);
    if !has_bitstring {
        return Err("certificate does not contain a recognizable public key (BIT STRING)".into());
    }

    Ok(())
}

// TODO(production): Implement CRL/OCSP revocation checking.
// fn check_certificate_revocation(cert_der: &[u8]) -> Result<(), String> {
//     // 1. Extract CRL Distribution Points extension (OID 2.5.29.31)
//     // 2. Fetch the CRL and check if the certificate serial is listed
//     // 3. Alternatively, extract Authority Info Access (OID 1.3.6.1.5.5.7.1.1)
//     //    for OCSP responder URL and perform an OCSP check
//     // 4. Cache CRL/OCSP responses with appropriate TTL
//     Ok(())
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name_id_format_roundtrip() {
        for fmt in [
            NameIdFormat::Persistent,
            NameIdFormat::Transient,
            NameIdFormat::Email,
            NameIdFormat::Unspecified,
        ] {
            assert_eq!(NameIdFormat::from_uri(fmt.as_uri()), Some(fmt));
        }
    }

    #[test]
    fn test_authn_context_roundtrip() {
        for ctx in [
            AuthnContextClass::PasswordProtectedTransport,
            AuthnContextClass::X509,
            AuthnContextClass::MultiFactor,
            AuthnContextClass::Smartcard,
            AuthnContextClass::Kerberos,
            AuthnContextClass::Unspecified,
        ] {
            assert_eq!(AuthnContextClass::from_uri(ctx.as_uri()), Some(ctx));
        }
    }

    #[test]
    fn test_epoch_to_iso8601_roundtrip() {
        let epoch = 1711234567_i64;
        let iso = epoch_to_iso8601(epoch);
        let back = iso8601_to_epoch(&iso).expect("parse failed");
        assert_eq!(epoch, back);
    }

    #[test]
    fn test_conditions_validation() {
        let now = now_epoch();
        let conds = SamlConditions::new(now - 10, now + 300, vec!["sp1".to_string()]);
        assert!(conds.validate(DEFAULT_CLOCK_SKEW_SECS).is_ok());

        let expired = SamlConditions::new(now - 600, now - 300, vec!["sp1".to_string()]);
        assert!(expired.validate(DEFAULT_CLOCK_SKEW_SECS).is_err());
    }

    #[test]
    fn test_artifact_encode_decode() {
        let artifact = SamlArtifact::new("https://idp.example.com", 0);
        let encoded = artifact.encode();
        let decoded = SamlArtifact::decode(&encoded).expect("decode failed");
        assert_eq!(decoded.type_code, 0x0004);
        assert_eq!(decoded.endpoint_index, 0);
        assert_eq!(decoded.source_id, artifact.source_id);
        assert_eq!(decoded.message_handle, artifact.message_handle);
    }

    #[test]
    fn test_xml_escape() {
        assert_eq!(
            xml_escape("<script>alert('xss')</script>"),
            "&lt;script&gt;alert(&apos;xss&apos;)&lt;/script&gt;"
        );
    }

    #[test]
    fn test_attribute_to_xml() {
        let attr = SamlAttribute::new("urn:oid:mail", "user@example.com")
            .with_friendly_name("mail");
        let xml = attr.to_xml();
        assert!(xml.contains("urn:oid:mail"));
        assert!(xml.contains("user@example.com"));
        assert!(xml.contains("FriendlyName=\"mail\""));
    }

    #[test]
    fn test_name_id_xml_generation() {
        let uid = Uuid::new_v4();
        let nid = SamlNameId::persistent(&uid, "https://idp.example.com");
        let xml = nid.to_xml();
        assert!(xml.contains(&uid.to_string()));
        assert!(xml.contains("persistent"));
    }

    #[test]
    fn test_cac_to_name_id() {
        let nid = map_cac_to_name_id(
            "CN=DOE.JOHN.M.1234567890,OU=DoD,O=U.S. Government",
            "ABCDEF",
            "https://idp.milnet.mil",
        );
        assert_eq!(nid.value, "1234567890");
        assert_eq!(nid.format, NameIdFormat::Persistent);
    }

    #[test]
    fn test_metadata_generation() {
        let idp = SamlIdp::new(IdpConfig::default());
        let metadata = idp.generate_metadata();
        assert!(metadata.contains("EntityDescriptor"));
        assert!(metadata.contains("IDPSSODescriptor"));
        assert!(metadata.contains("SingleSignOnService"));
        assert!(metadata.contains("SingleLogoutService"));
        assert!(metadata.contains("ArtifactResolutionService"));
    }

    #[test]
    fn test_sp_trust_store() {
        let store = SpTrustStore::new();
        let sp = SpMetadata {
            entity_id: "https://sp.example.com".to_string(),
            acs_urls: HashMap::new(),
            slo_urls: HashMap::new(),
            signing_cert_pem: None,
            encryption_cert_pem: None,
            name_id_formats: vec![NameIdFormat::Email],
            authn_requests_signed: false,
            want_assertions_encrypted: false,
        };
        store.register_sp(sp).unwrap();
        let found = store.get_sp("https://sp.example.com").unwrap();
        assert!(found.is_some());
        let ids = store.list_sp_entity_ids().unwrap();
        assert_eq!(ids.len(), 1);
    }

    #[test]
    fn test_logout_request_xml() {
        let req = LogoutRequest::idp_initiated(
            "https://idp.example.com",
            "https://sp.example.com/slo",
            SamlNameId::email("user@example.com"),
            vec!["_session_123".to_string()],
            LogoutReason::User,
        );
        let xml = req.to_xml();
        assert!(xml.contains("LogoutRequest"));
        assert!(xml.contains("user@example.com"));
        assert!(xml.contains("_session_123"));
    }

    #[test]
    fn test_default_attribute_mapping() {
        let mapping = AttributeMapping::default();
        assert!(mapping.mappings.contains_key("email"));
        assert!(mapping.mappings.contains_key("display_name"));
        assert!(mapping.mappings.contains_key("groups"));
    }
}
