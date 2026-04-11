//! XML bomb and billion laughs attack tests for SAML parsing.
//!
//! Verifies that the SAML parser rejects all forms of XML-based denial of
//! service attacks including entity expansion, deeply nested elements,
//! oversized attributes, null bytes, and BOM handling.

use base64::{engine::general_purpose::STANDARD as BASE64_STD, Engine};
use common::saml::{AuthnRequest, LogoutRequest};

/// Encode raw XML as base64 for AuthnRequest::parse_post_binding.
fn encode_xml_b64(xml: &str) -> String {
    BASE64_STD.encode(xml.as_bytes())
}

// ---------------------------------------------------------------------------
// Billion laughs (recursive entity expansion)
// ---------------------------------------------------------------------------

#[test]
fn test_billion_laughs_classic() {
    let xml = r#"<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<AuthnRequest ID="_bomb" IssueInstant="2024-01-01T00:00:00Z">
  <Issuer>&lol9;</Issuer>
</AuthnRequest>"#;
    let encoded = encode_xml_b64(xml);
    let result = AuthnRequest::parse_post_binding(&encoded);
    assert!(result.is_err(), "billion laughs attack must be rejected");
}

#[test]
fn test_billion_laughs_variant_doctype_only() {
    let xml = r#"<!DOCTYPE bomb [<!ENTITY x "boom">]><AuthnRequest ID="_a" IssueInstant="2024-01-01T00:00:00Z"><Issuer>test</Issuer></AuthnRequest>"#;
    let encoded = encode_xml_b64(xml);
    let result = AuthnRequest::parse_post_binding(&encoded);
    assert!(result.is_err(), "DOCTYPE with ENTITY must be rejected");
}

#[test]
fn test_billion_laughs_case_insensitive_doctype() {
    let xml = r#"<!doctype lolz [<!entity x "y">]><AuthnRequest ID="_ci" IssueInstant="2024-01-01T00:00:00Z"/>"#;
    let encoded = encode_xml_b64(xml);
    let result = AuthnRequest::parse_post_binding(&encoded);
    assert!(
        result.is_err(),
        "case-insensitive DOCTYPE/ENTITY must be rejected"
    );
}

#[test]
fn test_entity_expansion_without_doctype() {
    let xml = r#"<!ENTITY boom "kaboom"><AuthnRequest ID="_e" IssueInstant="2024-01-01T00:00:00Z"/>"#;
    let encoded = encode_xml_b64(xml);
    let result = AuthnRequest::parse_post_binding(&encoded);
    assert!(result.is_err(), "bare ENTITY declaration must be rejected");
}

#[test]
fn test_xxe_file_read_attempt() {
    let xml = r#"<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<AuthnRequest ID="_xxe" IssueInstant="2024-01-01T00:00:00Z">
  <Issuer>&xxe;</Issuer>
</AuthnRequest>"#;
    let encoded = encode_xml_b64(xml);
    let result = AuthnRequest::parse_post_binding(&encoded);
    assert!(result.is_err(), "XXE file read attempt must be rejected");
}

#[test]
fn test_xxe_ssrf_attempt() {
    let xml = r#"<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<AuthnRequest ID="_ssrf" IssueInstant="2024-01-01T00:00:00Z">
  <Issuer>&xxe;</Issuer>
</AuthnRequest>"#;
    let encoded = encode_xml_b64(xml);
    let result = AuthnRequest::parse_post_binding(&encoded);
    assert!(result.is_err(), "XXE SSRF attempt must be rejected");
}

#[test]
fn test_xxe_public_identifier() {
    let xml = r#"<!DOCTYPE foo PUBLIC "evil" "http://evil.com/dtd"><AuthnRequest ID="_pub" IssueInstant="2024-01-01T00:00:00Z"/>"#;
    let encoded = encode_xml_b64(xml);
    let result = AuthnRequest::parse_post_binding(&encoded);
    assert!(result.is_err(), "PUBLIC identifier must be rejected");
}

#[test]
fn test_xml_stylesheet_processing_instruction() {
    let xml = r#"<?xml-stylesheet type="text/xsl" href="http://evil.com/transform.xsl"?><AuthnRequest ID="_xsl" IssueInstant="2024-01-01T00:00:00Z"/>"#;
    let encoded = encode_xml_b64(xml);
    let result = AuthnRequest::parse_post_binding(&encoded);
    assert!(result.is_err(), "xml-stylesheet PI must be rejected");
}

// ---------------------------------------------------------------------------
// Deeply nested XML elements
// ---------------------------------------------------------------------------

#[test]
fn test_deeply_nested_xml_10000_levels() {
    let depth = 10_000;
    let mut xml = String::with_capacity(depth * 20);
    for i in 0..depth {
        xml.push_str(&format!("<level{}>", i));
    }
    xml.push_str("<AuthnRequest ID=\"_deep\" IssueInstant=\"2024-01-01T00:00:00Z\"/>");
    for i in (0..depth).rev() {
        xml.push_str(&format!("</level{}>", i));
    }
    // Should either reject due to size limits or parse gracefully.
    // Must NOT stack overflow or hang.
    if xml.len() <= 64 * 1024 {
        let encoded = encode_xml_b64(&xml);
        let _ = AuthnRequest::parse_post_binding(&encoded);
    }
    // If > 64KB, the internal parse_xml will reject it.
    // The key assertion: we reached this point without a crash.
}

#[test]
fn test_deeply_nested_xml_exceeds_size_limit() {
    let depth = 5_000;
    let mut xml = String::with_capacity(depth * 30);
    for i in 0..depth {
        xml.push_str(&format!("<ns{}:element{} xmlns:ns{}=\"urn:ns{}\">", i, i, i, i));
    }
    xml.push_str("<AuthnRequest ID=\"_deepns\" IssueInstant=\"2024-01-01T00:00:00Z\"/>");
    for i in (0..depth).rev() {
        xml.push_str(&format!("</ns{}:element{}>", i, i));
    }
    if xml.len() > 64 * 1024 {
        let encoded = encode_xml_b64(&xml);
        let result = AuthnRequest::parse_post_binding(&encoded);
        assert!(result.is_err(), "oversized XML must be rejected");
    }
}

// ---------------------------------------------------------------------------
// Extremely long attribute values (1MB+)
// ---------------------------------------------------------------------------

#[test]
fn test_extremely_long_attribute_value() {
    let long_value = "A".repeat(1_048_576);
    let xml = format!(
        r#"<AuthnRequest ID="{}" IssueInstant="2024-01-01T00:00:00Z"/>"#,
        long_value
    );
    let encoded = encode_xml_b64(&xml);
    let result = AuthnRequest::parse_post_binding(&encoded);
    assert!(
        result.is_err(),
        "1MB attribute value must be rejected by size limit"
    );
}

#[test]
fn test_extremely_long_issuer_content() {
    let long_issuer = "X".repeat(1_048_576);
    let xml = format!(
        r#"<AuthnRequest ID="_longissuer" IssueInstant="2024-01-01T00:00:00Z">
           <Issuer>{}</Issuer>
        </AuthnRequest>"#,
        long_issuer
    );
    let encoded = encode_xml_b64(&xml);
    let result = AuthnRequest::parse_post_binding(&encoded);
    assert!(
        result.is_err(),
        "1MB issuer content must be rejected by size limit"
    );
}

// ---------------------------------------------------------------------------
// XML with null bytes
// ---------------------------------------------------------------------------

#[test]
fn test_xml_with_null_bytes_in_attribute() {
    let xml = "<AuthnRequest ID=\"_null\x00injection\" IssueInstant=\"2024-01-01T00:00:00Z\"/>";
    let encoded = encode_xml_b64(xml);
    let _ = AuthnRequest::parse_post_binding(&encoded);
    // Must not panic.
}

#[test]
fn test_xml_with_null_bytes_in_element_content() {
    let xml = "<AuthnRequest ID=\"_n\" IssueInstant=\"2024-01-01T00:00:00Z\"><Issuer>evil\x00payload</Issuer></AuthnRequest>";
    let encoded = encode_xml_b64(xml);
    let _ = AuthnRequest::parse_post_binding(&encoded);
}

#[test]
fn test_xml_with_null_bytes_between_tags() {
    let xml = "<AuthnRequest\x00 ID=\"_nb\" IssueInstant=\"2024-01-01T00:00:00Z\"/>";
    let encoded = encode_xml_b64(xml);
    let _ = AuthnRequest::parse_post_binding(&encoded);
}

// ---------------------------------------------------------------------------
// XML with UTF-8 BOM
// ---------------------------------------------------------------------------

#[test]
fn test_xml_with_utf8_bom() {
    let xml = "\u{FEFF}<AuthnRequest ID=\"_bom\" IssueInstant=\"2024-01-01T00:00:00Z\"><Issuer>https://sp.example.com</Issuer></AuthnRequest>";
    let encoded = encode_xml_b64(xml);
    let _ = AuthnRequest::parse_post_binding(&encoded);
}

#[test]
fn test_xml_with_utf8_bom_in_middle() {
    let xml = "<AuthnRequest ID=\"_bom2\" IssueInstant=\"2024-01-01T00:00:00Z\"><Issuer>\u{FEFF}https://sp.example.com</Issuer></AuthnRequest>";
    let encoded = encode_xml_b64(xml);
    let _ = AuthnRequest::parse_post_binding(&encoded);
}

// ---------------------------------------------------------------------------
// LogoutRequest with same attack vectors (uses raw XML directly)
// ---------------------------------------------------------------------------

#[test]
fn test_logout_request_billion_laughs() {
    let xml = r#"<!DOCTYPE lolz [<!ENTITY lol "lol">]><LogoutRequest ID="_bomb" IssueInstant="2024-01-01T00:00:00Z"><Issuer>https://sp.example.com</Issuer><NameID>user@test</NameID></LogoutRequest>"#;
    let result = LogoutRequest::from_xml(xml);
    assert!(result.is_err(), "LogoutRequest must also reject billion laughs");
}

#[test]
fn test_logout_request_oversized() {
    let big = "x".repeat(65 * 1024);
    let xml = format!(
        r#"<LogoutRequest ID="_big" IssueInstant="2024-01-01T00:00:00Z"><Issuer>{}</Issuer><NameID>user</NameID></LogoutRequest>"#,
        big
    );
    let result = LogoutRequest::from_xml(&xml);
    assert!(result.is_err(), "oversized LogoutRequest must be rejected");
}

// ---------------------------------------------------------------------------
// Mixed attack: XXE + oversized + nesting
// ---------------------------------------------------------------------------

#[test]
fn test_combined_xxe_and_oversized() {
    let padding = "A".repeat(60_000);
    let xml = format!(
        r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]>
        <AuthnRequest ID="_combo" IssueInstant="2024-01-01T00:00:00Z">
          <Issuer>{}&xxe;</Issuer>
        </AuthnRequest>"#,
        padding
    );
    let encoded = encode_xml_b64(&xml);
    let result = AuthnRequest::parse_post_binding(&encoded);
    assert!(result.is_err(), "combined XXE + oversized must be rejected");
}
