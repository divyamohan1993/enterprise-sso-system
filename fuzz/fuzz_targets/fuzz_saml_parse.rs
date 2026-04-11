#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use common::saml::{AuthnRequest, LogoutRequest};

/// Structured SAML XML generator for more effective fuzzing.
/// Instead of random bytes, generates valid-ish XML structures
/// that exercise the SAML parser more deeply.
#[derive(Debug, Arbitrary)]
struct FuzzSamlInput {
    /// Use structured XML or raw bytes.
    use_structured: bool,
    /// AuthnRequest ID attribute.
    id: String,
    /// IssueInstant attribute.
    issue_instant: String,
    /// Issuer element content.
    issuer: String,
    /// ACS URL attribute.
    acs_url: String,
    /// Whether to include DOCTYPE (XXE probe).
    include_doctype: bool,
    /// DOCTYPE content if included.
    doctype_content: String,
    /// Whether to include an ENTITY declaration (XXE probe).
    include_entity: bool,
    /// Whether to include a processing instruction.
    include_pi: bool,
    /// Raw fallback data.
    raw_data: Vec<u8>,
    /// Nesting depth for wrapper elements.
    nesting_depth: u8,
    /// Whether to include NameIDPolicy element.
    include_name_id_policy: bool,
    /// NameID Format URI.
    name_id_format: String,
    /// Whether to include RequestedAuthnContext.
    include_authn_context: bool,
    /// Padding to add to the end.
    padding_len: u16,
}

impl FuzzSamlInput {
    fn to_authn_request_xml(&self) -> String {
        let mut xml = String::with_capacity(4096);

        if self.include_doctype {
            xml.push_str("<!DOCTYPE ");
            // Truncate doctype content to prevent OOM.
            let content: String = self.doctype_content.chars().take(200).collect();
            xml.push_str(&content);
            xml.push_str(">");
        }

        if self.include_entity {
            xml.push_str("<!ENTITY fuzz \"fuzzed\">");
        }

        if self.include_pi {
            xml.push_str("<?xml-stylesheet type=\"text/xsl\" href=\"http://fuzz.local/x.xsl\"?>");
        }

        // Add nesting (capped to prevent stack overflow).
        let depth = (self.nesting_depth % 20) as usize;
        for i in 0..depth {
            xml.push_str(&format!("<wrapper{}>", i));
        }

        let id: String = self.id.chars().take(200).collect();
        let instant: String = self.issue_instant.chars().take(100).collect();
        let issuer: String = self.issuer.chars().take(500).collect();
        let acs: String = self.acs_url.chars().take(500).collect();

        xml.push_str(&format!(
            r#"<AuthnRequest ID="{}" IssueInstant="{}" AssertionConsumerServiceURL="{}">"#,
            xml_escape(&id),
            xml_escape(&instant),
            xml_escape(&acs),
        ));

        xml.push_str(&format!("<Issuer>{}</Issuer>", xml_escape(&issuer)));

        if self.include_name_id_policy {
            let format: String = self.name_id_format.chars().take(200).collect();
            xml.push_str(&format!(
                r#"<NameIDPolicy Format="{}"/>"#,
                xml_escape(&format)
            ));
        }

        if self.include_authn_context {
            xml.push_str(
                "<RequestedAuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:X509</AuthnContextClassRef></RequestedAuthnContext>",
            );
        }

        xml.push_str("</AuthnRequest>");

        for i in (0..depth).rev() {
            xml.push_str(&format!("</wrapper{}>", i));
        }

        // Add padding (capped).
        let padding = (self.padding_len % 1000) as usize;
        for _ in 0..padding {
            xml.push(' ');
        }

        xml
    }

    fn to_logout_request_xml(&self) -> String {
        let id: String = self.id.chars().take(200).collect();
        let instant: String = self.issue_instant.chars().take(100).collect();
        let issuer: String = self.issuer.chars().take(500).collect();

        format!(
            r#"<LogoutRequest ID="{}" IssueInstant="{}"><Issuer>{}</Issuer><NameID>user@fuzz</NameID></LogoutRequest>"#,
            xml_escape(&id),
            xml_escape(&instant),
            xml_escape(&issuer),
        )
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fuzz_target!(|input: FuzzSamlInput| {
    if input.use_structured {
        let xml = input.to_authn_request_xml();
        let _ = AuthnRequest::parse_redirect_binding(&xml);
        let _ = AuthnRequest::parse_post_binding(&xml);

        let logout_xml = input.to_logout_request_xml();
        let _ = LogoutRequest::from_xml(&logout_xml);
    } else {
        let xml = String::from_utf8_lossy(&input.raw_data);
        let _ = AuthnRequest::parse_redirect_binding(&xml);
        let _ = AuthnRequest::parse_post_binding(&xml);
        let _ = LogoutRequest::from_xml(&xml);
    }
});
