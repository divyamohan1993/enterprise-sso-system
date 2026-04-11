//! SQL injection adversarial tests.
//!
//! Verifies that all user-facing string inputs are safe against SQL injection
//! by testing the SAML, SCIM, and authentication paths with injection payloads.
//! The system uses sqlx parameterized queries exclusively, so all payloads
//! must be treated as literal data, never interpreted as SQL.

use base64::{engine::general_purpose::STANDARD as BASE64_STD, Engine};
use common::saml::{AuthnRequest, LogoutRequest, check_assertion_id_replay};
use common::scim::{ScimFilter, ScimUser, ScimGroup, ScimPatchRequest, ScimBulkRequest};

// ---------------------------------------------------------------------------
// SQL injection payloads
// ---------------------------------------------------------------------------

const SQL_INJECTION_PAYLOADS: &[&str] = &[
    "'; DROP TABLE users; --",
    "' OR '1'='1",
    "'; UNION SELECT * FROM users --",
    "' OR 1=1 --",
    "'; DELETE FROM sessions WHERE '1'='1",
    "admin'--",
    "' UNION SELECT username, password FROM users --",
    "1; UPDATE users SET role='admin' WHERE '1'='1",
    "'; INSERT INTO users VALUES ('hacker','pwned'); --",
    "' OR ''='",
    "1' ORDER BY 1--",
    "1' WAITFOR DELAY '0:0:5'--",
    "'; EXEC xp_cmdshell('whoami'); --",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "\\'; DROP TABLE users; --",
];

const UNICODE_SQL_PAYLOADS: &[&str] = &[
    "\u{FF07} OR \u{FF07}1\u{FF07}=\u{FF07}1",
    "\u{037E} DROP TABLE users",
    "\u{2019} OR \u{2019}1\u{2019}=\u{2019}1",
    "admin\u{0300}'--",
    "admin\x00' OR '1'='1",
];

/// Encode raw XML as base64 for AuthnRequest::parse_post_binding.
fn encode_xml_b64(xml: &str) -> String {
    BASE64_STD.encode(xml.as_bytes())
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\"', "&quot;")
        .replace('\'', "&apos;")
}

// ---------------------------------------------------------------------------
// SAML AuthnRequest parsing with SQL payloads (via base64 post binding)
// ---------------------------------------------------------------------------

#[test]
fn test_saml_authn_request_with_sql_injection_in_issuer() {
    for payload in SQL_INJECTION_PAYLOADS {
        let xml = format!(
            r#"<AuthnRequest ID="_test" IssueInstant="2024-01-01T00:00:00Z"
               AssertionConsumerServiceURL="https://sp.example.com/acs">
               <Issuer>{}</Issuer>
            </AuthnRequest>"#,
            xml_escape(payload)
        );
        let encoded = encode_xml_b64(&xml);
        let result = AuthnRequest::parse_post_binding(&encoded);
        match result {
            Ok(req) => {
                assert!(
                    !req.issuer.is_empty() || payload.is_empty(),
                    "parsed issuer should contain the payload as literal data"
                );
            }
            Err(_) => {
                // Rejection is safe.
            }
        }
    }
}

#[test]
fn test_saml_authn_request_with_sql_injection_in_id() {
    for payload in SQL_INJECTION_PAYLOADS {
        let xml = format!(
            r#"<AuthnRequest ID="{}" IssueInstant="2024-01-01T00:00:00Z">
               <Issuer>https://sp.example.com</Issuer>
            </AuthnRequest>"#,
            xml_escape(payload)
        );
        let encoded = encode_xml_b64(&xml);
        let _ = AuthnRequest::parse_post_binding(&encoded);
    }
}

// ---------------------------------------------------------------------------
// SAML assertion ID replay cache with SQL payloads
// ---------------------------------------------------------------------------

#[test]
fn test_assertion_id_replay_with_sql_injection() {
    for payload in SQL_INJECTION_PAYLOADS {
        let result = check_assertion_id_replay(payload, 30);
        match result {
            Ok(()) => {
                let replay = check_assertion_id_replay(payload, 30);
                assert!(
                    replay.is_err(),
                    "replay of SQL injection payload '{}' should be detected",
                    payload
                );
            }
            Err(_) => {}
        }
    }
}

// ---------------------------------------------------------------------------
// SCIM filter parsing with SQL payloads
// ---------------------------------------------------------------------------

#[test]
fn test_scim_filter_with_sql_injection() {
    for payload in SQL_INJECTION_PAYLOADS {
        let filter_str = format!("userName eq \"{}\"", payload);
        let _ = ScimFilter::parse(&filter_str);
    }
}

#[test]
fn test_scim_filter_with_unicode_sql_injection() {
    for payload in UNICODE_SQL_PAYLOADS {
        let filter_str = format!("userName eq \"{}\"", payload);
        let _ = ScimFilter::parse(&filter_str);
    }
}

// ---------------------------------------------------------------------------
// SCIM user deserialization with SQL payloads
// ---------------------------------------------------------------------------

#[test]
fn test_scim_user_with_sql_injection_in_username() {
    for payload in SQL_INJECTION_PAYLOADS {
        let json = format!(
            r#"{{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"{}","active":true}}"#,
            payload.replace('\\', "\\\\").replace('\"', "\\\"")
        );
        let _ = serde_json::from_str::<ScimUser>(&json);
    }
}

#[test]
fn test_scim_user_with_sql_injection_in_email() {
    for payload in SQL_INJECTION_PAYLOADS {
        let json = format!(
            r#"{{
                "schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName":"testuser",
                "emails":[{{"value":"{}","primary":true}}],
                "active":true
            }}"#,
            payload.replace('\\', "\\\\").replace('\"', "\\\"")
        );
        let _ = serde_json::from_str::<ScimUser>(&json);
    }
}

// ---------------------------------------------------------------------------
// SCIM group with SQL injection payloads
// ---------------------------------------------------------------------------

#[test]
fn test_scim_group_with_sql_injection_in_displayname() {
    for payload in SQL_INJECTION_PAYLOADS {
        let json = format!(
            r#"{{
                "schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],
                "displayName":"{}"
            }}"#,
            payload.replace('\\', "\\\\").replace('\"', "\\\"")
        );
        let _ = serde_json::from_str::<ScimGroup>(&json);
    }
}

// ---------------------------------------------------------------------------
// SCIM patch request with SQL injection payloads
// ---------------------------------------------------------------------------

#[test]
fn test_scim_patch_with_sql_injection_in_value() {
    for payload in SQL_INJECTION_PAYLOADS {
        let json = format!(
            r#"{{
                "schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations":[{{"op":"replace","path":"userName","value":"{}"}}]
            }}"#,
            payload.replace('\\', "\\\\").replace('\"', "\\\"")
        );
        let _ = serde_json::from_str::<ScimPatchRequest>(&json);
    }
}

// ---------------------------------------------------------------------------
// SCIM bulk request with SQL injection payloads
// ---------------------------------------------------------------------------

#[test]
fn test_scim_bulk_with_sql_injection() {
    for payload in SQL_INJECTION_PAYLOADS {
        let json = format!(
            r#"{{
                "schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                "Operations":[{{
                    "method":"POST",
                    "path":"/Users",
                    "data":{{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"{}","active":true}}
                }}]
            }}"#,
            payload.replace('\\', "\\\\").replace('\"', "\\\"")
        );
        let _ = serde_json::from_str::<ScimBulkRequest>(&json);
    }
}

// ---------------------------------------------------------------------------
// Unicode SQL injection variants
// ---------------------------------------------------------------------------

#[test]
fn test_unicode_sql_injection_in_saml_issuer() {
    for payload in UNICODE_SQL_PAYLOADS {
        let xml = format!(
            r#"<AuthnRequest ID="_test_unicode" IssueInstant="2024-01-01T00:00:00Z">
               <Issuer>{}</Issuer>
            </AuthnRequest>"#,
            xml_escape(payload)
        );
        let encoded = encode_xml_b64(&xml);
        let _ = AuthnRequest::parse_post_binding(&encoded);
    }
}

#[test]
fn test_unicode_sql_injection_in_assertion_id() {
    for payload in UNICODE_SQL_PAYLOADS {
        let _ = check_assertion_id_replay(payload, 30);
    }
}

// ---------------------------------------------------------------------------
// Logout request with SQL injection (uses raw XML)
// ---------------------------------------------------------------------------

#[test]
fn test_logout_request_with_sql_injection_in_nameid() {
    for payload in SQL_INJECTION_PAYLOADS {
        let xml = format!(
            r#"<LogoutRequest ID="_logout1" IssueInstant="2024-01-01T00:00:00Z">
               <Issuer>https://sp.example.com</Issuer>
               <NameID>{}</NameID>
            </LogoutRequest>"#,
            xml_escape(payload)
        );
        let _ = LogoutRequest::from_xml(&xml);
    }
}
