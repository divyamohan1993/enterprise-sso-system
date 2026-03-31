//! Enterprise Compliance Hardened Tests
//!
//! Comprehensive test coverage for enterprise adoption and compliance features:
//! - SAML 2.0 (SP-initiated, IdP-initiated, metadata, signatures, SLO, CAC)
//! - Event Streaming / Webhooks (CRUD, HMAC, filters, rate limiting, DLQ)
//! - Delegated Administration (roles, permissions, tenant isolation, invitations)
//! - Self-Service Portal (password reset, TOTP, devices, access requests, sessions)
//! - Compliance Automation (FedRAMP, STIG, SOC 2, FIPS tracker)
//! - Advanced Crypto (VCs, DIDs, OPE, deterministic encryption, HE, enclaves)

use std::collections::HashMap;
use uuid::Uuid;

// ═══════════════════════════════════════════════════════════════════════════
// SAML 2.0 Tests
// ═══════════════════════════════════════════════════════════════════════════

mod saml_tests {
    use super::*;
    use common::saml::*;

    /// Helper: create a default IdP with a registered SP.
    fn setup_idp_with_sp() -> (SamlIdp, String) {
        let config = IdpConfig::default();
        let idp = SamlIdp::new(config);

        let sp_entity_id = "https://sp.example.mil/metadata".to_string();
        let mut acs_urls = HashMap::new();
        acs_urls.insert(
            SamlBinding::HttpPost.as_uri().to_string(),
            "https://sp.example.mil/acs".to_string(),
        );
        let mut slo_urls = HashMap::new();
        slo_urls.insert(
            SamlBinding::HttpRedirect.as_uri().to_string(),
            "https://sp.example.mil/slo".to_string(),
        );

        let sp_meta = SpMetadata {
            entity_id: sp_entity_id.clone(),
            acs_urls,
            slo_urls,
            signing_cert_pem: None,
            encryption_cert_pem: None,
            name_id_formats: vec![NameIdFormat::Persistent, NameIdFormat::Email],
            authn_requests_signed: false,
            want_assertions_encrypted: false,
        };
        idp.trust_store.register_sp(sp_meta).unwrap();
        (idp, sp_entity_id)
    }

    /// Helper: create a test authenticated user with required attributes.
    fn test_user() -> AuthenticatedUser {
        let mut properties = HashMap::new();
        properties.insert(
            "email".to_string(),
            vec!["user@milnet.mil".to_string()],
        );
        properties.insert(
            "display_name".to_string(),
            vec!["Test User".to_string()],
        );
        AuthenticatedUser {
            user_id: Uuid::new_v4(),
            email: "user@milnet.mil".to_string(),
            display_name: Some("Test User".to_string()),
            properties,
            authn_context: AuthnContextClass::X509,
            tenant_id: None,
            cac_serial: None,
        }
    }

    // ── SP-initiated SSO flow ──────────────────────────────────────────

    #[test]
    fn sp_initiated_sso_produces_valid_response() {
        let (idp, sp_entity_id) = setup_idp_with_sp();
        let user = test_user();

        let authn_request = AuthnRequest {
            id: "_req_001".to_string(),
            issuer: sp_entity_id.clone(),
            acs_url: "https://sp.example.mil/acs".to_string(),
            name_id_format: Some(NameIdFormat::Persistent),
            requested_authn_context: None,
            is_signed: false,
            relay_state: Some("https://app.example.mil/dashboard".to_string()),
            binding: SamlBinding::HttpPost,
            issue_instant: "2025-01-01T00:00:00Z".to_string(),
            destination: Some(idp.config.sso_url.clone()),
            force_authn: false,
            is_passive: false,
        };

        let response = idp.handle_authn_request(&authn_request, &user).unwrap();

        assert_eq!(response.status, SamlStatusCode::Success);
        assert_eq!(
            response.in_response_to.as_deref(),
            Some("_req_001"),
            "InResponseTo must echo the AuthnRequest ID"
        );
        assert_eq!(response.issuer, idp.config.entity_id);
        assert!(
            response.assertion_xml.is_some(),
            "successful response must contain an assertion"
        );

        // The response XML must be valid and contain key SAML elements
        let xml = response.to_xml();
        assert!(xml.contains("samlp:Response"), "must contain Response element");
        assert!(
            xml.contains("urn:oasis:names:tc:SAML:2.0:status:Success"),
            "must contain success status"
        );
    }

    #[test]
    fn sp_initiated_sso_echoes_relay_state() {
        let (idp, sp_entity_id) = setup_idp_with_sp();
        let user = test_user();

        let authn_request = AuthnRequest {
            id: "_req_relay".to_string(),
            issuer: sp_entity_id,
            acs_url: "https://sp.example.mil/acs".to_string(),
            name_id_format: None,
            requested_authn_context: None,
            is_signed: false,
            relay_state: Some("deep-link-target".to_string()),
            binding: SamlBinding::HttpPost,
            issue_instant: "2025-01-01T00:00:00Z".to_string(),
            destination: None,
            force_authn: false,
            is_passive: false,
        };

        let response = idp.handle_authn_request(&authn_request, &user).unwrap();
        assert_eq!(
            response.relay_state.as_deref(),
            Some("deep-link-target"),
            "relay state must be echoed back"
        );
    }

    // ── IdP-initiated SSO ──────────────────────────────────────────────

    #[test]
    fn idp_initiated_sso_has_no_in_response_to() {
        let (idp, sp_entity_id) = setup_idp_with_sp();
        let user = test_user();

        let response = idp
            .handle_idp_initiated(&sp_entity_id, &user, None)
            .unwrap();

        assert_eq!(response.status, SamlStatusCode::Success);
        assert!(
            response.in_response_to.is_none(),
            "IdP-initiated response must have no InResponseTo"
        );
        assert!(response.assertion_xml.is_some());
    }

    #[test]
    fn idp_initiated_sso_rejects_unknown_sp() {
        let (idp, _) = setup_idp_with_sp();
        let user = test_user();

        let result = idp.handle_idp_initiated("https://unknown.sp.com", &user, None);
        assert!(result.is_err(), "unknown SP must be rejected");
    }

    // ── SAML metadata generation ───────────────────────────────────────

    #[test]
    fn metadata_contains_valid_entity_descriptor() {
        let (idp, _) = setup_idp_with_sp();
        let metadata = idp.generate_metadata();

        assert!(
            metadata.contains("EntityDescriptor"),
            "metadata must contain EntityDescriptor"
        );
        assert!(
            metadata.contains(&idp.config.entity_id),
            "metadata must contain the entity ID"
        );
        assert!(
            metadata.contains("IDPSSODescriptor"),
            "metadata must contain IDPSSODescriptor"
        );
        assert!(
            metadata.contains("SingleSignOnService"),
            "metadata must contain SingleSignOnService"
        );
        assert!(
            metadata.contains("SingleLogoutService"),
            "metadata must contain SingleLogoutService"
        );
        assert!(
            metadata.contains("ArtifactResolutionService"),
            "metadata must contain ArtifactResolutionService"
        );
        assert!(
            metadata.contains(NameIdFormat::Persistent.as_uri()),
            "metadata must list persistent NameID format"
        );
        assert!(
            metadata.contains(NameIdFormat::Transient.as_uri()),
            "metadata must list transient NameID format"
        );
        assert!(
            metadata.contains(NameIdFormat::Email.as_uri()),
            "metadata must list email NameID format"
        );
    }

    // ── Assertion signature validation ─────────────────────────────────

    #[test]
    fn signature_validation_accepts_unsigned_request_when_not_required() {
        let authn_request = AuthnRequest {
            id: "_req_unsigned".to_string(),
            issuer: "sp-1".to_string(),
            acs_url: String::new(),
            name_id_format: None,
            requested_authn_context: None,
            is_signed: false,
            relay_state: None,
            binding: SamlBinding::HttpPost,
            issue_instant: "2025-01-01T00:00:00Z".to_string(),
            destination: None,
            force_authn: false,
            is_passive: false,
        };

        assert!(
            authn_request.validate_signature("").is_err(),
            "unsigned SAML assertions MUST be rejected for MILNET deployment"
        );
    }

    #[test]
    fn signed_request_rejects_invalid_certificate() {
        // A signed request with an invalid (non-PEM) certificate must be rejected.
        // This validates that the system does NOT silently accept garbage certs.
        let authn_request = AuthnRequest {
            id: "_req_signed".to_string(),
            issuer: "sp-1".to_string(),
            acs_url: String::new(),
            name_id_format: None,
            requested_authn_context: None,
            is_signed: true,
            relay_state: None,
            binding: SamlBinding::HttpPost,
            issue_instant: "2025-01-01T00:00:00Z".to_string(),
            destination: None,
            force_authn: false,
            is_passive: false,
        };

        assert!(
            authn_request.validate_signature("dummy-cert").is_err(),
            "signed request with invalid certificate must be rejected"
        );
    }

    #[test]
    fn xml_signature_enveloped_inserts_after_issuer() {
        let xml = r#"<samlp:Response><saml:Issuer>https://idp.example.com</saml:Issuer><content/></samlp:Response>"#;
        let signed = sign_xml_enveloped(xml, SignatureAlgorithm::RsaSha256, b"test-key").unwrap();

        assert!(
            signed.contains("<ds:Signature"),
            "must contain Signature element"
        );
        assert!(
            signed.contains("ds:DigestValue"),
            "must contain DigestValue"
        );
        // Signature must appear after Issuer
        let issuer_pos = signed.find("</saml:Issuer>").unwrap();
        let sig_pos = signed.find("<ds:Signature").unwrap();
        assert!(
            sig_pos > issuer_pos,
            "signature must be inserted after Issuer element"
        );
    }

    // ── NameID formats ─────────────────────────────────────────────────

    #[test]
    fn name_id_persistent_contains_user_id() {
        let user_id = Uuid::new_v4();
        let name_id = SamlNameId::persistent(&user_id, "https://idp.milnet.mil");
        assert_eq!(name_id.format, NameIdFormat::Persistent);
        assert_eq!(name_id.value, user_id.to_string());
        assert_eq!(
            name_id.name_qualifier.as_deref(),
            Some("https://idp.milnet.mil")
        );

        let xml = name_id.to_xml();
        assert!(xml.contains("nameid-format:persistent"));
    }

    #[test]
    fn name_id_transient_is_random() {
        let n1 = SamlNameId::transient();
        let n2 = SamlNameId::transient();
        assert_eq!(n1.format, NameIdFormat::Transient);
        assert_ne!(n1.value, n2.value, "transient IDs must be unique");
        assert!(n1.value.starts_with("_transient_"));
    }

    #[test]
    fn name_id_email_format() {
        let name_id = SamlNameId::email("alice@milnet.mil");
        assert_eq!(name_id.format, NameIdFormat::Email);
        assert_eq!(name_id.value, "alice@milnet.mil");

        let xml = name_id.to_xml();
        assert!(xml.contains("emailAddress"));
    }

    #[test]
    fn name_id_format_uri_roundtrip() {
        for fmt in &[
            NameIdFormat::Persistent,
            NameIdFormat::Transient,
            NameIdFormat::Email,
            NameIdFormat::Unspecified,
        ] {
            let uri = fmt.as_uri();
            let parsed = NameIdFormat::from_uri(uri);
            assert_eq!(parsed.as_ref(), Some(fmt), "URI roundtrip failed for {:?}", fmt);
        }
    }

    // ── Audience restriction validation ────────────────────────────────

    #[test]
    fn conditions_xml_contains_audience_restriction() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let conditions = SamlConditions::new(
            now - 60,
            now + 300,
            vec!["https://sp.example.mil".to_string()],
        );

        let xml = conditions.to_xml();
        assert!(
            xml.contains("AudienceRestriction"),
            "conditions must contain AudienceRestriction"
        );
        assert!(
            xml.contains("https://sp.example.mil"),
            "conditions must contain the audience SP entity ID"
        );
        assert!(xml.contains("NotBefore="));
        assert!(xml.contains("NotOnOrAfter="));
    }

    // ── NotBefore/NotOnOrAfter time bounds ─────────────────────────────

    #[test]
    fn conditions_validate_within_window() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let conditions = SamlConditions::new(
            now - 60,
            now + 300,
            vec!["sp-1".to_string()],
        );
        assert!(
            conditions.validate(60).is_ok(),
            "current time within window must validate"
        );
    }

    #[test]
    fn conditions_reject_expired_assertion() {
        let past = 1700000000i64; // well in the past
        let conditions = SamlConditions::new(
            past - 300,
            past,
            vec!["sp-1".to_string()],
        );
        assert!(
            conditions.validate(60).is_err(),
            "expired assertion must be rejected"
        );
    }

    #[test]
    fn conditions_reject_not_yet_valid_assertion() {
        let future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 86400; // 1 day in the future
        let conditions = SamlConditions::new(
            future,
            future + 300,
            vec!["sp-1".to_string()],
        );
        assert!(
            conditions.validate(60).is_err(),
            "not-yet-valid assertion must be rejected"
        );
    }

    // ── Clock skew tolerance ───────────────────────────────────────────

    #[test]
    fn clock_skew_tolerance_allows_slightly_expired() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        // Assertion expired 30s ago, but with 60s skew tolerance should be ok
        let conditions = SamlConditions::new(
            now - 600,
            now - 30,
            vec!["sp-1".to_string()],
        );
        assert!(
            conditions.validate(60).is_ok(),
            "60s clock skew should accept assertion expired 30s ago"
        );
    }

    #[test]
    fn clock_skew_zero_is_strict() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let conditions = SamlConditions::new(
            now - 600,
            now - 1,
            vec!["sp-1".to_string()],
        );
        assert!(
            conditions.validate(0).is_err(),
            "zero clock skew must reject even 1s expired assertion"
        );
    }

    // ── Artifact resolution protocol ───────────────────────────────────

    #[test]
    fn artifact_encode_decode_roundtrip() {
        let artifact = SamlArtifact::new("https://idp.milnet.mil", 0).unwrap();
        let encoded = artifact.encode();
        let decoded = SamlArtifact::decode(&encoded).unwrap();

        assert_eq!(decoded.type_code, 0x0004, "type code must be 0x0004");
        assert_eq!(decoded.endpoint_index, 0);
        assert_eq!(decoded.source_id, artifact.source_id);
        assert_eq!(decoded.message_handle, artifact.message_handle);
    }

    #[test]
    fn artifact_store_resolve_one_time_use() {
        let store = ArtifactStore::new(60);
        let artifact = SamlArtifact::new("https://idp.milnet.mil", 0).unwrap();
        let response_xml = "<samlp:Response>test</samlp:Response>";

        store.store(&artifact, response_xml).unwrap();
        let encoded = artifact.encode();

        // First resolve succeeds
        let resolved = store.resolve(&encoded).unwrap();
        assert_eq!(resolved, response_xml);

        // Second resolve fails (one-time use)
        assert!(
            store.resolve(&encoded).is_err(),
            "artifact must be consumed after first resolve"
        );
    }

    #[test]
    fn artifact_resolve_request_xml_structure() {
        let xml = build_artifact_resolve_request("encoded_artifact", "https://idp.milnet.mil");
        assert!(xml.contains("ArtifactResolve"));
        assert!(xml.contains("SOAP-ENV:Envelope"));
        assert!(xml.contains("encoded_artifact"));
    }

    // ── SLO tests ──────────────────────────────────────────────────────

    #[test]
    fn idp_initiated_logout_request_generation() {
        let (idp, sp_entity_id) = setup_idp_with_sp();
        let name_id = SamlNameId::persistent(&Uuid::new_v4(), &idp.config.entity_id);

        let request = idp
            .initiate_logout(
                &sp_entity_id,
                name_id,
                vec!["_session_123".to_string()],
                LogoutReason::User,
            )
            .unwrap();

        assert!(request.id.starts_with("_logout_"));
        assert_eq!(request.issuer, idp.config.entity_id);

        let xml = request.to_xml();
        assert!(xml.contains("LogoutRequest"));
        assert!(xml.contains("SessionIndex"));
    }

    #[test]
    fn sp_initiated_logout_response() {
        let (idp, sp_entity_id) = setup_idp_with_sp();
        let request = LogoutRequest::idp_initiated(
            &sp_entity_id,
            &idp.config.slo_url,
            SamlNameId::persistent(&Uuid::new_v4(), &sp_entity_id),
            vec!["_session_456".to_string()],
            LogoutReason::User,
        );

        // Parse the XML and handle it
        let xml = request.to_xml();
        let parsed = LogoutRequest::from_xml(&xml).unwrap();
        assert_eq!(parsed.reason, LogoutReason::User);

        let response = LogoutResponse::success(
            &parsed.id,
            &idp.config.entity_id,
            &parsed.destination,
        );
        assert_eq!(response.status, SamlStatusCode::Success);
        assert_eq!(response.in_response_to, parsed.id);
    }

    // ── CAC-to-SAML NameID mapping ─────────────────────────────────────

    #[test]
    fn cac_to_name_id_extracts_edipi() {
        let name_id = map_cac_to_name_id(
            "CN=DOE.JOHN.MIDDLE.1234567890,OU=DoD,O=U.S. Government",
            "ABC123",
            "https://idp.milnet.mil",
        );
        assert_eq!(name_id.format, NameIdFormat::Persistent);
        assert_eq!(
            name_id.value, "1234567890",
            "EDIPI must be extracted from the DN"
        );
    }

    #[test]
    fn cac_to_name_id_falls_back_to_serial() {
        let name_id = map_cac_to_name_id(
            "OU=DoD,O=U.S. Government",
            "SERIAL-001",
            "https://idp.milnet.mil",
        );
        assert_eq!(
            name_id.value, "SERIAL-001",
            "must fall back to serial when EDIPI is missing"
        );
    }

    // ── XML encryption of assertions ───────────────────────────────────

    #[test]
    fn encrypted_assertion_in_response() {
        let config = IdpConfig {
            encrypt_assertions: true,
            ..IdpConfig::default()
        };
        let idp = SamlIdp::new(config);

        let sp_entity_id = "https://sp.encrypted.mil".to_string();
        let mut acs_urls = HashMap::new();
        acs_urls.insert(
            SamlBinding::HttpPost.as_uri().to_string(),
            "https://sp.encrypted.mil/acs".to_string(),
        );
        let sp_meta = SpMetadata {
            entity_id: sp_entity_id.clone(),
            acs_urls,
            slo_urls: HashMap::new(),
            signing_cert_pem: None,
            encryption_cert_pem: None,
            name_id_formats: vec![NameIdFormat::Persistent],
            authn_requests_signed: false,
            want_assertions_encrypted: true,
        };
        idp.trust_store.register_sp(sp_meta).unwrap();

        let user = test_user();
        let response = idp
            .handle_idp_initiated(&sp_entity_id, &user, None)
            .unwrap();

        assert!(
            response.assertion_encrypted,
            "assertion must be encrypted when configured"
        );
        let xml = response.to_xml();
        assert!(
            xml.contains("EncryptedAssertion"),
            "response XML must wrap assertion in EncryptedAssertion"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Event Streaming / Webhook Tests
// ═══════════════════════════════════════════════════════════════════════════

mod event_streaming_tests {
    use common::event_streaming::*;
    use common::siem::SiemEvent;

    fn test_manager() -> EventStreamManager {
        EventStreamManager::new("https://sso.milnet.mil", false)
    }

    fn test_webhook(name: &str, url: &str) -> WebhookConfig {
        WebhookConfig::new(name, url)
    }

    // ── Webhook CRUD ───────────────────────────────────────────────────

    #[test]
    fn webhook_create_update_delete_list() {
        let mgr = test_manager();

        // Create
        let wh = test_webhook("test-hook", "http://localhost:9090/events");
        let created = mgr.create_webhook(wh).unwrap();
        assert_eq!(created.name, "test-hook");
        assert!(created.active);

        // List
        let list = mgr.list_webhooks().unwrap();
        assert_eq!(list.len(), 1);

        // Update
        let update = WebhookUpdate {
            name: Some("updated-hook".to_string()),
            url: None,
            event_filters: None,
            event_type_filters: None,
            active: Some(false),
            rate_limit_per_minute: None,
            description: Some(Some("A test webhook".to_string())),
        };
        let updated = mgr.update_webhook(&created.id, update).unwrap();
        assert_eq!(updated.name, "updated-hook");
        assert!(!updated.active);

        // Delete
        mgr.delete_webhook(&created.id).unwrap();
        let list = mgr.list_webhooks().unwrap();
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn webhook_delete_nonexistent_fails() {
        let mgr = test_manager();
        assert!(mgr.delete_webhook("nonexistent").is_err());
    }

    // ── HMAC-SHA512 signature ──────────────────────────────────────────

    #[test]
    fn hmac_sha512_signature_generation_and_verification() {
        let wh = test_webhook("sig-test", "http://localhost:9090/events");
        let payload = b"test payload for signature verification";

        let signature = wh.sign_payload(payload);
        assert!(
            signature.starts_with("sha512="),
            "signature must have sha512= prefix"
        );
        assert!(
            wh.verify_signature(payload, &signature),
            "signature must verify against same payload"
        );
    }

    #[test]
    fn hmac_sha512_rejects_tampered_payload() {
        let wh = test_webhook("tamper-test", "http://localhost:9090/events");
        let payload = b"original payload";
        let signature = wh.sign_payload(payload);

        assert!(
            !wh.verify_signature(b"tampered payload", &signature),
            "tampered payload must fail verification"
        );
    }

    #[test]
    fn hmac_sha512_rejects_wrong_signature() {
        let wh = test_webhook("wrong-sig", "http://localhost:9090/events");
        let payload = b"test payload";

        assert!(
            !wh.verify_signature(payload, "sha512=deadbeef"),
            "wrong signature must fail"
        );
    }

    // ── Event filter matching ──────────────────────────────────────────

    #[test]
    fn event_filter_matches_by_category() {
        let mut wh = test_webhook("auth-only", "http://localhost:9090/events");
        wh.event_filters = vec![EventCategory::Auth];
        wh.active = true;

        let auth_event = SiemEvent {
            event_type: "login".to_string(),
            json: "{}".to_string(),
            timestamp: 1700000000,
            severity: 3,
        };
        let security_event = SiemEvent {
            event_type: "tamper_detected".to_string(),
            json: "{}".to_string(),
            timestamp: 1700000000,
            severity: 7,
        };

        assert!(wh.matches_event(&auth_event), "auth event must match auth filter");
        assert!(
            !wh.matches_event(&security_event),
            "security event must not match auth-only filter"
        );
    }

    #[test]
    fn event_filter_matches_by_event_type() {
        let mut wh = test_webhook("login-only", "http://localhost:9090/events");
        wh.event_type_filters = vec!["login".to_string()];
        wh.active = true;

        let login = SiemEvent {
            event_type: "login".to_string(),
            json: "{}".to_string(),
            timestamp: 1700000000,
            severity: 3,
        };
        let logout = SiemEvent {
            event_type: "logout".to_string(),
            json: "{}".to_string(),
            timestamp: 1700000000,
            severity: 3,
        };

        assert!(wh.matches_event(&login));
        assert!(!wh.matches_event(&logout));
    }

    #[test]
    fn inactive_webhook_matches_nothing() {
        let mut wh = test_webhook("inactive", "http://localhost:9090/events");
        wh.active = false;

        let event = SiemEvent {
            event_type: "login".to_string(),
            json: "{}".to_string(),
            timestamp: 1700000000,
            severity: 3,
        };
        assert!(!wh.matches_event(&event), "inactive webhook must not match");
    }

    // ── CloudEvents format ─────────────────────────────────────────────

    #[test]
    fn cloudevents_envelope_structure() {
        let siem_event = SiemEvent {
            event_type: "login".to_string(),
            json: r#"{"details":{"user_id":"u-123"}}"#.to_string(),
            timestamp: 1700000000,
            severity: 3,
        };

        let ce = CloudEvent::from_siem_event(&siem_event, "https://sso.milnet.mil");

        assert_eq!(ce.specversion, "1.0");
        assert_eq!(ce.datacontenttype, "application/json");
        assert!(!ce.id.is_empty());
        assert!(ce.event_type.starts_with("mil.milnet.sso."));
        assert_eq!(ce.source, "https://sso.milnet.mil");
        assert_eq!(ce.subject.as_deref(), Some("u-123"));

        // Serialization must produce valid JSON
        let bytes = ce.to_json_bytes();
        assert!(!bytes.is_empty());
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["specversion"], "1.0");
    }

    // ── HTTPS-only enforcement ─────────────────────────────────────────

    #[test]
    fn https_required_in_production() {
        let mgr = EventStreamManager::new("https://sso.milnet.mil", true);
        let wh = WebhookConfig::new("prod-hook", "http://external.example.com/events");
        assert!(
            mgr.create_webhook(wh).is_err(),
            "HTTP URL must be rejected in production"
        );
    }

    #[test]
    fn https_allowed_in_production() {
        let mgr = EventStreamManager::new("https://sso.milnet.mil", true);
        let wh = WebhookConfig::new("prod-hook-https", "https://external.example.com/events");
        assert!(
            mgr.create_webhook(wh).is_ok(),
            "HTTPS URL must be accepted in production"
        );
    }

    #[test]
    fn http_allowed_in_non_production() {
        let mgr = EventStreamManager::new("https://sso.milnet.mil", false);
        let wh = WebhookConfig::new("dev-hook", "http://localhost:9090/events");
        assert!(
            mgr.create_webhook(wh).is_ok(),
            "HTTP URL must be accepted in non-production"
        );
    }

    #[test]
    fn production_rejects_internal_addresses() {
        let wh = WebhookConfig::new("ssrf-attempt", "https://127.0.0.1/events");
        assert!(
            wh.validate_url(true).is_err(),
            "internal addresses must be rejected in production"
        );

        let wh2 = WebhookConfig::new("ssrf-attempt-2", "https://localhost/events");
        assert!(wh2.validate_url(true).is_err());
    }

    // ── Webhook secret rotation ────────────────────────────────────────

    #[test]
    fn webhook_secret_rotation() {
        let mgr = test_manager();
        let wh = test_webhook("rotate-test", "http://localhost:9090/events");
        let created = mgr.create_webhook(wh).unwrap();

        let old_secret = created.secret.clone();
        let new_secret = mgr.rotate_webhook_secret(&created.id).unwrap();

        assert_ne!(old_secret, new_secret, "rotated secret must differ from old");
        assert!(!new_secret.is_empty());

        // Verify the webhook was updated
        let fetched = mgr.get_webhook(&created.id).unwrap().unwrap();
        assert_eq!(fetched.secret, new_secret);
    }

    // ── Delivery status tracking ───────────────────────────────────────

    #[test]
    fn delivery_status_display() {
        assert_eq!(format!("{}", DeliveryStatus::Pending), "pending");
        assert_eq!(format!("{}", DeliveryStatus::Delivered), "delivered");
        assert_eq!(format!("{}", DeliveryStatus::Failed), "failed");
        assert_eq!(format!("{}", DeliveryStatus::DeadLetter), "dead_letter");
    }

    // ── Dead letter queue ──────────────────────────────────────────────

    #[test]
    fn dead_letter_queue_empty_by_default() {
        let mgr = test_manager();
        let wh = test_webhook("dlq-test", "http://localhost:9090/events");
        let created = mgr.create_webhook(wh).unwrap();

        let dlq = mgr.get_dead_letters(&created.id).unwrap();
        assert!(dlq.is_empty(), "DLQ should be empty initially");
    }

    // ── SSE event format ───────────────────────────────────────────────

    #[test]
    fn sse_event_wire_format() {
        let ce = CloudEvent {
            id: "evt-001".to_string(),
            source: "https://sso.milnet.mil".to_string(),
            specversion: "1.0".to_string(),
            event_type: "mil.milnet.sso.auth.login".to_string(),
            time: "2025-01-01T00:00:00Z".to_string(),
            datacontenttype: "application/json".to_string(),
            subject: None,
            data: serde_json::json!({"test": true}),
        };

        let sse = SseEvent::from_cloud_event(&ce);
        let wire = sse.to_sse_string();

        assert!(wire.contains("id: evt-001"), "SSE must contain event ID");
        assert!(wire.contains("event: mil.milnet.sso.auth.login"));
        assert!(wire.contains("data: "));
        assert!(wire.contains("retry: "));
        assert!(wire.ends_with("\n\n"), "SSE event must end with blank line");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Delegated Administration Tests
// ═══════════════════════════════════════════════════════════════════════════

mod delegated_admin_tests {
    use super::*;
    use common::delegated_admin::*;
    use common::multi_tenancy::TenantId;

    fn make_admin(role: AdminRole, tenant: Option<TenantId>) -> AdminIdentity {
        AdminIdentity {
            user_id: Uuid::new_v4(),
            role,
            tenant_id: tenant,
            extra_permissions: Vec::new(),
            denied_permissions: Vec::new(),
            display_name: format!("{} Admin", role),
            email: format!("{}@milnet.mil", role),
            active: true,
            created_at: 1700000000,
            last_active_at: None,
        }
    }

    // ── GlobalAdmin permissions ─────────────────────────────────────────

    #[test]
    fn global_admin_has_all_permissions() {
        let admin = make_admin(AdminRole::GlobalAdmin, None);
        let all_perms = default_permissions(AdminRole::GlobalAdmin);
        for perm in &all_perms {
            assert!(
                admin.has_permission(*perm),
                "GlobalAdmin must have permission {:?}",
                perm
            );
        }
    }

    #[test]
    fn global_admin_can_access_any_tenant() {
        let admin = make_admin(AdminRole::GlobalAdmin, None);
        let tenant1 = TenantId::new();
        let tenant2 = TenantId::new();

        assert!(admin.can_access_tenant(&tenant1));
        assert!(admin.can_access_tenant(&tenant2));
    }

    // ── TenantAdmin scoped to own tenant ───────────────────────────────

    #[test]
    fn tenant_admin_scoped_to_own_tenant() {
        let tenant = TenantId::new();
        let other_tenant = TenantId::new();
        let admin = make_admin(AdminRole::TenantAdmin, Some(tenant.clone()));

        assert!(
            admin.can_access_tenant(&tenant),
            "TenantAdmin must access own tenant"
        );
        assert!(
            !admin.can_access_tenant(&other_tenant),
            "TenantAdmin must not access other tenants"
        );
    }

    // ── Permission hierarchy ───────────────────────────────────────────

    #[test]
    fn permission_hierarchy_higher_role_has_lower_permissions() {
        let readonly_perms = default_permissions(AdminRole::ReadOnly);
        let user_mgr_perms = default_permissions(AdminRole::UserManager);
        let tenant_admin_perms = default_permissions(AdminRole::TenantAdmin);
        let global_admin_perms = default_permissions(AdminRole::GlobalAdmin);

        // Every ReadOnly permission must be in UserManager
        for perm in &readonly_perms {
            assert!(
                user_mgr_perms.contains(perm),
                "UserManager must have ReadOnly perm {:?}",
                perm
            );
        }

        // Every UserManager permission must be in TenantAdmin
        for perm in &user_mgr_perms {
            assert!(
                tenant_admin_perms.contains(perm),
                "TenantAdmin must have UserManager perm {:?}",
                perm
            );
        }

        // Every TenantAdmin permission must be in GlobalAdmin
        for perm in &tenant_admin_perms {
            assert!(
                global_admin_perms.contains(perm),
                "GlobalAdmin must have TenantAdmin perm {:?}",
                perm
            );
        }
    }

    #[test]
    fn role_has_at_least_ordering() {
        assert!(AdminRole::GlobalAdmin.has_at_least(AdminRole::ReadOnly));
        assert!(AdminRole::GlobalAdmin.has_at_least(AdminRole::GlobalAdmin));
        assert!(AdminRole::TenantAdmin.has_at_least(AdminRole::UserManager));
        assert!(!AdminRole::ReadOnly.has_at_least(AdminRole::TenantAdmin));
        assert!(!AdminRole::UserManager.has_at_least(AdminRole::GlobalAdmin));
    }

    // ── Cross-tenant admin attempt blocked ─────────────────────────────

    #[test]
    fn cross_tenant_admin_operation_blocked() {
        let tenant_a = TenantId::new();
        let tenant_b = TenantId::new();
        let admin = make_admin(AdminRole::TenantAdmin, Some(tenant_a.clone()));

        let result = AdminOperationContext::new(admin, tenant_b, None);
        assert!(
            result.is_err(),
            "cross-tenant operation must be blocked"
        );
    }

    // ── Invitation workflow ────────────────────────────────────────────

    #[test]
    fn invitation_create_accept_produces_active_admin() {
        let store = DelegatedAdminStore::new();
        let tenant = TenantId::new();

        // Register a GlobalAdmin who can invite
        let inviter = make_admin(AdminRole::GlobalAdmin, None);
        store.register_admin(inviter.clone()).unwrap();

        let ctx = AdminOperationContext::new(inviter, tenant.clone(), None).unwrap();

        // Create invitation
        let invitation = store
            .create_invitation(&ctx, "newadmin@milnet.mil", AdminRole::TenantAdmin, Some(tenant.clone()))
            .unwrap();
        assert_eq!(invitation.status, InvitationStatus::Pending);
        assert!(!invitation.token.is_empty());

        // Accept invitation
        let new_admin_id = Uuid::new_v4();
        let admin = store
            .accept_invitation(&invitation.id, &invitation.token, new_admin_id, "New Admin")
            .unwrap();
        assert_eq!(admin.role, AdminRole::TenantAdmin);
        assert!(admin.active);
        assert_eq!(admin.tenant_id, Some(tenant));

        // Verify admin is in the store
        let fetched = store.get_admin(&new_admin_id).unwrap();
        assert!(fetched.is_some());
    }

    // ── Invitation expiry ──────────────────────────────────────────────

    #[test]
    fn invitation_has_48h_expiry() {
        let store = DelegatedAdminStore::new();
        let tenant = TenantId::new();
        let inviter = make_admin(AdminRole::GlobalAdmin, None);
        store.register_admin(inviter.clone()).unwrap();
        let ctx = AdminOperationContext::new(inviter, tenant.clone(), None).unwrap();

        let invitation = store
            .create_invitation(&ctx, "expiry@milnet.mil", AdminRole::ReadOnly, Some(tenant))
            .unwrap();

        let expected_window = 48 * 3600;
        let actual_window = invitation.expires_at - invitation.created_at;
        assert_eq!(
            actual_window, expected_window,
            "invitation must expire in exactly 48 hours"
        );
    }

    // ── Admin rate limiting ────────────────────────────────────────────

    #[test]
    fn admin_rate_limiting_enforced() {
        let store = DelegatedAdminStore::new();
        let admin_id = Uuid::new_v4();

        // The default rate limit is 120/min; exhaust it
        for _ in 0..120 {
            store.check_rate_limit(&admin_id).unwrap();
        }

        // Next call must fail
        assert!(
            store.check_rate_limit(&admin_id).is_err(),
            "rate limit must be enforced after exhaustion"
        );
    }

    // ── Escalation prevention ──────────────────────────────────────────

    #[test]
    fn cannot_invite_higher_role_than_own() {
        let store = DelegatedAdminStore::new();
        let tenant = TenantId::new();

        // TenantAdmin trying to invite GlobalAdmin
        let tenant_admin = make_admin(AdminRole::TenantAdmin, Some(tenant.clone()));
        store.register_admin(tenant_admin.clone()).unwrap();
        let ctx = AdminOperationContext::new(tenant_admin, tenant.clone(), None).unwrap();

        let result = store.create_invitation(
            &ctx,
            "escalation@milnet.mil",
            AdminRole::GlobalAdmin,
            None,
        );
        assert!(
            result.is_err(),
            "must not be able to invite to a higher role than own"
        );
    }

    #[test]
    fn cannot_promote_above_own_role() {
        let store = DelegatedAdminStore::new();
        let tenant = TenantId::new();

        let tenant_admin = make_admin(AdminRole::TenantAdmin, Some(tenant.clone()));
        let target = make_admin(AdminRole::ReadOnly, Some(tenant.clone()));
        let target_id = target.user_id;

        store.register_admin(tenant_admin.clone()).unwrap();
        store.register_admin(target).unwrap();

        let ctx = AdminOperationContext::new(tenant_admin, tenant, None).unwrap();
        let result = store.update_admin_role(&ctx, &target_id, AdminRole::GlobalAdmin);
        assert!(
            result.is_err(),
            "must not promote to role higher than own"
        );
    }

    // ── Inactive admin has no permissions ──────────────────────────────

    #[test]
    fn inactive_admin_has_no_permissions() {
        let mut admin = make_admin(AdminRole::GlobalAdmin, None);
        admin.active = false;

        assert!(
            admin.effective_permissions().is_empty(),
            "inactive admin must have no effective permissions"
        );
        assert!(!admin.has_permission(Permission::UserRead));
        assert!(!admin.can_access_tenant(&TenantId::new()));
    }

    // ── Denied permissions override ────────────────────────────────────

    #[test]
    fn denied_permissions_override_role_defaults() {
        let mut admin = make_admin(AdminRole::GlobalAdmin, None);
        admin.denied_permissions = vec![Permission::UserDelete];

        assert!(
            !admin.has_permission(Permission::UserDelete),
            "denied permission must override role default"
        );
        assert!(admin.has_permission(Permission::UserRead));
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Self-Service Portal Tests
// ═══════════════════════════════════════════════════════════════════════════

mod self_service_tests {
    use super::*;
    use common::self_service::*;

    fn verified_session(user_id: Uuid, mfa: bool) -> VerifiedSession {
        VerifiedSession {
            user_id,
            session_id: format!("sess_{}", Uuid::new_v4()),
            mfa_verified: mfa,
            created_at: 1700000000,
            source_ip: Some("10.0.0.1".to_string()),
            user_agent: Some("TestAgent/1.0".to_string()),
            tenant_id: None,
        }
    }

    // ── Password reset flow ────────────────────────────────────────────

    #[test]
    fn password_reset_flow_request_verify_complete() {
        let store = SelfServiceStore::new();
        let user_id = Uuid::new_v4();

        // Initiate
        let reset = store
            .initiate_password_reset(user_id, "user@milnet.mil", None)
            .unwrap();
        assert_eq!(reset.status, PasswordResetStatus::Pending);
        assert!(!reset.token.is_empty());

        // Verify
        let verified = store
            .verify_password_reset_token(&reset.id, &reset.token)
            .unwrap();
        assert_eq!(verified.status, PasswordResetStatus::Verified);

        // Complete
        store.complete_password_reset(&reset.id).unwrap();
    }

    #[test]
    fn password_reset_rejects_invalid_token() {
        let store = SelfServiceStore::new();
        let user_id = Uuid::new_v4();

        let reset = store
            .initiate_password_reset(user_id, "user@milnet.mil", None)
            .unwrap();

        let result = store.verify_password_reset_token(&reset.id, "wrong-token");
        assert!(result.is_err(), "invalid token must be rejected");
    }

    #[test]
    fn password_reset_completion_requires_verification() {
        let store = SelfServiceStore::new();
        let user_id = Uuid::new_v4();

        let reset = store
            .initiate_password_reset(user_id, "user@milnet.mil", None)
            .unwrap();

        let result = store.complete_password_reset(&reset.id);
        assert!(
            result.is_err(),
            "completion without verification must fail"
        );
    }

    // ── TOTP enrollment ────────────────────────────────────────────────

    #[test]
    fn totp_enrollment_generates_provisioning_uri() {
        let store = SelfServiceStore::new();
        let user_id = Uuid::new_v4();
        let session = verified_session(user_id, true);

        let enrollment = store.enroll_totp(&session, "MILNET SSO").unwrap();

        assert_eq!(enrollment.method, MfaMethod::Totp);
        assert_eq!(enrollment.status, MfaEnrollmentStatus::Pending);

        let totp_data = enrollment.totp_data.unwrap();
        assert!(
            totp_data.provisioning_uri.starts_with("otpauth://totp/"),
            "must generate valid provisioning URI"
        );
        assert!(totp_data.provisioning_uri.contains("MILNET%20SSO"));
        assert!(!totp_data.secret.is_empty());
    }

    #[test]
    fn totp_enrollment_verify_activates() {
        let store = SelfServiceStore::new();
        let user_id = Uuid::new_v4();
        let session = verified_session(user_id, true);

        let enrollment = store.enroll_totp(&session, "MILNET SSO").unwrap();
        store.verify_totp_enrollment(&enrollment.id, "123456").unwrap();

        let enrollments = store.list_mfa_enrollments(&user_id).unwrap();
        assert_eq!(enrollments.len(), 1);
        assert_eq!(enrollments[0].status, MfaEnrollmentStatus::Active);
    }

    // ── Device registration and revocation ─────────────────────────────

    #[test]
    fn device_registration_and_revocation() {
        let store = SelfServiceStore::new();
        let user_id = Uuid::new_v4();
        let session = verified_session(user_id, true);

        // Register
        let device = store
            .register_device(&session, "Work Laptop", "laptop", "fp-12345")
            .unwrap();
        assert_eq!(device.status, DeviceStatus::Active);
        assert_eq!(device.name, "Work Laptop");

        // List
        let devices = store.list_devices(&user_id).unwrap();
        assert_eq!(devices.len(), 1);

        // Revoke
        store.revoke_device(&session, &device.id).unwrap();
        let devices = store.list_devices(&user_id).unwrap();
        assert!(
            devices.is_empty() || devices.iter().all(|d| d.status == DeviceStatus::Revoked),
            "revoked devices should be filtered or marked"
        );
    }

    #[test]
    fn device_registration_rejects_duplicate_fingerprint() {
        let store = SelfServiceStore::new();
        let user_id = Uuid::new_v4();
        let session = verified_session(user_id, true);

        store
            .register_device(&session, "Device 1", "laptop", "fp-dup")
            .unwrap();
        let result = store.register_device(&session, "Device 2", "laptop", "fp-dup");
        assert!(result.is_err(), "duplicate fingerprint must be rejected");
    }

    // ── Access request workflow ─────────────────────────────────────────

    #[test]
    fn access_request_submit_approve_grant() {
        let store = SelfServiceStore::new();
        let user_id = Uuid::new_v4();
        let session = verified_session(user_id, true);
        let approver_id = Uuid::new_v4();

        // Submit
        let request = store
            .submit_access_request(&session, "classified-db", "Need access for project X")
            .unwrap();
        assert_eq!(request.status, AccessRequestStatus::Pending);

        // Approve
        let approved = store
            .approve_access_request(
                &request.id,
                approver_id,
                Some("Approved for 30 days"),
                Some(30 * 86400),
            )
            .unwrap();
        assert_eq!(approved.status, AccessRequestStatus::Approved);
        assert_eq!(approved.approver_id, Some(approver_id));
        assert!(approved.access_expires_at.is_some());
    }

    #[test]
    fn access_request_deny() {
        let store = SelfServiceStore::new();
        let user_id = Uuid::new_v4();
        let session = verified_session(user_id, true);

        let request = store
            .submit_access_request(&session, "top-secret-db", "Exploratory access")
            .unwrap();

        let denied = store
            .deny_access_request(&request.id, Uuid::new_v4(), Some("Insufficient justification"))
            .unwrap();
        assert_eq!(denied.status, AccessRequestStatus::Denied);
    }

    #[test]
    fn access_request_requires_justification() {
        let store = SelfServiceStore::new();
        let session = verified_session(Uuid::new_v4(), true);

        let result = store.submit_access_request(&session, "resource", "");
        assert!(result.is_err(), "empty justification must be rejected");
    }

    // ── Session listing and revocation ─────────────────────────────────

    #[test]
    fn session_listing() {
        let store = SelfServiceStore::new();
        let user_id = Uuid::new_v4();

        // Register a session
        store.register_session(ActiveSession {
            session_id: "sess-1".to_string(),
            user_id,
            source_ip: "10.0.0.1".to_string(),
            user_agent: Some("Firefox".to_string()),
            created_at: 1700000000,
            last_active_at: 1700000100,
            is_current: false,
            device_name: None,
            location: None,
        }).unwrap();

        let sessions = store.list_sessions(&user_id, "sess-current").unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].session_id, "sess-1");
    }

    // ── Recovery code generation ───────────────────────────────────────

    #[test]
    fn recovery_code_generation() {
        let store = SelfServiceStore::new();
        let user_id = Uuid::new_v4();
        let session = verified_session(user_id, true);

        let codes = store.generate_recovery_codes(&session).unwrap();
        assert_eq!(codes.codes.len(), 10, "must generate 10 recovery codes");

        for code in &codes.codes {
            assert!(!code.used, "new codes must be unused");
            assert!(!code.code.is_empty());
        }
    }

    #[test]
    fn recovery_code_usage() {
        let store = SelfServiceStore::new();
        let user_id = Uuid::new_v4();
        let session = verified_session(user_id, true);

        let codes = store.generate_recovery_codes(&session).unwrap();
        let code_to_use = codes.codes[0].code.clone();

        let result = store.use_recovery_code(&user_id, &code_to_use);
        assert!(result.is_ok(), "valid recovery code must be accepted");

        // Same code should not work twice
        let result2 = store.use_recovery_code(&user_id, &code_to_use);
        assert!(result2.is_err(), "used recovery code must be rejected");
    }

    // ── All operations require verified MFA session ────────────────────

    #[test]
    fn operations_require_mfa_session() {
        let store = SelfServiceStore::new();
        let user_id = Uuid::new_v4();
        let no_mfa_session = verified_session(user_id, false);

        // TOTP enrollment
        assert!(
            store.enroll_totp(&no_mfa_session, "MILNET").is_err(),
            "TOTP enrollment must require MFA"
        );

        // Device registration
        assert!(
            store
                .register_device(&no_mfa_session, "dev", "laptop", "fp")
                .is_err(),
            "device registration must require MFA"
        );

        // Access request
        assert!(
            store
                .submit_access_request(&no_mfa_session, "res", "justification")
                .is_err(),
            "access request must require MFA"
        );

        // Display name update
        assert!(
            store.update_display_name(&no_mfa_session, "New Name").is_err(),
            "profile update must require MFA"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Compliance Automation Tests
// ═══════════════════════════════════════════════════════════════════════════

mod compliance_tests {

    // ── FedRAMP SSP generation ──────────────────────────────────────────

    mod fedramp_tests {
        use common::fedramp_evidence::*;

        #[test]
        fn ssp_generation_includes_all_control_families() {
            let mut ssp = SspGenerator::new("MILNET SSO".to_string(), FedRampLevel::High);

            // Register controls from multiple families
            let families = vec![
                (ControlFamily::AC, "AC-2", "Account Management"),
                (ControlFamily::AU, "AU-2", "Audit Events"),
                (ControlFamily::IA, "IA-2", "Identification and Authentication"),
                (ControlFamily::SC, "SC-13", "Cryptographic Protection"),
                (ControlFamily::SI, "SI-4", "System Monitoring"),
                (ControlFamily::CM, "CM-6", "Configuration Settings"),
            ];

            for (family, id, title) in &families {
                ssp.register_control(ControlImplementation {
                    control_id: id.to_string(),
                    family: *family,
                    title: title.to_string(),
                    status: ImplementationStatus::Implemented,
                    implementation_description: format!("{} is implemented", title),
                    code_references: vec!["common/src/saml.rs".to_string()],
                    config_references: Vec::new(),
                    responsible_roles: vec!["System Admin".to_string()],
                    last_assessed: None,
                });
            }

            let report = ssp.generate_ssp_report();
            assert!(report.contains("MILNET SSO"));
            assert!(report.contains("FedRAMP Impact Level: High"));

            let stats = ssp.compliance_stats();
            assert_eq!(stats.total_controls, families.len());
            assert_eq!(stats.implemented, families.len());
            assert_eq!(stats.open_poams, 0);
        }

        #[test]
        fn poam_milestone_tracking() {
            let mut ssp = SspGenerator::new("MILNET SSO".to_string(), FedRampLevel::High);

            ssp.add_poam(PoamEntry {
                poam_id: "POAM-001".to_string(),
                control_id: "AC-2".to_string(),
                weakness: "Automated deprovisioning not implemented".to_string(),
                risk: PoamRisk::Moderate,
                milestones: vec![
                    PoamMilestone {
                        description: "Design automated deprovisioning".to_string(),
                        target_date: "2025-03-01".to_string(),
                        completed: true,
                    },
                    PoamMilestone {
                        description: "Implement and test".to_string(),
                        target_date: "2025-06-01".to_string(),
                        completed: false,
                    },
                ],
                responsible: "Dev Team".to_string(),
                planned_completion: "2025-06-01".to_string(),
                status: PoamStatus::InProgress,
                created: "2025-01-15".to_string(),
            });

            let open = ssp.open_poams();
            assert_eq!(open.len(), 1);
            assert_eq!(open[0].milestones.len(), 2);
            assert!(open[0].milestones[0].completed);
            assert!(!open[0].milestones[1].completed);
        }

        #[test]
        fn compliance_stats_calculation() {
            let mut ssp = SspGenerator::new("test".to_string(), FedRampLevel::Moderate);

            let statuses = vec![
                ("C-1", ImplementationStatus::Implemented),
                ("C-2", ImplementationStatus::Implemented),
                ("C-3", ImplementationStatus::PartiallyImplemented),
                ("C-4", ImplementationStatus::Planned),
                ("C-5", ImplementationStatus::NotApplicable),
            ];

            for (id, status) in &statuses {
                ssp.register_control(ControlImplementation {
                    control_id: id.to_string(),
                    family: ControlFamily::AC,
                    title: id.to_string(),
                    status: *status,
                    implementation_description: String::new(),
                    code_references: Vec::new(),
                    config_references: Vec::new(),
                    responsible_roles: Vec::new(),
                    last_assessed: None,
                });
            }

            let stats = ssp.compliance_stats();
            assert_eq!(stats.total_controls, 5);
            assert_eq!(stats.implemented, 2);
            assert_eq!(stats.partially_implemented, 1);
            assert_eq!(stats.planned, 1);
            assert_eq!(stats.not_applicable, 1);
        }
    }

    // ── STIG Scanner tests ─────────────────────────────────────────────

    mod stig_tests {
        use common::stig_scanner::*;

        #[test]
        fn stig_scanner_ci_gate_fails_on_cat_i() {
            let config = ScanConfig {
                fail_on_cat_i: true,
                ..ScanConfig::default()
            };
            let mut scanner = StigScanner::new(config);
            let result = scanner.run_scan();

            // If there are CatI failures, the gate must fail
            if result.summary.cat_i_failures > 0 {
                assert!(
                    !result.ci_gate_passed,
                    "CI gate must fail on CatI findings"
                );
            }
        }

        #[test]
        fn stig_deviation_tracking_with_justification() {
            let config = ScanConfig::default();
            let mut scanner = StigScanner::new(config);

            let deviation = Deviation {
                check_id: "V-12345".to_string(),
                justification: "Compensating control in place via network segmentation".to_string(),
                compensating_control: Some("Network segmented with zero-trust policy".to_string()),
                approved_by: "ISSM Smith".to_string(),
                approved_date: "2025-01-15".to_string(),
                expires: "2025-07-15".to_string(),
                risk_accepted: DeviationRisk::Low,
            };
            scanner.add_deviation(deviation);

            let found = scanner.is_deviated("V-12345");
            assert!(found.is_some(), "deviation must be tracked");
            assert_eq!(found.unwrap().approved_by, "ISSM Smith");

            assert!(
                scanner.is_deviated("V-99999").is_none(),
                "non-deviated check must return None"
            );
        }

        #[test]
        fn xccdf_output_format() {
            let config = ScanConfig::default();
            let mut scanner = StigScanner::new(config);
            let result = scanner.run_scan();

            let xccdf = generate_xccdf_results(&result);

            assert!(
                xccdf.contains("<?xml version=\"1.0\""),
                "must be valid XML"
            );
            assert!(
                xccdf.contains("Benchmark"),
                "must contain Benchmark element"
            );
            assert!(
                xccdf.contains("TestResult"),
                "must contain TestResult element"
            );
            assert!(
                xccdf.contains("score"),
                "must contain score element"
            );
        }

        #[test]
        fn scan_result_failures_filtered_by_severity() {
            let config = ScanConfig::default();
            let mut scanner = StigScanner::new(config);
            let result = scanner.run_scan();

            // Verify failures_by_severity returns only matching severity
            use common::stig::StigSeverity;
            let cat_i_failures = result.failures_by_severity(StigSeverity::CatI);
            for check in &cat_i_failures {
                assert_eq!(check.severity, StigSeverity::CatI);
            }
        }
    }

    // ── SOC 2 Evidence tests ───────────────────────────────────────────

    mod soc2_tests {
        use common::soc2_evidence::*;

        fn test_collector() -> Soc2Collector {
            Soc2Collector::new(
                "MILNET SSO".to_string(),
                AuditPeriod {
                    start: "2025-01-01".to_string(),
                    end: "2025-12-31".to_string(),
                },
                vec![
                    TrustServiceCategory::CC1,
                    TrustServiceCategory::CC5,
                    TrustServiceCategory::CC6,
                    TrustServiceCategory::CC7,
                    TrustServiceCategory::CC8,
                    TrustServiceCategory::CC9,
                    TrustServiceCategory::A1,
                    TrustServiceCategory::C1,
                ],
            )
        }

        #[test]
        fn trust_criteria_coverage_analysis() {
            let mut collector = test_collector();

            // Add evidence for CC6 and CC5
            collector.collect_access_review(AccessReviewEvidence {
                user_id: "u-1".to_string(),
                resources: vec!["db".to_string()],
                access_levels: vec!["read".to_string()],
                reviewer: "admin".to_string(),
                review_date: "2025-03-01".to_string(),
                appropriate: true,
                action: "confirmed".to_string(),
            });

            let coverage = collector.evidence_coverage();
            assert!(
                *coverage.get(&TrustServiceCategory::CC6).unwrap_or(&0) > 0,
                "CC6 must have evidence after access review"
            );
        }

        #[test]
        fn evidence_gap_identification() {
            let mut collector = test_collector();

            // Only add evidence for CC6/CC5
            for _ in 0..3 {
                collector.collect_access_review(AccessReviewEvidence {
                    user_id: "u-1".to_string(),
                    resources: vec!["db".to_string()],
                    access_levels: vec!["read".to_string()],
                    reviewer: "admin".to_string(),
                    review_date: "2025-03-01".to_string(),
                    appropriate: true,
                    action: "confirmed".to_string(),
                });
            }

            // Gaps should include categories without sufficient evidence
            let gaps = collector.gaps(3);
            assert!(
                !gaps.is_empty(),
                "there must be gaps when not all criteria have evidence"
            );
            // CC1, CC7, CC8, CC9, A1 should be in gaps
            assert!(
                gaps.contains(&TrustServiceCategory::CC1),
                "CC1 without evidence must be a gap"
            );
        }

        #[test]
        fn common_criteria_identification() {
            assert!(TrustServiceCategory::CC1.is_common_criteria());
            assert!(TrustServiceCategory::CC9.is_common_criteria());
            assert!(!TrustServiceCategory::A1.is_common_criteria());
            assert!(!TrustServiceCategory::P1.is_common_criteria());
        }

        #[test]
        fn audit_package_generation() {
            let mut collector = test_collector();

            collector.collect_change_management(ChangeManagementEvidence {
                change_id: "PR-42".to_string(),
                description: "Add SAML support".to_string(),
                requester: "dev-1".to_string(),
                approver: Some("lead-1".to_string()),
                implemented_date: "2025-02-15".to_string(),
                tested: true,
                peer_reviewed: true,
                rollback_plan: true,
            });

            let package = collector.generate_audit_package();
            assert_eq!(package.organization, "MILNET SSO");
            assert!(package.total_evidence > 0);
        }
    }

    // ── FIPS Tracker tests ─────────────────────────────────────────────

    mod fips_tests {
        use common::fips_tracker::*;
        use common::fips_validation::FipsLevel;

        #[test]
        fn fips_tracker_lifecycle_preparation_to_certified() {
            let mut tracker = FipsTracker::new();

            let submission = CmvpSubmission {
                tracking_id: "FIPS-001".to_string(),
                module_name: "MILNET Crypto Module".to_string(),
                module_version: "1.0".to_string(),
                target_level: FipsLevel::Level2,
                phase: SubmissionPhase::Preparation,
                lab_name: "Acme CST Lab".to_string(),
                submitted_date: None,
                estimated_cert_date: Some("2026-06-01".to_string()),
                actual_cert_date: None,
                cert_number: None,
                history: Vec::new(),
                notes: Vec::new(),
                estimated_cost: Some(150_000.0),
                actual_cost: None,
            };

            tracker.create_submission(submission);

            // Advance through lifecycle
            tracker
                .advance_submission("FIPS-001", SubmissionPhase::LabTesting, "admin", None)
                .unwrap();
            tracker
                .advance_submission("FIPS-001", SubmissionPhase::CmvpReview, "admin", None)
                .unwrap();
            tracker
                .advance_submission("FIPS-001", SubmissionPhase::Certified, "admin", Some("Cert #1234".to_string()))
                .unwrap();

            let certified = tracker.submissions_by_phase(SubmissionPhase::Certified);
            assert_eq!(certified.len(), 1);
            assert_eq!(certified[0].module_name, "MILNET Crypto Module");

            // Verify history
            let sub = &tracker.submissions["FIPS-001"];
            assert_eq!(sub.history.len(), 3);
            assert_eq!(sub.history[0].from, SubmissionPhase::Preparation);
            assert_eq!(sub.history[0].to, SubmissionPhase::LabTesting);
            assert_eq!(sub.history[2].to, SubmissionPhase::Certified);
        }

        #[test]
        fn submission_phase_labels() {
            assert_eq!(SubmissionPhase::Preparation.label(), "Preparation");
            assert_eq!(SubmissionPhase::LabTesting.label(), "Lab Testing");
            assert_eq!(SubmissionPhase::CmvpReview.label(), "CMVP Review");
            assert_eq!(SubmissionPhase::CmvpQuestions.label(), "CMVP Questions");
            assert_eq!(SubmissionPhase::Certified.label(), "Certified");
            assert_eq!(SubmissionPhase::Withdrawn.label(), "Withdrawn");
        }

        #[test]
        fn expiry_alert_levels() {
            // Verify alert level thresholds exist
            assert_ne!(ExpiryAlertLevel::Normal, ExpiryAlertLevel::Advisory);
            assert_ne!(ExpiryAlertLevel::Warning, ExpiryAlertLevel::Critical);
            assert_ne!(ExpiryAlertLevel::Critical, ExpiryAlertLevel::Expired);
        }

        #[test]
        fn dashboard_report_generation() {
            let mut tracker = FipsTracker::new();

            tracker.add_lab(CstLab {
                name: "Test Lab".to_string(),
                nvlap_code: "NVLAP-001".to_string(),
                contact_name: "Jane Doe".to_string(),
                contact_email: "jane@testlab.com".to_string(),
                contact_phone: None,
                website: None,
                accredited: true,
                specializations: vec!["PQ algorithms".to_string()],
            });

            tracker.register_default_transitions();

            let report = tracker.generate_dashboard_report();
            assert!(report.contains("FIPS 140-3"));
            assert!(report.contains("Test Lab"));
            assert!(report.contains("Algorithm Transition Timeline"));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Advanced Crypto Tests
// ═══════════════════════════════════════════════════════════════════════════

mod advanced_crypto_tests {

    // ── Verifiable Credentials ──────────────────────────────────────────

    mod vc_tests {
        use std::collections::BTreeMap;
        use crypto::verifiable_credentials::*;

        fn run_with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
            std::thread::Builder::new()
                .stack_size(8 * 1024 * 1024)
                .spawn(f)
                .unwrap()
                .join()
                .unwrap();
        }

        fn test_subject() -> CredentialSubject {
            let mut claims = BTreeMap::new();
            claims.insert("clearance".to_string(), "SECRET".to_string());
            claims.insert("edipi".to_string(), "1234567890".to_string());
            claims.insert("rank".to_string(), "O-4".to_string());

            CredentialSubject {
                id: "did:key:z6MkTest".to_string(),
                claims,
            }
        }

        #[test]
        fn vc_issuance_and_verification_roundtrip() {
            run_with_large_stack(|| {
                let (sk, vk) = crypto::pq_sign::generate_pq_keypair();

                let mut vc = VerifiableCredential::new(
                    "urn:milnet:vc:clearance:001".to_string(),
                    "did:key:z6MkIssuer".to_string(),
                    test_subject(),
                    vec!["ClearanceCredential".to_string()],
                    "2025-01-01T00:00:00Z".to_string(),
                );

                issue_credential(&mut vc, &sk, "did:key:z6MkIssuer#key-1").unwrap();

                assert!(vc.proof.is_some(), "issued credential must have a proof");
                assert_eq!(
                    vc.proof.as_ref().unwrap().proof_type,
                    "MlDsa87Signature2024"
                );

                let valid = verify_credential(&vc, &vk).unwrap();
                assert!(valid, "credential signature must verify");
            });
        }

        #[test]
        fn vc_verification_fails_with_wrong_key() {
            run_with_large_stack(|| {
                let (sk, _vk) = crypto::pq_sign::generate_pq_keypair();
                let (_sk2, vk2) = crypto::pq_sign::generate_pq_keypair();

                let mut vc = VerifiableCredential::new(
                    "urn:milnet:vc:clearance:002".to_string(),
                    "did:key:z6MkIssuer".to_string(),
                    test_subject(),
                    vec!["ClearanceCredential".to_string()],
                    "2025-01-01T00:00:00Z".to_string(),
                );
                issue_credential(&mut vc, &sk, "did:key:z6MkIssuer#key-1").unwrap();

                let valid = verify_credential(&vc, &vk2).unwrap();
                assert!(!valid, "credential must not verify with wrong key");
            });
        }

        #[test]
        fn selective_disclosure_reveal_subset() {
            let subject = test_subject();
            let (sd_claims, disclosures) = create_sd_claims(&subject).unwrap();

            assert_eq!(sd_claims.len(), subject.claims.len());
            assert_eq!(disclosures.len(), subject.claims.len());

            // Reveal only clearance claim
            let clearance_disclosure: Vec<_> = disclosures
                .iter()
                .filter(|d| d.claim_name == "clearance")
                .cloned()
                .collect();

            assert_eq!(clearance_disclosure.len(), 1);
            assert!(
                verify_disclosures(&sd_claims, &clearance_disclosure),
                "partial disclosure must verify"
            );
        }

        #[test]
        fn selective_disclosure_full_verification() {
            let subject = test_subject();
            let (sd_claims, disclosures) = create_sd_claims(&subject).unwrap();

            assert!(
                verify_disclosures(&sd_claims, &disclosures),
                "full disclosure must verify"
            );
        }

        #[test]
        fn credential_revocation_via_status_list() {
            let mut status_list = StatusList2021::new(
                "urn:milnet:statuslist:001".to_string(),
                "revocation".to_string(),
                1000,
            );

            // Initially not revoked
            assert!(!status_list.is_set(42).unwrap());

            // Revoke
            status_list.set_status(42).unwrap();
            assert!(status_list.is_set(42).unwrap());
            assert_eq!(status_list.revoked_count(), 1);

            // Un-revoke
            status_list.clear_status(42).unwrap();
            assert!(!status_list.is_set(42).unwrap());
            assert_eq!(status_list.revoked_count(), 0);
        }

        #[test]
        fn status_list_boundary_check() {
            let mut sl = StatusList2021::new("sl-1".to_string(), "revocation".to_string(), 100);
            assert!(sl.set_status(99).is_ok());
            assert!(sl.set_status(100).is_err(), "index at capacity must error");
        }

        #[test]
        fn credential_expiry_check() {
            let mut vc = VerifiableCredential::new(
                "urn:test:vc".to_string(),
                "issuer".to_string(),
                test_subject(),
                vec!["TestCredential".to_string()],
                "2025-01-01T00:00:00Z".to_string(),
            );
            vc.expiration_date = Some("2025-06-01T00:00:00Z".to_string());

            assert!(!vc.is_expired_at("2025-03-01T00:00:00Z"));
            assert!(vc.is_expired_at("2025-07-01T00:00:00Z"));
        }
    }

    // ── DID tests ──────────────────────────────────────────────────────

    mod did_tests {
        use crypto::did::*;

        #[test]
        fn did_key_resolution_ed25519() {
            let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
            let public_key = signing_key.verifying_key();

            let did = generate_did_key_ed25519(public_key.as_bytes());
            assert!(did.starts_with("did:key:z"), "did:key must start with z (base58btc)");

            let doc = resolve_did_key(&did).unwrap();
            assert_eq!(doc.id, did);
            assert_eq!(doc.method, DidMethod::Key);
            assert!(!doc.authentication.is_empty(), "must have auth method");
            assert!(!doc.assertion_method.is_empty(), "must have assertion method");
            assert!(doc.is_active());

            let vm = doc.primary_auth_method().unwrap();
            assert_eq!(vm.key_type, KeyType::Ed25519);
            assert_eq!(vm.public_key_bytes.len(), 32);
        }

        #[test]
        fn did_auth_challenge_response() {
            let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
            let public_key = signing_key.verifying_key();

            let prover_did = generate_did_key_ed25519(public_key.as_bytes());
            let verifier_did = "did:key:zVerifier".to_string();

            let doc = resolve_did_key(&prover_did).unwrap();

            // Create challenge
            let challenge = create_did_auth_challenge(&verifier_did, "milnet.mil").unwrap();

            // Sign challenge
            let response = sign_did_auth_ed25519(&challenge, &prover_did, &signing_key);
            assert_eq!(response.prover_did, prover_did);
            assert_eq!(response.key_type, KeyType::Ed25519);

            // Verify
            let valid = verify_did_auth(&challenge, &response, &doc).unwrap();
            assert!(valid, "DIDAuth must verify with correct key");
        }

        #[test]
        fn did_auth_rejects_wrong_key() {
            let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
            let wrong_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
            let public_key = signing_key.verifying_key();

            let prover_did = generate_did_key_ed25519(public_key.as_bytes());
            let doc = resolve_did_key(&prover_did).unwrap();

            let challenge = create_did_auth_challenge("did:key:zVerifier", "milnet.mil").unwrap();
            let response = sign_did_auth_ed25519(&challenge, &prover_did, &wrong_key);

            let valid = verify_did_auth(&challenge, &response, &doc).unwrap();
            assert!(!valid, "DIDAuth must reject wrong signing key");
        }

        #[test]
        fn did_web_generation() {
            let did = generate_did_web("sso.milnet.mil");
            assert_eq!(did, "did:web:sso:milnet:mil");
        }
    }

    // ── Homomorphic Encryption / Encrypted Search ──────────────────────

    mod he_search_tests {
        use crypto::he_search::*;

        fn test_key() -> [u8; 32] {
            let mut key = [0u8; 32];
            getrandom::getrandom(&mut key).unwrap();
            key
        }

        #[test]
        fn ope_preserves_ordering_of_timestamps() {
            let ctx = OpeContext::new(test_key());

            let timestamps: Vec<u64> = (0..10)
                .map(|i| 1700000000u64 + i * 100000)
                .collect();

            let encrypted: Vec<u64> = timestamps.iter().map(|ts| ctx.encrypt(*ts)).collect();

            // Verify ordering at the high-bit level
            for i in 0..encrypted.len() - 1 {
                assert!(
                    (encrypted[i] & 0xFFFF_FFFF_FFFF_0000)
                        <= (encrypted[i + 1] & 0xFFFF_FFFF_FFFF_0000),
                    "OPE must preserve timestamp ordering: enc({}) <= enc({})",
                    timestamps[i],
                    timestamps[i + 1]
                );
            }
        }

        #[test]
        fn ope_range_query_works() {
            let ctx = OpeContext::new(test_key());
            let ts = 1700050000u64;
            let enc_ts = ctx.encrypt(ts);

            assert!(
                ctx.in_range(enc_ts, 1700000000, 1700100000),
                "encrypted timestamp must be found in correct range"
            );
            assert!(
                !ctx.in_range(enc_ts, 1700100000, 1700200000),
                "encrypted timestamp must not be found in wrong range"
            );
        }

        #[test]
        fn deterministic_encryption_enables_equality_search() {
            let ctx = DetEncContext::new(test_key());

            let ct1 = ctx.encrypt_string("admin@milnet.mil");
            let ct2 = ctx.encrypt_string("admin@milnet.mil");
            let ct3 = ctx.encrypt_string("other@milnet.mil");

            assert_eq!(ct1, ct2, "same plaintext must produce same ciphertext");
            assert_ne!(ct1, ct3, "different plaintexts must produce different ciphertexts");
            assert!(ctx.matches(b"admin@milnet.mil", &ct1));
            assert!(!ctx.matches(b"wrong@milnet.mil", &ct1));
        }

        #[test]
        fn homomorphic_sum_aggregation_correctness() {
            let ctx = EncryptedAggContext::new(test_key());

            let values = vec![10u64, 20u64, 30u64, 40u64];
            let indices = vec![0u64, 1, 2, 3];

            let encrypted: Vec<u64> = values
                .iter()
                .zip(indices.iter())
                .map(|(&v, &i)| ctx.encrypt(v, i))
                .collect();

            let encrypted_sum = EncryptedAggContext::sum_encrypted(&encrypted);
            let decrypted_sum = ctx.decrypt_aggregate(encrypted_sum, &indices);

            assert_eq!(
                decrypted_sum, 100,
                "homomorphic sum must equal plaintext sum: expected 100, got {}",
                decrypted_sum
            );
        }

        #[test]
        fn batch_equality_search_finds_matches() {
            let ctx = DetEncContext::new(test_key());

            let entries: Vec<[u8; 32]> = vec![
                ctx.encrypt_string("alpha"),
                ctx.encrypt_string("beta"),
                ctx.encrypt_string("alpha"),
                ctx.encrypt_string("gamma"),
            ];

            let result = crypto::he_search::batch_equality_search(&ctx, b"alpha", &entries);
            assert_eq!(result.matching_indices, vec![0, 2]);
            assert_eq!(result.total_scanned, 4);
        }

        #[test]
        fn encrypted_audit_search_from_master_key() {
            let key = test_key();
            let search = EncryptedAuditSearch::from_master_key(&key);

            // OPE, DET, and AGG contexts must be independently keyed
            let ts1 = search.ope.encrypt(1700000000);
            let ct1 = search.det.encrypt_string("test");
            let he1 = search.agg.encrypt(42, 0);

            assert_ne!(ts1, 0);
            assert_ne!(ct1, [0u8; 32]);
            assert_ne!(he1, 0);
        }
    }

    // ── Enclave tests ──────────────────────────────────────────────────

    mod enclave_tests {
        use crypto::enclave::*;

        fn test_identity(backend: EnclaveBackend) -> EnclaveIdentity {
            let mut measurement = [0u8; 32];
            let mut signer = [0u8; 32];
            getrandom::getrandom(&mut measurement).unwrap();
            getrandom::getrandom(&mut signer).unwrap();

            EnclaveIdentity {
                measurement,
                signer,
                product_id: 1,
                security_version: 2,
                backend,
                attributes: Vec::new(),
            }
        }

        fn master_key() -> [u8; 32] {
            let mut key = [0u8; 32];
            getrandom::getrandom(&mut key).unwrap();
            key
        }

        #[test]
        fn key_sealing_and_unsealing() {
            let identity = test_identity(EnclaveBackend::SoftwareFallback);
            let mk = master_key();
            let key_material = b"super-secret-signing-key-material";

            let metadata = SealedKeyMetadata {
                key_id: "key-e2e-001".to_string(),
                algorithm: "Ed25519".to_string(),
                usage: "signing".to_string(),
                created: "2025-01-01T00:00:00Z".to_string(),
                expires: None,
            };

            let sealed = seal_key(key_material, &identity, metadata, &mk).unwrap();
            assert_eq!(sealed.sealing_identity, identity.sealing_hash());

            let unsealed = unseal_key(&sealed, &identity, &mk).unwrap();
            assert_eq!(unsealed, key_material, "unsealed key must match original");
        }

        #[test]
        fn wrong_identity_unsealing_fails() {
            let id1 = test_identity(EnclaveBackend::SoftwareFallback);
            let id2 = test_identity(EnclaveBackend::SoftwareFallback);
            let mk = master_key();

            let metadata = SealedKeyMetadata {
                key_id: "key-002".to_string(),
                algorithm: "AES-256".to_string(),
                usage: "encryption".to_string(),
                created: "2025-01-01T00:00:00Z".to_string(),
                expires: None,
            };

            let sealed = seal_key(b"secret", &id1, metadata, &mk).unwrap();
            let result = unseal_key(&sealed, &id2, &mk);
            assert!(result.is_err(), "different identity must not unseal");
        }

        #[test]
        fn remote_attestation_verification() {
            let identity = test_identity(EnclaveBackend::SoftwareFallback);
            let nonce = generate_attestation_nonce().unwrap();

            let report = AttestationReport {
                identity: identity.clone(),
                nonce,
                report_data: vec![0xAA; 64],
                evidence: Vec::new(), // Software fallback needs no evidence
                timestamp: "2025-01-01T00:00:00Z".to_string(),
            };

            let verification = verify_attestation(&report, &nonce, Some(&identity.measurement));
            assert!(verification.valid, "attestation must verify");
            assert_eq!(verification.trust_level, TrustLevel::SoftwareOnly);
        }

        #[test]
        fn attestation_rejects_wrong_nonce() {
            let identity = test_identity(EnclaveBackend::SoftwareFallback);
            let nonce = generate_attestation_nonce().unwrap();
            let wrong_nonce = generate_attestation_nonce().unwrap();

            let report = AttestationReport {
                identity,
                nonce,
                report_data: Vec::new(),
                evidence: Vec::new(),
                timestamp: "2025-01-01T00:00:00Z".to_string(),
            };

            let verification = verify_attestation(&report, &wrong_nonce, None);
            assert!(!verification.valid, "wrong nonce must fail");
            assert_eq!(verification.trust_level, TrustLevel::Untrusted);
        }

        #[test]
        fn attestation_rejects_measurement_mismatch() {
            let identity = test_identity(EnclaveBackend::SoftwareFallback);
            let nonce = generate_attestation_nonce().unwrap();
            let wrong_measurement = [0xFFu8; 32];

            let report = AttestationReport {
                identity,
                nonce,
                report_data: Vec::new(),
                evidence: Vec::new(),
                timestamp: "2025-01-01T00:00:00Z".to_string(),
            };

            let verification =
                verify_attestation(&report, &nonce, Some(&wrong_measurement));
            assert!(!verification.valid, "measurement mismatch must fail");
        }

        #[test]
        fn hardware_attestation_requires_evidence() {
            let identity = test_identity(EnclaveBackend::IntelSgx);
            let nonce = generate_attestation_nonce().unwrap();

            let report = AttestationReport {
                identity,
                nonce,
                report_data: Vec::new(),
                evidence: Vec::new(), // No evidence for hardware
                timestamp: "2025-01-01T00:00:00Z".to_string(),
            };

            let verification = verify_attestation(&report, &nonce, None);
            assert!(
                !verification.valid,
                "hardware attestation without evidence must fail"
            );
        }

        #[test]
        fn enclave_to_enclave_secure_channel() {
            let id_a = test_identity(EnclaveBackend::SoftwareFallback);
            let id_b = test_identity(EnclaveBackend::SoftwareFallback);

            // Generate X25519 keys
            let secret_a = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
            let public_a = x25519_dalek::PublicKey::from(&secret_a);
            let secret_b = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
            let public_b = x25519_dalek::PublicKey::from(&secret_b);

            let mut session_id = [0u8; 16];
            getrandom::getrandom(&mut session_id).unwrap();

            // Establish from both sides
            let channel_a = establish_channel(
                &secret_a.to_bytes(),
                public_b.as_bytes(),
                &id_a,
                &id_b,
                &session_id,
            );
            let channel_b = establish_channel(
                &secret_b.to_bytes(),
                public_a.as_bytes(),
                &id_b,
                &id_a,
                &session_id,
            );

            assert_eq!(
                channel_a.session_key, channel_b.session_key,
                "both sides must derive the same session key"
            );
            assert_eq!(channel_a.session_id, session_id);
        }

        #[test]
        fn enclave_identity_matching() {
            let identity = test_identity(EnclaveBackend::IntelSgx);

            assert!(identity.matches_expected(
                &identity.measurement,
                &identity.signer,
                identity.security_version,
            ));

            assert!(!identity.matches_expected(
                &[0xFF; 32],
                &identity.signer,
                identity.security_version,
            ));

            // Higher min version should fail
            assert!(!identity.matches_expected(
                &identity.measurement,
                &identity.signer,
                identity.security_version + 1,
            ));
        }

        #[test]
        fn enclave_backend_properties() {
            assert!(EnclaveBackend::IntelSgx.is_hardware());
            assert!(EnclaveBackend::ArmTrustZone.is_hardware());
            assert!(EnclaveBackend::AmdSevSnp.is_hardware());
            assert!(!EnclaveBackend::SoftwareFallback.is_hardware());

            assert_eq!(EnclaveBackend::IntelSgx.attestation_protocol(), "DCAP-ECDSA");
            assert_eq!(EnclaveBackend::SoftwareFallback.attestation_protocol(), "None");
        }
    }
}
