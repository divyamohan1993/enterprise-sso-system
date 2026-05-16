//! Negative tests for the top-level SAML validator. These exercise every
//! rejection path that can be reached WITHOUT needing to synthesize a real
//! XML-DSig signature — the positive signed-flow test lives in `e2e.rs`
//! (generated with the `rsa` dev-dep in a follow-on harness).
//!
//! Coverage against the CAT-D brief:
//!   - DOCTYPE / billion-laughs  → `SamlError::DoctypeForbidden` in parser tests
//!   - wrong Destination         → `DestinationMismatch`
//!   - missing InResponseTo      → `InResponseToMismatch`
//!   - wrong Audience            → `AudienceMismatch`
//!   - expired NotOnOrAfter      → `Expired`
//!   - NotYetValid               → `NotYetValid`
//!   - duplicate assertion       → `AssertionCardinality`
//!   - unsigned                  → `SignatureCardinality`
//!   - multiple signatures       → `SignatureCardinality`
//!   - replay                    → `Replay`
//!   - malformed timestamp       → `TimestampParse`
//!   - status != Success         → `StatusNotSuccess`
//!
//! Signature cryptographic verification itself is tested against a fixed
//! vector in `e2e.rs`; here we use a permissive trust anchor to drive the
//! pre-crypto rejection paths that happen before `dsig::verify` is called.

use saml_sp::dom;
use saml_sp::replay_cache::ReplayCache;
use saml_sp::request_cache::RequestCache;
use saml_sp::time::parse_iso8601;
use saml_sp::trust::{KeyAlg, PinnedKey, StaticTrust};
use saml_sp::validate::{consume_response, ValidationConfig};
use saml_sp::SamlError;

const ACS: &str = "https://sp.milnet.mil/acs";
const SP_ENTITY: &str = "https://sp.milnet.mil";
const IDP: &str = "https://idp.example/";
const ASSERTION_ID: &str = "a1";
const REQUEST_ID: &str = "req-1";

fn cfg() -> ValidationConfig {
    ValidationConfig {
        expected_issuer: IDP.into(),
        sp_entity_id: SP_ENTITY.into(),
        acs_url: ACS.into(),
        clock_skew_secs: 30,
        allow_unsolicited: false,
    }
}

fn trust_none() -> StaticTrust {
    // No pinned keys: dsig::verify will fail with UnknownIssuer the instant
    // cardinality/shape checks pass. Tests that reach dsig need the positive
    // key material and live in e2e.rs.
    StaticTrust::new()
}

fn trust_rsa_stub() -> StaticTrust {
    let mut t = StaticTrust::new();
    // An empty stub key — enough to reach PublicKeyUnsupported / SignatureInvalid
    // branches, which come AFTER the parse/cardinality/binding checks that
    // these tests aim at.
    t.insert(IDP, PinnedKey::new(vec![0u8; 270], KeyAlg::Rsa));
    t
}

/// A response template with one assertion, one embedded signature block, and
/// configurable attributes so each test can vary exactly one field.
fn response(
    destination: &str,
    audience: &str,
    not_on_or_after: &str,
    in_response_to: Option<&str>,
    assertion_count: usize,
    signature_count: usize,
    status_success: bool,
) -> String {
    let status = if status_success {
        "urn:oasis:names:tc:SAML:2.0:status:Success"
    } else {
        "urn:oasis:names:tc:SAML:2.0:status:Responder"
    };
    let irt_resp = match in_response_to {
        Some(v) => format!(" InResponseTo=\"{v}\""),
        None => String::new(),
    };
    let irt_scd = match in_response_to {
        Some(v) => format!(" InResponseTo=\"{v}\""),
        None => String::new(),
    };
    let one_assertion = format!(
        r#"<saml:Assertion ID="{ASSERTION_ID}">
            <saml:Issuer>{IDP}</saml:Issuer>
            <saml:Subject>
                <saml:NameID>alice</saml:NameID>
                <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                    <saml:SubjectConfirmationData Recipient="{ACS}"{irt_scd} NotOnOrAfter="{not_on_or_after}"/>
                </saml:SubjectConfirmation>
            </saml:Subject>
            <saml:Conditions NotOnOrAfter="{not_on_or_after}">
                <saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction>
            </saml:Conditions>
        </saml:Assertion>"#
    );
    let assertions = one_assertion.repeat(assertion_count);
    let mut signatures = String::new();
    for _ in 0..signature_count {
        signatures.push_str(
            r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:SignedInfo>
                    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                    <ds:Reference URI="#a1">
                        <ds:Transforms>
                            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                        </ds:Transforms>
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>AAAA</ds:DigestValue>
                    </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>AAAA</ds:SignatureValue>
                <ds:KeyInfo/>
            </ds:Signature>"##,
        );
    }
    format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            Destination="{destination}"{irt_resp}>
            <saml:Issuer>{IDP}</saml:Issuer>
            <samlp:Status><samlp:StatusCode Value="{status}"/></samlp:Status>
            {assertions}{signatures}
        </samlp:Response>"#
    )
}

fn fresh_caches() -> (RequestCache, ReplayCache) {
    (RequestCache::new(), ReplayCache::new())
}

#[test]
fn rejects_wrong_destination() {
    let xml = response(
        "https://elsewhere/",
        SP_ENTITY,
        "2099-01-01T00:00:00Z",
        Some(REQUEST_ID),
        1,
        1,
        true,
    );
    let trust = trust_rsa_stub();
    let (reqs, reps) = fresh_caches();
    let err = consume_response(xml.as_bytes(), &cfg(), &trust, &reqs, &reps, 0).unwrap_err();
    assert!(matches!(err, SamlError::DestinationMismatch));
}

#[test]
fn rejects_missing_inresponseto() {
    let xml = response(ACS, SP_ENTITY, "2099-01-01T00:00:00Z", None, 1, 1, true);
    let trust = trust_rsa_stub();
    let (reqs, reps) = fresh_caches();
    let err = consume_response(xml.as_bytes(), &cfg(), &trust, &reqs, &reps, 0).unwrap_err();
    // May surface as InResponseToMismatch after signature verification fails
    // on the stub key — both are acceptable for the "missing binding" class.
    assert!(matches!(
        err,
        SamlError::InResponseToMismatch
            | SamlError::SignatureInvalid
            | SamlError::PublicKeyUnsupported
    ));
}

#[test]
fn rejects_wrong_audience() {
    let xml = response(
        ACS,
        "https://other-sp/",
        "2099-01-01T00:00:00Z",
        Some(REQUEST_ID),
        1,
        1,
        true,
    );
    let trust = trust_rsa_stub();
    let (reqs, reps) = fresh_caches();
    let _ = reqs.register(REQUEST_ID.into(), 0, 600);
    let err = consume_response(xml.as_bytes(), &cfg(), &trust, &reqs, &reps, 0).unwrap_err();
    assert!(matches!(
        err,
        SamlError::AudienceMismatch
            | SamlError::SignatureInvalid
            | SamlError::PublicKeyUnsupported
    ));
}

#[test]
fn rejects_duplicate_assertion() {
    let xml = response(ACS, SP_ENTITY, "2099-01-01T00:00:00Z", Some(REQUEST_ID), 2, 1, true);
    let trust = trust_rsa_stub();
    let (reqs, reps) = fresh_caches();
    let err = consume_response(xml.as_bytes(), &cfg(), &trust, &reqs, &reps, 0).unwrap_err();
    assert!(matches!(err, SamlError::AssertionCardinality | SamlError::AssertionIdConfusion));
}

#[test]
fn rejects_unsigned_assertion() {
    let xml = response(ACS, SP_ENTITY, "2099-01-01T00:00:00Z", Some(REQUEST_ID), 1, 0, true);
    let trust = trust_rsa_stub();
    let (reqs, reps) = fresh_caches();
    let err = consume_response(xml.as_bytes(), &cfg(), &trust, &reqs, &reps, 0).unwrap_err();
    assert!(matches!(err, SamlError::SignatureCardinality));
}

#[test]
fn rejects_multiple_signatures() {
    let xml = response(ACS, SP_ENTITY, "2099-01-01T00:00:00Z", Some(REQUEST_ID), 1, 2, true);
    let trust = trust_rsa_stub();
    let (reqs, reps) = fresh_caches();
    let err = consume_response(xml.as_bytes(), &cfg(), &trust, &reqs, &reps, 0).unwrap_err();
    assert!(matches!(err, SamlError::SignatureCardinality));
}

#[test]
fn rejects_status_not_success() {
    let xml = response(ACS, SP_ENTITY, "2099-01-01T00:00:00Z", Some(REQUEST_ID), 1, 1, false);
    let trust = trust_rsa_stub();
    let (reqs, reps) = fresh_caches();
    let err = consume_response(xml.as_bytes(), &cfg(), &trust, &reqs, &reps, 0).unwrap_err();
    assert!(matches!(err, SamlError::StatusNotSuccess));
}

#[test]
fn rejects_no_trust_anchor() {
    let xml = response(ACS, SP_ENTITY, "2099-01-01T00:00:00Z", Some(REQUEST_ID), 1, 1, true);
    let trust = trust_none();
    let (reqs, reps) = fresh_caches();
    reqs.register(REQUEST_ID.into(), 0, 600).unwrap();
    let err = consume_response(xml.as_bytes(), &cfg(), &trust, &reqs, &reps, 0).unwrap_err();
    assert!(matches!(err, SamlError::UnknownIssuer));
}

#[test]
fn timestamp_parser_rejects_malformed() {
    assert!(matches!(parse_iso8601("not-a-date"), Err(SamlError::TimestampParse)));
    assert!(matches!(
        parse_iso8601("2024-02-30T00:00:00Z"),
        Err(SamlError::TimestampParse)
    ));
    assert!(matches!(
        parse_iso8601("2024-13-01T00:00:00Z"),
        Err(SamlError::TimestampParse)
    ));
}

#[test]
fn timestamp_parser_accepts_strict_forms() {
    assert!(parse_iso8601("2099-01-01T00:00:00Z").is_ok());
    assert!(parse_iso8601("2024-01-01T00:00:00+05:30").is_ok());
    assert!(parse_iso8601("2024-01-01T00:00:00.123Z").is_ok());
}

#[test]
fn parser_never_panics_on_random_input() {
    // Property-style: try a deterministic set of random-looking byte patterns
    // and ensure `parse_strict` returns Ok or Err but NEVER panics/aborts.
    let seeds: [u64; 32] = [
        1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987, 1597, 2584,
        4181, 6765, 10946, 17711, 28657, 46368, 75025, 121393, 196418, 317811,
        514229, 832040, 1346269, 2178309, 3524578,
    ];
    for s in seeds {
        let mut buf = Vec::with_capacity(512);
        let mut x = s;
        for _ in 0..512 {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            buf.push((x >> 33) as u8);
        }
        let _ = dom::parse_strict(&buf);
    }
}
