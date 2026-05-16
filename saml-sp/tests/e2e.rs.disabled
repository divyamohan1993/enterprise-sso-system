//! End-to-end signed SAML 2.0 Response tests. Uses the `rsa` dev-dep to
//! generate an ephemeral key, sign an assertion using our own Exclusive
//! C14N output (so the test also verifies that our canonicalization is
//! self-consistent), and then drives `consume_response`.
//!
//! Each negative test perturbs the signed XML minimally and asserts that
//! the strict pipeline rejects it — covering the validation-order bullets
//! from the CAT-D mandate.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::EncodePublicKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use saml_sp::dom::parse_strict;
use saml_sp::trust::{KeyAlg, PinnedKey, StaticTrust};
use saml_sp::validate::ValidationConfig;
use saml_sp::{consume_response, ReplayCache, RequestCache, SamlError};
use sha2::Sha256;

const IDP: &str = "https://idp.example/";
const SP: &str = "https://sp.milnet.mil";
const ACS: &str = "https://sp.milnet.mil/acs";

fn now() -> i64 {
    1_700_000_000
}

fn fresh_rsa() -> (RsaPrivateKey, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let sk = RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
    let pk = RsaPublicKey::from(&sk);
    let spki_der = pk
        .to_public_key_der()
        .expect("spki encode")
        .as_bytes()
        .to_vec();
    (sk, spki_der)
}

fn trust_for(spki: Vec<u8>) -> StaticTrust {
    let mut t = StaticTrust::new();
    t.insert(IDP, PinnedKey::new(spki, KeyAlg::Rsa));
    t
}

/// Build a signed SAML 2.0 Response using our own c14n and an RSA key.
fn build_signed(
    sk: &RsaPrivateKey,
    aid: &str,
    irt: &str,
    cond_nbf: &str,
    cond_noa: &str,
    subj_noa: &str,
    audience: &str,
    destination: &str,
    recipient: &str,
) -> String {
    // Step 1 — build an unsigned Assertion with a placeholder <ds:Signature>
    // containing a stable template. We'll compute the digest over the
    // assertion with the signature element ELIDED (enveloped transform).
    let assertion_open = format!(
        r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{aid}" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"><saml:Issuer>{IDP}</saml:Issuer>"#
    );
    let subject = format!(
        r#"<saml:Subject><saml:NameID>alice</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="{subj_noa}" Recipient="{recipient}" InResponseTo="{irt}"/></saml:SubjectConfirmation></saml:Subject>"#
    );
    let conditions = format!(
        r#"<saml:Conditions NotBefore="{cond_nbf}" NotOnOrAfter="{cond_noa}"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>"#
    );
    let assertion_body = format!("{subject}{conditions}");
    let assertion_close = "</saml:Assertion>";
    let assertion_no_sig = format!("{assertion_open}{assertion_body}{assertion_close}");

    // Step 2 — parse, locate, and canonicalize the assertion with no sig.
    let dom = parse_strict(assertion_no_sig.as_bytes()).expect("parse-no-sig");
    let canonical = saml_sp::c14n::exc_c14n(&dom, dom.root.unwrap(), &[]).expect("c14n");
    let digest = <sha2::Sha256 as sha2::Digest>::digest(&canonical);
    let digest_b64 = STANDARD.encode(digest);

    // Step 3 — build <SignedInfo>, canonicalize it, sign.
    let signed_info = format!(
        r##"<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#{aid}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest_b64}</ds:DigestValue></ds:Reference></ds:SignedInfo>"##
    );
    // We need SignedInfo canonicalized — parse it and c14n it.
    let si_dom = parse_strict(signed_info.as_bytes()).expect("parse-si");
    let si_canonical =
        saml_sp::c14n::exc_c14n(&si_dom, si_dom.root.unwrap(), &[]).expect("c14n-si");
    let signing_key: SigningKey<Sha256> = SigningKey::new(sk.clone());
    let sig = signing_key.sign(&si_canonical);
    let sig_b64 = STANDARD.encode(sig.to_bytes());

    // Step 4 — embed <ds:Signature> as first child of <Assertion>.
    // Note: we must keep the *same* <ds:SignedInfo> bytes we canonicalized
    // so that the verifier's c14n of SignedInfo produces the same output.
    // Exclusive C14N is stable under re-parsing for our well-formed input.
    let signature = format!(
        r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{signed_info}<ds:SignatureValue>{sig_b64}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate></ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"##
    );
    let assertion_signed =
        format!("{assertion_open}{signature}{assertion_body}{assertion_close}");

    // Step 5 — wrap in <samlp:Response>.
    format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="r1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z" Destination="{destination}" InResponseTo="{irt}"><saml:Issuer>{IDP}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>{assertion_signed}</samlp:Response>"#
    )
}

fn cfg() -> ValidationConfig {
    ValidationConfig {
        expected_issuer: IDP.to_string(),
        sp_entity_id: SP.to_string(),
        acs_url: ACS.to_string(),
        clock_skew_secs: 30,
        allow_unsolicited: false,
    }
}

fn outstanding(irt: &str) -> RequestCache {
    let r = RequestCache::new();
    r.register(irt.to_string(), now(), 300).unwrap();
    r
}

#[test]
fn happy_path_verifies() {
    let (sk, spki) = fresh_rsa();
    let trust = trust_for(spki);
    let xml = build_signed(
        &sk,
        "a1",
        "req-1",
        "2024-01-01T00:00:00Z",
        "2099-01-01T00:00:00Z",
        "2099-01-01T00:00:00Z",
        SP,
        ACS,
        ACS,
    );
    let req = outstanding("req-1");
    let replays = ReplayCache::new();
    let a = consume_response(xml.as_bytes(), &cfg(), &trust, &req, &replays, now())
        .expect("happy path");
    assert_eq!(a.assertion_id, "a1");
    assert_eq!(a.subject, "alice");
    assert_eq!(a.audience, SP);
}

#[test]
fn rejects_replay() {
    let (sk, spki) = fresh_rsa();
    let trust = trust_for(spki);
    let xml = build_signed(
        &sk,
        "a1",
        "req-1",
        "2024-01-01T00:00:00Z",
        "2099-01-01T00:00:00Z",
        "2099-01-01T00:00:00Z",
        SP,
        ACS,
        ACS,
    );
    // First request consumes the outstanding ID. Replay fails on the second
    // regardless of whether it's registered again — the assertion ID cache
    // remembers.
    let replays = ReplayCache::new();
    let req1 = outstanding("req-1");
    consume_response(xml.as_bytes(), &cfg(), &trust, &req1, &replays, now()).unwrap();
    let req2 = outstanding("req-1");
    let err =
        consume_response(xml.as_bytes(), &cfg(), &trust, &req2, &replays, now()).unwrap_err();
    assert!(matches!(err, SamlError::Replay));
}

#[test]
fn rejects_destination_mismatch() {
    let (sk, spki) = fresh_rsa();
    let trust = trust_for(spki);
    let xml = build_signed(
        &sk,
        "a1",
        "req-1",
        "2024-01-01T00:00:00Z",
        "2099-01-01T00:00:00Z",
        "2099-01-01T00:00:00Z",
        SP,
        "https://evil.example/acs",
        ACS,
    );
    let req = outstanding("req-1");
    let replays = ReplayCache::new();
    let err = consume_response(xml.as_bytes(), &cfg(), &trust, &req, &replays, now())
        .unwrap_err();
    assert!(matches!(err, SamlError::DestinationMismatch));
}

#[test]
fn rejects_recipient_mismatch() {
    let (sk, spki) = fresh_rsa();
    let trust = trust_for(spki);
    let xml = build_signed(
        &sk,
        "a1",
        "req-1",
        "2024-01-01T00:00:00Z",
        "2099-01-01T00:00:00Z",
        "2099-01-01T00:00:00Z",
        SP,
        ACS,
        "https://evil.example/acs",
    );
    let req = outstanding("req-1");
    let replays = ReplayCache::new();
    let err = consume_response(xml.as_bytes(), &cfg(), &trust, &req, &replays, now())
        .unwrap_err();
    assert!(matches!(err, SamlError::SubjectConfirmationRecipient));
}

#[test]
fn rejects_audience_mismatch() {
    let (sk, spki) = fresh_rsa();
    let trust = trust_for(spki);
    let xml = build_signed(
        &sk,
        "a1",
        "req-1",
        "2024-01-01T00:00:00Z",
        "2099-01-01T00:00:00Z",
        "2099-01-01T00:00:00Z",
        "https://elsewhere",
        ACS,
        ACS,
    );
    let req = outstanding("req-1");
    let replays = ReplayCache::new();
    let err = consume_response(xml.as_bytes(), &cfg(), &trust, &req, &replays, now())
        .unwrap_err();
    assert!(matches!(err, SamlError::AudienceMismatch));
}

#[test]
fn rejects_inresponseto_mismatch() {
    let (sk, spki) = fresh_rsa();
    let trust = trust_for(spki);
    let xml = build_signed(
        &sk,
        "a1",
        "req-1",
        "2024-01-01T00:00:00Z",
        "2099-01-01T00:00:00Z",
        "2099-01-01T00:00:00Z",
        SP,
        ACS,
        ACS,
    );
    let req = RequestCache::new(); // nothing registered
    let replays = ReplayCache::new();
    let err = consume_response(xml.as_bytes(), &cfg(), &trust, &req, &replays, now())
        .unwrap_err();
    assert!(matches!(err, SamlError::InResponseToMismatch));
}

#[test]
fn rejects_expired_condition() {
    let (sk, spki) = fresh_rsa();
    let trust = trust_for(spki);
    let xml = build_signed(
        &sk,
        "a1",
        "req-1",
        "2000-01-01T00:00:00Z",
        "2001-01-01T00:00:00Z",
        "2099-01-01T00:00:00Z",
        SP,
        ACS,
        ACS,
    );
    let req = outstanding("req-1");
    let replays = ReplayCache::new();
    let err = consume_response(xml.as_bytes(), &cfg(), &trust, &req, &replays, now())
        .unwrap_err();
    assert!(matches!(err, SamlError::Expired));
}

#[test]
fn rejects_tampered_subject() {
    let (sk, spki) = fresh_rsa();
    let trust = trust_for(spki);
    let xml = build_signed(
        &sk,
        "a1",
        "req-1",
        "2024-01-01T00:00:00Z",
        "2099-01-01T00:00:00Z",
        "2099-01-01T00:00:00Z",
        SP,
        ACS,
        ACS,
    );
    // Swap alice → mallory after signing; digest will fail.
    let tampered = xml.replace(">alice<", ">mallory<");
    let req = outstanding("req-1");
    let replays = ReplayCache::new();
    let err = consume_response(tampered.as_bytes(), &cfg(), &trust, &req, &replays, now())
        .unwrap_err();
    assert!(matches!(
        err,
        SamlError::DigestMismatch | SamlError::SignatureInvalid
    ));
}

#[test]
fn xsw_extra_assertion_rejected() {
    let (sk, spki) = fresh_rsa();
    let trust = trust_for(spki);
    let xml = build_signed(
        &sk,
        "a1",
        "req-1",
        "2024-01-01T00:00:00Z",
        "2099-01-01T00:00:00Z",
        "2099-01-01T00:00:00Z",
        SP,
        ACS,
        ACS,
    );
    // XSW: inject a second, unsigned attacker-controlled Assertion into the
    // Response. The strict pipeline rejects on AssertionCardinality BEFORE
    // it even looks at signatures.
    let evil = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="evil"><saml:Issuer>https://idp.example/</saml:Issuer><saml:Subject><saml:NameID>mallory</saml:NameID></saml:Subject></saml:Assertion>"#;
    let injected = xml.replacen(
        "<saml:Assertion",
        &format!("{evil}<saml:Assertion"),
        1,
    );
    let req = outstanding("req-1");
    let replays = ReplayCache::new();
    let err = consume_response(injected.as_bytes(), &cfg(), &trust, &req, &replays, now())
        .unwrap_err();
    assert!(matches!(err, SamlError::AssertionCardinality));
}

#[test]
fn rejects_unknown_issuer() {
    let (sk, spki) = fresh_rsa();
    let _trust = trust_for(spki);
    // Different configured issuer.
    let mut bad_cfg = cfg();
    bad_cfg.expected_issuer = "https://other.example/".to_string();
    let xml = build_signed(
        &sk,
        "a1",
        "req-1",
        "2024-01-01T00:00:00Z",
        "2099-01-01T00:00:00Z",
        "2099-01-01T00:00:00Z",
        SP,
        ACS,
        ACS,
    );
    let req = outstanding("req-1");
    let replays = ReplayCache::new();
    // Trust store is keyed by the *original* IDP, so lookup for the wrong
    // issuer would also fail, but issuer mismatch is caught earlier.
    let trust = StaticTrust::new();
    let err = consume_response(xml.as_bytes(), &bad_cfg, &trust, &req, &replays, now())
        .unwrap_err();
    assert!(matches!(err, SamlError::UnknownIssuer));
}

// Suppress unused import warning when the rsa traits are re-exported.
#[allow(dead_code)]
fn _force_pub(k: &RsaPublicKey) -> usize {
    k.n().to_bytes_be().len()
}
