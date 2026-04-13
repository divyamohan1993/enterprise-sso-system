use saml_sp::*;

const SAMPLE: &str = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                       xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Issuer>https://idp.example/</saml:Issuer>
  <saml:Assertion>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"></ds:Signature>
    <saml:Subject><saml:NameID>alice@example</saml:NameID></saml:Subject>
    <saml:Conditions NotOnOrAfter="2099-01-01T00:00:00Z">
      <saml:AudienceRestriction><saml:Audience>https://sp.milnet.mil</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
      <saml:Attribute Name="email"><saml:AttributeValue>alice@example</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"#;

#[test]
fn parses_required_fields() {
    let a = extract_assertion(SAMPLE.as_bytes()).unwrap();
    assert_eq!(a.subject, "alice@example");
    assert_eq!(a.audience, "https://sp.milnet.mil");
    assert!(a.has_signature);
    assert_eq!(a.attributes.get("email").unwrap()[0], "alice@example");
}

#[test]
fn rejects_unsigned() {
    let mut a = extract_assertion(SAMPLE.as_bytes()).unwrap();
    a.has_signature = false;
    let err = validate(&a, "https://sp.milnet.mil", 0, &AlwaysAcceptVerifier, b"").unwrap_err();
    matches!(err, SamlError::UnsignedRejected);
}

#[test]
fn rejects_audience_mismatch() {
    let a = extract_assertion(SAMPLE.as_bytes()).unwrap();
    let err = validate(&a, "https://other", 0, &AlwaysAcceptVerifier, b"").unwrap_err();
    matches!(err, SamlError::AudienceMismatch(_, _));
}
