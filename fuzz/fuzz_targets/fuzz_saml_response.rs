#![no_main]
use libfuzzer_sys::fuzz_target;
use common::saml::{AuthnRequest, LogoutRequest, SamlResponse, SamlStatusCode};

fuzz_target!(|data: &[u8]| {
    let xml = String::from_utf8_lossy(data);

    // Fuzz AuthnRequest parsing (both bindings)
    let _ = AuthnRequest::parse_redirect_binding(&xml);
    let _ = AuthnRequest::parse_post_binding(&xml);

    // Fuzz LogoutRequest parsing
    let _ = LogoutRequest::from_xml(&xml);

    // Fuzz SamlResponse XML generation with random inputs
    // Use the raw bytes to construct a response and verify to_xml doesn't panic
    if data.len() >= 4 {
        let response = SamlResponse {
            id: format!("_fuzz_{}", hex::encode(&data[..2.min(data.len())])),
            in_response_to: Some(String::from_utf8_lossy(&data[..data.len().min(32)]).into_owned()),
            destination: String::from_utf8_lossy(&data[..data.len().min(64)]).into_owned(),
            issue_instant: "2024-01-01T00:00:00Z".to_string(),
            issuer: String::from_utf8_lossy(&data[..data.len().min(32)]).into_owned(),
            status: SamlStatusCode::Success,
            status_message: Some(String::from_utf8_lossy(data).into_owned()),
            assertion_xml: Some(String::from_utf8_lossy(data).into_owned()),
            assertion_encrypted: data.first().map_or(false, |b| b % 2 == 0),
            relay_state: None,
        };
        let _ = response.to_xml();
        let _ = response.to_base64();
    }
});
