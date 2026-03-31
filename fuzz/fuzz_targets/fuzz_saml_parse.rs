#![no_main]
use libfuzzer_sys::fuzz_target;
use common::saml::{AuthnRequest, LogoutRequest};
fuzz_target!(|data: &[u8]| { let xml = String::from_utf8_lossy(data); let _ = AuthnRequest::parse_redirect_binding(&xml); let _ = AuthnRequest::parse_post_binding(&xml); let _ = LogoutRequest::from_xml(&xml); });
