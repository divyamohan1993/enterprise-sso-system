#![no_main]
use libfuzzer_sys::fuzz_target;
use common::config::ErrorLevel;
use common::ocsp_crl::{OcspConfig, CrlConfig, RevocationStatus};
use common::cert_lifecycle::{RotationPolicy, OcspStaple, CrlEntry};

fuzz_target!(|data: &[u8]| {
    // Fuzz JSON deserialization of config-related types
    let _ = serde_json::from_slice::<ErrorLevel>(data);
    let _ = serde_json::from_slice::<OcspConfig>(data);
    let _ = serde_json::from_slice::<CrlConfig>(data);
    let _ = serde_json::from_slice::<RotationPolicy>(data);
    let _ = serde_json::from_slice::<RevocationStatus>(data);
    let _ = serde_json::from_slice::<OcspStaple>(data);
    let _ = serde_json::from_slice::<CrlEntry>(data);

    // Fuzz TOML deserialization of the same types
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = toml::from_str::<ErrorLevel>(text);
        let _ = toml::from_str::<OcspConfig>(text);
        let _ = toml::from_str::<CrlConfig>(text);
        let _ = toml::from_str::<RotationPolicy>(text);
    }

    // Fuzz ErrorLevel::from_u8 with arbitrary bytes
    if let Some(&b) = data.first() {
        let _ = ErrorLevel::from_u8(b);
    }
});
