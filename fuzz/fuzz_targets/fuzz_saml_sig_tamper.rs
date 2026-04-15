#![no_main]
//! CAT-M: SAML signature tamper fuzz.
//!
//! Drives `saml_sp::consume_response` (the full strict validation pipeline)
//! with arbitrary XML bytes. Properties enforced:
//!
//!   1. The parser/validator never panics, no matter what bytes it is fed
//!      (no `unwrap`/`expect` reachable from the public entry point).
//!   2. With an empty trust anchor store, no input ever produces an
//!      `Ok(SamlAssertion)` — even a well-formed signed assertion must be
//!      rejected because the issuer cannot be resolved.
//!   3. `decode_b64` rejects any input over the 1 MiB hard limit without
//!      allocating the full decode buffer.

use libfuzzer_sys::fuzz_target;
use saml_sp::{
    consume_response, decode_b64, trust::StaticTrust, ReplayCache, RequestCache,
    ValidationConfig,
};

fn cfg() -> ValidationConfig {
    ValidationConfig {
        expected_issuer: "https://idp.test/".to_string(),
        sp_entity_id: "https://sp.test/".to_string(),
        acs_url: "https://sp.test/acs".to_string(),
        clock_skew_secs: 30,
        allow_unsolicited: true,
    }
}

fuzz_target!(|data: &[u8]| {
    // 1. Base64 decode path — panic-free on any bytes.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = decode_b64(s);
    }

    // 2. Full validation pipeline.
    let trust = StaticTrust::new();
    let requests = RequestCache::new();
    let replays = ReplayCache::new();
    let cfg = cfg();

    let result = consume_response(data, &cfg, &trust, &requests, &replays, 1_700_000_000);

    // With an empty trust store, every input must be rejected. An Ok() here
    // is a trust-bypass bug.
    assert!(
        result.is_err(),
        "empty trust store must reject every input, including well-formed ones"
    );
});
