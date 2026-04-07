#![no_main]
use libfuzzer_sys::fuzz_target;
use crypto::did::{resolve_did_key, DidDocument, VerificationMethod, ServiceEndpoint};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);

    // Fuzz did:key resolution with arbitrary strings
    let _ = resolve_did_key(&text);

    // Fuzz DID document JSON deserialization
    let _ = serde_json::from_slice::<DidDocument>(data);
    let _ = serde_json::from_slice::<VerificationMethod>(data);
    let _ = serde_json::from_slice::<ServiceEndpoint>(data);
});
