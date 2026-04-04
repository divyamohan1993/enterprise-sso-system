#![no_main]
use libfuzzer_sys::fuzz_target;
use common::scim::{ScimFilter, ScimUser, ScimGroup, ScimPatchRequest, ScimBulkRequest};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);

    // Fuzz SCIM filter expression parsing
    let _ = ScimFilter::parse(&text);

    // Fuzz SCIM user JSON deserialization
    let _ = serde_json::from_slice::<ScimUser>(data);

    // Fuzz SCIM group JSON deserialization
    let _ = serde_json::from_slice::<ScimGroup>(data);

    // Fuzz SCIM patch request deserialization
    let _ = serde_json::from_slice::<ScimPatchRequest>(data);

    // Fuzz SCIM bulk request deserialization
    let _ = serde_json::from_slice::<ScimBulkRequest>(data);
});
