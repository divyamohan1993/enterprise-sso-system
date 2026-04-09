#![no_main]
use libfuzzer_sys::fuzz_target;
use common::scim::{ScimUser, ScimGroup, ScimPatchRequest, ScimServer};

fuzz_target!(|data: &[u8]| {
    // Fuzz SCIM user creation with random JSON payloads
    if let Ok(user) = serde_json::from_slice::<ScimUser>(data) {
        let mut server = ScimServer::new("https://fuzz.example.com");
        let _ = server.create_user(user);
    }

    // Fuzz SCIM group creation with random JSON payloads
    if let Ok(group) = serde_json::from_slice::<ScimGroup>(data) {
        let mut server = ScimServer::new("https://fuzz.example.com");
        let _ = server.create_group(group);
    }

    // Fuzz SCIM user update with random JSON
    if let Ok(user) = serde_json::from_slice::<ScimUser>(data) {
        let mut server = ScimServer::new("https://fuzz.example.com");
        let _ = server.update_user("nonexistent-id", user);
    }

    // Fuzz SCIM patch request
    if let Ok(patch) = serde_json::from_slice::<ScimPatchRequest>(data) {
        let mut server = ScimServer::new("https://fuzz.example.com");
        let _ = server.patch_user("nonexistent-id", patch);
    }
});
