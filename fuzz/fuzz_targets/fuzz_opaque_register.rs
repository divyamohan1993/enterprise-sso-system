#![no_main]
use libfuzzer_sys::fuzz_target;
use opaque::store::CredentialStore;
use opaque::service::{handle_register_start, handle_register_finish};

static STORE: std::sync::LazyLock<CredentialStore> =
    std::sync::LazyLock::new(|| CredentialStore::new());

fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return; // Bound input size to avoid timeouts
    }

    // Path 1: Fuzz registration start (deserialize RegistrationRequest)
    let _ = handle_register_start(&STORE, "fuzzuser", data);

    // Path 2: Fuzz registration finish (deserialize RegistrationUpload)
    // Uses a separate code path through ServerRegistration::finish
    let mut store_clone = CredentialStore::new();
    let _ = handle_register_finish(&mut store_clone, "fuzzuser", data);
});
