#![no_main]
use libfuzzer_sys::fuzz_target;
use opaque::store::CredentialStore;
use opaque::service::handle_login_start;
static STORE: std::sync::LazyLock<CredentialStore> = std::sync::LazyLock::new(|| CredentialStore::new());
fuzz_target!(|data: &[u8]| { let _ = handle_login_start(&STORE, "fuzzuser", data); });
