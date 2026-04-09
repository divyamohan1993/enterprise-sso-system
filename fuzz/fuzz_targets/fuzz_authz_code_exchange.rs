#![no_main]
use libfuzzer_sys::fuzz_target;
use sso_protocol::authorize::AuthorizationStore;
use uuid::Uuid;

fuzz_target!(|data: &[u8]| {
    let mut store = AuthorizationStore::new();

    // Create a valid code to test consumption with fuzzed inputs
    let user_id = Uuid::nil();
    let code_result = store.create_code_with_tier(
        "fuzz-client",
        "https://fuzz.example.com/callback",
        user_id,
        "openid",
        Some("fuzz-challenge".to_string()),
        None,
        2,
    );

    // Fuzz code consumption with random strings
    let fuzz_code = String::from_utf8_lossy(data);
    let _ = store.consume_code(&fuzz_code);

    // If we got a valid code, try consuming with fuzzed variations
    if let Ok(valid_code) = code_result {
        // Consume with the valid code
        let _ = store.consume_code(&valid_code);
        // Double consumption must fail
        let result = store.consume_code(&valid_code);
        assert!(result.is_none(), "double consumption must be rejected");
    }

    // Fuzz with empty and boundary strings
    let _ = store.consume_code("");
    let _ = store.consume_code(&"A".repeat(10000));

    // Test is_code_consumed with fuzz data
    let _ = store.is_code_consumed(&fuzz_code);
});
