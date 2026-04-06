#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The admin challenge page is a static HTML handler; fuzz any input that
    // might reach it as an HTTP request body or query string. We exercise the
    // HTML constant parsing path by treating fuzz input as a potential URL or
    // request fragment. Since challenge_page() is async and takes no input,
    // we fuzz the raw bytes as if they were an HTTP path/query to ensure no
    // panic in string handling code around the admin module.
    let _s = String::from_utf8_lossy(data);
    // Exercise serde_json parsing as admin endpoints accept JSON bodies
    let _ = serde_json::from_slice::<serde_json::Value>(data);
});
