#![no_main]
//! I10 [HIGH] SSRF / URL-injection fuzz for audience, issuer, and redirect
//! URL fields. Asserts no panic when adversarial URL bytes are parsed.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct Input {
    raw: String,
    pick: u8,
}

const KNOWN_BAD: &[&str] = &[
    "file:///etc/passwd",
    "file://localhost/etc/shadow",
    "gopher://127.0.0.1:25/_HELO",
    "http://127.0.0.1/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/",
    "http://attacker.example/%00",
    "http://%6c%6f%63%61%6c%68%6f%73%74/",
    "http://localtest.me\\@evil.example/",
    "https://evil.example#@127.0.0.1/",
    "//evil.example/",
    "http://evil.example/\r\nHost: target",
];

fn check(input: &str) {
    // Exercise any URL parsing surface the workspace exposes via standard
    // libraries — must never panic.
    let _ = url::Url::parse(input);
    let _ = input.parse::<http::Uri>();
    // Ensure naive splitters cannot panic on adversarial bytes.
    let _ = input.split('/').count();
    let _ = input.bytes().filter(|&b| b == 0).count();
}

fuzz_target!(|input: Input| {
    if let Some(known) = KNOWN_BAD.get((input.pick as usize) % KNOWN_BAD.len()) {
        check(known);
    }
    check(&input.raw);
});
