//! B12 — Aggressive fuzz / property tests for the FIDO CBOR parser.
//!
//! Goal: the custom CBOR reader in `verification.rs` must NEVER panic on
//! arbitrary input, and must return Err on truncated, oversized, or
//! malformed structures. We seed a corpus of crafted edge cases plus
//! pseudo-random byte streams.

use fido::verification::{
    parse_authenticator_data, parse_attestation_auth_data, verify_attestation_object,
};

const FAKE_RP: &str = "sso.milnet.example";
const ZERO_HASH: [u8; 32] = [0u8; 32];

fn must_not_panic(label: &str, bytes: &[u8]) {
    // Parser dispatch entry points — none of these may panic.
    let _ = parse_authenticator_data(bytes);
    let _ = parse_attestation_auth_data(bytes, FAKE_RP);
    let _ = verify_attestation_object(bytes, &ZERO_HASH, FAKE_RP);
    // Reaching here means no panic occurred.
    let _ = label;
}

#[test]
fn fuzz_corpus_empty_inputs() {
    must_not_panic("empty", &[]);
    must_not_panic("one_zero", &[0u8]);
    must_not_panic("all_ff_short", &[0xFFu8; 4]);
}

#[test]
fn fuzz_corpus_truncated_at_every_offset() {
    // A "valid-ish" attestation object built then truncated byte by byte.
    let valid: Vec<u8> = vec![
        0xA3, // map(3)
        0x63, b'f', b'm', b't',
        0x64, b'n', b'o', b'n', b'e',
        0x67, b'a', b't', b't', b'S', b't', b'm', b't',
        0xA0, // empty map
        0x68, b'a', b'u', b't', b'h', b'D', b'a', b't', b'a',
        0x40, // bstr(0)
    ];
    for n in 0..=valid.len() {
        must_not_panic(&format!("trunc{n}"), &valid[..n]);
    }
}

#[test]
fn fuzz_corpus_oversized_length_claims() {
    // CBOR map with claimed length 65535 but only one entry actually present.
    let mut buf: Vec<u8> = Vec::new();
    buf.push(0xB9); // map (uint16 length follows)
    buf.push(0xFF);
    buf.push(0xFF);
    must_not_panic("oversized_map", &buf);

    // CBOR bstr claiming 4 GiB length.
    let mut bstr: Vec<u8> = vec![0x5B];
    bstr.extend_from_slice(&[0xFFu8; 8]);
    must_not_panic("oversized_bstr_u64", &bstr);

    // Array claiming 2^32 items.
    let mut arr: Vec<u8> = vec![0x9A, 0xFF, 0xFF, 0xFF, 0xFF];
    must_not_panic("oversized_array_u32", &arr);
    arr.extend_from_slice(&[0u8; 16]);
    must_not_panic("oversized_array_with_data", &arr);
}

#[test]
fn fuzz_corpus_recursive_maps() {
    // Deeply nested maps to test stack safety / iteration bounds.
    let mut buf = Vec::new();
    for _ in 0..2048 {
        buf.push(0xA1); // map(1)
        buf.push(0x60); // text(0) ""
    }
    must_not_panic("deep_nesting", &buf);
}

#[test]
fn fuzz_corpus_random_bytes_never_panic() {
    // Deterministic LCG so the test is reproducible without rand crate.
    let mut state: u64 = 0xDEAD_BEEF_CAFE_F00D;
    for case in 0..2048 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let len = (state as usize) % 256;
        let mut buf = vec![0u8; len];
        for b in buf.iter_mut() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *b = (state >> 33) as u8;
        }
        must_not_panic(&format!("rand{case}"), &buf);
    }
}

#[test]
fn fuzz_corpus_negative_int_overflows() {
    // CBOR negative int with maximum magnitude.
    must_not_panic("nint_max", &[0x3B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    // Tagged value with huge tag.
    must_not_panic("tag_huge", &[0xDB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
}

#[test]
fn fuzz_corpus_authdata_minimum_boundary() {
    // 36 bytes — one byte short of MIN_AUTH_DATA_LEN
    let buf = vec![0u8; 36];
    assert!(parse_authenticator_data(&buf).is_err());
    // 37 bytes — minimum valid header
    let buf = vec![0u8; 37];
    assert!(parse_authenticator_data(&buf).is_ok());
    // AT flag set but no attested data attached → parse_attestation must fail
    let mut buf = vec![0u8; 37];
    buf[32] = 0x45; // UP|UV|AT
    assert!(parse_attestation_auth_data(&buf, FAKE_RP).is_err());
}

#[test]
fn fuzz_corpus_credential_id_length_overflow() {
    // Build attestation authdata with a credential ID length that overflows
    // the underlying buffer.
    let mut buf = vec![0u8; 37];
    buf[32] = 0x45; // flags UP|UV|AT
    // AAGUID (16 zero bytes)
    buf.extend_from_slice(&[0u8; 16]);
    // Claim a 65535-byte credential ID
    buf.extend_from_slice(&[0xFF, 0xFF]);
    // No additional bytes — the parser must reject without panicking.
    let r = parse_attestation_auth_data(&buf, FAKE_RP);
    assert!(r.is_err());
}
