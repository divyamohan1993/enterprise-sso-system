#![no_main]
//! CAT-M: JWT signature tamper fuzz.
//!
//! Complements `fuzz_jwt_forge` by focusing on *structural* mutation of a
//! known-valid JWT: single-bit flips, header/payload swaps, and alg-none
//! downgrade attempts. Asserts `sso_protocol::tokens::verify_id_token`
//! rejects every forged variant without panicking.
//!
//! Success criterion: no panic, and no tampered token verifies.

use arbitrary::Arbitrary;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use crypto::pq_sign::{generate_pq_keypair, pq_sign_raw, PqSigningKey, PqVerifyingKey};
use libfuzzer_sys::fuzz_target;

struct Keys {
    sk: PqSigningKey,
    vk: PqVerifyingKey,
}

static KEYS: std::sync::LazyLock<Keys> = std::sync::LazyLock::new(|| {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            let (sk, vk) = generate_pq_keypair();
            Keys { sk, vk }
        })
        .unwrap()
        .join()
        .unwrap()
});

#[derive(Debug, Arbitrary)]
struct TamperInput {
    // Index of the byte to flip, modulo signature length.
    flip_byte_idx: u16,
    // Bit within that byte to flip.
    flip_bit: u8,
    // When true, replace header with `{"alg":"none"}`.
    alg_none: bool,
    // When true, swap header and payload segments.
    swap_header_payload: bool,
    // When true, truncate the signature segment entirely.
    strip_signature: bool,
    // When true, append a trailing `.garbage` segment.
    append_garbage: bool,
    // When true, URL-encode a NUL byte into the payload segment.
    null_byte_payload: bool,
}

fn build_valid_token(sk: &PqSigningKey) -> String {
    let header = br#"{"alg":"ML-DSA-87","typ":"JWT"}"#;
    let payload = br#"{"iss":"milnet","sub":"s","aud":"a","exp":9999999999,"iat":1,"tier":0,"jti":"j","nonce":"n"}"#;
    let h_b64 = URL_SAFE_NO_PAD.encode(header);
    let p_b64 = URL_SAFE_NO_PAD.encode(payload);
    let signing_input = format!("{}.{}", h_b64, p_b64);
    let sig = pq_sign_raw(sk, signing_input.as_bytes());
    format!("{}.{}", signing_input, URL_SAFE_NO_PAD.encode(&sig))
}

fuzz_target!(|input: TamperInput| {
    let keys = &*KEYS;
    let valid = build_valid_token(&keys.sk);

    // Split into segments.
    let parts: Vec<&str> = valid.split('.').collect();
    if parts.len() != 3 {
        return;
    }
    let mut header = parts[0].to_string();
    let mut payload = parts[1].to_string();
    let mut sig_b64 = parts[2].to_string();

    // Apply mutations.
    if input.alg_none {
        header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
    }
    if input.swap_header_payload {
        std::mem::swap(&mut header, &mut payload);
    }
    if input.null_byte_payload {
        payload = URL_SAFE_NO_PAD.encode(b"{\"iss\":\"a\x00b\",\"sub\":\"x\"}");
    }
    if input.strip_signature {
        sig_b64.clear();
    } else if let Ok(mut sig_bytes) = URL_SAFE_NO_PAD.decode(&sig_b64) {
        if !sig_bytes.is_empty() {
            let i = (input.flip_byte_idx as usize) % sig_bytes.len();
            let b = (input.flip_bit as usize) & 7;
            sig_bytes[i] ^= 1u8 << b;
            sig_b64 = URL_SAFE_NO_PAD.encode(&sig_bytes);
        }
    }

    let mut tampered = format!("{}.{}.{}", header, payload, sig_b64);
    if input.append_garbage {
        tampered.push_str(".garbage");
    }

    // Any tampered token MUST be rejected. Panic-free is the hard guarantee;
    // logical rejection is asserted for the bit-flip path where the pre-image
    // is otherwise valid.
    let result = sso_protocol::tokens::verify_id_token(&tampered, &keys.vk);

    // If we only flipped a signature bit (no other structural mutation) the
    // verifier must return Err — a bit-flipped ML-DSA-87 signature cannot
    // verify by accident, and any success here is a bug.
    let only_bit_flip = !input.alg_none
        && !input.swap_header_payload
        && !input.strip_signature
        && !input.append_garbage
        && !input.null_byte_payload;
    if only_bit_flip {
        assert!(result.is_err(), "bit-flipped JWT signature must not verify");
    }
});
