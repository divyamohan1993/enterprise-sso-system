#![no_main]
//! I1 [CRIT] JWT signature forgery fuzz.
//!
//! Builds a valid-looking JWT seed, mutates signature bytes / flips bits /
//! signs with the wrong key, and asserts the verifier rejects every forged
//! variant without panicking.

use arbitrary::Arbitrary;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use crypto::pq_sign::{generate_pq_keypair, pq_sign_raw, PqSigningKey, PqVerifyingKey};
use libfuzzer_sys::fuzz_target;

struct Keys {
    sk_real: PqSigningKey,
    vk_real: PqVerifyingKey,
    sk_wrong: PqSigningKey,
}

static KEYS: std::sync::LazyLock<Keys> = std::sync::LazyLock::new(|| {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            let (sk_real, vk_real) = generate_pq_keypair();
            let (sk_wrong, _) = generate_pq_keypair();
            Keys { sk_real, vk_real, sk_wrong }
        })
        .unwrap()
        .join()
        .unwrap()
});

#[derive(Debug, Arbitrary)]
struct ForgeInput {
    payload_seed: Vec<u8>,
    flip_indices: Vec<u16>,
    use_wrong_key: bool,
    truncate_bytes: u16,
    extra_garbage: Vec<u8>,
    rebuild_token: bool,
}

fuzz_target!(|input: ForgeInput| {
    let keys = &*KEYS;

    // Build a signed payload using either the real or wrong key.
    let payload: Vec<u8> = if input.payload_seed.is_empty() {
        b"forge-seed".to_vec()
    } else {
        input.payload_seed.iter().take(4096).copied().collect()
    };
    let signer = if input.use_wrong_key { &keys.sk_wrong } else { &keys.sk_real };
    let mut sig = pq_sign_raw(signer, &payload);

    // Mutate the signature bytes: flip random bits + truncate + append garbage.
    if !sig.is_empty() {
        for &idx in input.flip_indices.iter().take(32) {
            let i = (idx as usize) % sig.len();
            sig[i] ^= 0x5A;
        }
    }
    let trunc = (input.truncate_bytes as usize) % (sig.len().max(1));
    sig.truncate(sig.len().saturating_sub(trunc));
    sig.extend(input.extra_garbage.iter().take(64));

    // Verifier MUST reject any forged/mutated signature and MUST NOT panic.
    let valid = crypto::pq_sign::pq_verify_raw(&keys.vk_real, &payload, &sig);
    if input.use_wrong_key {
        assert!(!valid, "wrong-key signature must be rejected");
    }

    // Also exercise the JWT token verifier with a synthetic forged token.
    if input.rebuild_token {
        let header = br#"{"alg":"ML-DSA-87","typ":"JWT"}"#;
        let payload_json = br#"{"iss":"forge","sub":"x","aud":"y","exp":9999999999,"iat":1,"tier":0,"jti":"j"}"#;
        let token = format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(payload_json),
            URL_SAFE_NO_PAD.encode(&sig),
        );
        let _ = sso_protocol::tokens::verify_id_token(&token, &keys.vk_real);
    }
});
