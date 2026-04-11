#![no_main]
use arbitrary::Arbitrary;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use crypto::dpop::{generate_dpop_keypair, verify_dpop_proof};
use libfuzzer_sys::fuzz_target;

static VK: std::sync::LazyLock<crypto::dpop::DpopVerifyingKey> =
    std::sync::LazyLock::new(|| {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| generate_dpop_keypair().1)
            .unwrap()
            .join()
            .unwrap()
    });

/// Structured DPoP proof input for more effective fuzzing.
/// Generates JWT-like structures with DPoP-specific fields.
#[derive(Debug, Arbitrary)]
struct FuzzDpopInput {
    /// Use structured JWT or raw bytes.
    use_structured: bool,
    /// Header fields.
    alg: String,
    typ: String,
    /// Payload fields.
    htm: String,
    htu: String,
    iat: i64,
    jti: String,
    /// Access token hash.
    ath: Vec<u8>,
    /// Signature bytes.
    sig_bytes: Vec<u8>,
    /// HTTP method for verification.
    http_method: String,
    /// HTTP URI for verification.
    http_uri: String,
    /// Time offset for iat validation.
    time_offset: i64,
    /// Raw fallback data.
    raw_data: Vec<u8>,
}

impl FuzzDpopInput {
    fn to_dpop_jwt(&self) -> Vec<u8> {
        let header = format!(
            r#"{{"alg":"{}","typ":"{}"}}"#,
            &self.alg.chars().take(50).collect::<String>(),
            &self.typ.chars().take(20).collect::<String>(),
        );
        let payload = format!(
            r#"{{"htm":"{}","htu":"{}","iat":{},"jti":"{}"}}"#,
            &self.htm.chars().take(20).collect::<String>(),
            &self.htu.chars().take(500).collect::<String>(),
            self.iat,
            &self.jti.chars().take(100).collect::<String>(),
        );

        let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let sig_data: Vec<u8> = self.sig_bytes.iter().take(8192).copied().collect();
        let sig_b64 = URL_SAFE_NO_PAD.encode(&sig_data);

        format!("{}.{}.{}", header_b64, payload_b64, sig_b64).into_bytes()
    }
}

fuzz_target!(|input: FuzzDpopInput| {
    let proof = if input.use_structured {
        input.to_dpop_jwt()
    } else {
        input.raw_data.clone()
    };

    let hash: Vec<u8> = input.ath.iter().take(64).copied().collect();
    let mut ath = [0u8; 64];
    for (i, b) in hash.iter().enumerate() {
        if i < 64 { ath[i] = *b; }
    }

    let method: String = input.http_method.chars().take(10).collect();
    let uri: String = input.http_uri.chars().take(500).collect();

    let _ = verify_dpop_proof(
        &VK,
        &proof,
        &proof, // nonce = proof (fuzz both paths)
        input.time_offset,
        &ath,
        method.as_bytes(),
        uri.as_bytes(),
        None,
    );
});
