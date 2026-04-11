#![no_main]
use arbitrary::Arbitrary;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use crypto::pq_sign::generate_pq_keypair;
use libfuzzer_sys::fuzz_target;

static VK: std::sync::LazyLock<crypto::pq_sign::PqVerifyingKey> =
    std::sync::LazyLock::new(|| {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| generate_pq_keypair().1)
            .unwrap()
            .join()
            .unwrap()
    });

/// Structured JWT-like input for more effective fuzzing.
/// Generates base64url(header).base64url(payload).base64url(sig) structures
/// that exercise the JWT parser more deeply than random bytes.
#[derive(Debug, Arbitrary)]
struct FuzzJwtInput {
    /// Use structured JWT or raw string.
    use_structured: bool,
    /// Header JSON fields.
    alg: String,
    typ: String,
    kid: String,
    /// Payload JSON fields.
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    iat: i64,
    tier: u8,
    jti: String,
    /// Signature bytes (will be base64url-encoded).
    sig_bytes: Vec<u8>,
    /// Raw fallback.
    raw_token: String,
    /// Number of dots in the token (to test malformed structures).
    extra_dots: u8,
}

impl FuzzJwtInput {
    fn to_jwt_string(&self) -> String {
        let header = format!(
            r#"{{"alg":"{}","typ":"{}","kid":"{}"}}"#,
            &self.alg.chars().take(50).collect::<String>(),
            &self.typ.chars().take(20).collect::<String>(),
            &self.kid.chars().take(100).collect::<String>(),
        );
        let payload = format!(
            r#"{{"iss":"{}","sub":"{}","aud":"{}","exp":{},"iat":{},"tier":{},"jti":"{}"}}"#,
            &self.iss.chars().take(200).collect::<String>(),
            &self.sub.chars().take(200).collect::<String>(),
            &self.aud.chars().take(200).collect::<String>(),
            self.exp,
            self.iat,
            self.tier,
            &self.jti.chars().take(100).collect::<String>(),
        );

        let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());

        // Use provided sig bytes (capped to prevent OOM).
        let sig_data: Vec<u8> = self.sig_bytes.iter().take(8192).copied().collect();
        let sig_b64 = URL_SAFE_NO_PAD.encode(&sig_data);

        let mut token = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);

        // Add extra dots to test malformed token handling.
        for _ in 0..(self.extra_dots % 5) {
            token.push('.');
            token.push_str(&sig_b64);
        }

        token
    }
}

fuzz_target!(|input: FuzzJwtInput| {
    let token = if input.use_structured {
        input.to_jwt_string()
    } else {
        input.raw_token.clone()
    };
    let _ = sso_protocol::tokens::verify_id_token(&token, &VK);
});
