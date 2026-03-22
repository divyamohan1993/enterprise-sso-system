use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, SignerMut};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

/// RSA key size for OIDC signing (3072-bit per CNSA 2.0 requirements).
const RSA_KEY_BITS: usize = 3072;

#[derive(Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub nonce: Option<String>,
    pub auth_time: i64,
    pub tier: u8,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub id_token: String,
    pub scope: String,
}

/// Wrapper around an RSA private key used for signing OIDC ID tokens with RS256.
pub struct OidcSigningKey {
    private_key: RsaPrivateKey,
    kid: String,
}

impl OidcSigningKey {
    /// Generate a new RSA-3072 signing key for OIDC.
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let private_key =
            RsaPrivateKey::new(&mut rng, RSA_KEY_BITS).expect("RSA key generation failed");
        Self {
            private_key,
            kid: "milnet-rs256-v1".to_string(),
        }
    }

    /// Return the public key for JWKS.
    pub fn public_key(&self) -> &RsaPublicKey {
        self.private_key.as_ref()
    }

    /// Key ID for JWK `kid` field.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Build the JWKS JSON value for this key.
    pub fn jwks_json(&self) -> serde_json::Value {
        let pub_key = self.public_key();
        let n = URL_SAFE_NO_PAD.encode(pub_key.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(pub_key.e().to_bytes_be());
        serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": self.kid,
                "n": n,
                "e": e
            }]
        })
    }
}

/// Create an RS256-signed JWT (for the OIDC layer)
pub fn create_id_token(
    issuer: &str,
    user_id: &Uuid,
    client_id: &str,
    nonce: Option<String>,
    signing_key: &OidcSigningKey,
) -> String {
    create_id_token_with_tier(issuer, user_id, client_id, nonce, signing_key, 2)
}

/// Create an RS256-signed JWT with an explicit tier claim
pub fn create_id_token_with_tier(
    issuer: &str,
    user_id: &Uuid,
    client_id: &str,
    nonce: Option<String>,
    signing_key: &OidcSigningKey,
    tier: u8,
) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let header = serde_json::json!({
        "alg": "RS256",
        "typ": "JWT",
        "kid": signing_key.kid()
    });
    let claims = IdTokenClaims {
        iss: issuer.to_string(),
        sub: user_id.to_string(),
        aud: client_id.to_string(),
        exp: now + 3600,
        iat: now,
        nonce,
        auth_time: now,
        tier,
    };

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{header_b64}.{claims_b64}");

    let mut signer = SigningKey::<Sha256>::new(signing_key.private_key.clone());
    let signature = signer
        .sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_vec());

    format!("{signing_input}.{sig_b64}")
}

/// Verify an RS256-signed JWT using the RSA public key.
pub fn verify_id_token(token: &str, public_key: &RsaPublicKey) -> Result<IdTokenClaims, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("invalid JWT: expected 3 parts".into());
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| format!("base64 decode sig: {e}"))?;

    use rsa::pkcs1v15::VerifyingKey;
    use rsa::signature::Verifier;
    let verifying_key = VerifyingKey::<Sha256>::new(public_key.clone());
    let signature = rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice())
        .map_err(|e| format!("invalid signature: {e}"))?;
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|e| format!("RS256 verification failed: {e}"))?;

    let claims_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| format!("base64 decode claims: {e}"))?;
    let claims: IdTokenClaims =
        serde_json::from_slice(&claims_bytes).map_err(|e| format!("parse claims: {e}"))?;

    Ok(claims)
}
