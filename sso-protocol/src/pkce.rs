// CNSA 2.0 exception: SHA-256 mandated by RFC 7636 S256 method;
// CNSA 2.0 exception granted for OAuth interoperability.
// Changing this hash would break all OAuth 2.0/2.1 PKCE clients.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Verify a PKCE code_verifier against a stored code_challenge (S256 method).
/// Uses constant-time comparison as a defense-in-depth measure.
pub fn verify_pkce(code_verifier: &str, code_challenge: &str) -> bool {
    let hash = Sha256::digest(code_verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(hash);
    let a = computed.as_bytes();
    let b = code_challenge.as_bytes();
    a.len() == b.len() && a.ct_eq(b).into()
}

/// Enforce that PKCE is present. Returns an error if code_challenge is None.
/// PKCE MUST be mandatory for all authorization requests per OAuth 2.1 / RFC 9126.
pub fn require_pkce(code_challenge: Option<&str>) -> Result<(), &'static str> {
    match code_challenge {
        Some(_) => Ok(()),
        None => Err("PKCE code_challenge is required for all authorization requests"),
    }
}

pub fn generate_challenge(verifier: &str) -> String {
    let hash = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}
