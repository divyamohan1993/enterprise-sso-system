// CNSA 2.0 exception: SHA-256 mandated by RFC 7636 S256 method;
// CNSA 2.0 exception granted for OAuth interoperability.
// Changing this hash would break all OAuth 2.0/2.1 PKCE clients.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Validate that a PKCE code_verifier is 43-128 characters per RFC 7636 Section 4.1.
pub fn validate_verifier_length(verifier: &str) -> Result<(), &'static str> {
    let len = verifier.len();
    if len < 43 {
        Err("PKCE code_verifier too short: minimum 43 characters per RFC 7636")
    } else if len > 128 {
        Err("PKCE code_verifier too long: maximum 128 characters per RFC 7636")
    } else {
        Ok(())
    }
}

/// Verify a PKCE code_verifier against a stored code_challenge (S256 method).
/// Uses constant-time comparison as a defense-in-depth measure.
/// Returns false if the verifier length is outside the RFC 7636 range (43-128).
pub fn verify_pkce(code_verifier: &str, code_challenge: &str) -> bool {
    if validate_verifier_length(code_verifier).is_err() {
        return false;
    }
    let hash = Sha256::digest(code_verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(hash);
    let a = computed.as_bytes();
    let b = code_challenge.as_bytes();
    a.len() == b.len() && a.ct_eq(b).into()
}

/// Enforce that PKCE is present. Returns an error if code_challenge is None.
/// PKCE MUST be mandatory for all authorization requests per OAuth 2.1 / RFC 9126.
///
/// This function MUST be called at the start of every authorization code creation
/// flow. It is not optional — OAuth 2.1 (draft-ietf-oauth-v2-1) requires PKCE
/// for ALL clients, including confidential clients.
pub fn require_pkce(code_challenge: Option<&str>) -> Result<(), &'static str> {
    match code_challenge {
        Some(c) if !c.is_empty() => Ok(()),
        _ => Err("PKCE code_challenge is required for all authorization requests"),
    }
}

/// Combined PKCE enforcement and verification in one call.
/// Enforces that both code_challenge and code_verifier are present, then
/// verifies the S256 challenge. Returns an error if PKCE is missing or invalid.
pub fn verify_pkce_mandatory(
    code_verifier: Option<&str>,
    code_challenge: Option<&str>,
) -> Result<(), &'static str> {
    let challenge = code_challenge
        .ok_or("PKCE code_challenge is required for all authorization requests")?;
    let verifier = code_verifier
        .ok_or("PKCE code_verifier is required for token exchange")?;
    if challenge.is_empty() || verifier.is_empty() {
        return Err("PKCE code_challenge and code_verifier must not be empty");
    }
    validate_verifier_length(verifier)?;
    if verify_pkce(verifier, challenge) {
        Ok(())
    } else {
        Err("PKCE verification failed: code_verifier does not match code_challenge")
    }
}

/// Validate that the `code_challenge_method` is S256.
///
/// Per OAuth 2.1 (draft-ietf-oauth-v2-1) and this system's security policy,
/// only the S256 method is accepted. The "plain" method is explicitly forbidden
/// because it transmits the verifier in the clear, defeating PKCE's purpose.
///
/// Returns `Ok(())` if the method is `"S256"` or `None` (defaults to S256).
/// Returns `Err` for any other value, including `"plain"`.
pub fn validate_challenge_method(method: Option<&str>) -> Result<(), &'static str> {
    match method {
        None | Some("S256") => Ok(()),
        Some("plain") => Err("code_challenge_method 'plain' is forbidden — only S256 is accepted"),
        Some(_) => Err("unsupported code_challenge_method — only S256 is accepted"),
    }
}

pub fn generate_challenge(verifier: &str) -> String {
    let hash = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verifier_length_42_chars_rejected() {
        let verifier = "a".repeat(42);
        assert!(validate_verifier_length(&verifier).is_err());
    }

    #[test]
    fn test_verifier_length_43_chars_accepted() {
        let verifier = "a".repeat(43);
        assert!(validate_verifier_length(&verifier).is_ok());
    }

    #[test]
    fn test_verifier_length_128_chars_accepted() {
        let verifier = "a".repeat(128);
        assert!(validate_verifier_length(&verifier).is_ok());
    }

    #[test]
    fn test_verifier_length_129_chars_rejected() {
        let verifier = "a".repeat(129);
        assert!(validate_verifier_length(&verifier).is_err());
    }

    #[test]
    fn test_verify_pkce_rejects_short_verifier() {
        let verifier = "a".repeat(42);
        let challenge = generate_challenge(&verifier);
        assert!(!verify_pkce(&verifier, &challenge));
    }

    #[test]
    fn test_verify_pkce_rejects_long_verifier() {
        let verifier = "a".repeat(129);
        let challenge = generate_challenge(&verifier);
        assert!(!verify_pkce(&verifier, &challenge));
    }

    #[test]
    fn test_verify_pkce_mandatory_rejects_short_verifier() {
        let verifier = "a".repeat(42);
        let challenge = generate_challenge(&verifier);
        let result = verify_pkce_mandatory(Some(&verifier), Some(&challenge));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));
    }

    #[test]
    fn test_verify_pkce_valid_length() {
        let verifier = "a".repeat(43);
        let challenge = generate_challenge(&verifier);
        assert!(verify_pkce(&verifier, &challenge));
    }

    #[test]
    fn test_validate_challenge_method_s256() {
        assert!(validate_challenge_method(Some("S256")).is_ok());
    }

    #[test]
    fn test_validate_challenge_method_none_defaults_s256() {
        assert!(validate_challenge_method(None).is_ok());
    }

    #[test]
    fn test_validate_challenge_method_plain_rejected() {
        let err = validate_challenge_method(Some("plain")).unwrap_err();
        assert!(err.contains("plain"));
        assert!(err.contains("forbidden"));
    }

    #[test]
    fn test_validate_challenge_method_unknown_rejected() {
        assert!(validate_challenge_method(Some("RS256")).is_err());
    }
}
