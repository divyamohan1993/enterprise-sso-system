//! WebAuthn authenticator data parsing and signature verification.
//!
//! Implements authenticator data validation per the W3C WebAuthn spec
//! (§6.1 "Authenticator Data"). Actual ECDSA signature verification
//! is stubbed until a suitable crypto crate (e.g. `p256`) is added.
//!
//! CNSA 2.0 exception: SHA-256 is mandated by the W3C WebAuthn specification
//! and FIDO2 CTAP2 protocol for RP ID hashing and client data hashing.
//! Changing this hash would break all WebAuthn authenticators. CNSA 2.0
//! exception granted for FIDO2/WebAuthn interoperability.

use sha2::{Digest, Sha256};

/// Minimum authenticator data length:
///   32 bytes (RP ID hash) + 1 byte (flags) + 4 bytes (sign count) = 37
const MIN_AUTH_DATA_LEN: usize = 37;

/// Authenticator data flags (§6.1).
const FLAG_UP: u8 = 0b0000_0001; // bit 0 — User Present
const FLAG_UV: u8 = 0b0000_0100; // bit 2 — User Verified
const FLAG_AT: u8 = 0b0100_0000; // bit 6 — Attested credential data included

/// Parsed representation of the authenticator data binary blob.
#[derive(Debug, Clone)]
pub struct ParsedAuthData {
    /// SHA-256 hash of the RP ID that the authenticator used.
    pub rp_id_hash: [u8; 32],
    /// Raw flags byte.
    pub flags: u8,
    /// Signature counter reported by the authenticator.
    pub sign_count: u32,
    /// True if the User Present flag is set.
    pub user_present: bool,
    /// True if the User Verified flag is set.
    pub user_verified: bool,
    /// True if attested credential data is included.
    pub attested_credential_data: bool,
}

/// Parse the raw authenticator data bytes per WebAuthn §6.1.
///
/// Returns the parsed structure or a descriptive error.
pub fn parse_authenticator_data(auth_data: &[u8]) -> Result<ParsedAuthData, &'static str> {
    if auth_data.len() < MIN_AUTH_DATA_LEN {
        return Err("Authenticator data too short (must be >= 37 bytes)");
    }

    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&auth_data[0..32]);

    let flags = auth_data[32];

    let sign_count = u32::from_be_bytes([
        auth_data[33],
        auth_data[34],
        auth_data[35],
        auth_data[36],
    ]);

    Ok(ParsedAuthData {
        rp_id_hash,
        flags,
        sign_count,
        user_present: flags & FLAG_UP != 0,
        user_verified: flags & FLAG_UV != 0,
        attested_credential_data: flags & FLAG_AT != 0,
    })
}

/// Validate that the RP ID hash in authenticator data matches the expected RP ID.
pub fn validate_rp_id_hash(parsed: &ParsedAuthData, expected_rp_id: &str) -> Result<(), &'static str> {
    let expected_hash = Sha256::digest(expected_rp_id.as_bytes());
    if parsed.rp_id_hash[..] != expected_hash[..] {
        return Err("RP ID hash mismatch");
    }
    Ok(())
}

/// Validate that the User Present (UP) flag is set, as required by WebAuthn.
pub fn validate_user_present(parsed: &ParsedAuthData) -> Result<(), &'static str> {
    if !parsed.user_present {
        return Err("User Present flag not set");
    }
    Ok(())
}

/// Validate that the User Verified (UV) flag is set (when policy requires it).
pub fn validate_user_verified(parsed: &ParsedAuthData) -> Result<(), &'static str> {
    if !parsed.user_verified {
        return Err("User Verified flag not set but required by policy");
    }
    Ok(())
}

/// Verify the authenticator's signature over `authenticator_data || client_data_hash`.
///
/// # Algorithm support
///
/// WebAuthn ES256 uses ECDSA with the NIST P-256 curve and SHA-256.
/// The `public_key` is expected in COSE key format or uncompressed SEC1 form.
///
/// # Current status
///
/// This is a **verification stub**. Full cryptographic verification requires
/// the `p256` crate (or equivalent). All structural and policy checks are
/// performed; only the final ECDSA `verify()` call is stubbed.
///
/// TODO(crypto): Add `p256 = "0.13"` to Cargo.toml, then replace the stub
/// body with:
/// ```ignore
/// use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
/// let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
///     .map_err(|_| "Invalid public key")?;
/// let sig = Signature::from_der(signature)
///     .map_err(|_| "Invalid signature encoding")?;
/// let mut msg = authenticator_data.to_vec();
/// msg.extend_from_slice(&client_data_hash);
/// verifying_key.verify(&msg, &sig)
///     .map_err(|_| "Signature verification failed")?;
/// ```
pub fn verify_signature_es256(
    authenticator_data: &[u8],
    client_data_hash: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<(), &'static str> {
    if authenticator_data.len() < MIN_AUTH_DATA_LEN {
        return Err("Authenticator data too short for signature verification");
    }
    if client_data_hash.len() != 32 {
        return Err("Client data hash must be 32 bytes (SHA-256)");
    }
    if signature.is_empty() {
        return Err("Signature is empty");
    }
    if public_key.is_empty() {
        return Err("Public key is empty");
    }

    if public_key.len() == 65 && public_key[0] != 0x04 {
        return Err("Uncompressed public key must start with 0x04");
    }

    // Real ECDSA P-256 signature verification
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

    let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|_| "Invalid public key encoding")?;

    let sig = Signature::from_der(signature)
        .map_err(|_| "Invalid DER signature encoding")?;

    // The signed message is: authenticator_data || client_data_hash
    let mut msg = authenticator_data.to_vec();
    msg.extend_from_slice(client_data_hash);

    verifying_key.verify(&msg, &sig)
        .map_err(|_| "ES256 signature verification failed")?;

    Ok(())
}

/// Full authentication response verification pipeline.
///
/// Validates authenticator data structure, RP ID, flags, sign count,
/// and (when crypto is available) the assertion signature.
///
/// `require_user_verification`: set to `true` when policy demands UV.
///
/// Returns the new sign count on success so the caller can persist it.
pub fn verify_authentication_response(
    auth_result: &crate::types::AuthenticationResult,
    stored_credential: &crate::types::StoredCredential,
    expected_rp_id: &str,
    require_user_verification: bool,
) -> Result<u32, &'static str> {
    // 1. Parse authenticator data
    let parsed = parse_authenticator_data(&auth_result.authenticator_data)?;

    // 2. Validate RP ID hash
    validate_rp_id_hash(&parsed, expected_rp_id)?;

    // 3. Validate UP flag (always required)
    validate_user_present(&parsed)?;

    // 4. Validate UV flag (when required by policy)
    if require_user_verification {
        validate_user_verified(&parsed)?;
    }

    // 5. Validate sign count (detect cloned authenticators)
    //    The new count must be strictly greater than the stored count.
    //    A sign_count of 0 on both sides is a special case: some authenticators
    //    do not implement counters and always report 0. We allow that.
    if stored_credential.sign_count > 0 || parsed.sign_count > 0 {
        if parsed.sign_count <= stored_credential.sign_count {
            return Err("Possible authenticator clone detected");
        }
    }

    // 6. Compute client data hash
    let client_data_hash = Sha256::digest(&auth_result.client_data);

    // 7. Verify signature over (authenticator_data || client_data_hash)
    verify_signature_es256(
        &auth_result.authenticator_data,
        &client_data_hash,
        &auth_result.signature,
        &stored_credential.public_key,
    )?;

    Ok(parsed.sign_count)
}

/// Parse attestation data from a registration response.
///
/// Extracts the RP ID hash from the authenticator data embedded in the
/// attestation object, validates it against the expected RP ID, and
/// extracts the credential ID and public key.
///
/// The `attestation_object` is expected to be a CBOR-encoded map with
/// at minimum an `authData` field. For simplicity, we do a best-effort
/// parse of the raw authData bytes when provided directly.
pub fn parse_attestation_auth_data(
    auth_data: &[u8],
    expected_rp_id: &str,
) -> Result<AttestationData, &'static str> {
    let parsed = parse_authenticator_data(auth_data)?;

    // Validate RP ID hash
    validate_rp_id_hash(&parsed, expected_rp_id)?;

    // Validate UP flag (must be set during registration)
    validate_user_present(&parsed)?;

    // The AT flag must be set for registration (attested credential data present)
    if !parsed.attested_credential_data {
        return Err("Attested credential data flag not set in registration response");
    }

    // Parse attested credential data (follows the 37-byte fixed header):
    //   16 bytes  — AAGUID
    //   2 bytes   — credential ID length (big-endian)
    //   L bytes   — credential ID
    //   remaining — COSE public key
    if auth_data.len() < MIN_AUTH_DATA_LEN + 18 {
        return Err("Authenticator data too short for attested credential data");
    }

    let cred_id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    let cred_id_start = 55;
    let cred_id_end = cred_id_start + cred_id_len;

    if auth_data.len() < cred_id_end + 1 {
        return Err("Authenticator data truncated before public key");
    }

    let credential_id = auth_data[cred_id_start..cred_id_end].to_vec();
    let public_key_cose = auth_data[cred_id_end..].to_vec();

    Ok(AttestationData {
        credential_id,
        public_key_cose,
        sign_count: parsed.sign_count,
    })
}

/// Data extracted from attestation during registration.
#[derive(Debug, Clone)]
pub struct AttestationData {
    pub credential_id: Vec<u8>,
    pub public_key_cose: Vec<u8>,
    pub sign_count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::SignatureEncoding;

    /// Helper: generate a P-256 keypair and sign authenticator_data || client_data_hash
    fn sign_auth_data(auth_data: &[u8], client_data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        use p256::ecdsa::SigningKey;
        use p256::ecdsa::signature::Signer;
        use sha2::{Sha256, Digest};
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();
        let public_key = verifying_key.to_sec1_bytes().to_vec();

        let client_data_hash = Sha256::digest(client_data);
        let mut msg = auth_data.to_vec();
        msg.extend_from_slice(&client_data_hash);

        let sig: p256::ecdsa::Signature = signing_key.sign(&msg);
        (sig.to_der().to_vec(), public_key)
    }

    /// Helper: build a minimal 37-byte authenticator data blob.
    fn make_auth_data(rp_id: &str, flags: u8, sign_count: u32) -> Vec<u8> {
        let rp_hash = Sha256::digest(rp_id.as_bytes());
        let mut data = Vec::with_capacity(37);
        data.extend_from_slice(&rp_hash);
        data.push(flags);
        data.extend_from_slice(&sign_count.to_be_bytes());
        data
    }

    /// Helper: build auth data with attested credential data appended.
    fn make_auth_data_with_cred(
        rp_id: &str,
        flags: u8,
        sign_count: u32,
        credential_id: &[u8],
        public_key_cose: &[u8],
    ) -> Vec<u8> {
        let mut data = make_auth_data(rp_id, flags, sign_count);
        // AAGUID (16 bytes of zeros)
        data.extend_from_slice(&[0u8; 16]);
        // credential ID length (2 bytes, big-endian)
        let cred_len = credential_id.len() as u16;
        data.extend_from_slice(&cred_len.to_be_bytes());
        // credential ID
        data.extend_from_slice(credential_id);
        // COSE public key
        data.extend_from_slice(public_key_cose);
        data
    }

    #[test]
    fn test_parse_authenticator_data_valid() {
        let auth_data = make_auth_data("sso.milnet.example", 0x05, 42);
        let parsed = parse_authenticator_data(&auth_data).unwrap();
        assert!(parsed.user_present);
        assert!(parsed.user_verified);
        assert!(!parsed.attested_credential_data);
        assert_eq!(parsed.sign_count, 42);
    }

    #[test]
    fn test_parse_authenticator_data_too_short() {
        let short = vec![0u8; 36];
        assert_eq!(
            parse_authenticator_data(&short).unwrap_err(),
            "Authenticator data too short (must be >= 37 bytes)"
        );
    }

    #[test]
    fn test_validate_rp_id_hash_ok() {
        let auth_data = make_auth_data("sso.milnet.example", 0x01, 0);
        let parsed = parse_authenticator_data(&auth_data).unwrap();
        assert!(validate_rp_id_hash(&parsed, "sso.milnet.example").is_ok());
    }

    #[test]
    fn test_validate_rp_id_hash_mismatch() {
        let auth_data = make_auth_data("sso.milnet.example", 0x01, 0);
        let parsed = parse_authenticator_data(&auth_data).unwrap();
        assert_eq!(
            validate_rp_id_hash(&parsed, "evil.example.com").unwrap_err(),
            "RP ID hash mismatch"
        );
    }

    #[test]
    fn test_user_present_flag() {
        let data_up_set = make_auth_data("x", 0x01, 0);
        let parsed = parse_authenticator_data(&data_up_set).unwrap();
        assert!(validate_user_present(&parsed).is_ok());

        let data_up_clear = make_auth_data("x", 0x00, 0);
        let parsed = parse_authenticator_data(&data_up_clear).unwrap();
        assert_eq!(
            validate_user_present(&parsed).unwrap_err(),
            "User Present flag not set"
        );
    }

    #[test]
    fn test_user_verified_flag() {
        // UV = bit 2 = 0x04
        let data_uv_set = make_auth_data("x", 0x05, 0); // UP + UV
        let parsed = parse_authenticator_data(&data_uv_set).unwrap();
        assert!(validate_user_verified(&parsed).is_ok());

        let data_uv_clear = make_auth_data("x", 0x01, 0); // UP only
        let parsed = parse_authenticator_data(&data_uv_clear).unwrap();
        assert_eq!(
            validate_user_verified(&parsed).unwrap_err(),
            "User Verified flag not set but required by policy"
        );
    }

    #[test]
    fn test_verify_signature_structural_checks() {
        let auth_data = make_auth_data("x", 0x05, 1);
        let hash = [0u8; 32];
        let sig = vec![0x30, 0x44]; // minimal DER-like
        let pubkey = vec![0x04; 65]; // uncompressed point prefix

        // Empty signature
        assert_eq!(
            verify_signature_es256(&auth_data, &hash, &[], &pubkey).unwrap_err(),
            "Signature is empty"
        );

        // Empty public key
        assert_eq!(
            verify_signature_es256(&auth_data, &hash, &sig, &[]).unwrap_err(),
            "Public key is empty"
        );

        // Bad client data hash length
        assert_eq!(
            verify_signature_es256(&auth_data, &[0u8; 16], &sig, &pubkey).unwrap_err(),
            "Client data hash must be 32 bytes (SHA-256)"
        );

        // Auth data too short
        assert_eq!(
            verify_signature_es256(&[0u8; 10], &hash, &sig, &pubkey).unwrap_err(),
            "Authenticator data too short for signature verification"
        );
    }

    #[test]
    fn test_verify_authentication_response_sign_count() {
        use crate::types::{AuthenticationResult, StoredCredential};
        use uuid::Uuid;

        let rp_id = "sso.milnet.example";
        let user_id = Uuid::new_v4();

        // flags: UP | UV = 0x05, sign_count = 10
        let auth_data = make_auth_data(rp_id, 0x05, 10);
        let client_data = b"test-client-data".to_vec();

        let (signature, public_key) = sign_auth_data(&auth_data, &client_data);

        let auth_result = AuthenticationResult {
            credential_id: vec![1, 2, 3],
            authenticator_data: auth_data,
            client_data,
            signature,
        };

        // Stored credential with sign_count = 5 (< 10, should pass)
        let stored = StoredCredential {
            credential_id: vec![1, 2, 3],
            public_key,
            user_id,
            sign_count: 5,
            authenticator_type: "cross-platform".into(),
        };

        let new_count = verify_authentication_response(&auth_result, &stored, rp_id, true).unwrap();
        assert_eq!(new_count, 10);
    }

    #[test]
    fn test_verify_authentication_response_clone_detected() {
        use crate::types::{AuthenticationResult, StoredCredential};
        use uuid::Uuid;

        let rp_id = "sso.milnet.example";
        let user_id = Uuid::new_v4();

        // sign_count = 5 in authenticator data, but stored is 10
        let auth_data = make_auth_data(rp_id, 0x05, 5);

        let auth_result = AuthenticationResult {
            credential_id: vec![1, 2, 3],
            authenticator_data: auth_data,
            client_data: b"test".to_vec(),
            signature: vec![0x30, 0x44],
        };

        let stored = StoredCredential {
            credential_id: vec![1, 2, 3],
            public_key: vec![0x04; 65],
            user_id,
            sign_count: 10,
            authenticator_type: "platform".into(),
        };

        let err = verify_authentication_response(&auth_result, &stored, rp_id, true).unwrap_err();
        assert_eq!(err, "Possible authenticator clone detected");
    }

    #[test]
    fn test_verify_authentication_response_equal_sign_count_rejected() {
        use crate::types::{AuthenticationResult, StoredCredential};
        use uuid::Uuid;

        let rp_id = "sso.milnet.example";
        let auth_data = make_auth_data(rp_id, 0x05, 5);

        let auth_result = AuthenticationResult {
            credential_id: vec![1, 2, 3],
            authenticator_data: auth_data,
            client_data: b"test".to_vec(),
            signature: vec![0x30, 0x44],
        };

        let stored = StoredCredential {
            credential_id: vec![1, 2, 3],
            public_key: vec![0x04; 65],
            user_id: Uuid::new_v4(),
            sign_count: 5,
            authenticator_type: "platform".into(),
        };

        let err = verify_authentication_response(&auth_result, &stored, rp_id, true).unwrap_err();
        assert_eq!(err, "Possible authenticator clone detected");
    }

    #[test]
    fn test_verify_authentication_response_zero_counters_allowed() {
        use crate::types::{AuthenticationResult, StoredCredential};
        use uuid::Uuid;

        let rp_id = "sso.milnet.example";
        // Both stored and reported sign counts are 0 (authenticator doesn't support counters)
        let auth_data = make_auth_data(rp_id, 0x05, 0);
        let client_data = b"test".to_vec();

        let (signature, public_key) = sign_auth_data(&auth_data, &client_data);

        let auth_result = AuthenticationResult {
            credential_id: vec![1, 2, 3],
            authenticator_data: auth_data,
            client_data,
            signature,
        };

        let stored = StoredCredential {
            credential_id: vec![1, 2, 3],
            public_key,
            user_id: Uuid::new_v4(),
            sign_count: 0,
            authenticator_type: "cross-platform".into(),
        };

        let result = verify_authentication_response(&auth_result, &stored, rp_id, true);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_verify_authentication_response_rp_id_mismatch() {
        use crate::types::{AuthenticationResult, StoredCredential};
        use uuid::Uuid;

        // Auth data is for "evil.com", but we expect "sso.milnet.example"
        let auth_data = make_auth_data("evil.com", 0x05, 1);

        let auth_result = AuthenticationResult {
            credential_id: vec![1, 2, 3],
            authenticator_data: auth_data,
            client_data: b"test".to_vec(),
            signature: vec![0x30, 0x44],
        };

        let stored = StoredCredential {
            credential_id: vec![1, 2, 3],
            public_key: vec![0x04; 65],
            user_id: Uuid::new_v4(),
            sign_count: 0,
            authenticator_type: "cross-platform".into(),
        };

        let err = verify_authentication_response(&auth_result, &stored, "sso.milnet.example", true)
            .unwrap_err();
        assert_eq!(err, "RP ID hash mismatch");
    }

    #[test]
    fn test_verify_authentication_response_uv_not_required() {
        use crate::types::{AuthenticationResult, StoredCredential};
        use uuid::Uuid;

        let rp_id = "sso.milnet.example";
        // flags: UP only (0x01), no UV
        let auth_data = make_auth_data(rp_id, 0x01, 1);
        let client_data = b"test".to_vec();

        let (signature, public_key) = sign_auth_data(&auth_data, &client_data);

        let auth_result = AuthenticationResult {
            credential_id: vec![1, 2, 3],
            authenticator_data: auth_data,
            client_data,
            signature,
        };

        let stored = StoredCredential {
            credential_id: vec![1, 2, 3],
            public_key,
            user_id: Uuid::new_v4(),
            sign_count: 0,
            authenticator_type: "cross-platform".into(),
        };

        // UV not required — should pass
        let result = verify_authentication_response(&auth_result, &stored, rp_id, false);
        assert!(result.is_ok());

        // UV required — should fail (fails before signature verification)
        let auth_data2 = make_auth_data(rp_id, 0x01, 2);
        let auth_result2 = AuthenticationResult {
            credential_id: vec![1, 2, 3],
            authenticator_data: auth_data2,
            client_data: b"test".to_vec(),
            signature: vec![0x30, 0x44],
        };
        let err = verify_authentication_response(&auth_result2, &stored, rp_id, true).unwrap_err();
        assert_eq!(err, "User Verified flag not set but required by policy");
    }

    #[test]
    fn test_parse_attestation_auth_data_valid() {
        let rp_id = "sso.milnet.example";
        let cred_id = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let cose_key = vec![0x01, 0x02, 0x03]; // dummy COSE key

        // flags: UP | UV | AT = 0x45
        let auth_data = make_auth_data_with_cred(rp_id, 0x45, 0, &cred_id, &cose_key);

        let att = parse_attestation_auth_data(&auth_data, rp_id).unwrap();
        assert_eq!(att.credential_id, cred_id);
        assert_eq!(att.public_key_cose, cose_key);
        assert_eq!(att.sign_count, 0);
    }

    #[test]
    fn test_parse_attestation_auth_data_no_at_flag() {
        let rp_id = "sso.milnet.example";
        // flags: UP | UV = 0x05 (no AT flag)
        let auth_data = make_auth_data(rp_id, 0x05, 0);

        let err = parse_attestation_auth_data(&auth_data, rp_id).unwrap_err();
        assert_eq!(err, "Attested credential data flag not set in registration response");
    }

    #[test]
    fn test_parse_attestation_auth_data_rp_mismatch() {
        let cred_id = vec![0xAA];
        let cose_key = vec![0x01];
        let auth_data = make_auth_data_with_cred("evil.com", 0x45, 0, &cred_id, &cose_key);

        let err = parse_attestation_auth_data(&auth_data, "sso.milnet.example").unwrap_err();
        assert_eq!(err, "RP ID hash mismatch");
    }
}
