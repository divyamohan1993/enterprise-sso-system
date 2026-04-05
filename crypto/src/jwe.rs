#![forbid(unsafe_code)]

//! JWE-style token claims encryption using AES-256-GCM.
//!
//! Encrypts `TokenClaims` so they are NEVER plaintext on the wire.
//! Uses envelope encryption with a dedicated claims Data Encryption Key (DEK).

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

use common::types::{EncryptedClaims, EncryptedToken, Token, TokenClaims};

/// AAD for JWE claims encryption — binds ciphertext to purpose.
const JWE_CLAIMS_AAD: &[u8] = b"MILNET-JWE-CLAIMS-v1";

/// Encrypt TokenClaims into an EncryptedClaims blob.
pub fn encrypt_claims(
    claims: &TokenClaims,
    claims_dek: &[u8; 32],
) -> Result<EncryptedClaims, String> {
    let plaintext = postcard::to_allocvec(claims)
        .map_err(|e| format!("claims serialization failed: {e}"))?;

    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| format!("nonce generation failed: {e}"))?;

    let cipher = match Aes256Gcm::new_from_slice(claims_dek) {
        Ok(c) => c,
        Err(_) => return Err("AES-256-GCM key init failed for JWE claims".into()),
    };
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: &plaintext,
                aad: JWE_CLAIMS_AAD,
            },
        )
        .map_err(|e| format!("claims encryption failed: {e}"))?;

    Ok(EncryptedClaims {
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Decrypt EncryptedClaims back to TokenClaims.
pub fn decrypt_claims(
    encrypted: &EncryptedClaims,
    claims_dek: &[u8; 32],
) -> Result<TokenClaims, String> {
    let cipher = match Aes256Gcm::new_from_slice(claims_dek) {
        Ok(c) => c,
        Err(_) => return Err("AES-256-GCM key init failed for JWE claims".into()),
    };
    let nonce = Nonce::from_slice(&encrypted.nonce);

    let plaintext = cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: &encrypted.ciphertext,
                aad: JWE_CLAIMS_AAD,
            },
        )
        .map_err(|_| "claims decryption failed — tampered or wrong key".to_string())?;

    postcard::from_bytes(&plaintext)
        .map_err(|e| format!("claims deserialization failed: {e}"))
}

/// Encrypt a Token into an EncryptedToken for wire transmission.
///
/// The signing is performed over plaintext claims (for verifier-side decryption
/// and verification), but the final token has claims encrypted so they are
/// never plaintext on the wire.
pub fn encrypt_token(token: Token, claims_dek: &[u8; 32]) -> Result<EncryptedToken, String> {
    let encrypted_claims = encrypt_claims(&token.claims, claims_dek)?;
    Ok(EncryptedToken {
        header: token.header.clone(),
        encrypted_claims,
        ratchet_tag: token.ratchet_tag,
        frost_signature: token.frost_signature,
        pq_signature: token.pq_signature.clone(),
    })
}

/// Decrypt an EncryptedToken back to a Token for verification.
pub fn decrypt_token(
    encrypted_token: EncryptedToken,
    claims_dek: &[u8; 32],
) -> Result<Token, String> {
    let claims = decrypt_claims(&encrypted_token.encrypted_claims, claims_dek)?;
    Ok(Token {
        header: encrypted_token.header.clone(),
        claims,
        ratchet_tag: encrypted_token.ratchet_tag,
        frost_signature: encrypted_token.frost_signature,
        pq_signature: encrypted_token.pq_signature.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    /// Helper: build a test TokenClaims.
    fn test_claims() -> TokenClaims {
        TokenClaims {
            sub: Uuid::nil(),
            iss: [0xAA; 32],
            iat: 1_700_000_000_000_000,
            exp: 1_700_000_030_000_000,
            scope: 0x0000_000F,
            dpop_hash: [0xBB; 64],
            ceremony_id: [0xCC; 32],
            tier: 1,
            ratchet_epoch: 42,
            token_id: [0xAB; 16],
            aud: Some("test-service".to_string()),
            classification: 0,
        }
    }

    /// Helper: generate a random 32-byte DEK.
    fn random_dek() -> [u8; 32] {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).unwrap();
        key
    }

    #[test]
    fn round_trip_encrypt_decrypt() {
        let claims = test_claims();
        let dek = random_dek();

        let encrypted = encrypt_claims(&claims, &dek).unwrap();
        let decrypted = decrypt_claims(&encrypted, &dek).unwrap();

        assert_eq!(claims.sub, decrypted.sub);
        assert_eq!(claims.iss, decrypted.iss);
        assert_eq!(claims.iat, decrypted.iat);
        assert_eq!(claims.exp, decrypted.exp);
        assert_eq!(claims.scope, decrypted.scope);
        assert_eq!(claims.dpop_hash, decrypted.dpop_hash);
        assert_eq!(claims.ceremony_id, decrypted.ceremony_id);
        assert_eq!(claims.tier, decrypted.tier);
        assert_eq!(claims.ratchet_epoch, decrypted.ratchet_epoch);
        assert_eq!(claims.token_id, decrypted.token_id);
        assert_eq!(claims.aud, decrypted.aud);
        assert_eq!(claims.classification, decrypted.classification);
    }

    #[test]
    fn wrong_key_rejected() {
        let claims = test_claims();
        let dek = random_dek();
        let wrong_dek = random_dek();

        let encrypted = encrypt_claims(&claims, &dek).unwrap();
        let result = decrypt_claims(&encrypted, &wrong_dek);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("claims decryption failed — tampered or wrong key"));
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let claims = test_claims();
        let dek = random_dek();

        let mut encrypted = encrypt_claims(&claims, &dek).unwrap();
        // Flip a byte in the ciphertext
        if let Some(byte) = encrypted.ciphertext.first_mut() {
            *byte ^= 0xFF;
        }

        let result = decrypt_claims(&encrypted, &dek);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("claims decryption failed — tampered or wrong key"));
    }

    #[test]
    fn nonce_uniqueness() {
        let claims = test_claims();
        let dek = random_dek();

        let enc1 = encrypt_claims(&claims, &dek).unwrap();
        let enc2 = encrypt_claims(&claims, &dek).unwrap();

        // Nonces must differ (probabilistically guaranteed with 96-bit random nonces)
        assert_ne!(enc1.nonce, enc2.nonce);
        // Ciphertexts must also differ due to different nonces
        assert_ne!(enc1.ciphertext, enc2.ciphertext);

        // Both must decrypt successfully to the same claims
        let dec1 = decrypt_claims(&enc1, &dek).unwrap();
        let dec2 = decrypt_claims(&enc2, &dek).unwrap();
        assert_eq!(dec1.sub, dec2.sub);
        assert_eq!(dec1.exp, dec2.exp);
    }

    #[test]
    fn empty_claims_edge_case() {
        // Minimal claims with default/zero values
        let claims = TokenClaims {
            sub: Uuid::nil(),
            iss: [0u8; 32],
            iat: 0,
            exp: 0,
            scope: 0,
            dpop_hash: [0u8; 64],
            ceremony_id: [0u8; 32],
            tier: 0,
            ratchet_epoch: 0,
            token_id: [0u8; 16],
            aud: None,
            classification: 0,
        };
        let dek = random_dek();

        let encrypted = encrypt_claims(&claims, &dek).unwrap();
        let decrypted = decrypt_claims(&encrypted, &dek).unwrap();

        assert_eq!(claims.sub, decrypted.sub);
        assert_eq!(claims.aud, decrypted.aud);
        assert_eq!(claims.scope, decrypted.scope);
    }

    #[test]
    fn tampered_nonce_rejected() {
        let claims = test_claims();
        let dek = random_dek();

        let mut encrypted = encrypt_claims(&claims, &dek).unwrap();
        // Flip a byte in the nonce — GCM will reject
        encrypted.nonce[0] ^= 0xFF;

        let result = decrypt_claims(&encrypted, &dek);
        assert!(result.is_err());
    }

    #[test]
    fn token_round_trip() {
        let token = Token::test_fixture_unsigned();
        let dek = random_dek();

        let encrypted = encrypt_token(token.clone(), &dek).unwrap();
        // Verify claims are NOT plaintext — the encrypted token has no .claims field
        assert!(!encrypted.encrypted_claims.ciphertext.is_empty());

        let decrypted = decrypt_token(encrypted, &dek).unwrap();
        assert_eq!(token.claims.sub, decrypted.claims.sub);
        assert_eq!(token.claims.exp, decrypted.claims.exp);
        assert_eq!(token.header.version, decrypted.header.version);
        assert_eq!(token.frost_signature, decrypted.frost_signature);
        assert_eq!(token.pq_signature, decrypted.pq_signature);
    }
}
