// RSA verify-only shim wrapping aws-lc-rs.
//
// Replaces the `rsa` crate (RUSTSEC-2023-0071) for the only call site that
// needed it: Google JWKS RS256 verification. Verify-only — no signing, no
// key generation, no padding modes other than RSASSA-PKCS1-v1_5 with SHA-256
// (RS256) which is what RFC 7518 mandates for that JOSE algorithm.
//
// Constant-time output where applicable; aws-lc-rs is FIPS-validated and
// CNSA-2.0 ready, satisfying the same constraints as the rest of the MILNET
// crypto path.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! RSA verify-only shim over aws-lc-rs.

use aws_lc_rs::signature::{UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256};
use thiserror::Error;

/// Errors produced by the shim.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// The signature did not verify under the supplied key.
    #[error("RSA signature verification failed")]
    BadSignature,
    /// The supplied DER-encoded public key was malformed or unsupported.
    #[error("invalid RSA public key encoding")]
    BadKey,
}

/// Verify a PKCS#1-v1.5 SHA-256 signature (the RS256 JOSE alg) using a
/// DER-encoded RSA public key (SubjectPublicKeyInfo, X.509 form — the
/// format produced by `RsaPublicKey::to_public_key_der` in the rsa crate).
///
/// Verify-only. Constant-time wrt the signature bytes per aws-lc-rs.
pub fn verify_rs256_spki_der(
    spki_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    let key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, spki_der);
    key.verify(message, signature).map_err(|_| VerifyError::BadSignature)
}

/// Verify using raw RSA modulus (`n`) and public exponent (`e`) bytes,
/// matching the JWKS JSON shape (`n`, `e` fields are base64url-decoded
/// big-endian integers). Constructs the equivalent SPKI DER internally.
pub fn verify_rs256_jwk(
    n_be: &[u8],
    e_be: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    let spki = jwk_to_spki_der(n_be, e_be).ok_or(VerifyError::BadKey)?;
    verify_rs256_spki_der(&spki, message, signature)
}

// Minimal DER encoder for an RSA SubjectPublicKeyInfo. Sufficient for the
// RS256 verify path; rejects modulus < 256 bytes (2048 bits) per RFC 8017
// security guidance and our CNSA-2.0 floor.
fn jwk_to_spki_der(n_be: &[u8], e_be: &[u8]) -> Option<Vec<u8>> {
    let n = strip_leading_zeros(n_be);
    let e = strip_leading_zeros(e_be);
    if n.len() < 256 {
        return None;
    }

    // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    let mut rsa_pk = Vec::with_capacity(n.len() + e.len() + 16);
    rsa_pk.extend_from_slice(&der_integer(&n));
    rsa_pk.extend_from_slice(&der_integer(&e));
    let rsa_pk_seq = der_sequence(&rsa_pk);

    // BIT STRING wrapping the RSAPublicKey
    let mut bitstring = Vec::with_capacity(rsa_pk_seq.len() + 1);
    bitstring.push(0x00); // unused-bits = 0
    bitstring.extend_from_slice(&rsa_pk_seq);
    let bitstring_tlv = der_tlv(0x03, &bitstring);

    // AlgorithmIdentifier for rsaEncryption: 1.2.840.113549.1.1.1
    let alg_id = der_sequence(&[
        der_oid(&[1, 2, 840, 113549, 1, 1, 1]),
        vec![0x05, 0x00], // NULL
    ].concat());

    // SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey }
    let mut spki_body = Vec::with_capacity(alg_id.len() + bitstring_tlv.len());
    spki_body.extend_from_slice(&alg_id);
    spki_body.extend_from_slice(&bitstring_tlv);
    Some(der_sequence(&spki_body))
}

fn strip_leading_zeros(b: &[u8]) -> Vec<u8> {
    let mut i = 0;
    while i < b.len() && b[i] == 0 {
        i += 1;
    }
    b[i..].to_vec()
}

fn der_integer(unsigned_be: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(unsigned_be.len() + 1);
    if unsigned_be.first().copied().unwrap_or(0) & 0x80 != 0 {
        body.push(0x00);
    }
    body.extend_from_slice(unsigned_be);
    der_tlv(0x02, &body)
}

fn der_sequence(body: &[u8]) -> Vec<u8> {
    der_tlv(0x30, body)
}

fn der_oid(arcs: &[u32]) -> Vec<u8> {
    let mut body = Vec::with_capacity(arcs.len() + 4);
    body.push((arcs[0] * 40 + arcs[1]) as u8);
    for &arc in &arcs[2..] {
        let mut buf = [0u8; 5];
        let mut n = arc;
        let mut i = 5;
        loop {
            i -= 1;
            buf[i] = (n & 0x7f) as u8;
            n >>= 7;
            if n == 0 {
                break;
            }
        }
        for b in &mut buf[i..4] {
            *b |= 0x80;
        }
        body.extend_from_slice(&buf[i..]);
    }
    der_tlv(0x06, &body)
}

fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 4);
    out.push(tag);
    let len = body.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else if len < 0x10000 {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xff) as u8);
    } else {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push(((len >> 8) & 0xff) as u8);
        out.push((len & 0xff) as u8);
    }
    out.extend_from_slice(body);
    out
}
