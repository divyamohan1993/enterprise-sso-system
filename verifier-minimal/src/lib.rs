#![forbid(unsafe_code)]
//! verifier-minimal — D13 minimal-TCB verifier.
//!
//! Purpose: provide a tiny, auditable verifier for ML-DSA-87 signatures and
//! FROST(Ristretto255) group signatures. The whole point of the crate is that
//! its dependency closure is small enough that a security reviewer can read
//! every line of TCB code in one sitting.
//!
//! Hard rules:
//!   * No `tokio` and no async — verification is a synchronous pure function.
//!   * No `serde` — payloads are decoded with hand-written postcard helpers.
//!   * No `common` / `shard` dependencies — the only crate we trust beyond
//!     std is `crypto`, plus the underlying primitive crates (`ml-dsa`,
//!     `frost-ristretto255`, `sha2`).
//!
//! Wire format for a `MinimalReceipt`:
//!
//! ```text
//!   payload_len  : varint(u32)
//!   payload      : payload_len bytes
//!   pq_vk_len    : varint(u32)
//!   pq_vk        : pq_vk_len bytes (encoded ML-DSA-87 verifying key)
//!   pq_sig_len   : varint(u32)
//!   pq_sig       : pq_sig_len bytes
//!   frost_pk_len : varint(u32)
//!   frost_pk     : frost_pk_len bytes (postcard PublicKeyPackage)
//!   frost_sig_len: varint(u32)
//!   frost_sig    : frost_sig_len bytes (postcard Signature)
//! ```
//!
//! `verify_receipt_bytes` returns `Ok(())` only when *both* the ML-DSA-87 and
//! FROST signatures verify against `payload`.

use ml_dsa::{
    signature::Verifier as _, EncodedVerifyingKey, MlDsa87, Signature as MlDsaSignature,
    VerifyingKey as MlDsaVerifyingKey,
};

use frost_ristretto255::{Signature as FrostSignature, VerifyingKey as FrostVerifyingKey};

/// Errors produced by the minimal verifier.
#[derive(Debug)]
pub enum VerifyError {
    Truncated,
    LengthOverflow,
    MlDsaDecodeFailed,
    MlDsaVerifyFailed,
    FrostDecodeFailed,
    FrostVerifyFailed,
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            VerifyError::Truncated => "truncated receipt",
            VerifyError::LengthOverflow => "length field overflows buffer",
            VerifyError::MlDsaDecodeFailed => "ml-dsa-87 decode failed",
            VerifyError::MlDsaVerifyFailed => "ml-dsa-87 verify failed",
            VerifyError::FrostDecodeFailed => "frost decode failed",
            VerifyError::FrostVerifyFailed => "frost verify failed",
        };
        f.write_str(s)
    }
}

impl std::error::Error for VerifyError {}

/// A decoded receipt held only in borrowed slices — zero allocation.
#[derive(Debug, Clone, Copy)]
pub struct MinimalReceipt<'a> {
    pub payload: &'a [u8],
    pub pq_vk: &'a [u8],
    pub pq_sig: &'a [u8],
    pub frost_vk: &'a [u8],
    pub frost_sig: &'a [u8],
}

/// Read a postcard-style varint(u32) length prefix from the front of `buf`,
/// returning the length and the remaining slice.
fn read_varint_u32(buf: &[u8]) -> Result<(u32, &[u8]), VerifyError> {
    // postcard::take_from_bytes::<u32> would do this, but pulling the trait
    // adds two crates' worth of TCB. The varint is identical to the standard
    // little-endian base-128 encoding used by postcard.
    let mut value: u32 = 0;
    let mut shift: u32 = 0;
    let mut i = 0usize;
    loop {
        if i >= buf.len() {
            return Err(VerifyError::Truncated);
        }
        let byte = buf[i];
        i += 1;
        let chunk = (byte & 0x7f) as u32;
        value = value
            .checked_add(chunk << shift)
            .ok_or(VerifyError::LengthOverflow)?;
        if byte & 0x80 == 0 {
            return Ok((value, &buf[i..]));
        }
        shift += 7;
        if shift >= 32 {
            return Err(VerifyError::LengthOverflow);
        }
    }
}

/// Read a length-prefixed byte slice.
fn read_len_prefixed(buf: &[u8]) -> Result<(&[u8], &[u8]), VerifyError> {
    let (len, rest) = read_varint_u32(buf)?;
    let len = len as usize;
    if len > rest.len() {
        return Err(VerifyError::LengthOverflow);
    }
    Ok((&rest[..len], &rest[len..]))
}

/// Parse a `MinimalReceipt` from a flat byte buffer.
pub fn parse_receipt(buf: &[u8]) -> Result<MinimalReceipt<'_>, VerifyError> {
    let (payload, rest) = read_len_prefixed(buf)?;
    let (pq_vk, rest) = read_len_prefixed(rest)?;
    let (pq_sig, rest) = read_len_prefixed(rest)?;
    let (frost_vk, rest) = read_len_prefixed(rest)?;
    let (frost_sig, _rest) = read_len_prefixed(rest)?;
    Ok(MinimalReceipt {
        payload,
        pq_vk,
        pq_sig,
        frost_vk,
        frost_sig,
    })
}

/// Verify both signatures in a parsed receipt.
pub fn verify_receipt(receipt: &MinimalReceipt<'_>) -> Result<(), VerifyError> {
    verify_ml_dsa(receipt.payload, receipt.pq_vk, receipt.pq_sig)?;
    verify_frost(receipt.payload, receipt.frost_vk, receipt.frost_sig)?;
    Ok(())
}

/// One-shot: parse + verify.
pub fn verify_receipt_bytes(buf: &[u8]) -> Result<(), VerifyError> {
    let r = parse_receipt(buf)?;
    verify_receipt(&r)
}

/// Verify an ML-DSA-87 signature using only the encoded verifying key.
pub fn verify_ml_dsa(
    payload: &[u8],
    encoded_vk: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    let enc = EncodedVerifyingKey::<MlDsa87>::try_from(encoded_vk)
        .map_err(|_| VerifyError::MlDsaDecodeFailed)?;
    let vk = MlDsaVerifyingKey::<MlDsa87>::decode(&enc);
    let sig = MlDsaSignature::<MlDsa87>::try_from(signature)
        .map_err(|_| VerifyError::MlDsaDecodeFailed)?;
    vk.verify(payload, &sig)
        .map_err(|_| VerifyError::MlDsaVerifyFailed)
}

/// Verify a FROST(Ristretto255) group signature.
///
/// `encoded_vk` is the raw 32-byte VerifyingKey serialization (NOT a postcard
/// PublicKeyPackage — we drop that layer to keep the TCB small).
/// `signature` is the postcard-serialized `frost_ristretto255::Signature`.
pub fn verify_frost(
    payload: &[u8],
    encoded_vk: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    let vk: FrostVerifyingKey =
        postcard::from_bytes(encoded_vk).map_err(|_| VerifyError::FrostDecodeFailed)?;
    let sig: FrostSignature =
        postcard::from_bytes(signature).map_err(|_| VerifyError::FrostDecodeFailed)?;
    vk.verify(payload, &sig)
        .map_err(|_| VerifyError::FrostVerifyFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip_small() {
        // postcard encodes 0..=127 as a single byte
        let buf = [0x05u8, 0xaa];
        let (v, rest) = read_varint_u32(&buf).unwrap();
        assert_eq!(v, 5);
        assert_eq!(rest, &[0xaa]);
    }

    #[test]
    fn varint_two_bytes() {
        let buf = [0x80u8, 0x01, 0xff];
        let (v, rest) = read_varint_u32(&buf).unwrap();
        assert_eq!(v, 128);
        assert_eq!(rest, &[0xff]);
    }

    #[test]
    fn truncated_returns_err() {
        assert!(matches!(read_varint_u32(&[]), Err(VerifyError::Truncated)));
        assert!(matches!(
            read_len_prefixed(&[0x05u8, 1, 2]),
            Err(VerifyError::LengthOverflow)
        ));
    }
}
