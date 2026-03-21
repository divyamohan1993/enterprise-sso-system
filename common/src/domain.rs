//! Domain separation constants (spec C.10).
//!
//! Each constant is a unique byte-string prefix used to ensure that signatures,
//! HMACs, and hashes produced in one context cannot be replayed in another.

pub const FROST_TOKEN: &[u8] = b"MILNET-SSO-v1-FROST-TOKEN";
pub const RECEIPT_SIGN: &[u8] = b"MILNET-SSO-v1-RECEIPT";
pub const DPOP_PROOF: &[u8] = b"MILNET-SSO-v1-DPOP";
pub const AUDIT_ENTRY: &[u8] = b"MILNET-SSO-v1-AUDIT";
pub const MODULE_ATTEST: &[u8] = b"MILNET-SSO-v1-ATTEST";
pub const RATCHET_ADVANCE: &[u8] = b"MILNET-SSO-v1-RATCHET";
pub const SHARD_AUTH: &[u8] = b"MILNET-SSO-v1-SHARD";
pub const TOKEN_TAG: &[u8] = b"MILNET-SSO-v1-TOKEN-TAG";
pub const KT_LEAF: &[u8] = b"MILNET-SSO-v1-KT-LEAF";
pub const RECEIPT_CHAIN: &[u8] = b"MILNET-SSO-v1-RECEIPT-CHAIN";
pub const ACTION_BIND: &[u8] = b"MILNET-SSO-v1-ACTION";
