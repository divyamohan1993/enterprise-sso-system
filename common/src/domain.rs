//! Domain separation constants (spec C.10).
//!
//! Each constant is a unique byte-string prefix used to ensure that signatures,
//! HMACs, and hashes produced in one context cannot be replayed in another.
//!
//! CNSA 2.0 compliance notes:
//! - Constants suffixed with "-v2" indicate upgraded hash algorithms (SHA-512).
//! - Constants still at "-v1" either use CNSA 2.0-compliant algorithms already,
//!   or are constrained by external specifications (e.g., RFC 7636 PKCE, WebAuthn).

pub const FROST_TOKEN: &[u8] = b"MILNET-SSO-v1-FROST-TOKEN";
pub const RECEIPT_SIGN: &[u8] = b"MILNET-SSO-v2-RECEIPT";
pub const DPOP_PROOF: &[u8] = b"MILNET-SSO-v1-DPOP";
pub const AUDIT_ENTRY: &[u8] = b"MILNET-SSO-v2-AUDIT";
pub const MODULE_ATTEST: &[u8] = b"MILNET-SSO-v1-ATTEST";
pub const RATCHET_ADVANCE: &[u8] = b"MILNET-SSO-v1-RATCHET";
pub const SHARD_AUTH: &[u8] = b"MILNET-SSO-v1-SHARD";
pub const TOKEN_TAG: &[u8] = b"MILNET-SSO-v1-TOKEN-TAG";
pub const KT_LEAF: &[u8] = b"MILNET-SSO-v2-KT-LEAF";
pub const RECEIPT_CHAIN: &[u8] = b"MILNET-SSO-v2-RECEIPT-CHAIN";
pub const ACTION_BIND: &[u8] = b"MILNET-SSO-v1-ACTION";

// ── Military hardening domain separators ──
pub const ENVELOPE_AAD: &[u8] = b"MILNET-SSO-v1-ENVELOPE-AAD";
pub const KEY_WRAP: &[u8] = b"MILNET-SSO-v1-KEY-WRAP";
pub const SEAL_KEY: &[u8] = b"MILNET-SSO-v1-SEAL";
pub const MASTER_KEK_DERIVE: &[u8] = b"MILNET-SSO-v1-MASTER-KEK";
pub const ATTEST_MANIFEST: &[u8] = b"MILNET-SSO-v1-ATTEST-MANIFEST";
pub const ENTROPY_COMBINE: &[u8] = b"MILNET-SSO-v1-ENTROPY";
