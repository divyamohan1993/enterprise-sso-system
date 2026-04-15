//! Per-domain key hierarchy (CAT-O DT-OVERRIDE).
//!
//! Replaces the single `cached_master_kek()` derivation root with a set of
//! independent per-domain roots. Every HMAC / encryption key in the system
//! used to chain back to one cached master KEK; compromise of any node
//! exfiltrating that KEK yielded the entire keyspace. Per-domain roots
//! bound blast radius: a node that only holds `KeyDomain::Ratchet` cannot
//! derive `KeyDomain::TokenSign` even with full memory disclosure, because
//! HKDF-Extract/Expand with distinct labels and (in hardened deployments)
//! distinct input keying material is one-way.
//!
//! # Derivation
//!
//! Each domain root is derived via HKDF-SHA512 with a domain-unique label
//! and `b"MILNET-DOMAIN-ROOT-v1"` as salt. In the baseline build the input
//! keying material is `sealed_keys::get_master_kek()`; in hardened military
//! deployments the deployment layer SHOULD provide per-domain IKM sourced
//! from independent Shamir 3-of-5 share sets sealed to distinct vTPM
//! handles (see `load_domain_ikm` hook below), at which point the domains
//! are cryptographically independent rather than merely label-separated.
//!
//! # Node scoping
//!
//! A node enumerates only the domains it legitimately needs via
//! `load_allowed_domains()`; `domain_root()` panics in debug / returns an
//! error in release for disallowed domains so an RCE on e.g. the ratchet
//! service cannot opportunistically derive `KeyDomain::TokenSign` even if
//! the IKM happens to be resident.

use std::collections::HashSet;
use std::sync::OnceLock;

use hkdf::Hkdf;
use sha2::Sha512;

/// Logical key domains. Each domain has an independent root key; keys
/// derived under one domain cannot be used to derive keys in another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyDomain {
    /// TLS / mTLS session material (pre-shared cert CA keys, ticket keys).
    Tls,
    /// Audit log encryption and HMAC chain anchor.
    Audit,
    /// Key transparency leaf and internal tree node keys.
    Kt,
    /// Double-ratchet chain seeds.
    Ratchet,
    /// Threshold-signature nonce derivation (FROST/MuSig2 per-session nonces).
    TssNonce,
    /// OPAQUE OPRF server-side blinding key.
    OpaqueOprf,
    /// Token signing keys (JWT/DPoP/CWT), held only on token-issuer nodes.
    TokenSign,
    /// Shard-layer HMACs (replay cache, routing MACs).
    ShardHmac,
    /// Legacy shim domain: delegates callers that still use
    /// `cached_master_kek()`. Will be removed once every caller migrates.
    Legacy,
}

impl KeyDomain {
    /// HKDF `info` label. Must stay stable across releases; extend by
    /// adding new variants, never by mutating existing labels.
    pub const fn label(self) -> &'static [u8] {
        match self {
            KeyDomain::Tls => b"MILNET-DOMAIN-ROOT-TLS-v1",
            KeyDomain::Audit => b"MILNET-DOMAIN-ROOT-AUDIT-v1",
            KeyDomain::Kt => b"MILNET-DOMAIN-ROOT-KT-v1",
            KeyDomain::Ratchet => b"MILNET-DOMAIN-ROOT-RATCHET-v1",
            KeyDomain::TssNonce => b"MILNET-DOMAIN-ROOT-TSS-NONCE-v1",
            KeyDomain::OpaqueOprf => b"MILNET-DOMAIN-ROOT-OPAQUE-OPRF-v1",
            KeyDomain::TokenSign => b"MILNET-DOMAIN-ROOT-TOKEN-SIGN-v1",
            KeyDomain::ShardHmac => b"MILNET-DOMAIN-ROOT-SHARD-HMAC-v1",
            KeyDomain::Legacy => b"MILNET-DOMAIN-ROOT-LEGACY-v1",
        }
    }

    /// Env var name a deployment can set to pin this node's allowed
    /// domain list, e.g. `MILNET_KEY_DOMAINS=ratchet,tls`.
    pub const fn env_name(self) -> &'static str {
        match self {
            KeyDomain::Tls => "tls",
            KeyDomain::Audit => "audit",
            KeyDomain::Kt => "kt",
            KeyDomain::Ratchet => "ratchet",
            KeyDomain::TssNonce => "tss_nonce",
            KeyDomain::OpaqueOprf => "opaque_oprf",
            KeyDomain::TokenSign => "token_sign",
            KeyDomain::ShardHmac => "shard_hmac",
            KeyDomain::Legacy => "legacy",
        }
    }

    fn all() -> &'static [KeyDomain] {
        &[
            KeyDomain::Tls,
            KeyDomain::Audit,
            KeyDomain::Kt,
            KeyDomain::Ratchet,
            KeyDomain::TssNonce,
            KeyDomain::OpaqueOprf,
            KeyDomain::TokenSign,
            KeyDomain::ShardHmac,
            KeyDomain::Legacy,
        ]
    }
}

/// HKDF salt. Constant across the fleet so nodes derive the same root
/// from the same IKM; separation comes from `KeyDomain::label()`.
const DOMAIN_ROOT_SALT: &[u8] = b"MILNET-DOMAIN-ROOT-v1";

/// Error returned when a caller asks for a domain this node is not
/// authorized to derive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainDenied {
    pub domain: KeyDomain,
}

impl std::fmt::Display for DomainDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "key domain {:?} not permitted on this node (MILNET_KEY_DOMAINS)",
            self.domain
        )
    }
}

impl std::error::Error for DomainDenied {}

// Per-domain caches. OnceLock ensures a single derivation per process;
// zeroization of the derived root on drop is left to the consumer holding
// the returned slice (same contract as `cached_master_kek()`).
static TLS_ROOT: OnceLock<[u8; 32]> = OnceLock::new();
static AUDIT_ROOT: OnceLock<[u8; 32]> = OnceLock::new();
static KT_ROOT: OnceLock<[u8; 32]> = OnceLock::new();
static RATCHET_ROOT: OnceLock<[u8; 32]> = OnceLock::new();
static TSS_NONCE_ROOT: OnceLock<[u8; 32]> = OnceLock::new();
static OPAQUE_OPRF_ROOT: OnceLock<[u8; 32]> = OnceLock::new();
static TOKEN_SIGN_ROOT: OnceLock<[u8; 32]> = OnceLock::new();
static SHARD_HMAC_ROOT: OnceLock<[u8; 32]> = OnceLock::new();
static LEGACY_ROOT: OnceLock<[u8; 32]> = OnceLock::new();

static ALLOWED_DOMAINS: OnceLock<HashSet<KeyDomain>> = OnceLock::new();

fn cell_for(domain: KeyDomain) -> &'static OnceLock<[u8; 32]> {
    match domain {
        KeyDomain::Tls => &TLS_ROOT,
        KeyDomain::Audit => &AUDIT_ROOT,
        KeyDomain::Kt => &KT_ROOT,
        KeyDomain::Ratchet => &RATCHET_ROOT,
        KeyDomain::TssNonce => &TSS_NONCE_ROOT,
        KeyDomain::OpaqueOprf => &OPAQUE_OPRF_ROOT,
        KeyDomain::TokenSign => &TOKEN_SIGN_ROOT,
        KeyDomain::ShardHmac => &SHARD_HMAC_ROOT,
        KeyDomain::Legacy => &LEGACY_ROOT,
    }
}

/// Returns the set of domains this node may derive. Parses
/// `MILNET_KEY_DOMAINS` (comma-separated domain env_names); if unset,
/// permits everything (back-compat for MLP / single-node deployments).
pub fn allowed_domains() -> &'static HashSet<KeyDomain> {
    ALLOWED_DOMAINS.get_or_init(|| {
        match std::env::var("MILNET_KEY_DOMAINS") {
            Ok(v) if !v.trim().is_empty() => {
                let mut set = HashSet::new();
                for tok in v.split(',').map(|s| s.trim().to_ascii_lowercase()) {
                    if tok.is_empty() {
                        continue;
                    }
                    for d in KeyDomain::all() {
                        if d.env_name() == tok {
                            set.insert(*d);
                        }
                    }
                }
                // Legacy shim is always allowed during the transition so
                // cached_master_kek() keeps working under any scoping.
                set.insert(KeyDomain::Legacy);
                set
            }
            _ => KeyDomain::all().iter().copied().collect(),
        }
    })
}

/// Hook for hardened deployments to override the input keying material
/// for a specific domain with per-domain Shamir-reconstructed material
/// sealed to a distinct vTPM handle. Default implementation returns
/// `None`, meaning fall back to the shared master KEK plus HKDF label
/// separation (domain independence via domain separation of HKDF).
///
/// Deployments wanting true independence should set e.g.
/// `MILNET_DOMAIN_IKM_<DOMAIN>=<hex-32>` pointing at per-domain sealed
/// material; this function reads those and returns them.
fn load_domain_ikm(domain: KeyDomain) -> Option<[u8; 32]> {
    let var = format!("MILNET_DOMAIN_IKM_{}", domain.env_name().to_uppercase());
    let hex = std::env::var(var).ok()?;
    let hex = hex.trim();
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
        out[i] = byte;
    }
    Some(out)
}

/// Derive and return the root key for `domain`. Fails if this node is
/// not permitted to derive that domain.
///
/// The returned slice is cached in a process-static `OnceLock` and is
/// valid for the lifetime of the process.
pub fn try_domain_root(domain: KeyDomain) -> Result<&'static [u8; 32], DomainDenied> {
    if !allowed_domains().contains(&domain) {
        return Err(DomainDenied { domain });
    }
    let cell = cell_for(domain);
    Ok(cell.get_or_init(|| derive(domain)))
}

/// Derive and return the root key for `domain`, panicking if the domain
/// is not permitted on this node. Convenience for call sites that have
/// already validated domain scoping at startup.
pub fn domain_root(domain: KeyDomain) -> &'static [u8; 32] {
    match try_domain_root(domain) {
        Ok(k) => k,
        Err(e) => panic!("{}", e),
    }
}

fn derive(domain: KeyDomain) -> [u8; 32] {
    // Prefer per-domain IKM if the deployment provided it; otherwise
    // fall back to the shared master KEK. Domain separation via HKDF
    // `info` labels gives us label-level independence in both cases;
    // per-domain IKM gives cryptographic independence.
    let ikm_owned = load_domain_ikm(domain);
    let ikm: &[u8] = match &ikm_owned {
        Some(v) => v.as_slice(),
        None => crate::sealed_keys::get_master_kek().as_slice(),
    };
    let hk = Hkdf::<Sha512>::new(Some(DOMAIN_ROOT_SALT), ikm);
    let mut out = [0u8; 32];
    hk.expand(domain.label(), &mut out)
        .expect("HKDF-SHA512 expand to 32 bytes cannot fail");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_are_distinct() {
        // Clearing caches between test runs is not possible with
        // OnceLock; instead, derive fresh values directly.
        let a = derive(KeyDomain::Tls);
        let b = derive(KeyDomain::TokenSign);
        let c = derive(KeyDomain::Ratchet);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[test]
    fn labels_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for d in KeyDomain::all() {
            assert!(seen.insert(d.label()), "duplicate label for {:?}", d);
        }
    }

    #[test]
    fn ratchet_compromise_does_not_leak_token_sign() {
        // Blast-radius test: given the ratchet domain root, you should
        // not be able to compute the token-sign domain root without the
        // master KEK. This is guaranteed by HKDF-Expand's one-way
        // property (distinct `info` labels over the same PRK yield
        // independent outputs; neither can derive the other without
        // the shared PRK, and an attacker who stole only the ratchet
        // output cannot recover the PRK).
        let ratchet = derive(KeyDomain::Ratchet);
        let token = derive(KeyDomain::TokenSign);
        // Attempt a naive "derive token from ratchet" — must not match.
        let hk = Hkdf::<Sha512>::new(Some(DOMAIN_ROOT_SALT), &ratchet);
        let mut attacker_guess = [0u8; 32];
        hk.expand(KeyDomain::TokenSign.label(), &mut attacker_guess)
            .unwrap();
        assert_ne!(attacker_guess, token);
    }
}
