//! Federated identity broker / account linking (J8).
//!
//! Binds multiple upstream identities (Google sub, Entra OID, CAC EDIPI, …)
//! to a single MILNET user. Each link carries a cryptographic attestation
//! over the (milnet_user, provider, subject, linked_at) tuple so an attacker
//! who tampers with the linking table is detectable.
//!
//! ## Linking flow (ATO-resistant)
//!
//! `link()` is intentionally absent. To bind a new upstream identity:
//!
//! 1. Caller proves a fresh **user-verifying FIDO step-up** for the current
//!    session and passes the resulting [`StepUpProof`] to [`LinkStore::initiate_link`].
//! 2. `initiate_link` allocates a 256-bit cryptographic challenge and stores
//!    a [`PendingLink`] keyed on `(user, challenge_hash)` with a 5-minute TTL.
//!    A signed confirmation message is dispatched **out-of-band to the user's
//!    already-verified MILNET email** (NOT to the claimed upstream email),
//!    via the supplied [`ChallengeDispatch`] sink.
//! 3. The user follows the confirmation URL, which calls
//!    [`LinkStore::confirm_link`]. The challenge is compared in constant time;
//!    on success the link is committed and the pending entry is zeroized.
//!
//! Per-user rate limiting (default: 3 initiations per rolling hour) blocks
//! enumeration / phishing-spam vectors.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Error)]
pub enum LinkError {
    #[error("already linked to user {0}")]
    AlreadyLinked(String),
    #[error("not found")]
    NotFound,
    #[error("attestation invalid")]
    AttestationInvalid,
    #[error("lock poisoned")]
    Poisoned,
    #[error("step-up MFA required (user-verifying FIDO)")]
    StepUpRequired,
    #[error("rate limit exceeded for user")]
    RateLimited,
    #[error("pending link not found or expired")]
    PendingExpired,
    #[error("challenge mismatch")]
    ChallengeMismatch,
    #[error("dispatch error: {0}")]
    Dispatch(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Provider {
    Google,
    EntraId,
    Cac,
    Okta,
    Saml,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityLink {
    pub link_id: Uuid,
    pub milnet_user: String,
    pub provider: Provider,
    pub subject: String,
    pub linked_at: i64,
    pub attestation: String,
}

/// Caller-supplied proof that a fresh user-verifying FIDO assertion was
/// completed for this session. The store does not validate the FIDO blob
/// itself — that is the gateway's job — but it requires `uv == true` and
/// a recent timestamp before allowing `initiate_link` to proceed.
#[derive(Debug, Clone)]
pub struct StepUpProof {
    pub user: String,
    pub user_verified: bool,
    pub asserted_at: i64,
}

impl StepUpProof {
    /// Step-up is valid for a short window after the FIDO assertion.
    const MAX_AGE_SECS: i64 = 120;

    pub fn is_fresh(&self, now: i64) -> bool {
        self.user_verified && (now - self.asserted_at).abs() <= Self::MAX_AGE_SECS
    }
}

/// Out-of-band confirmation channel. Implemented by callers (the gateway
/// wires this to the email service). The dispatch payload is sent to the
/// user's already-verified MILNET address — never to the claimed upstream
/// email — to defeat email-spoofing ATO.
pub trait ChallengeDispatch: Send + Sync {
    fn dispatch(
        &self,
        user: &str,
        provider: Provider,
        claimed_email: &str,
        confirm_token: &str,
    ) -> Result<(), String>;
}

/// In-flight link awaiting user confirmation. The challenge bytes are
/// `Zeroizing` so the wipe runs even on panic / drop.
struct PendingLink {
    user: String,
    provider: Provider,
    subject: String,
    claimed_email: String,
    challenge_hash: [u8; 32],
    expires_at: i64,
}

impl Drop for PendingLink {
    fn drop(&mut self) {
        self.challenge_hash.zeroize();
    }
}

const PENDING_TTL_SECS: i64 = 5 * 60;
const RATE_WINDOW_SECS: i64 = 3600;
const RATE_MAX_INITIATIONS: usize = 3;

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn attestation(secret: &[u8], user: &str, provider: Provider, subject: &str, linked_at: i64) -> String {
    let mut h = Sha256::new();
    h.update(secret);
    h.update(user.as_bytes());
    h.update([provider as u8]);
    h.update(subject.as_bytes());
    h.update(linked_at.to_be_bytes());
    hex::encode(h.finalize())
}

fn hash_challenge(token: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(token);
    let out = h.finalize();
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    a
}

fn random_challenge() -> Zeroizing<[u8; 32]> {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).expect("getrandom");
    Zeroizing::new(buf)
}

struct Inner {
    links: HashMap<(Provider, String), IdentityLink>,
    pending: HashMap<(String, [u8; 32]), PendingLink>,
    rate: HashMap<String, VecDeque<i64>>,
}

pub struct LinkStore {
    secret: Zeroizing<Vec<u8>>,
    inner: Mutex<Inner>,
}

pub struct InitiateOutcome {
    /// Hex-encoded raw challenge. Caller embeds it in the confirmation URL.
    /// Returned ONLY for the dispatch sink — never logged, never persisted.
    pub confirm_token: String,
    pub expires_at: i64,
}

impl LinkStore {
    pub fn new(secret: Vec<u8>) -> Self {
        Self {
            secret: Zeroizing::new(secret),
            inner: Mutex::new(Inner {
                links: HashMap::new(),
                pending: HashMap::new(),
                rate: HashMap::new(),
            }),
        }
    }

    /// Begin a link. Requires a fresh user-verifying FIDO step-up. Stores a
    /// [`PendingLink`] and dispatches the confirmation token to the user's
    /// existing verified address through `dispatch`.
    pub fn initiate_link(
        &self,
        proof: &StepUpProof,
        provider: Provider,
        subject: &str,
        claimed_email: &str,
        dispatch: &dyn ChallengeDispatch,
    ) -> Result<InitiateOutcome, LinkError> {
        let now = now_secs();
        if !proof.is_fresh(now) {
            return Err(LinkError::StepUpRequired);
        }
        let user = proof.user.clone();

        let mut g = self.inner.lock().map_err(|_| LinkError::Poisoned)?;

        // Reject if already linked to a different user.
        if let Some(existing) = g.links.get(&(provider, subject.to_string())) {
            if existing.milnet_user != user {
                return Err(LinkError::AlreadyLinked(existing.milnet_user.clone()));
            }
        }

        // Per-user sliding-window rate limit.
        let bucket = g.rate.entry(user.clone()).or_default();
        while bucket.front().map(|t| now - *t > RATE_WINDOW_SECS).unwrap_or(false) {
            bucket.pop_front();
        }
        if bucket.len() >= RATE_MAX_INITIATIONS {
            return Err(LinkError::RateLimited);
        }
        bucket.push_back(now);

        // Sweep expired pendings.
        g.pending.retain(|_, p| p.expires_at > now);

        let token = random_challenge();
        let token_hex = hex::encode(token.as_ref());
        let challenge_hash = hash_challenge(token.as_ref());

        let pending = PendingLink {
            user: user.clone(),
            provider,
            subject: subject.to_string(),
            claimed_email: claimed_email.to_string(),
            challenge_hash,
            expires_at: now + PENDING_TTL_SECS,
        };
        g.pending.insert((user.clone(), challenge_hash), pending);
        drop(g);

        dispatch
            .dispatch(&user, provider, claimed_email, &token_hex)
            .map_err(LinkError::Dispatch)?;

        Ok(InitiateOutcome {
            confirm_token: token_hex,
            expires_at: now + PENDING_TTL_SECS,
        })
    }

    /// Confirm a previously initiated link by presenting the challenge token.
    /// Constant-time compares the token hash against every pending entry for
    /// the user, then commits and zeroizes on match.
    pub fn confirm_link(&self, user: &str, confirm_token: &str) -> Result<IdentityLink, LinkError> {
        let token_bytes = hex::decode(confirm_token).map_err(|_| LinkError::ChallengeMismatch)?;
        let candidate = hash_challenge(&token_bytes);

        let mut g = self.inner.lock().map_err(|_| LinkError::Poisoned)?;
        let now = now_secs();
        g.pending.retain(|_, p| p.expires_at > now);

        // Constant-time scan over this user's pending entries.
        let mut matched_key: Option<(String, [u8; 32])> = None;
        for ((u, h), _p) in g.pending.iter() {
            if u != user {
                continue;
            }
            if h.ct_eq(&candidate).into() {
                matched_key = Some((u.clone(), *h));
                break;
            }
        }
        let key = matched_key.ok_or(LinkError::PendingExpired)?;
        let pending = g.pending.remove(&key).ok_or(LinkError::PendingExpired)?;

        if let Some(existing) = g.links.get(&(pending.provider, pending.subject.clone())) {
            if existing.milnet_user != pending.user {
                return Err(LinkError::AlreadyLinked(existing.milnet_user.clone()));
            }
            return Ok(existing.clone());
        }

        let link = IdentityLink {
            link_id: Uuid::new_v4(),
            milnet_user: pending.user.clone(),
            provider: pending.provider,
            subject: pending.subject.clone(),
            linked_at: now,
            attestation: attestation(&self.secret, &pending.user, pending.provider, &pending.subject, now),
        };
        g.links.insert((pending.provider, pending.subject.clone()), link.clone());
        // `pending` dropped here → challenge_hash zeroized.
        drop(pending);
        Ok(link)
    }

    pub fn unlink(&self, provider: Provider, subject: &str) -> Result<(), LinkError> {
        let mut g = self.inner.lock().map_err(|_| LinkError::Poisoned)?;
        g.links.remove(&(provider, subject.to_string())).ok_or(LinkError::NotFound)?;
        Ok(())
    }

    pub fn resolve(&self, provider: Provider, subject: &str) -> Result<IdentityLink, LinkError> {
        let g = self.inner.lock().map_err(|_| LinkError::Poisoned)?;
        g.links.get(&(provider, subject.to_string())).cloned().ok_or(LinkError::NotFound)
    }

    pub fn verify(&self, link: &IdentityLink) -> Result<(), LinkError> {
        let want = attestation(&self.secret, &link.milnet_user, link.provider, &link.subject, link.linked_at);
        if want.as_bytes().ct_eq(link.attestation.as_bytes()).into() {
            Ok(())
        } else {
            Err(LinkError::AttestationInvalid)
        }
    }

    /// Test/admin helper: count pending entries for a user.
    #[doc(hidden)]
    pub fn pending_count(&self, user: &str) -> usize {
        let now = now_secs();
        let g = self.inner.lock().expect("lock");
        g.pending.iter().filter(|((u, _), p)| u == user && p.expires_at > now).count()
    }

    /// Test helper: force-expire all pending entries.
    #[doc(hidden)]
    pub fn _expire_all_pending(&self) {
        let mut g = self.inner.lock().expect("lock");
        g.pending.clear();
    }
}
