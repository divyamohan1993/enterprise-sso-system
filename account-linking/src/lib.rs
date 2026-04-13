//! Federated identity broker / account linking (J8).
//!
//! Binds multiple upstream identities (Google sub, Entra OID, CAC EDIPI, …)
//! to a single MILNET user. Each link carries a cryptographic attestation
//! over the (milnet_user, provider, subject, linked_at) tuple so an attacker
//! who tampers with the linking table is detectable.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use thiserror::Error;
use uuid::Uuid;

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

pub struct LinkStore {
    secret: Vec<u8>,
    inner: Mutex<HashMap<(Provider, String), IdentityLink>>,
}

impl LinkStore {
    pub fn new(secret: Vec<u8>) -> Self {
        Self { secret, inner: Mutex::new(HashMap::new()) }
    }

    pub fn link(&self, user: &str, provider: Provider, subject: &str) -> Result<IdentityLink, LinkError> {
        let mut g = self.inner.lock().map_err(|_| LinkError::Poisoned)?;
        let key = (provider, subject.to_string());
        if let Some(existing) = g.get(&key) {
            if existing.milnet_user != user {
                return Err(LinkError::AlreadyLinked(existing.milnet_user.clone()));
            }
            return Ok(existing.clone());
        }
        let now = now_secs();
        let link = IdentityLink {
            link_id: Uuid::new_v4(),
            milnet_user: user.into(),
            provider,
            subject: subject.into(),
            linked_at: now,
            attestation: attestation(&self.secret, user, provider, subject, now),
        };
        g.insert(key, link.clone());
        Ok(link)
    }

    pub fn unlink(&self, provider: Provider, subject: &str) -> Result<(), LinkError> {
        let mut g = self.inner.lock().map_err(|_| LinkError::Poisoned)?;
        g.remove(&(provider, subject.to_string())).ok_or(LinkError::NotFound)?;
        Ok(())
    }

    pub fn resolve(&self, provider: Provider, subject: &str) -> Result<IdentityLink, LinkError> {
        let g = self.inner.lock().map_err(|_| LinkError::Poisoned)?;
        g.get(&(provider, subject.to_string())).cloned().ok_or(LinkError::NotFound)
    }

    pub fn verify(&self, link: &IdentityLink) -> Result<(), LinkError> {
        let want = attestation(&self.secret, &link.milnet_user, link.provider, &link.subject, link.linked_at);
        if want == link.attestation {
            Ok(())
        } else {
            Err(LinkError::AttestationInvalid)
        }
    }
}
