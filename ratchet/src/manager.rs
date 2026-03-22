//! Session manager — tracks multiple ratchet chains keyed by session ID.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::chain::RatchetChain;

// ── Wire message types ─────────────────────────────────────────────────

/// Requests handled by the Ratchet Session Manager over SHARD transport.
#[derive(Debug, Serialize, Deserialize)]
pub struct RatchetRequest {
    pub action: RatchetAction,
}

/// Actions that can be performed on ratchet sessions.
///
/// Note: there is intentionally no `GetKey` variant — exposing raw chain
/// keys would break forward secrecy per spec.
#[derive(Debug, Serialize, Deserialize)]
pub enum RatchetAction {
    CreateSession {
        session_id: Uuid,
        /// 64-byte initial key sent as Vec since serde doesn't natively
        /// support `[u8; 64]`.
        initial_key: Vec<u8>,
    },
    Advance {
        session_id: Uuid,
        client_entropy: [u8; 32],
        server_entropy: [u8; 32],
    },
    GetTag {
        session_id: Uuid,
        claims_bytes: Vec<u8>,
    },
    Destroy {
        session_id: Uuid,
    },
}

/// Response returned by the Ratchet Session Manager.
#[derive(Debug, Serialize, Deserialize)]
pub struct RatchetResponse {
    pub success: bool,
    pub epoch: Option<u64>,
    pub tag: Option<Vec<u8>>,
    pub error: Option<String>,
}

/// Manages forward-secret ratchet sessions with thread-safe access.
///
/// Each session is identified by a UUID and backed by its own
/// [`RatchetChain`]. The sessions map is protected by an `RwLock` for
/// safe concurrent access — read locks for lookups, write locks for
/// mutations. When a session is destroyed the chain key is securely
/// erased via `ZeroizeOnDrop`.
pub struct SessionManager {
    sessions: RwLock<HashMap<Uuid, RatchetChain>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Create a new session and return its initial epoch (always 0).
    pub fn create_session(&self, session_id: Uuid, master_secret: &[u8; 64]) -> u64 {
        let chain = RatchetChain::new(master_secret);
        let epoch = chain.epoch();
        let mut sessions = self.sessions.write().expect("sessions lock poisoned");
        sessions.insert(session_id, chain);
        epoch
    }

    /// Advance a session's chain by one epoch, returning the new epoch.
    pub fn advance_session(
        &self,
        session_id: &Uuid,
        client_entropy: &[u8; 32],
        server_entropy: &[u8; 32],
    ) -> Result<u64, String> {
        let mut sessions = self.sessions.write().expect("sessions lock poisoned");
        let chain = sessions
            .get_mut(session_id)
            .ok_or_else(|| "session not found".to_string())?;
        if chain.is_expired() {
            return Err("session expired (8h max)".into());
        }
        chain.advance(client_entropy, server_entropy);
        Ok(chain.epoch())
    }

    /// Generate a ratchet tag for the given session's current epoch.
    pub fn generate_tag(&self, session_id: &Uuid, claims_bytes: &[u8]) -> Result<[u8; 64], String> {
        let sessions = self.sessions.read().expect("sessions lock poisoned");
        let chain = sessions
            .get(session_id)
            .ok_or_else(|| "session not found".to_string())?;
        Ok(chain.generate_tag(claims_bytes))
    }

    /// Verify a ratchet tag for the given session.
    pub fn verify_tag(
        &self,
        session_id: &Uuid,
        claims_bytes: &[u8],
        tag: &[u8; 64],
        token_epoch: u64,
    ) -> Result<bool, String> {
        let sessions = self.sessions.read().expect("sessions lock poisoned");
        let chain = sessions
            .get(session_id)
            .ok_or_else(|| "session not found".to_string())?;
        Ok(chain.verify_tag(claims_bytes, tag, token_epoch))
    }

    /// Destroy a session, securely erasing its chain key.
    pub fn destroy_session(&self, session_id: &Uuid) {
        let mut sessions = self.sessions.write().expect("sessions lock poisoned");
        sessions.remove(session_id); // ZeroizeOnDrop handles key cleanup
    }

    /// Destroy a session with explicit zeroization of the chain key
    /// before removal from the map. This ensures the key material is
    /// erased even if `ZeroizeOnDrop` is somehow bypassed.
    pub fn destroy_session_secure(&mut self, session_id: &Uuid) {
        let sessions = self.sessions.get_mut().expect("sessions lock poisoned");
        if let Some(mut chain) = sessions.remove(session_id) {
            // Explicitly zeroize before drop. The ZeroizeOnDrop derive
            // on RatchetChain will also fire, but belt-and-suspenders.
            chain.zeroize();
        }
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}
