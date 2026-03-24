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

const NONCE_LEN: usize = 12;
fn encrypt_chain_key(kek: &[u8; 32], chain_key: &[u8; 64], session_id: &Uuid) -> Vec<u8> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
    let cipher = Aes256Gcm::new_from_slice(kek).expect("32-byte key");
    let mut nb = [0u8; NONCE_LEN]; getrandom::getrandom(&mut nb).expect("entropy");
    let nonce = Nonce::from_slice(&nb);
    let ct = cipher.encrypt(nonce, aes_gcm::aead::Payload { msg: chain_key.as_ref(), aad: session_id.as_bytes() }).expect("enc");
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len()); out.extend_from_slice(&nb); out.extend_from_slice(&ct); out
}
fn decrypt_chain_key(kek: &[u8; 32], sealed: &[u8], session_id: &Uuid) -> Result<[u8; 64], String> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
    if sealed.len() < NONCE_LEN + 16 { return Err("too short".into()); }
    let cipher = Aes256Gcm::new_from_slice(kek).expect("32-byte key");
    let pt = cipher.decrypt(Nonce::from_slice(&sealed[..NONCE_LEN]), aes_gcm::aead::Payload { msg: &sealed[NONCE_LEN..], aad: session_id.as_bytes() }).map_err(|_| "decrypt failed".to_string())?;
    if pt.len() != 64 { return Err(format!("expected 64, got {}", pt.len())); }
    let mut k = [0u8; 64]; k.copy_from_slice(&pt); Ok(k)
}
fn now_us() -> i64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_micros() as i64 }

pub struct PersistentSessionManager { memory: SessionManager, pool: sqlx::PgPool, kek: [u8; 32] }
impl PersistentSessionManager {
    pub async fn new(pool: sqlx::PgPool, kek: [u8; 32]) -> Result<Self, String> { let m = Self { memory: SessionManager::new(), pool, kek }; m.load_from_db().await?; Ok(m) }
    async fn load_from_db(&self) -> Result<(), String> {
        let rows: Vec<(Uuid, i64, Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>)> = sqlx::query_as("SELECT session_id, current_epoch, chain_key_encrypted, client_entropy, server_entropy FROM ratchet_sessions").fetch_all(&self.pool).await.map_err(|e| format!("load: {e}"))?;
        let mut ss = self.memory.sessions.write().expect("lock");
        for (sid, ep, enc, _, _) in rows { let ck = decrypt_chain_key(&self.kek, &enc, &sid)?; let ch = RatchetChain::from_persisted(ck, ep as u64); if let Some(ex) = ss.get(&sid) { if (ep as u64) < ex.epoch() { return Err(format!("rollback {sid}")); } } ss.insert(sid, ch); }
        Ok(())
    }
    pub async fn create_session(&self, sid: Uuid, ms: &[u8; 64]) -> Result<u64, String> {
        let ep = self.memory.create_session(sid, ms);
        let ck = { self.memory.sessions.read().expect("l").get(&sid).expect("c").current_key() };
        let enc = encrypt_chain_key(&self.kek, &ck, &sid); let now = now_us();
        sqlx::query("INSERT INTO ratchet_sessions (session_id,current_epoch,chain_key_encrypted,created_at,last_advanced_at) VALUES ($1,$2,$3,$4,$5) ON CONFLICT(session_id) DO UPDATE SET current_epoch=$2,chain_key_encrypted=$3,last_advanced_at=$5")
            .bind(sid).bind(ep as i64).bind(&enc).bind(now).bind(now).execute(&self.pool).await.map_err(|e| format!("persist: {e}"))?; Ok(ep)
    }
    pub async fn advance_session(&self, sid: &Uuid, ce: &[u8; 32], se: &[u8; 32]) -> Result<u64, String> {
        let ep = self.memory.advance_session(sid, ce, se)?;
        let ck = { self.memory.sessions.read().expect("l").get(sid).expect("e").current_key() };
        let enc = encrypt_chain_key(&self.kek, &ck, sid); let now = now_us();
        let r = sqlx::query("UPDATE ratchet_sessions SET current_epoch=$2,chain_key_encrypted=$3,client_entropy=$4,server_entropy=$5,last_advanced_at=$6 WHERE session_id=$1 AND current_epoch<$2")
            .bind(sid).bind(ep as i64).bind(&enc).bind(&ce[..]).bind(&se[..]).bind(now).execute(&self.pool).await.map_err(|e| format!("persist: {e}"))?;
        if r.rows_affected() == 0 { return Err(format!("monotonicity violation {sid}")); } Ok(ep)
    }
    pub fn generate_tag(&self, sid: &Uuid, cb: &[u8]) -> Result<[u8; 64], String> { self.memory.generate_tag(sid, cb) }
    pub fn verify_tag(&self, sid: &Uuid, cb: &[u8], tag: &[u8; 64], te: u64) -> Result<bool, String> { self.memory.verify_tag(sid, cb, tag, te) }
    pub async fn destroy_session(&self, sid: &Uuid) -> Result<(), String> { self.memory.destroy_session(sid); sqlx::query("DELETE FROM ratchet_sessions WHERE session_id=$1").bind(sid).execute(&self.pool).await.map_err(|e| format!("del: {e}"))?; Ok(()) }
}
impl Drop for PersistentSessionManager { fn drop(&mut self) { self.kek.zeroize(); } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn test_enc_dec_roundtrip() { let mut k = [0u8; 32]; getrandom::getrandom(&mut k).unwrap(); let s = Uuid::new_v4(); let mut ck = [0u8; 64]; getrandom::getrandom(&mut ck).unwrap(); assert_eq!(ck, decrypt_chain_key(&k, &encrypt_chain_key(&k, &ck, &s), &s).unwrap()); }
    #[test] fn test_wrong_kek() { let mut k1 = [0u8; 32]; getrandom::getrandom(&mut k1).unwrap(); let mut k2 = [0u8; 32]; getrandom::getrandom(&mut k2).unwrap(); assert!(decrypt_chain_key(&k2, &encrypt_chain_key(&k1, &[0xAB; 64], &Uuid::new_v4()), &Uuid::new_v4()).is_err()); }
    #[test] fn test_tampered() { let mut k = [0u8; 32]; getrandom::getrandom(&mut k).unwrap(); let s = Uuid::new_v4(); let mut sealed = encrypt_chain_key(&k, &[0xEF; 64], &s); if sealed.len() > 15 { sealed[15] ^= 0xFF; } assert!(decrypt_chain_key(&k, &sealed, &s).is_err()); }
    #[test] fn test_create_advance() { let m = SessionManager::new(); let s = Uuid::new_v4(); assert_eq!(m.create_session(s, &[0x42u8; 64]), 0); assert_eq!(m.advance_session(&s, &[0x11; 32], &[0x22; 32]).unwrap(), 1); }
    #[test] fn test_tag() { let m = SessionManager::new(); let s = Uuid::new_v4(); m.create_session(s, &[0x42u8; 64]); let t = m.generate_tag(&s, b"c").unwrap(); assert!(m.verify_tag(&s, b"c", &t, 0).unwrap()); }
    #[test] fn test_destroy() { let m = SessionManager::new(); let s = Uuid::new_v4(); m.create_session(s, &[0x42u8; 64]); m.destroy_session(&s); assert!(m.generate_tag(&s, b"x").is_err()); }
}
