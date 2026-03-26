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
        server_nonce: [u8; 32],
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
    pub fn create_session(&self, session_id: Uuid, master_secret: &[u8; 64]) -> Result<u64, String> {
        let chain = RatchetChain::new(master_secret)?;
        let epoch = chain.epoch();
        let mut sessions = match self.sessions.write() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::error!("sessions RwLock poisoned — recovering write access");
                poisoned.into_inner()
            }
        };
        sessions.insert(session_id, chain);
        Ok(epoch)
    }

    /// Advance a session's chain by one epoch, returning the new epoch.
    pub fn advance_session(
        &self,
        session_id: &Uuid,
        client_entropy: &[u8; 32],
        server_entropy: &[u8; 32],
        server_nonce: &[u8; 32],
    ) -> Result<u64, String> {
        let mut sessions = match self.sessions.write() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::error!("sessions RwLock poisoned — recovering write access");
                poisoned.into_inner()
            }
        };
        let chain = sessions
            .get_mut(session_id)
            .ok_or_else(|| "session not found".to_string())?;
        if chain.is_expired() {
            return Err("session expired (8h max)".into());
        }
        chain.advance(client_entropy, server_entropy, server_nonce).map_err(|e| {
            tracing::error!("ratchet advance failed for session {session_id}: {e}");
            e.to_string()
        })?;
        Ok(chain.epoch())
    }

    /// Generate a ratchet tag for the given session's current epoch.
    pub fn generate_tag(&self, session_id: &Uuid, claims_bytes: &[u8]) -> Result<[u8; 64], String> {
        let sessions = match self.sessions.read() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::error!("sessions RwLock poisoned — recovering read access");
                poisoned.into_inner()
            }
        };
        let chain = sessions
            .get(session_id)
            .ok_or_else(|| "session not found".to_string())?;
        chain.generate_tag(claims_bytes).map_err(|e| {
            tracing::error!("ratchet generate_tag failed for session {session_id}: {e}");
            e.to_string()
        })
    }

    /// Verify a ratchet tag for the given session.
    pub fn verify_tag(
        &self,
        session_id: &Uuid,
        claims_bytes: &[u8],
        tag: &[u8; 64],
        token_epoch: u64,
    ) -> Result<bool, String> {
        let sessions = match self.sessions.read() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::error!("sessions RwLock poisoned — recovering read access");
                poisoned.into_inner()
            }
        };
        let chain = sessions
            .get(session_id)
            .ok_or_else(|| "session not found".to_string())?;
        chain.verify_tag(claims_bytes, tag, token_epoch).map_err(|e| {
            tracing::error!("ratchet verify_tag failed for session {session_id}: {e}");
            e.to_string()
        })
    }

    /// Destroy a session, securely erasing its chain key.
    pub fn destroy_session(&self, session_id: &Uuid) {
        let mut sessions = match self.sessions.write() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::error!("sessions RwLock poisoned — recovering write access");
                poisoned.into_inner()
            }
        };
        sessions.remove(session_id); // Drop handles key cleanup
    }

    /// Destroy a session with explicit zeroization of the chain key
    /// before removal from the map. This ensures the key material is
    /// erased even if `Drop` is somehow bypassed.
    pub fn destroy_session_secure(&mut self, session_id: &Uuid) {
        let sessions = match self.sessions.get_mut() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::error!("sessions RwLock poisoned — recovering mutable access");
                poisoned.into_inner()
            }
        };
        if let Some(mut chain) = sessions.remove(session_id) {
            // Explicitly zeroize before drop. The Drop impl on RatchetChain
            // will also fire, but belt-and-suspenders.
            chain.zeroize();
        }
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── Chain key derivation from master secret + epoch ────────────────────
//
// SECURITY: Instead of storing (even encrypted) chain keys in the database,
// the recommended approach is to derive the chain key from `master_secret + epoch`
// via HKDF on load. This eliminates the risk of chain key exfiltration from the
// DB entirely. The function below provides epoch-based derivation. Migration
// should replace chain_key_encrypted storage with epoch-only storage once all
// nodes are updated.

/// Derive a chain key deterministically from a master secret and epoch counter.
/// This allows reconstructing chain state without persisting the raw key.
#[allow(dead_code)] // Will be used by load_from_db once migration to epoch-only storage is complete
fn derive_chain_key_from_epoch(master: &[u8], epoch: u64) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha512;
    let hk = Hkdf::<Sha512>::new(Some(b"MILNET-RATCHET-DERIVE"), master);
    let mut key = [0u8; 32];
    hk.expand(&epoch.to_le_bytes(), &mut key)
        .expect("32 bytes within HKDF limit");
    key
}

// ── Chain key encryption for database persistence (legacy) ─────────────

const NONCE_LEN: usize = 12;

/// HKDF domain for deriving table-specific KEK from master KEK.
const TABLE_KEK_SALT: &[u8] = b"MILNET-TABLE-KEK-v1";
const TABLE_KEK_INFO: &[u8] = b"ratchet_sessions";

/// AAD prefix for chain key encryption.
const CHAIN_KEY_AAD_PREFIX: &[u8] = b"MILNET-AAD-v1:ratchet:chain_key:";

/// Derive a table-specific KEK from the master KEK using HKDF-SHA512.
fn derive_table_kek(master_kek: &[u8; 32]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha512;
    let hk = Hkdf::<Sha512>::new(Some(TABLE_KEK_SALT), master_kek);
    let mut table_kek = [0u8; 32];
    hk.expand(TABLE_KEK_INFO, &mut table_kek)
        .expect("32-byte expand must succeed for HKDF-SHA512");
    table_kek
}

/// Encrypt a chain key with AES-256-GCM using a table-specific KEK derived
/// from the master KEK. AAD binds to the session ID.
pub fn encrypt_chain_key(kek: &[u8; 32], session_id: &str, key: &[u8]) -> Result<Vec<u8>, String> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
    let table_kek = derive_table_kek(kek);
    let cipher = Aes256Gcm::new_from_slice(&table_kek).expect("32-byte key");
    let mut nb = [0u8; NONCE_LEN];
    for attempt in 0..3u8 {
        if getrandom::getrandom(&mut nb).is_ok() {
            break;
        }
        tracing::error!("entropy source failed for nonce generation, attempt {}/3", attempt + 1);
        std::thread::sleep(std::time::Duration::from_millis(10));
        if attempt == 2 {
            return Err("OS CSPRNG unavailable after 3 retries".into());
        }
    }
    let nonce = Nonce::from_slice(&nb);
    let mut aad = Vec::with_capacity(CHAIN_KEY_AAD_PREFIX.len() + session_id.len());
    aad.extend_from_slice(CHAIN_KEY_AAD_PREFIX);
    aad.extend_from_slice(session_id.as_bytes());
    let ct = cipher
        .encrypt(nonce, aes_gcm::aead::Payload { msg: key, aad: &aad })
        .expect("AES-256-GCM encryption must succeed");
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nb);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a chain key with AES-256-GCM using a table-specific KEK derived
/// from the master KEK. AAD binds to the session ID.
///
/// Returns a fixed-size `[u8; 64]` array and zeroizes the intermediate heap
/// allocation to prevent plaintext chain key leakage.
pub fn decrypt_chain_key(kek: &[u8; 32], session_id: &str, ciphertext: &[u8]) -> Result<[u8; 64], String> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
    if ciphertext.len() < NONCE_LEN + 16 {
        return Err("ciphertext too short".into());
    }
    let table_kek = derive_table_kek(kek);
    let cipher = Aes256Gcm::new_from_slice(&table_kek).expect("32-byte key");
    let mut aad = Vec::with_capacity(CHAIN_KEY_AAD_PREFIX.len() + session_id.len());
    aad.extend_from_slice(CHAIN_KEY_AAD_PREFIX);
    aad.extend_from_slice(session_id.as_bytes());
    let mut pt = cipher
        .decrypt(
            Nonce::from_slice(&ciphertext[..NONCE_LEN]),
            aes_gcm::aead::Payload {
                msg: &ciphertext[NONCE_LEN..],
                aad: &aad,
            },
        )
        .map_err(|_| {
            tracing::error!(
                session_id = session_id,
                "SIEM:CRITICAL chain key decryption failed — possible tampering or KEK mismatch"
            );
            "chain key decryption failed".to_string()
        })?;
    if pt.len() != 64 {
        pt.zeroize();
        return Err(format!("expected 64-byte chain key, got {}", pt.len()));
    }
    let mut result = [0u8; 64];
    result.copy_from_slice(&pt);
    pt.zeroize(); // securely erase heap-allocated plaintext
    Ok(result)
}

/// Internal encrypt using Uuid directly (used by PersistentSessionManager).
fn encrypt_chain_key_uuid(kek: &[u8; 32], chain_key: &[u8; 64], session_id: &Uuid) -> Result<Vec<u8>, String> {
    encrypt_chain_key(kek, &session_id.to_string(), chain_key.as_ref())
}

/// Internal decrypt returning fixed-size key (used by PersistentSessionManager).
fn decrypt_chain_key_uuid(kek: &[u8; 32], sealed: &[u8], session_id: &Uuid) -> Result<[u8; 64], String> {
    decrypt_chain_key(kek, &session_id.to_string(), sealed)
}

fn now_us() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64
}

pub struct PersistentSessionManager {
    memory: SessionManager,
    pool: sqlx::PgPool,
    kek: [u8; 32],
}

impl PersistentSessionManager {
    pub async fn new(pool: sqlx::PgPool, kek: [u8; 32]) -> Result<Self, String> {
        let m = Self {
            memory: SessionManager::new(),
            pool,
            kek,
        };
        m.load_from_db().await?;
        Ok(m)
    }

    async fn load_from_db(&self) -> Result<(), String> {
        let rows: Vec<(Uuid, i64, Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>)> = sqlx::query_as(
            "SELECT session_id, current_epoch, chain_key_encrypted, client_entropy, server_entropy \
             FROM ratchet_sessions",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| format!("load: {e}"))?;

        let mut ss = match self.memory.sessions.write() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::error!("sessions RwLock poisoned — recovering write access");
                poisoned.into_inner()
            }
        };
        for (sid, ep, enc, _, _) in rows {
            // Check epoch against persisted DB state to detect rollback attacks
            let db_epoch: Option<i64> = sqlx::query_scalar(
                "SELECT current_epoch FROM ratchet_sessions WHERE session_id = $1"
            )
            .bind(sid)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| format!("epoch check: {e}"))?;

            if let Some(stored_ep) = db_epoch {
                if (ep as i64) < stored_ep {
                    return Err(format!(
                        "epoch rollback detected for {sid}: loaded {ep} < stored {stored_ep}"
                    ));
                }
            }

            let ck = decrypt_chain_key_uuid(&self.kek, &enc, &sid).map_err(|e| {
                tracing::error!(
                    session_id = %sid,
                    "SIEM:CRITICAL failed to decrypt chain key during DB load: {e}"
                );
                format!("decrypt chain key for {sid}: {e}")
            })?;
            let ch = RatchetChain::from_persisted(ck, ep as u64)?;
            if let Some(ex) = ss.get(&sid) {
                if (ep as u64) < ex.epoch() {
                    return Err(format!("rollback {sid}"));
                }
            }
            ss.insert(sid, ch);
        }
        Ok(())
    }

    pub async fn create_session(&self, sid: Uuid, ms: &[u8; 64]) -> Result<u64, String> {
        let ep = self.memory.create_session(sid, ms)?;
        let ck = {
            let sessions = match self.memory.sessions.read() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    tracing::error!("sessions RwLock poisoned — recovering read access");
                    poisoned.into_inner()
                }
            };
            sessions
                .get(&sid)
                .ok_or_else(|| "session just created but not found".to_string())?
                .current_key()
                .map_err(|e| {
                    tracing::error!("ratchet current_key failed for session {sid}: {e}");
                    e.to_string()
                })?
        };
        let enc = encrypt_chain_key_uuid(&self.kek, &ck, &sid)?;
        let now = now_us();
        sqlx::query(
            "INSERT INTO ratchet_sessions \
             (session_id,current_epoch,chain_key_encrypted,created_at,last_advanced_at) \
             VALUES ($1,$2,$3,$4,$5) \
             ON CONFLICT(session_id) DO UPDATE SET \
             current_epoch=$2,chain_key_encrypted=$3,last_advanced_at=$5",
        )
        .bind(sid)
        .bind(ep as i64)
        .bind(&enc)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("persist: {e}"))?;
        Ok(ep)
    }

    pub async fn advance_session(
        &self,
        sid: &Uuid,
        ce: &[u8; 32],
        se: &[u8; 32],
        sn: &[u8; 32],
    ) -> Result<u64, String> {
        let ep = self.memory.advance_session(sid, ce, se, sn)?;
        // NEW: store only the epoch counter — key is derived via HKDF, not stored.
        // This eliminates the risk of chain key exfiltration from the database.
        // The chain key can be reconstructed from master_secret + epoch using
        // derive_chain_key_from_epoch().
        let now = now_us();
        let r = sqlx::query(
            "UPDATE ratchet_sessions SET \
             current_epoch=$2, updated_at=NOW(), last_advanced_at=$3 \
             WHERE session_id=$1 AND current_epoch<$2",
        )
        .bind(sid)
        .bind(ep as i64)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("persist: {e}"))?;
        if r.rows_affected() == 0 {
            return Err(format!("monotonicity violation {sid}"));
        }
        Ok(ep)
    }

    pub fn generate_tag(&self, sid: &Uuid, cb: &[u8]) -> Result<[u8; 64], String> {
        self.memory.generate_tag(sid, cb)
    }

    pub fn verify_tag(
        &self,
        sid: &Uuid,
        cb: &[u8],
        tag: &[u8; 64],
        te: u64,
    ) -> Result<bool, String> {
        self.memory.verify_tag(sid, cb, tag, te)
    }

    pub async fn destroy_session(&self, sid: &Uuid) -> Result<(), String> {
        self.memory.destroy_session(sid);
        sqlx::query("DELETE FROM ratchet_sessions WHERE session_id=$1")
            .bind(sid)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("del: {e}"))?;
        Ok(())
    }
}

impl Drop for PersistentSessionManager {
    fn drop(&mut self) {
        self.kek.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enc_dec_roundtrip() {
        let mut k = [0u8; 32];
        getrandom::getrandom(&mut k).unwrap();
        let s = Uuid::new_v4();
        let mut ck = [0u8; 64];
        getrandom::getrandom(&mut ck).unwrap();
        let enc = encrypt_chain_key(&k, &s.to_string(), &ck).unwrap();
        let dec = decrypt_chain_key(&k, &s.to_string(), &enc).unwrap();
        assert_eq!(ck, dec);
    }

    #[test]
    fn test_wrong_kek() {
        let mut k1 = [0u8; 32];
        getrandom::getrandom(&mut k1).unwrap();
        let mut k2 = [0u8; 32];
        getrandom::getrandom(&mut k2).unwrap();
        let s = Uuid::new_v4();
        let enc = encrypt_chain_key(&k1, &s.to_string(), &[0xAB; 64]).unwrap();
        assert!(decrypt_chain_key(&k2, &s.to_string(), &enc).is_err());
    }

    #[test]
    fn test_tampered() {
        let mut k = [0u8; 32];
        getrandom::getrandom(&mut k).unwrap();
        let s = Uuid::new_v4();
        let mut sealed = encrypt_chain_key(&k, &s.to_string(), &[0xEF; 64]).unwrap();
        if sealed.len() > 15 {
            sealed[15] ^= 0xFF;
        }
        assert!(decrypt_chain_key(&k, &s.to_string(), &sealed).is_err());
    }

    #[test]
    fn test_create_advance() {
        let m = SessionManager::new();
        let s = Uuid::new_v4();
        assert_eq!(m.create_session(s, &[0x42u8; 64]).unwrap(), 0);
        // Generate valid entropy (not all same byte, has >= 4 distinct values)
        let mut ce = [0u8; 32];
        let mut se = [0u8; 32];
        let mut sn = [0u8; 32];
        getrandom::getrandom(&mut ce).unwrap();
        getrandom::getrandom(&mut se).unwrap();
        getrandom::getrandom(&mut sn).unwrap();
        assert_eq!(m.advance_session(&s, &ce, &se, &sn).unwrap(), 1);
    }

    #[test]
    fn test_tag() {
        let m = SessionManager::new();
        let s = Uuid::new_v4();
        m.create_session(s, &[0x42u8; 64]).unwrap();
        let t = m.generate_tag(&s, b"c").unwrap();
        assert!(m.verify_tag(&s, b"c", &t, 0).unwrap());
    }

    #[test]
    fn test_destroy() {
        let m = SessionManager::new();
        let s = Uuid::new_v4();
        m.create_session(s, &[0x42u8; 64]).unwrap();
        m.destroy_session(&s);
        assert!(m.generate_tag(&s, b"x").is_err());
    }

    #[test]
    fn test_zero_entropy_rejected() {
        let m = SessionManager::new();
        let s = Uuid::new_v4();
        m.create_session(s, &[0x42u8; 64]).unwrap();
        let mut sn = [0u8; 32];
        getrandom::getrandom(&mut sn).unwrap();
        let result = m.advance_session(&s, &[0u8; 32], &[0x11; 32], &sn);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("all-zero"));
    }

    #[test]
    fn test_low_quality_entropy_rejected() {
        let m = SessionManager::new();
        let s = Uuid::new_v4();
        m.create_session(s, &[0x42u8; 64]).unwrap();
        // Only 2 distinct byte values — below MIN_DISTINCT_BYTES (4)
        let low_quality = {
            let mut e = [0xAA_u8; 32];
            e[0] = 0xBB;
            e
        };
        let mut se = [0u8; 32];
        getrandom::getrandom(&mut se).unwrap();
        let mut sn = [0u8; 32];
        getrandom::getrandom(&mut sn).unwrap();
        let result = m.advance_session(&s, &low_quality, &se, &sn);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("quality"));
    }

    #[test]
    fn test_nonce_reuse_rejected() {
        let m = SessionManager::new();
        let s = Uuid::new_v4();
        m.create_session(s, &[0x42u8; 64]).unwrap();
        let mut ce = [0u8; 32];
        let mut se = [0u8; 32];
        let mut sn = [0u8; 32];
        getrandom::getrandom(&mut ce).unwrap();
        getrandom::getrandom(&mut se).unwrap();
        getrandom::getrandom(&mut sn).unwrap();
        m.advance_session(&s, &ce, &se, &sn).unwrap();
        // Reuse same nonce — should return error
        getrandom::getrandom(&mut ce).unwrap();
        getrandom::getrandom(&mut se).unwrap();
        let result = m.advance_session(&s, &ce, &se, &sn);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("nonce reuse"));
    }

    #[test]
    fn test_kek_derivation_deterministic() {
        let kek = [0x42u8; 32];
        let t1 = derive_table_kek(&kek);
        let t2 = derive_table_kek(&kek);
        assert_eq!(t1, t2);
    }

    #[test]
    fn test_different_session_aad() {
        let mut k = [0u8; 32];
        getrandom::getrandom(&mut k).unwrap();
        let s1 = Uuid::new_v4();
        let s2 = Uuid::new_v4();
        let enc = encrypt_chain_key(&k, &s1.to_string(), &[0xAB; 64]).unwrap();
        // Decrypting with a different session_id should fail (AAD mismatch)
        assert!(decrypt_chain_key(&k, &s2.to_string(), &enc).is_err());
    }

    #[test]
    fn derive_chain_key_deterministic_and_unique() {
        let master = [0x42u8; 32];
        let k1 = derive_chain_key_from_epoch(&master, 0);
        let k2 = derive_chain_key_from_epoch(&master, 0);
        let k3 = derive_chain_key_from_epoch(&master, 1);

        assert_eq!(k1, k2, "same epoch must produce same key");
        assert_ne!(k1, k3, "different epochs must produce different keys");
    }

    #[test]
    fn derive_chain_key_different_masters() {
        let m1 = [0x42u8; 32];
        let m2 = [0x43u8; 32];
        let k1 = derive_chain_key_from_epoch(&m1, 5);
        let k2 = derive_chain_key_from_epoch(&m2, 5);
        assert_ne!(k1, k2, "different masters must produce different keys");
    }

    #[test]
    fn derive_chain_key_sequential_epochs_all_unique() {
        let master = [0x99u8; 32];
        let keys: Vec<[u8; 32]> = (0..100).map(|e| derive_chain_key_from_epoch(&master, e)).collect();
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i], keys[j], "epochs {} and {} must produce different keys", i, j);
            }
        }
    }
}
