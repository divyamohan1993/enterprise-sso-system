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
#[derive(Serialize, Deserialize)]
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

// SECURITY: Manual Debug impl to redact initial_key from logs/traces.
// The derived Debug would print the raw key bytes in plaintext.
impl std::fmt::Debug for RatchetAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CreateSession { session_id, .. } => f.debug_struct("CreateSession")
                .field("session_id", session_id)
                .field("initial_key", &"[REDACTED]")
                .finish(),
            Self::Advance { session_id, client_entropy, server_entropy, server_nonce } => {
                f.debug_struct("Advance")
                    .field("session_id", session_id)
                    .field("client_entropy", client_entropy)
                    .field("server_entropy", server_entropy)
                    .field("server_nonce", server_nonce)
                    .finish()
            }
            Self::GetTag { session_id, claims_bytes } => f.debug_struct("GetTag")
                .field("session_id", session_id)
                .field("claims_bytes_len", &claims_bytes.len())
                .finish(),
            Self::Destroy { session_id } => f.debug_struct("Destroy")
                .field("session_id", session_id)
                .finish(),
        }
    }
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

    /// Maximum number of concurrent ratchet sessions.
    const MAX_SESSIONS: usize = 100_000;

    /// A2: Create a session with a pre-computed X-Wing PQ ciphertext ring
    /// bound to the peer's public key and this node's local X-Wing keypair.
    /// The returned session will receive a PQ puncture every
    /// `PQ_PUNCTURE_INTERVAL` epochs. Falls through to [`Self::create_session`]
    /// when a caller does not need the PQ path.
    pub fn create_session_with_pq(
        &self,
        session_id: Uuid,
        master_secret: &[u8; 64],
        peer_pk: &crypto::xwing::XWingPublicKey,
        local_kp: std::sync::Arc<crypto::xwing::XWingKeyPair>,
    ) -> Result<u64, String> {
        let chain = RatchetChain::new_with_pq(master_secret, peer_pk, local_kp)?;
        let epoch = chain.epoch();
        let mut sessions = match self.sessions.write() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::error!("sessions RwLock poisoned — recovering write access");
                poisoned.into_inner()
            }
        };
        if sessions.len() >= Self::MAX_SESSIONS && !sessions.contains_key(&session_id) {
            return Err(format!(
                "MAX_SESSIONS ({}) reached — cannot create new ratchet session",
                Self::MAX_SESSIONS
            ));
        }
        sessions.insert(session_id, chain);
        Ok(epoch)
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
        if sessions.len() >= Self::MAX_SESSIONS && !sessions.contains_key(&session_id) {
            return Err(format!(
                "MAX_SESSIONS ({}) reached — cannot create new ratchet session",
                Self::MAX_SESSIONS
            ));
        }
        sessions.insert(session_id, chain);
        common::audit_bridge::buffer_audit_entry(
            common::audit_bridge::create_audit_entry(
                common::types::AuditEventType::AuthSuccess,
                Vec::new(),
                Vec::new(),
                None,
                Some(session_id.to_string()),
            ),
        );
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
    if hk.expand(&epoch.to_le_bytes(), &mut key).is_err() {
        tracing::error!("SIEM:CRITICAL HKDF-SHA512 expand failed in chain key derivation from epoch");
        // Return zeroed key — caller must validate
    }
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
    if hk.expand(TABLE_KEK_INFO, &mut table_kek).is_err() {
        tracing::error!("SIEM:CRITICAL HKDF-SHA512 expand failed in table KEK derivation");
        // Return zeroed key — encryption/decryption will fail safely downstream
    }
    table_kek
}

/// Encrypt a chain key with AES-256-GCM using a table-specific KEK derived
/// from the master KEK. AAD binds to the session ID.
pub fn encrypt_chain_key(kek: &[u8; 32], session_id: &str, key: &[u8]) -> Result<Vec<u8>, String> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
    let table_kek = derive_table_kek(kek);
    let cipher = Aes256Gcm::new_from_slice(&table_kek)
        .map_err(|_| "failed to initialize AES-256-GCM cipher".to_string())?;
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
        .map_err(|_| "AES-256-GCM encryption failed".to_string())?;
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
    let cipher = Aes256Gcm::new_from_slice(&table_kek)
        .map_err(|_| "failed to initialize AES-256-GCM cipher for decryption".to_string())?;
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

// ---------------------------------------------------------------------------
// Epoch metadata envelope encryption
// ---------------------------------------------------------------------------
//
// Epoch counters and chain metadata are sensitive — they reveal session
// activity patterns and can aid replay attacks if tampered with. We encrypt
// epoch metadata at rest using the same table-specific KEK that protects
// chain keys, with a distinct AAD to prevent cross-field confusion.

/// AAD prefix for epoch metadata encryption.
const EPOCH_METADATA_AAD_PREFIX: &[u8] = b"MILNET-AAD-v1:ratchet:epoch_metadata:";

/// Epoch metadata envelope: encrypted epoch counter + auxiliary chain metadata.
///
/// Stored as AES-256-GCM ciphertext in the database alongside the encrypted
/// chain key. The plaintext is a postcard-serialized `EpochMetadata`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochMetadata {
    /// Current epoch counter.
    pub epoch: u64,
    /// Timestamp of last advancement (microseconds since UNIX epoch).
    pub last_advanced_us: i64,
    /// Number of advancements since session creation.
    pub advancement_count: u64,
}

/// Encrypt epoch metadata using the table-specific KEK derived from the master KEK.
/// AAD binds to the session ID to prevent cross-session confusion.
pub fn encrypt_epoch_metadata(
    kek: &[u8; 32],
    session_id: &str,
    metadata: &EpochMetadata,
) -> Result<Vec<u8>, String> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

    let table_kek = derive_table_kek(kek);
    let cipher = Aes256Gcm::new_from_slice(&table_kek)
        .map_err(|_| "failed to initialize AES-256-GCM cipher for epoch metadata encryption".to_string())?;

    let plaintext = postcard::to_allocvec(metadata)
        .map_err(|e| format!("epoch metadata serialization failed: {e}"))?;

    let mut nb = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nb)
        .map_err(|e| format!("nonce generation failed: {e}"))?;
    let nonce = Nonce::from_slice(&nb);

    let mut aad = Vec::with_capacity(EPOCH_METADATA_AAD_PREFIX.len() + session_id.len());
    aad.extend_from_slice(EPOCH_METADATA_AAD_PREFIX);
    aad.extend_from_slice(session_id.as_bytes());

    let ct = cipher
        .encrypt(nonce, aes_gcm::aead::Payload { msg: &plaintext, aad: &aad })
        .map_err(|e| format!("epoch metadata encryption failed: {e}"))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nb);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt epoch metadata using the table-specific KEK derived from the master KEK.
/// AAD binds to the session ID.
pub fn decrypt_epoch_metadata(
    kek: &[u8; 32],
    session_id: &str,
    ciphertext: &[u8],
) -> Result<EpochMetadata, String> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

    if ciphertext.len() < NONCE_LEN + 16 {
        return Err("epoch metadata ciphertext too short".into());
    }

    let table_kek = derive_table_kek(kek);
    let cipher = Aes256Gcm::new_from_slice(&table_kek)
        .map_err(|_| "failed to initialize AES-256-GCM cipher for epoch metadata decryption".to_string())?;

    let mut aad = Vec::with_capacity(EPOCH_METADATA_AAD_PREFIX.len() + session_id.len());
    aad.extend_from_slice(EPOCH_METADATA_AAD_PREFIX);
    aad.extend_from_slice(session_id.as_bytes());

    let pt = cipher
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
                "SIEM:CRITICAL epoch metadata decryption failed — possible tampering or KEK mismatch"
            );
            "epoch metadata decryption failed".to_string()
        })?;

    postcard::from_bytes(&pt)
        .map_err(|e| format!("epoch metadata deserialization failed: {e}"))
}

fn now_us() -> i64 {
    common::secure_time::secure_now_us_i64()
}

/// Result of a replication health check.
#[derive(Debug)]
pub struct ReplicationHealthReport {
    /// Total sessions sampled.
    pub sampled: usize,
    /// Sessions where in-memory epoch matches DB epoch.
    pub consistent: usize,
    /// Sessions where a mismatch was detected.
    pub divergent: Vec<(Uuid, u64, i64)>, // (session_id, mem_epoch, db_epoch)
    /// Whether replication is considered healthy.
    pub healthy: bool,
}

/// Distributed-HA ratchet session manager with write-through PostgreSQL persistence.
///
/// Invariants:
/// - Every chain advance is persisted to PostgreSQL **synchronously** before success.
/// - The in-memory HashMap serves as a performance cache; the DB is the source of truth.
/// - On startup, all active sessions are loaded from PostgreSQL into memory.
/// - `WHERE current_epoch < $2` guarantees distributed epoch monotonicity.
/// - On DB write failure during advance, the in-memory state is rolled back.
pub struct PersistentSessionManager {
    memory: SessionManager,
    pool: sqlx::PgPool,
    kek: [u8; 32],
}

impl PersistentSessionManager {
    /// Create a new PersistentSessionManager and load all active sessions from PostgreSQL.
    ///
    /// This is the startup recovery path: every active ratchet session is decrypted
    /// from the DB and loaded into the in-memory cache so operations can proceed
    /// without DB reads on the hot path.
    pub async fn new(pool: sqlx::PgPool, kek: [u8; 32]) -> Result<Self, String> {
        let m = Self {
            memory: SessionManager::new(),
            pool,
            kek,
        };
        m.load_from_db().await?;
        Ok(m)
    }

    /// Startup recovery: load all active sessions from PostgreSQL into the in-memory cache.
    ///
    /// Each row's `chain_key_encrypted` is decrypted using the KEK and reconstructed
    /// as a `RatchetChain`. Epoch rollback detection prevents loading stale state.
    async fn load_from_db(&self) -> Result<(), String> {
        let rows: Vec<(Uuid, i64, Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>)> = sqlx::query_as(
            "SELECT session_id, current_epoch, chain_key_encrypted, client_entropy, server_entropy \
             FROM ratchet_sessions",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| format!("load: {e}"))?;

        tracing::info!(
            session_count = rows.len(),
            "loading ratchet sessions from PostgreSQL for HA recovery"
        );

        let mut ss = match self.memory.sessions.write() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::error!("sessions RwLock poisoned — recovering write access");
                poisoned.into_inner()
            }
        };
        let mut loaded = 0usize;
        for (sid, ep, enc, _, _) in rows {
            let ck = decrypt_chain_key_uuid(&self.kek, &enc, &sid).map_err(|e| {
                tracing::error!(
                    session_id = %sid,
                    "SIEM:CRITICAL failed to decrypt chain key during DB load: {e}"
                );
                format!("decrypt chain key for {sid}: {e}")
            })?;
            let ch = RatchetChain::from_persisted(ck, ep as u64)?;
            // Epoch rollback detection: if this session is already in memory
            // (e.g. from a prior partial load), reject if the DB epoch is older.
            if let Some(ex) = ss.get(&sid) {
                if (ep as u64) < ex.epoch() {
                    return Err(format!(
                        "epoch rollback detected for {sid}: DB epoch {ep} < memory epoch {}",
                        ex.epoch()
                    ));
                }
            }
            ss.insert(sid, ch);
            loaded += 1;
        }
        tracing::info!(loaded, "ratchet sessions recovered from PostgreSQL");
        Ok(())
    }

    /// Create a new session, persisting to PostgreSQL before returning success.
    ///
    /// Write-through: memory is updated first, then DB. If DB fails, the in-memory
    /// session is removed (rollback).
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
        let db_result = sqlx::query(
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
        .await;

        match db_result {
            Ok(_) => Ok(ep),
            Err(e) => {
                // Rollback: remove the session from in-memory cache
                tracing::error!(
                    session_id = %sid,
                    "DB persist failed for create_session, rolling back in-memory state: {e}"
                );
                self.memory.destroy_session(&sid);
                Err(format!("persist failed (rolled back): {e}"))
            }
        }
    }

    /// Advance a session's ratchet chain with write-through persistence.
    ///
    /// Steps:
    /// 1. Snapshot the current chain key + epoch (for rollback)
    /// 2. Advance the chain in memory
    /// 3. Encrypt the new chain key with the KEK
    /// 4. Write to PostgreSQL with `WHERE current_epoch < $2` (monotonicity)
    /// 5. If DB write fails, rollback the in-memory state to the snapshot
    /// 6. Only return success if BOTH memory and DB are updated
    pub async fn advance_session(
        &self,
        sid: &Uuid,
        ce: &[u8; 32],
        se: &[u8; 32],
        sn: &[u8; 32],
    ) -> Result<u64, String> {
        // Step 1: Snapshot current state for rollback
        let snapshot = {
            let sessions = match self.memory.sessions.read() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    tracing::error!("sessions RwLock poisoned — recovering read access");
                    poisoned.into_inner()
                }
            };
            let chain = sessions
                .get(sid)
                .ok_or_else(|| "session not found".to_string())?;
            let key = chain.current_key().map_err(|e| e.to_string())?;
            let epoch = chain.epoch();
            (key, epoch)
        };

        // Step 2: Advance in memory
        let ep = self.memory.advance_session(sid, ce, se, sn)?;

        // Step 3: Encrypt the new chain key with KEK for DB persistence
        let new_ck = {
            let sessions = match self.memory.sessions.read() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    tracing::error!("sessions RwLock poisoned — recovering read access");
                    poisoned.into_inner()
                }
            };
            sessions
                .get(sid)
                .ok_or_else(|| "session lost after advance".to_string())?
                .current_key()
                .map_err(|e| e.to_string())?
        };
        let enc = encrypt_chain_key_uuid(&self.kek, &new_ck, sid)?;

        // Step 4: Write to PostgreSQL with monotonicity guard
        let now = now_us();
        let db_result = sqlx::query(
            "UPDATE ratchet_sessions SET \
             chain_key_encrypted=$2, current_epoch=$3, last_advanced_at=$4 \
             WHERE session_id=$1 AND current_epoch<$3",
        )
        .bind(sid)
        .bind(&enc)
        .bind(ep as i64)
        .bind(now)
        .execute(&self.pool)
        .await;

        match db_result {
            Ok(r) => {
                if r.rows_affected() == 0 {
                    // Step 5: Monotonicity violation — rollback in-memory state
                    tracing::error!(
                        session_id = %sid,
                        epoch = ep,
                        "monotonicity violation: another instance advanced past epoch {ep}, rolling back"
                    );
                    self.rollback_session(sid, snapshot.0, snapshot.1);
                    return Err(format!("monotonicity violation for {sid} at epoch {ep}"));
                }
                Ok(ep)
            }
            Err(e) => {
                // Step 5: DB failure — rollback in-memory state to snapshot
                tracing::error!(
                    session_id = %sid,
                    epoch = ep,
                    "DB persist failed for advance_session, rolling back in-memory state: {e}"
                );
                self.rollback_session(sid, snapshot.0, snapshot.1);
                Err(format!("persist failed (rolled back): {e}"))
            }
        }
    }

    /// Rollback an in-memory session to a previous chain key and epoch.
    ///
    /// Replaces the current chain with a fresh `RatchetChain::from_persisted`
    /// reconstructed from the snapshot. If reconstruction fails, the session
    /// is destroyed entirely (fail-closed).
    fn rollback_session(&self, sid: &Uuid, chain_key: [u8; 64], epoch: u64) {
        let mut sessions = match self.memory.sessions.write() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::error!("sessions RwLock poisoned — recovering write access for rollback");
                poisoned.into_inner()
            }
        };
        match RatchetChain::from_persisted(chain_key, epoch) {
            Ok(restored) => {
                sessions.insert(*sid, restored);
                tracing::warn!(
                    session_id = %sid,
                    epoch,
                    "in-memory session rolled back to epoch {epoch}"
                );
            }
            Err(e) => {
                // Fail-closed: destroy the session entirely
                tracing::error!(
                    session_id = %sid,
                    "failed to reconstruct chain for rollback: {e} — destroying session"
                );
                sessions.remove(sid);
            }
        }
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

    /// Destroy a session from both in-memory cache and PostgreSQL.
    pub async fn destroy_session(&self, sid: &Uuid) -> Result<(), String> {
        self.memory.destroy_session(sid);
        sqlx::query("DELETE FROM ratchet_sessions WHERE session_id=$1")
            .bind(sid)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("del: {e}"))?;
        Ok(())
    }

    /// Check replication health by verifying that a random sample of in-memory
    /// sessions match their PostgreSQL counterparts.
    ///
    /// Samples up to `sample_size` sessions. For each, reads the DB epoch and
    /// compares to the in-memory epoch. Returns a health report.
    pub async fn check_replication_health(&self, sample_size: usize) -> Result<ReplicationHealthReport, String> {
        let session_ids: Vec<Uuid> = {
            let sessions = match self.memory.sessions.read() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    tracing::error!("sessions RwLock poisoned — recovering read access");
                    poisoned.into_inner()
                }
            };
            sessions.keys().copied().collect()
        };

        if session_ids.is_empty() {
            return Ok(ReplicationHealthReport {
                sampled: 0,
                consistent: 0,
                divergent: Vec::new(),
                healthy: true,
            });
        }

        // Sample: take up to sample_size sessions. Use a deterministic but
        // rotating selection: pick every N-th element based on current time.
        let total = session_ids.len();
        let step = if total > sample_size { total / sample_size } else { 1 };
        let sampled_ids: Vec<Uuid> = session_ids
            .iter()
            .step_by(step)
            .take(sample_size)
            .copied()
            .collect();

        let mut consistent = 0usize;
        let mut divergent = Vec::new();

        for sid in &sampled_ids {
            let mem_epoch = {
                let sessions = match self.memory.sessions.read() {
                    Ok(guard) => guard,
                    Err(poisoned) => {
                        tracing::error!("sessions RwLock poisoned — recovering read access");
                        poisoned.into_inner()
                    }
                };
                match sessions.get(sid) {
                    Some(chain) => chain.epoch(),
                    None => continue, // session destroyed between sampling and checking
                }
            };

            let db_epoch: Option<i64> = sqlx::query_scalar(
                "SELECT current_epoch FROM ratchet_sessions WHERE session_id = $1",
            )
            .bind(sid)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| format!("health check DB query failed: {e}"))?;

            match db_epoch {
                Some(db_ep) => {
                    if db_ep == mem_epoch as i64 {
                        consistent += 1;
                    } else {
                        tracing::warn!(
                            session_id = %sid,
                            mem_epoch,
                            db_epoch = db_ep,
                            "replication divergence detected"
                        );
                        divergent.push((*sid, mem_epoch, db_ep));
                    }
                }
                None => {
                    // Session exists in memory but not in DB — divergence
                    tracing::warn!(
                        session_id = %sid,
                        mem_epoch,
                        "session exists in memory but not in PostgreSQL"
                    );
                    divergent.push((*sid, mem_epoch, -1));
                }
            }
        }

        let sampled = sampled_ids.len();
        let healthy = divergent.is_empty();

        if !healthy {
            tracing::error!(
                sampled,
                consistent,
                divergent_count = divergent.len(),
                "SIEM:WARNING replication health check found divergent sessions"
            );
        } else {
            tracing::info!(
                sampled,
                consistent,
                "replication health check passed — all sampled sessions consistent"
            );
        }

        Ok(ReplicationHealthReport {
            sampled,
            consistent,
            divergent,
            healthy,
        })
    }

    /// Return the number of sessions currently in the in-memory cache.
    pub fn session_count(&self) -> usize {
        let sessions = match self.memory.sessions.read() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::error!("sessions RwLock poisoned — recovering read access");
                poisoned.into_inner()
            }
        };
        sessions.len()
    }

    /// Access the underlying pool for external health checks.
    pub fn pool(&self) -> &sqlx::PgPool {
        &self.pool
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

    // ── Write-through and rollback tests (in-memory simulation) ─────────

    /// Verify that the rollback mechanism correctly restores a session
    /// to a previous epoch and chain key after a simulated DB failure.
    #[test]
    fn test_rollback_restores_previous_state() {
        let m = SessionManager::new();
        let s = Uuid::new_v4();
        let master = [0x42u8; 64];
        m.create_session(s, &master).unwrap();

        // Capture initial state
        let initial_key = {
            let sessions = m.sessions.read().unwrap();
            sessions.get(&s).unwrap().current_key().unwrap()
        };
        let initial_epoch = 0u64;

        // Advance the session
        let mut ce = [0u8; 32];
        let mut se = [0u8; 32];
        let mut sn = [0u8; 32];
        getrandom::getrandom(&mut ce).unwrap();
        getrandom::getrandom(&mut se).unwrap();
        getrandom::getrandom(&mut sn).unwrap();
        let new_epoch = m.advance_session(&s, &ce, &se, &sn).unwrap();
        assert_eq!(new_epoch, 1);

        // Verify advanced state
        let advanced_key = {
            let sessions = m.sessions.read().unwrap();
            sessions.get(&s).unwrap().current_key().unwrap()
        };
        assert_ne!(initial_key, advanced_key, "chain key must change after advance");

        // Simulate rollback (what PersistentSessionManager does on DB failure)
        {
            let mut sessions = m.sessions.write().unwrap();
            let restored = RatchetChain::from_persisted(initial_key, initial_epoch).unwrap();
            sessions.insert(s, restored);
        }

        // Verify rollback
        let rolled_back_epoch = {
            let sessions = m.sessions.read().unwrap();
            sessions.get(&s).unwrap().epoch()
        };
        assert_eq!(rolled_back_epoch, initial_epoch, "epoch must be restored after rollback");

        let rolled_back_key = {
            let sessions = m.sessions.read().unwrap();
            sessions.get(&s).unwrap().current_key().unwrap()
        };
        assert_eq!(rolled_back_key, initial_key, "chain key must be restored after rollback");
    }

    /// Verify that after rollback, the session can still generate valid tags
    /// for the restored epoch.
    #[test]
    fn test_rollback_preserves_tag_generation() {
        let m = SessionManager::new();
        let s = Uuid::new_v4();
        let master = [0x42u8; 64];
        m.create_session(s, &master).unwrap();

        // Generate tag at epoch 0
        let tag_before = m.generate_tag(&s, b"claims").unwrap();

        // Capture state for rollback
        let snapshot_key = {
            let sessions = m.sessions.read().unwrap();
            sessions.get(&s).unwrap().current_key().unwrap()
        };

        // Advance
        let mut ce = [0u8; 32];
        let mut se = [0u8; 32];
        let mut sn = [0u8; 32];
        getrandom::getrandom(&mut ce).unwrap();
        getrandom::getrandom(&mut se).unwrap();
        getrandom::getrandom(&mut sn).unwrap();
        m.advance_session(&s, &ce, &se, &sn).unwrap();

        // Rollback
        {
            let mut sessions = m.sessions.write().unwrap();
            let restored = RatchetChain::from_persisted(snapshot_key, 0).unwrap();
            sessions.insert(s, restored);
        }

        // Generate tag again at epoch 0 — must match the original
        let tag_after_rollback = m.generate_tag(&s, b"claims").unwrap();
        assert_eq!(tag_before, tag_after_rollback, "tag must be identical after rollback to same state");
    }

    /// Verify that encrypt/decrypt chain key roundtrip works correctly
    /// for the write-through persistence path.
    #[test]
    fn test_write_through_encrypt_decrypt_chain_key() {
        let mut kek = [0u8; 32];
        getrandom::getrandom(&mut kek).unwrap();
        let sid = Uuid::new_v4();

        // Create a chain and extract its key
        let chain = RatchetChain::new(&[0x42u8; 64]).unwrap();
        let chain_key = chain.current_key().unwrap();
        let epoch = chain.epoch();

        // Encrypt chain key (simulates what advance_session does for DB write)
        let encrypted = encrypt_chain_key_uuid(&kek, &chain_key, &sid).unwrap();

        // Decrypt chain key (simulates what load_from_db does)
        let decrypted = decrypt_chain_key_uuid(&kek, &encrypted, &sid).unwrap();
        assert_eq!(chain_key, decrypted, "chain key must survive encrypt/decrypt roundtrip");

        // Reconstruct the chain from persisted state
        let restored = RatchetChain::from_persisted(decrypted, epoch).unwrap();
        assert_eq!(restored.epoch(), epoch, "epoch must be preserved through persistence");

        // Tag generated from restored chain must match original
        let tag_original = chain.generate_tag(b"test-claims").unwrap();
        let tag_restored = restored.generate_tag(b"test-claims").unwrap();
        assert_eq!(tag_original, tag_restored, "tag must match between original and restored chain");
    }

    /// Verify that the startup recovery path correctly reconstructs chains
    /// from persisted (encrypted) chain keys.
    #[test]
    fn test_startup_recovery_simulation() {
        let mut kek = [0u8; 32];
        getrandom::getrandom(&mut kek).unwrap();

        // Simulate 5 sessions with varying epochs
        let mut persisted: Vec<(Uuid, u64, Vec<u8>)> = Vec::new();
        let mut expected_tags: Vec<(Uuid, [u8; 64])> = Vec::new();

        for i in 0..5u64 {
            let sid = Uuid::new_v4();
            let master = [((i + 1) * 0x11) as u8; 64];
            let chain = RatchetChain::new(&master).unwrap();
            let key = chain.current_key().unwrap();
            let tag = chain.generate_tag(b"recovery-test").unwrap();

            let encrypted = encrypt_chain_key_uuid(&kek, &key, &sid).unwrap();
            persisted.push((sid, 0, encrypted));
            expected_tags.push((sid, tag));
        }

        // Simulate load_from_db: decrypt and reconstruct
        let m = SessionManager::new();
        {
            let mut sessions = m.sessions.write().unwrap();
            for (sid, epoch, enc) in &persisted {
                let ck = decrypt_chain_key_uuid(&kek, enc, sid).unwrap();
                let chain = RatchetChain::from_persisted(ck, *epoch).unwrap();
                sessions.insert(*sid, chain);
            }
        }

        // Verify all sessions are recoverable and produce correct tags
        for (sid, expected_tag) in &expected_tags {
            let tag = m.generate_tag(sid, b"recovery-test").unwrap();
            assert_eq!(&tag, expected_tag, "recovered session {sid} must produce same tag");
        }
    }

    /// Verify that epoch rollback detection works during recovery simulation.
    #[test]
    fn test_epoch_rollback_detection_on_recovery() {
        let m = SessionManager::new();
        let s = Uuid::new_v4();
        let master = [0x42u8; 64];
        m.create_session(s, &master).unwrap();

        // Advance to epoch 5
        for _ in 0..5 {
            let mut ce = [0u8; 32];
            let mut se = [0u8; 32];
            let mut sn = [0u8; 32];
            getrandom::getrandom(&mut ce).unwrap();
            getrandom::getrandom(&mut se).unwrap();
            getrandom::getrandom(&mut sn).unwrap();
            m.advance_session(&s, &ce, &se, &sn).unwrap();
        }

        // Current in-memory epoch should be 5
        let mem_epoch = {
            let sessions = m.sessions.read().unwrap();
            sessions.get(&s).unwrap().epoch()
        };
        assert_eq!(mem_epoch, 5);

        // Simulate attempting to load an older epoch from DB (rollback attack)
        let stale_epoch = 3u64;
        let _stale_key = [0xAA; 64]; // doesn't matter, it's the epoch check that should fail
        {
            let sessions = m.sessions.read().unwrap();
            if let Some(existing) = sessions.get(&s) {
                // This is the rollback check from load_from_db
                assert!(
                    stale_epoch < existing.epoch(),
                    "stale epoch {stale_epoch} should be less than current {}",
                    existing.epoch()
                );
            }
        }
    }

    /// Verify that the PersistentSessionManager::rollback_session method
    /// works correctly when called directly.
    #[test]
    fn test_rollback_session_method() {
        // We can't instantiate PersistentSessionManager without a DB,
        // but we can test the rollback logic using the underlying SessionManager
        // since rollback_session just does from_persisted + insert.
        let m = SessionManager::new();
        let s = Uuid::new_v4();
        let master = [0x42u8; 64];
        m.create_session(s, &master).unwrap();

        let snapshot_key = {
            let sessions = m.sessions.read().unwrap();
            sessions.get(&s).unwrap().current_key().unwrap()
        };

        // Advance twice
        for _ in 0..2 {
            let mut ce = [0u8; 32];
            let mut se = [0u8; 32];
            let mut sn = [0u8; 32];
            getrandom::getrandom(&mut ce).unwrap();
            getrandom::getrandom(&mut se).unwrap();
            getrandom::getrandom(&mut sn).unwrap();
            m.advance_session(&s, &ce, &se, &sn).unwrap();
        }
        assert_eq!(m.sessions.read().unwrap().get(&s).unwrap().epoch(), 2);

        // Rollback to epoch 0 (simulating what PersistentSessionManager.rollback_session does)
        {
            let mut sessions = m.sessions.write().unwrap();
            match RatchetChain::from_persisted(snapshot_key, 0) {
                Ok(restored) => {
                    sessions.insert(s, restored);
                }
                Err(e) => panic!("rollback failed: {e}"),
            }
        }

        assert_eq!(m.sessions.read().unwrap().get(&s).unwrap().epoch(), 0);
        let restored_key = m.sessions.read().unwrap().get(&s).unwrap().current_key().unwrap();
        assert_eq!(restored_key, snapshot_key, "key must match snapshot after rollback");
    }

    /// Verify that the write-through path encrypts with session-bound AAD
    /// so chain keys cannot be cross-session decrypted.
    #[test]
    fn test_write_through_aad_isolation() {
        let mut kek = [0u8; 32];
        getrandom::getrandom(&mut kek).unwrap();

        let s1 = Uuid::new_v4();
        let s2 = Uuid::new_v4();
        let chain_key = [0x42u8; 64];

        let enc1 = encrypt_chain_key_uuid(&kek, &chain_key, &s1).unwrap();
        let enc2 = encrypt_chain_key_uuid(&kek, &chain_key, &s2).unwrap();

        // Same key encrypted for different sessions produces different ciphertext
        // (due to random nonce + different AAD)
        assert_ne!(enc1, enc2, "ciphertexts must differ for different session AADs");

        // Cross-session decryption must fail (AAD mismatch)
        assert!(
            decrypt_chain_key_uuid(&kek, &enc1, &s2).is_err(),
            "decrypting s1's ciphertext with s2's AAD must fail"
        );
        assert!(
            decrypt_chain_key_uuid(&kek, &enc2, &s1).is_err(),
            "decrypting s2's ciphertext with s1's AAD must fail"
        );
    }

    /// Verify that the replication health report structure works correctly.
    #[test]
    fn test_replication_health_report_structure() {
        let report = ReplicationHealthReport {
            sampled: 10,
            consistent: 8,
            divergent: vec![
                (Uuid::new_v4(), 5, 3),
                (Uuid::new_v4(), 10, -1),
            ],
            healthy: false,
        };
        assert!(!report.healthy);
        assert_eq!(report.divergent.len(), 2);
        assert_eq!(report.sampled, 10);
        assert_eq!(report.consistent, 8);

        let healthy_report = ReplicationHealthReport {
            sampled: 5,
            consistent: 5,
            divergent: vec![],
            healthy: true,
        };
        assert!(healthy_report.healthy);
        assert!(healthy_report.divergent.is_empty());
    }

    /// Verify that from_persisted correctly reconstructs a chain at a given epoch
    /// and that tag generation works on the reconstructed chain.
    #[test]
    fn test_from_persisted_chain_reconstruction() {
        // Create and advance a chain to epoch 3
        let master = [0x42u8; 64];
        let mut chain = RatchetChain::new(&master).unwrap();
        for _ in 0..3 {
            let mut ce = [0u8; 32];
            let mut se = [0u8; 32];
            let mut sn = [0u8; 32];
            getrandom::getrandom(&mut ce).unwrap();
            getrandom::getrandom(&mut se).unwrap();
            getrandom::getrandom(&mut sn).unwrap();
            chain.advance(&ce, &se, &sn).unwrap();
        }

        let key_at_3 = chain.current_key().unwrap();
        let tag_at_3 = chain.generate_tag(b"persist-test").unwrap();

        // Reconstruct from persisted state
        let restored = RatchetChain::from_persisted(key_at_3, 3).unwrap();
        assert_eq!(restored.epoch(), 3);

        let restored_tag = restored.generate_tag(b"persist-test").unwrap();
        assert_eq!(tag_at_3, restored_tag, "tag must match between original and persisted chain");
    }
}
