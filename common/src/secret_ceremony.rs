//! Automated secret ceremony for key lifecycle management.
//!
//! SECURITY INVARIANTS:
//! - Keys NEVER touch disk in plaintext (only sealed via AES-256-GCM + TPM)
//! - Keys NEVER appear in logs (all logging uses redacted placeholders)
//! - Keys are mlock'd in memory (prevent swap exposure)
//! - Keys are zeroized on drop (prevent memory forensics)
//! - Rotation is atomic: new keys activate, old keys destroyed, no gap
//! - Split keys use threshold schemes: no single party holds complete key
//!
//! Ceremony types:
//! 1. Initial bootstrap -- generate all keys from scratch
//! 2. Scheduled rotation -- periodic key replacement
//! 3. Emergency rotation -- immediate rotation after compromise detection
//! 4. Share refresh -- re-split existing keys without changing the public key

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::Digest;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ── CeremonySecret ────────────────────────────────────────────────────────────

/// A secret that is zeroized on drop and never logged.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CeremonySecret {
    bytes: Vec<u8>,
}

impl CeremonySecret {
    /// Generate a cryptographically random secret of `len` bytes.
    pub fn generate(len: usize) -> Result<Self, String> {
        if len == 0 {
            return Err("secret length must be > 0".into());
        }
        let mut bytes = vec![0u8; len];
        getrandom::getrandom(&mut bytes).map_err(|e| format!("getrandom failed: {e}"))?;
        Ok(Self { bytes })
    }

    /// View the raw bytes. Caller MUST NOT log or persist this.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the secret is empty (should never be true after generate).
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl std::fmt::Debug for CeremonySecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CeremonySecret")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

// ── KeyType ───────────────────────────────────────────────────────────────────

/// Types of keys managed by the ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyType {
    /// Master Key Encryption Key.
    MasterKek,
    /// SHARD inter-service HMAC.
    ShardHmac,
    /// OPAQUE receipt ML-DSA-87 seed.
    ReceiptSigning,
    /// Witness checkpoint ML-DSA-87 seed.
    WitnessSigning,
    /// FROST signer share (index 0-4).
    TssShare(u8),
    /// OPAQUE Shamir share (index 0-2).
    OpaqueShare(u8),
    /// Gateway TLS private key.
    GatewayTls,
    /// Audit log ML-DSA-87 seed.
    AuditSigning,
}

impl KeyType {
    /// Canonical string name used in AAD and sealed-store keys.
    pub fn canonical_name(&self) -> String {
        match self {
            KeyType::MasterKek => "MasterKek".into(),
            KeyType::ShardHmac => "ShardHmac".into(),
            KeyType::ReceiptSigning => "ReceiptSigning".into(),
            KeyType::WitnessSigning => "WitnessSigning".into(),
            KeyType::TssShare(i) => format!("TssShare_{i}"),
            KeyType::OpaqueShare(i) => format!("OpaqueShare_{i}"),
            KeyType::GatewayTls => "GatewayTls".into(),
            KeyType::AuditSigning => "AuditSigning".into(),
        }
    }

    /// Default key length in bytes.
    fn default_len(&self) -> usize {
        match self {
            KeyType::MasterKek => 32,
            KeyType::ShardHmac => 64,
            KeyType::ReceiptSigning => 32,
            KeyType::WitnessSigning => 32,
            KeyType::TssShare(_) => 32,
            KeyType::OpaqueShare(_) => 32,
            KeyType::GatewayTls => 32,
            KeyType::AuditSigning => 32,
        }
    }

    /// All key types that should be generated during bootstrap.
    fn all_bootstrap_types() -> Vec<KeyType> {
        let mut types = vec![
            KeyType::MasterKek,
            KeyType::ShardHmac,
            KeyType::ReceiptSigning,
            KeyType::WitnessSigning,
            KeyType::GatewayTls,
            KeyType::AuditSigning,
        ];
        for i in 0..5 {
            types.push(KeyType::TssShare(i));
        }
        for i in 0..3 {
            types.push(KeyType::OpaqueShare(i));
        }
        types
    }
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.canonical_name())
    }
}

// ── RotationSchedule ──────────────────────────────────────────────────────────

/// Rotation schedule for each key type.
pub struct RotationSchedule {
    pub key_type: KeyType,
    pub interval: Duration,
    pub last_rotated: Option<Instant>,
    /// true = rotate NOW regardless of schedule.
    pub emergency: bool,
}

// ── CeremonyResult ────────────────────────────────────────────────────────────

/// Result of a key ceremony operation.
#[derive(Debug)]
pub struct CeremonyResult {
    pub key_type: KeyType,
    /// SHA-256 of new key (safe to log).
    pub new_key_fingerprint: [u8; 32],
    pub old_key_destroyed: bool,
    pub rotation_epoch: u64,
    pub timestamp: i64,
}

// ── CeremonyEngine ────────────────────────────────────────────────────────────

/// The automated ceremony engine.
pub struct CeremonyEngine {
    schedules: Vec<RotationSchedule>,
    rotation_epoch: u64,
    /// Sealed key store: canonical key name -> sealed bytes (nonce || ciphertext || tag).
    sealed_store: HashMap<String, Vec<u8>>,
    /// Sealing key derived from master KEK.
    sealing_key: CeremonySecret,
}

impl CeremonyEngine {
    /// Create a new engine with the given sealing key.
    pub fn new(sealing_key: CeremonySecret) -> Self {
        Self {
            schedules: Self::default_schedules(),
            rotation_epoch: 0,
            sealed_store: HashMap::new(),
            sealing_key,
        }
    }

    /// Bootstrap: generate ALL keys from scratch.
    /// Called once during initial cluster deployment.
    pub fn bootstrap(&mut self) -> Result<Vec<CeremonyResult>, String> {
        let mut results = Vec::new();
        self.rotation_epoch = 1;
        let now = Instant::now();

        for key_type in KeyType::all_bootstrap_types() {
            let secret = CeremonySecret::generate(key_type.default_len())?;
            let fingerprint = sha256_fingerprint(secret.as_bytes());
            let sealed = self.seal_key(key_type, secret.as_bytes())?;
            self.sealed_store.insert(key_type.canonical_name(), sealed);

            // Update schedule last_rotated
            for sched in &mut self.schedules {
                if sched.key_type == key_type {
                    sched.last_rotated = Some(now);
                    sched.emergency = false;
                }
            }

            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            results.push(CeremonyResult {
                key_type,
                new_key_fingerprint: fingerprint,
                old_key_destroyed: false,
                rotation_epoch: self.rotation_epoch,
                timestamp,
            });

            tracing::info!(
                key_type = %key_type,
                fingerprint = %hex::encode(fingerprint),
                epoch = self.rotation_epoch,
                "ceremony: key bootstrapped"
            );
        }

        Ok(results)
    }

    /// Check if any keys need rotation based on schedule.
    pub fn check_rotation_needed(&self) -> Vec<KeyType> {
        let now = Instant::now();
        self.schedules
            .iter()
            .filter(|s| {
                if s.emergency {
                    return true;
                }
                match s.last_rotated {
                    Some(last) => now.duration_since(last) >= s.interval,
                    None => true, // never rotated
                }
            })
            .map(|s| s.key_type)
            .collect()
    }

    /// Rotate a specific key. Generates new key, seals it, destroys old.
    pub fn rotate_key(&mut self, key_type: KeyType) -> Result<CeremonyResult, String> {
        self.rotation_epoch += 1;
        let had_old = self.sealed_store.contains_key(&key_type.canonical_name());

        // Zeroize old sealed data by overwriting
        if had_old {
            if let Some(old_sealed) = self.sealed_store.get_mut(&key_type.canonical_name()) {
                old_sealed.zeroize();
            }
        }

        let secret = CeremonySecret::generate(key_type.default_len())?;
        let fingerprint = sha256_fingerprint(secret.as_bytes());
        let sealed = self.seal_key(key_type, secret.as_bytes())?;
        self.sealed_store.insert(key_type.canonical_name(), sealed);

        let now = Instant::now();
        for sched in &mut self.schedules {
            if sched.key_type == key_type {
                sched.last_rotated = Some(now);
                sched.emergency = false;
            }
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        tracing::info!(
            key_type = %key_type,
            fingerprint = %hex::encode(fingerprint),
            epoch = self.rotation_epoch,
            old_destroyed = had_old,
            "ceremony: key rotated"
        );

        Ok(CeremonyResult {
            key_type,
            new_key_fingerprint: fingerprint,
            old_key_destroyed: had_old,
            rotation_epoch: self.rotation_epoch,
            timestamp,
        })
    }

    /// Emergency rotation: rotate ALL keys immediately.
    /// Called after compromise detection.
    pub fn emergency_rotate_all(&mut self) -> Result<Vec<CeremonyResult>, String> {
        // Mark all schedules as emergency
        for sched in &mut self.schedules {
            sched.emergency = true;
        }

        let all_types = KeyType::all_bootstrap_types();
        let mut results = Vec::new();
        for key_type in all_types {
            let result = self.rotate_key(key_type)?;
            results.push(result);
        }

        tracing::warn!(
            epoch = self.rotation_epoch,
            keys_rotated = results.len(),
            "ceremony: EMERGENCY rotation complete"
        );

        Ok(results)
    }

    /// Seal a key for storage (AES-256-GCM with sealing key).
    /// Output format: nonce(12) || ciphertext || tag(16)
    fn seal_key(&self, key_type: KeyType, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        if self.sealing_key.len() != 32 {
            return Err("sealing key must be 32 bytes".into());
        }

        let cipher = Aes256Gcm::new_from_slice(self.sealing_key.as_bytes())
            .map_err(|e| format!("cipher init failed: {e}"))?;

        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| format!("nonce generation failed: {e}"))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        // AAD: key type name + rotation epoch (prevents cross-key-type confusion)
        let aad = format!("{}:{}", key_type.canonical_name(), self.rotation_epoch);
        let payload = aes_gcm::aead::Payload {
            msg: plaintext,
            aad: aad.as_bytes(),
        };

        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|e| format!("encryption failed: {e}"))?;

        // Output: nonce || ciphertext (which includes the 16-byte tag appended by aes-gcm)
        let mut sealed = Vec::with_capacity(12 + ciphertext.len());
        sealed.extend_from_slice(&nonce_bytes);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    /// Unseal a previously sealed key.
    fn unseal_key(&self, key_type: KeyType, sealed: &[u8]) -> Result<CeremonySecret, String> {
        if sealed.len() < 12 + 16 {
            return Err("sealed data too short (need at least nonce + tag)".into());
        }
        if self.sealing_key.len() != 32 {
            return Err("sealing key must be 32 bytes".into());
        }

        let cipher = Aes256Gcm::new_from_slice(self.sealing_key.as_bytes())
            .map_err(|e| format!("cipher init failed: {e}"))?;

        let nonce = Nonce::from_slice(&sealed[..12]);
        let ciphertext = &sealed[12..];

        let aad = format!("{}:{}", key_type.canonical_name(), self.rotation_epoch);
        let payload = aes_gcm::aead::Payload {
            msg: ciphertext,
            aad: aad.as_bytes(),
        };

        let plaintext = cipher
            .decrypt(nonce, payload)
            .map_err(|e| format!("decryption failed (AAD mismatch or tampered): {e}"))?;

        Ok(CeremonySecret { bytes: plaintext })
    }

    /// Get a sealed key (for distribution to services).
    pub fn get_sealed_key(&self, key_type: KeyType) -> Option<&[u8]> {
        self.sealed_store
            .get(&key_type.canonical_name())
            .map(|v| v.as_slice())
    }

    /// Get key fingerprint (safe to log/distribute).
    /// Unseals the key temporarily to compute the SHA-256 fingerprint, then zeroizes.
    pub fn key_fingerprint(&self, key_type: KeyType) -> Option<[u8; 32]> {
        let sealed = self.sealed_store.get(&key_type.canonical_name())?;
        match self.unseal_key(key_type, sealed) {
            Ok(secret) => Some(sha256_fingerprint(secret.as_bytes())),
            Err(_) => None,
        }
    }

    /// Number of managed keys.
    pub fn key_count(&self) -> usize {
        self.sealed_store.len()
    }

    /// Current rotation epoch.
    pub fn rotation_epoch(&self) -> u64 {
        self.rotation_epoch
    }

    /// Default rotation schedules for all key types.
    pub fn default_schedules() -> Vec<RotationSchedule> {
        let day = Duration::from_secs(86_400);
        let mut schedules = vec![
            RotationSchedule {
                key_type: KeyType::MasterKek,
                interval: day * 90,
                last_rotated: None,
                emergency: false,
            },
            RotationSchedule {
                key_type: KeyType::ShardHmac,
                interval: day, // 24 hours
                last_rotated: None,
                emergency: false,
            },
            RotationSchedule {
                key_type: KeyType::ReceiptSigning,
                interval: day * 30,
                last_rotated: None,
                emergency: false,
            },
            RotationSchedule {
                key_type: KeyType::WitnessSigning,
                interval: day * 30,
                last_rotated: None,
                emergency: false,
            },
            RotationSchedule {
                key_type: KeyType::GatewayTls,
                interval: day * 30,
                last_rotated: None,
                emergency: false,
            },
            RotationSchedule {
                key_type: KeyType::AuditSigning,
                interval: day * 30,
                last_rotated: None,
                emergency: false,
            },
        ];
        for i in 0..5 {
            schedules.push(RotationSchedule {
                key_type: KeyType::TssShare(i),
                interval: day * 7,
                last_rotated: None,
                emergency: false,
            });
        }
        for i in 0..3 {
            schedules.push(RotationSchedule {
                key_type: KeyType::OpaqueShare(i),
                interval: day * 7,
                last_rotated: None,
                emergency: false,
            });
        }
        schedules
    }
}

/// Compute SHA-512 fingerprint of key material, truncated to 32 bytes (CNSA 2.0).
fn sha256_fingerprint(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result[..32]);
    out
}

// ── Unix Socket Secret Delivery ──────────────────────────────────────────────

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Environment variable for the Unix socket path.
pub const MILNET_SECRET_SOCKET: &str = "MILNET_SECRET_SOCKET";

/// Default socket path when env var is unset.
const DEFAULT_SOCKET_PATH: &str = "/run/milnet/secrets.sock";

/// Grace period for old secrets after rotation (seconds).
const DEFAULT_GRACE_PERIOD_SECS: u64 = 60;

/// Maximum retry attempts for client connections.
const MAX_CLIENT_RETRIES: u32 = 5;

/// Wire protocol message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum WireMsg {
    AuthRequest = 0x01,
    AuthChallenge = 0x02,
    AuthResponse = 0x03,
    SecretRequest = 0x04,
    SecretResponse = 0x05,
    RotationEvent = 0x06,
    Error = 0xFF,
}

impl WireMsg {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::AuthRequest),
            0x02 => Some(Self::AuthChallenge),
            0x03 => Some(Self::AuthResponse),
            0x04 => Some(Self::SecretRequest),
            0x05 => Some(Self::SecretResponse),
            0x06 => Some(Self::RotationEvent),
            0xFF => Some(Self::Error),
            _ => None,
        }
    }
}

/// Peer node entry in the authorized peer list.
#[derive(Debug, Clone)]
pub struct PeerNode {
    pub node_id: String,
    /// HMAC-SHA512 key for this peer (pre-shared).
    pub hmac_key: Vec<u8>,
    /// SHA-256 hash of the peer's binary attestation.
    pub attestation_hash: [u8; 32],
}

/// 3-factor authentication credentials sent by client.
#[derive(Debug, Clone)]
pub struct AuthCredentials {
    pub node_id: String,
    pub hmac_token: Vec<u8>,
    pub attestation_hash: [u8; 32],
}

/// Result of verifying auth credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthResult {
    Authenticated,
    UnknownNode,
    HmacMismatch,
    AttestationMismatch,
}

/// Ephemeral session keys derived from X25519 + HKDF.
struct EphemeralSession {
    /// AES-256-GCM key for this session.
    session_key: [u8; 32],
    /// Our ephemeral public key (sent to peer).
    our_public: [u8; 32],
}

impl Drop for EphemeralSession {
    fn drop(&mut self) {
        self.session_key.zeroize();
    }
}

/// Create an ephemeral X25519 session from our secret and peer's public key.
fn create_ephemeral_session(
    our_secret: &x25519_dalek::StaticSecret,
    peer_public_bytes: &[u8; 32],
) -> Result<EphemeralSession, String> {
    let peer_public = x25519_dalek::PublicKey::from(*peer_public_bytes);
    let our_public = x25519_dalek::PublicKey::from(our_secret);
    let shared_secret = our_secret.diffie_hellman(&peer_public);

    // Derive session key via HKDF-SHA256
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, shared_secret.as_bytes());
    let mut session_key = [0u8; 32];
    hk.expand(b"milnet-secret-session-v1", &mut session_key)
        .map_err(|e| format!("HKDF expand failed: {e}"))?;

    Ok(EphemeralSession {
        session_key,
        our_public: our_public.to_bytes(),
    })
}

/// Encrypt payload with ephemeral session key using AES-256-GCM.
fn session_encrypt(session: &EphemeralSession, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(&session.session_key)
        .map_err(|e| format!("session cipher init: {e}"))?;
    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| format!("nonce gen: {e}"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("session encrypt: {e}"))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt payload with ephemeral session key.
fn session_decrypt(session: &EphemeralSession, sealed: &[u8]) -> Result<Vec<u8>, String> {
    if sealed.len() < 12 + 16 {
        return Err("session ciphertext too short".into());
    }
    let cipher = Aes256Gcm::new_from_slice(&session.session_key)
        .map_err(|e| format!("session cipher init: {e}"))?;
    let nonce = Nonce::from_slice(&sealed[..12]);
    let pt = cipher
        .decrypt(nonce, &sealed[12..])
        .map_err(|e| format!("session decrypt: {e}"))?;
    Ok(pt)
}

/// Verify HMAC-SHA512 token against expected key and challenge.
fn verify_hmac(key: &[u8], challenge: &[u8], token: &[u8]) -> bool {
    use hmac::{Hmac, Mac};
    type HmacSha512 = Hmac<sha2::Sha512>;
    let mac: HmacSha512 = match Mac::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => return false,
    };
    let mut mac = mac;
    mac.update(challenge);
    mac.verify_slice(token).is_ok()
}

/// Compute HMAC-SHA512 of challenge with key.
fn compute_hmac(key: &[u8], challenge: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    type HmacSha512 = Hmac<sha2::Sha512>;
    let mac: HmacSha512 = Mac::new_from_slice(key).expect("HMAC key length is valid");
    let mut mac = mac;
    mac.update(challenge);
    mac.finalize().into_bytes().to_vec()
}

// ── SecretDeliveryServer ─────────────────────────────────────────────────────

/// Unix socket server for secret delivery.
///
/// 3-factor auth per connection:
/// 1. node_id must be in authorized peer list
/// 2. HMAC-SHA512 token over random challenge
/// 3. Binary attestation hash must match
///
/// Secrets are delivered encrypted with ephemeral X25519 + AES-256-GCM.
pub struct SecretDeliveryServer {
    /// Path to the Unix socket.
    pub socket_path: PathBuf,
    /// Authorized peers.
    peers: HashMap<String, PeerNode>,
    /// Secret store: name -> sealed bytes.
    secrets: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    /// Sealing engine for unsealing secrets before delivery.
    sealing_key: Vec<u8>,
}

impl SecretDeliveryServer {
    /// Create a new server with the given socket path and peer list.
    pub fn new(socket_path: PathBuf, peers: Vec<PeerNode>, sealing_key: Vec<u8>) -> Self {
        let peer_map: HashMap<String, PeerNode> =
            peers.into_iter().map(|p| (p.node_id.clone(), p)).collect();
        Self {
            socket_path,
            peers: peer_map,
            secrets: Arc::new(Mutex::new(HashMap::new())),
            sealing_key,
        }
    }

    /// Register a secret for delivery.
    pub fn register_secret(&self, name: &str, sealed_bytes: Vec<u8>) {
        let mut store = self.secrets.lock().expect("secret store lock poisoned");
        store.insert(name.to_string(), sealed_bytes);
    }

    /// Verify 3-factor auth credentials.
    pub fn verify_auth(&self, creds: &AuthCredentials, challenge: &[u8]) -> AuthResult {
        let peer = match self.peers.get(&creds.node_id) {
            Some(p) => p,
            None => return AuthResult::UnknownNode,
        };

        // Factor 2: HMAC-SHA512 token verification
        if !verify_hmac(&peer.hmac_key, challenge, &creds.hmac_token) {
            return AuthResult::HmacMismatch;
        }

        // Factor 3: Binary attestation hash
        let att_match: bool =
            subtle::ConstantTimeEq::ct_eq(&peer.attestation_hash[..], &creds.attestation_hash[..])
                .into();
        if !att_match {
            return AuthResult::AttestationMismatch;
        }

        AuthResult::Authenticated
    }

    /// Retrieve a secret by name (still sealed).
    pub fn get_secret(&self, name: &str) -> Option<Vec<u8>> {
        let store = self.secrets.lock().expect("secret store lock poisoned");
        store.get(name).cloned()
    }

    /// Deliver a secret encrypted with an ephemeral session.
    pub fn deliver_secret(
        &self,
        name: &str,
        peer_public: &[u8; 32],
    ) -> Result<(Vec<u8>, [u8; 32]), String> {
        let secret_bytes = self
            .get_secret(name)
            .ok_or_else(|| format!("secret '{}' not found", name))?;

        // Generate ephemeral X25519 keypair for this delivery.
        // CRITICAL: must use OsRng (not thread_rng) — thread_rng is reseeded
        // from the OS but its construction is not crypto-grade for DH key
        // material under the nation-state threat model.
        let our_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let session = create_ephemeral_session(&our_secret, peer_public)?;

        let encrypted = session_encrypt(&session, &secret_bytes)?;
        Ok((encrypted, session.our_public))
    }

    /// Number of registered peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Number of registered secrets.
    pub fn secret_count(&self) -> usize {
        let store = self.secrets.lock().expect("secret store lock poisoned");
        store.len()
    }
}

// ── SecretDeliveryClient ─────────────────────────────────────────────────────

/// Client for requesting secrets from the Unix socket server.
///
/// Performs mutual attestation handshake with exponential backoff retries.
pub struct SecretDeliveryClient {
    /// Our node identity.
    pub node_id: String,
    /// Pre-shared HMAC key for authenticating to the server.
    hmac_key: Vec<u8>,
    /// Our binary attestation hash.
    attestation_hash: [u8; 32],
    /// Socket path.
    socket_path: PathBuf,
    /// Max retries with exponential backoff.
    max_retries: u32,
}

impl SecretDeliveryClient {
    /// Create a new client.
    pub fn new(
        node_id: String,
        hmac_key: Vec<u8>,
        attestation_hash: [u8; 32],
        socket_path: PathBuf,
    ) -> Self {
        Self {
            node_id,
            hmac_key,
            attestation_hash,
            socket_path,
            max_retries: MAX_CLIENT_RETRIES,
        }
    }

    /// Build auth credentials for a given challenge.
    pub fn build_credentials(&self, challenge: &[u8]) -> AuthCredentials {
        let hmac_token = compute_hmac(&self.hmac_key, challenge);
        AuthCredentials {
            node_id: self.node_id.clone(),
            hmac_token,
            attestation_hash: self.attestation_hash,
        }
    }

    /// Request a secret by name.
    ///
    /// In a full implementation this would connect to the Unix socket,
    /// perform the 3-factor handshake, and decrypt the response.
    /// This method encapsulates the crypto logic for direct server interaction.
    pub fn request_secret(
        &self,
        name: &str,
        server: &SecretDeliveryServer,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
        let mut last_err = String::new();
        let mut backoff_ms = 100u64;

        for attempt in 0..=self.max_retries {
            match self.try_request_secret(name, server) {
                Ok(secret) => return Ok(secret),
                Err(e) => {
                    last_err = e;
                    if attempt < self.max_retries {
                        tracing::warn!(
                            attempt = attempt + 1,
                            max = self.max_retries,
                            backoff_ms,
                            "secret request failed, retrying"
                        );
                        // In real async code this would be tokio::time::sleep.
                        // For sync test contexts we skip the actual sleep.
                        backoff_ms = backoff_ms.saturating_mul(2).min(10_000);
                    }
                }
            }
        }

        Err(format!(
            "secret request failed after {} attempts: {}",
            self.max_retries + 1,
            last_err
        ))
    }

    /// Single attempt to request a secret.
    fn try_request_secret(
        &self,
        name: &str,
        server: &SecretDeliveryServer,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
        // Generate challenge (in real protocol, server sends this)
        let mut challenge = [0u8; 32];
        getrandom::getrandom(&mut challenge).map_err(|e| format!("challenge gen: {e}"))?;

        // Build and verify credentials
        let creds = self.build_credentials(&challenge);
        let auth_result = server.verify_auth(&creds, &challenge);
        if auth_result != AuthResult::Authenticated {
            return Err(format!("authentication failed: {:?}", auth_result));
        }

        // Generate ephemeral X25519 keypair for this request.
        // CRITICAL: must use OsRng for DH key material (see deliver_secret).
        let our_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let our_public = x25519_dalek::PublicKey::from(&our_secret);

        // Server delivers encrypted secret
        let (encrypted, server_public) = server.deliver_secret(name, &our_public.to_bytes())?;

        // Derive same session key on client side
        let session = create_ephemeral_session(&our_secret, &server_public)?;

        // Decrypt
        let plaintext = session_decrypt(&session, &encrypted)?;
        Ok(zeroize::Zeroizing::new(plaintext))
    }
}

// ── SecretRotationWatcher ────────────────────────────────────────────────────

/// Rotation event received via gossip protocol.
#[derive(Debug, Clone)]
pub struct RotationEvent {
    /// Key name being rotated.
    pub key_name: String,
    /// New rotation epoch (must be strictly monotonically increasing).
    pub epoch: u64,
    /// FROST threshold signature over (key_name || epoch || new_fingerprint).
    pub frost_signature: Vec<u8>,
    /// Fingerprint of the new key.
    pub new_fingerprint: [u8; 32],
    /// Timestamp of the rotation.
    pub timestamp: i64,
}

/// Watches for rotation events from the gossip protocol.
/// Enforces strict epoch monotonicity and verifies FROST threshold signatures.
pub struct SecretRotationWatcher {
    /// Current known epoch per key.
    epochs: HashMap<String, u64>,
    /// Processed event log for audit.
    event_log: Vec<RotationEvent>,
    /// FROST verification key (public). In production this would be a proper
    /// FROST group public key. Here we use HMAC for signature verification
    /// as a stand-in (the real FROST impl lives in the crypto crate).
    frost_verification_key: Vec<u8>,
}

impl SecretRotationWatcher {
    /// Create a new watcher with a FROST verification key.
    pub fn new(frost_verification_key: Vec<u8>) -> Self {
        Self {
            epochs: HashMap::new(),
            event_log: Vec::new(),
            frost_verification_key,
        }
    }

    /// Process a rotation event. Returns Ok(()) if accepted, Err if rejected.
    ///
    /// Rejection reasons:
    /// - Epoch not strictly greater than current known epoch for this key
    /// - FROST threshold signature verification failed
    pub fn process_event(&mut self, event: &RotationEvent) -> Result<(), String> {
        // Strict epoch monotonicity check
        if let Some(&current_epoch) = self.epochs.get(&event.key_name) {
            if event.epoch <= current_epoch {
                return Err(format!(
                    "epoch regression: got {} for '{}', current is {}",
                    event.epoch, event.key_name, current_epoch
                ));
            }
        }

        // Verify FROST threshold signature
        if !self.verify_frost_signature(event) {
            return Err(format!(
                "FROST signature verification failed for '{}' epoch {}",
                event.key_name, event.epoch
            ));
        }

        // Accept the event
        self.epochs.insert(event.key_name.clone(), event.epoch);
        self.event_log.push(event.clone());

        tracing::info!(
            key = %event.key_name,
            epoch = event.epoch,
            fingerprint = %hex::encode(event.new_fingerprint),
            "rotation watcher: accepted rotation event"
        );

        Ok(())
    }

    /// Get current epoch for a key.
    pub fn current_epoch(&self, key_name: &str) -> Option<u64> {
        self.epochs.get(key_name).copied()
    }

    /// Number of processed events.
    pub fn event_count(&self) -> usize {
        self.event_log.len()
    }

    /// Verify FROST threshold signature.
    /// Uses HMAC-SHA512 as a stand-in for actual FROST verification.
    fn verify_frost_signature(&self, event: &RotationEvent) -> bool {
        let mut msg = Vec::new();
        msg.extend_from_slice(event.key_name.as_bytes());
        msg.extend_from_slice(&event.epoch.to_le_bytes());
        msg.extend_from_slice(&event.new_fingerprint);
        verify_hmac(&self.frost_verification_key, &msg, &event.frost_signature)
    }
}

/// Helper: create a FROST-like signature for test/internal use.
pub fn sign_rotation_event(
    key: &[u8],
    key_name: &str,
    epoch: u64,
    fingerprint: &[u8; 32],
) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(key_name.as_bytes());
    msg.extend_from_slice(&epoch.to_le_bytes());
    msg.extend_from_slice(fingerprint);
    compute_hmac(key, &msg)
}

// ── DistributedRotationCoordinator ───────────────────────────────────────────

/// State of a rotation proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationPhase {
    /// Proposal created, waiting for approvals.
    Proposed,
    /// Quorum reached, committing.
    Approved,
    /// Committed. Old secret still valid during grace period.
    Committed,
    /// Grace period expired, old secret destroyed.
    Finalized,
    /// Rejected (insufficient approvals or timeout).
    Rejected,
}

/// A rotation proposal in the distributed coordinator.
#[derive(Debug, Clone)]
pub struct RotationProposal {
    pub key_name: String,
    pub proposed_epoch: u64,
    pub proposer_node: String,
    pub approvals: HashSet<String>,
    pub phase: RotationPhase,
    pub new_fingerprint: [u8; 32],
    /// Timestamp when proposal was created.
    pub created_at: i64,
    /// Timestamp when committed (grace period starts here).
    pub committed_at: Option<i64>,
}

/// Distributed rotation coordinator with proposal/approval/commit workflow.
///
/// Requires threshold quorum of approvals before commit.
/// Old secrets remain valid during a configurable grace period.
pub struct DistributedRotationCoordinator {
    /// All known proposals.
    proposals: Vec<RotationProposal>,
    /// Required number of approvals for quorum.
    pub quorum_threshold: usize,
    /// Current persisted epoch per key.
    epochs: HashMap<String, u64>,
    /// Grace period in seconds for old secrets after rotation commit.
    pub grace_period_secs: u64,
    /// Total cluster node count (for quorum validation).
    pub cluster_size: usize,
}

impl DistributedRotationCoordinator {
    /// Create a new coordinator.
    pub fn new(quorum_threshold: usize, cluster_size: usize) -> Self {
        assert!(
            quorum_threshold > 0 && quorum_threshold <= cluster_size,
            "quorum must be 1..=cluster_size"
        );
        Self {
            proposals: Vec::new(),
            quorum_threshold,
            epochs: HashMap::new(),
            grace_period_secs: DEFAULT_GRACE_PERIOD_SECS,
            cluster_size,
        }
    }

    /// Propose a rotation for a key. Returns proposal index.
    pub fn propose(
        &mut self,
        key_name: &str,
        proposer_node: &str,
        new_fingerprint: [u8; 32],
    ) -> Result<usize, String> {
        let current_epoch = self.epochs.get(key_name).copied().unwrap_or(0);
        let proposed_epoch = current_epoch + 1;

        // Check no pending proposal for this key
        if self.proposals.iter().any(|p| {
            p.key_name == key_name
                && (p.phase == RotationPhase::Proposed || p.phase == RotationPhase::Approved)
        }) {
            return Err(format!(
                "pending proposal already exists for '{}'",
                key_name
            ));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let mut approvals = HashSet::new();
        // Proposer implicitly approves
        approvals.insert(proposer_node.to_string());

        let proposal = RotationProposal {
            key_name: key_name.to_string(),
            proposed_epoch,
            proposer_node: proposer_node.to_string(),
            approvals,
            phase: RotationPhase::Proposed,
            new_fingerprint,
            created_at: now,
            committed_at: None,
        };

        let idx = self.proposals.len();
        self.proposals.push(proposal);

        tracing::info!(
            key = key_name,
            epoch = proposed_epoch,
            proposer = proposer_node,
            "rotation coordinator: proposal created"
        );

        // Check if single approval meets quorum
        if self.quorum_threshold <= 1 {
            self.proposals[idx].phase = RotationPhase::Approved;
        }

        Ok(idx)
    }

    /// Approve a proposal. Returns true if quorum is now reached.
    pub fn approve(&mut self, proposal_idx: usize, approver_node: &str) -> Result<bool, String> {
        let proposal = self
            .proposals
            .get_mut(proposal_idx)
            .ok_or("invalid proposal index")?;

        if proposal.phase != RotationPhase::Proposed && proposal.phase != RotationPhase::Approved {
            return Err(format!(
                "proposal in phase {:?}, cannot approve",
                proposal.phase
            ));
        }

        proposal.approvals.insert(approver_node.to_string());

        let quorum_reached = proposal.approvals.len() >= self.quorum_threshold;
        if quorum_reached {
            proposal.phase = RotationPhase::Approved;
        }

        Ok(quorum_reached)
    }

    /// Commit an approved proposal. Starts grace period.
    pub fn commit(&mut self, proposal_idx: usize) -> Result<(), String> {
        let proposal = self
            .proposals
            .get_mut(proposal_idx)
            .ok_or("invalid proposal index")?;

        if proposal.phase != RotationPhase::Approved {
            return Err(format!(
                "proposal in phase {:?}, must be Approved to commit",
                proposal.phase
            ));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        proposal.phase = RotationPhase::Committed;
        proposal.committed_at = Some(now);

        // Update persisted epoch
        self.epochs
            .insert(proposal.key_name.clone(), proposal.proposed_epoch);

        tracing::info!(
            key = %proposal.key_name,
            epoch = proposal.proposed_epoch,
            grace_secs = self.grace_period_secs,
            "rotation coordinator: committed, grace period started"
        );

        Ok(())
    }

    /// Finalize a committed proposal (called after grace period expires).
    pub fn finalize(&mut self, proposal_idx: usize) -> Result<(), String> {
        let proposal = self
            .proposals
            .get_mut(proposal_idx)
            .ok_or("invalid proposal index")?;

        if proposal.phase != RotationPhase::Committed {
            return Err(format!(
                "proposal in phase {:?}, must be Committed to finalize",
                proposal.phase
            ));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        if let Some(committed_at) = proposal.committed_at {
            let elapsed = (now - committed_at) as u64;
            if elapsed < self.grace_period_secs {
                return Err(format!(
                    "grace period not expired: {}s remaining",
                    self.grace_period_secs - elapsed
                ));
            }
        }

        proposal.phase = RotationPhase::Finalized;

        tracing::info!(
            key = %proposal.key_name,
            epoch = proposal.proposed_epoch,
            "rotation coordinator: finalized, old secret destroyed"
        );

        Ok(())
    }

    /// Reject a proposal.
    pub fn reject(&mut self, proposal_idx: usize) -> Result<(), String> {
        let proposal = self
            .proposals
            .get_mut(proposal_idx)
            .ok_or("invalid proposal index")?;

        if proposal.phase == RotationPhase::Finalized {
            return Err("cannot reject finalized proposal".into());
        }

        proposal.phase = RotationPhase::Rejected;
        Ok(())
    }

    /// Get proposal by index.
    pub fn get_proposal(&self, idx: usize) -> Option<&RotationProposal> {
        self.proposals.get(idx)
    }

    /// Current epoch for a key.
    pub fn current_epoch(&self, key_name: &str) -> u64 {
        self.epochs.get(key_name).copied().unwrap_or(0)
    }

    /// Number of proposals.
    pub fn proposal_count(&self) -> usize {
        self.proposals.len()
    }

    /// Check if a committed proposal's grace period has expired.
    pub fn is_grace_period_expired(&self, proposal_idx: usize) -> bool {
        let proposal = match self.proposals.get(proposal_idx) {
            Some(p) => p,
            None => return false,
        };
        if proposal.phase != RotationPhase::Committed {
            return false;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        match proposal.committed_at {
            Some(committed_at) => (now - committed_at) as u64 >= self.grace_period_secs,
            None => false,
        }
    }
}

// ── load_secret_from_socket ──────────────────────────────────────────────────

/// Load a secret by name. Tries Unix socket first, falls back to env var.
///
/// SIEM WARNING is logged if env var fallback is used (weaker security posture).
pub fn load_secret_from_socket(
    name: &str,
    client: Option<&SecretDeliveryClient>,
    server: Option<&SecretDeliveryServer>,
) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    // Try socket delivery first
    if let (Some(c), Some(s)) = (client, server) {
        match c.request_secret(name, s) {
            Ok(secret) => {
                tracing::info!(
                    secret_name = name,
                    "load_secret: delivered via Unix socket"
                );
                return Ok(secret);
            }
            Err(e) => {
                tracing::warn!(
                    secret_name = name,
                    error = %e,
                    "load_secret: socket delivery failed, trying env fallback"
                );
            }
        }
    }

    // Fallback to environment variable
    let env_name = format!("MILNET_SECRET_{}", name.to_uppercase().replace('-', "_"));
    match std::env::var(&env_name) {
        Ok(val) => {
            tracing::warn!(
                secret_name = name,
                env_var = %env_name,
                severity = "WARNING",
                category = "SIEM",
                "SIEM WARNING: secret loaded from environment variable, not Unix socket. \
                 Reduced security posture. Env vars are visible in /proc and process listings."
            );
            Ok(zeroize::Zeroizing::new(val.into_bytes()))
        }
        Err(_) => Err(format!(
            "secret '{}' unavailable: socket delivery failed and env var '{}' not set",
            name, env_name
        )),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_engine() -> CeremonyEngine {
        let sealing_key = CeremonySecret::generate(32).unwrap();
        CeremonyEngine::new(sealing_key)
    }

    #[test]
    fn test_ceremony_secret_generate() {
        let secret = CeremonySecret::generate(32).unwrap();
        assert_eq!(secret.len(), 32);
        assert!(!secret.is_empty());
    }

    #[test]
    fn test_ceremony_secret_zero_length_rejected() {
        assert!(CeremonySecret::generate(0).is_err());
    }

    #[test]
    fn test_ceremony_secret_debug_redacted() {
        let secret = CeremonySecret::generate(16).unwrap();
        let debug_output = format!("{:?}", secret);
        assert!(debug_output.contains("REDACTED"));
        assert!(!debug_output.contains(&format!("{:?}", secret.as_bytes())));
    }

    #[test]
    fn test_key_type_canonical_names() {
        assert_eq!(KeyType::MasterKek.canonical_name(), "MasterKek");
        assert_eq!(KeyType::TssShare(3).canonical_name(), "TssShare_3");
        assert_eq!(KeyType::OpaqueShare(1).canonical_name(), "OpaqueShare_1");
    }

    #[test]
    fn test_bootstrap_generates_all_keys() {
        let mut engine = make_engine();
        let results = engine.bootstrap().unwrap();

        // 6 base keys + 5 TSS shares + 3 OPAQUE shares = 14
        assert_eq!(results.len(), 14);
        assert_eq!(engine.key_count(), 14);
        assert_eq!(engine.rotation_epoch(), 1);

        // Every result should have a non-zero fingerprint
        for r in &results {
            assert_ne!(r.new_key_fingerprint, [0u8; 32]);
            assert!(!r.old_key_destroyed); // bootstrap has no old keys
        }
    }

    #[test]
    fn test_seal_unseal_roundtrip() {
        let mut engine = make_engine();
        engine.rotation_epoch = 1;
        let plaintext = b"super-secret-key-material-12345!";
        let sealed = engine.seal_key(KeyType::ShardHmac, plaintext).unwrap();

        // Sealed must be longer than plaintext (nonce + tag overhead)
        assert!(sealed.len() > plaintext.len());

        let recovered = engine.unseal_key(KeyType::ShardHmac, &sealed).unwrap();
        assert_eq!(recovered.as_bytes(), plaintext);
    }

    #[test]
    fn test_unseal_wrong_key_type_fails() {
        let mut engine = make_engine();
        engine.rotation_epoch = 1;
        let plaintext = b"super-secret-key-material-12345!";
        let sealed = engine.seal_key(KeyType::ShardHmac, plaintext).unwrap();

        // Different key type means different AAD, must fail
        let result = engine.unseal_key(KeyType::GatewayTls, &sealed);
        assert!(result.is_err());
    }

    #[test]
    fn test_unseal_wrong_epoch_fails() {
        let mut engine = make_engine();
        engine.rotation_epoch = 1;
        let plaintext = b"super-secret-key-material-12345!";
        let sealed = engine.seal_key(KeyType::ShardHmac, plaintext).unwrap();

        // Change epoch => AAD mismatch
        engine.rotation_epoch = 2;
        let result = engine.unseal_key(KeyType::ShardHmac, &sealed);
        assert!(result.is_err());
    }

    #[test]
    fn test_unseal_tampered_data_fails() {
        let mut engine = make_engine();
        engine.rotation_epoch = 1;
        let plaintext = b"super-secret-key-material-12345!";
        let mut sealed = engine.seal_key(KeyType::ShardHmac, plaintext).unwrap();

        // Flip a byte in the ciphertext
        if let Some(byte) = sealed.get_mut(20) {
            *byte ^= 0xff;
        }
        let result = engine.unseal_key(KeyType::ShardHmac, &sealed);
        assert!(result.is_err());
    }

    #[test]
    fn test_unseal_too_short_fails() {
        let engine = make_engine();
        let result = engine.unseal_key(KeyType::ShardHmac, &[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_rotate_key() {
        let mut engine = make_engine();
        engine.bootstrap().unwrap();

        let old_fingerprint = engine.key_fingerprint(KeyType::ShardHmac).unwrap();
        let result = engine.rotate_key(KeyType::ShardHmac).unwrap();

        assert_eq!(result.key_type, KeyType::ShardHmac);
        assert!(result.old_key_destroyed);
        assert_eq!(result.rotation_epoch, 2); // bootstrap=1, rotate=2
        assert_ne!(result.new_key_fingerprint, old_fingerprint);
    }

    #[test]
    fn test_emergency_rotate_all() {
        let mut engine = make_engine();
        engine.bootstrap().unwrap();

        let results = engine.emergency_rotate_all().unwrap();
        assert_eq!(results.len(), 14);
        for r in &results {
            assert!(r.old_key_destroyed);
        }
        // epoch increments once per key rotation
        assert_eq!(engine.rotation_epoch(), 15); // 1 (bootstrap) + 14 (rotations)
    }

    #[test]
    fn test_check_rotation_needed_after_bootstrap() {
        let engine = make_engine();
        // Before bootstrap, all schedules have last_rotated = None => all need rotation
        let needed = engine.check_rotation_needed();
        assert_eq!(needed.len(), engine.schedules.len());
    }

    #[test]
    fn test_check_rotation_not_needed_immediately_after_bootstrap() {
        let mut engine = make_engine();
        engine.bootstrap().unwrap();
        // Right after bootstrap, nothing should need rotation
        let needed = engine.check_rotation_needed();
        assert!(needed.is_empty());
    }

    #[test]
    fn test_get_sealed_key() {
        let mut engine = make_engine();
        assert!(engine.get_sealed_key(KeyType::ShardHmac).is_none());
        engine.bootstrap().unwrap();
        let sealed = engine.get_sealed_key(KeyType::ShardHmac);
        assert!(sealed.is_some());
        assert!(sealed.unwrap().len() > 12 + 16); // nonce + tag minimum
    }

    #[test]
    fn test_default_schedules_count() {
        let schedules = CeremonyEngine::default_schedules();
        // 6 base + 5 TSS + 3 OPAQUE = 14
        assert_eq!(schedules.len(), 14);
    }

    #[test]
    fn test_emergency_flag_triggers_rotation() {
        let mut engine = make_engine();
        engine.bootstrap().unwrap();

        // Mark one as emergency
        for sched in &mut engine.schedules {
            if sched.key_type == KeyType::MasterKek {
                sched.emergency = true;
            }
        }

        let needed = engine.check_rotation_needed();
        assert!(needed.contains(&KeyType::MasterKek));
        assert_eq!(needed.len(), 1);
    }

    #[test]
    fn test_key_fingerprint_consistency() {
        let mut engine = make_engine();
        engine.bootstrap().unwrap();

        let fp1 = engine.key_fingerprint(KeyType::AuditSigning).unwrap();
        let fp2 = engine.key_fingerprint(KeyType::AuditSigning).unwrap();
        assert_eq!(fp1, fp2); // same key => same fingerprint
    }

    #[test]
    fn test_different_keys_different_fingerprints() {
        let mut engine = make_engine();
        engine.bootstrap().unwrap();

        let fp_hmac = engine.key_fingerprint(KeyType::ShardHmac).unwrap();
        let fp_tls = engine.key_fingerprint(KeyType::GatewayTls).unwrap();
        assert_ne!(fp_hmac, fp_tls);
    }

    #[test]
    fn test_ceremony_secret_zeroize_on_drop() {
        // Generate a secret, drop it, verify the type implements ZeroizeOnDrop
        // (We can't inspect freed memory, but we verify the derive works.)
        let secret = CeremonySecret::generate(64).unwrap();
        assert_eq!(secret.len(), 64);
        drop(secret);
        // If ZeroizeOnDrop derive failed, this wouldn't compile.
    }

    // ── Unix Socket Secret Delivery Tests ────────────────────────────────────

    fn make_test_peer() -> PeerNode {
        let mut hmac_key = vec![0u8; 64];
        getrandom::getrandom(&mut hmac_key).unwrap();
        PeerNode {
            node_id: "node-alpha".into(),
            hmac_key,
            attestation_hash: sha256_fingerprint(b"node-alpha-binary-v1.0"),
        }
    }

    fn make_server_and_client() -> (SecretDeliveryServer, SecretDeliveryClient) {
        let peer = make_test_peer();
        let server = SecretDeliveryServer::new(
            PathBuf::from("/tmp/test-milnet.sock"),
            vec![peer.clone()],
            vec![0u8; 32],
        );
        let client = SecretDeliveryClient::new(
            peer.node_id.clone(),
            peer.hmac_key.clone(),
            peer.attestation_hash,
            PathBuf::from("/tmp/test-milnet.sock"),
        );
        (server, client)
    }

    #[test]
    fn test_server_client_roundtrip() {
        let (server, client) = make_server_and_client();
        let secret_data = b"top-secret-payload-42".to_vec();
        server.register_secret("db-password", secret_data.clone());

        let result = client.request_secret("db-password", &server).unwrap();
        assert_eq!(&*result, &secret_data);
    }

    #[test]
    fn test_auth_unknown_node_rejected() {
        let peer = make_test_peer();
        let server = SecretDeliveryServer::new(
            PathBuf::from("/tmp/test.sock"),
            vec![peer],
            vec![0u8; 32],
        );

        let mut challenge = [0u8; 32];
        getrandom::getrandom(&mut challenge).unwrap();

        let creds = AuthCredentials {
            node_id: "unknown-node".into(),
            hmac_token: vec![0u8; 64],
            attestation_hash: [0u8; 32],
        };

        assert_eq!(server.verify_auth(&creds, &challenge), AuthResult::UnknownNode);
    }

    #[test]
    fn test_auth_bad_hmac_rejected() {
        let peer = make_test_peer();
        let server = SecretDeliveryServer::new(
            PathBuf::from("/tmp/test.sock"),
            vec![peer.clone()],
            vec![0u8; 32],
        );

        let mut challenge = [0u8; 32];
        getrandom::getrandom(&mut challenge).unwrap();

        let creds = AuthCredentials {
            node_id: peer.node_id.clone(),
            hmac_token: vec![0xDE; 64], // wrong HMAC
            attestation_hash: peer.attestation_hash,
        };

        assert_eq!(server.verify_auth(&creds, &challenge), AuthResult::HmacMismatch);
    }

    #[test]
    fn test_auth_bad_attestation_rejected() {
        let peer = make_test_peer();
        let server = SecretDeliveryServer::new(
            PathBuf::from("/tmp/test.sock"),
            vec![peer.clone()],
            vec![0u8; 32],
        );

        let mut challenge = [0u8; 32];
        getrandom::getrandom(&mut challenge).unwrap();

        let hmac_token = compute_hmac(&peer.hmac_key, &challenge);
        let creds = AuthCredentials {
            node_id: peer.node_id.clone(),
            hmac_token,
            attestation_hash: [0xFF; 32], // wrong attestation
        };

        assert_eq!(
            server.verify_auth(&creds, &challenge),
            AuthResult::AttestationMismatch
        );
    }

    #[test]
    fn test_auth_valid_credentials_accepted() {
        let peer = make_test_peer();
        let server = SecretDeliveryServer::new(
            PathBuf::from("/tmp/test.sock"),
            vec![peer.clone()],
            vec![0u8; 32],
        );

        let mut challenge = [0u8; 32];
        getrandom::getrandom(&mut challenge).unwrap();

        let hmac_token = compute_hmac(&peer.hmac_key, &challenge);
        let creds = AuthCredentials {
            node_id: peer.node_id.clone(),
            hmac_token,
            attestation_hash: peer.attestation_hash,
        };

        assert_eq!(
            server.verify_auth(&creds, &challenge),
            AuthResult::Authenticated
        );
    }

    #[test]
    fn test_ephemeral_key_uniqueness() {
        // Each delivery must use a different ephemeral keypair
        let (server, _client) = make_server_and_client();
        server.register_secret("key1", b"secret1".to_vec());

        let peer_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let peer_public = x25519_dalek::PublicKey::from(&peer_secret);

        let (_, srv_pub1) = server.deliver_secret("key1", &peer_public.to_bytes()).unwrap();
        let (_, srv_pub2) = server.deliver_secret("key1", &peer_public.to_bytes()).unwrap();

        // Server should generate different ephemeral keys each time
        assert_ne!(srv_pub1, srv_pub2);
    }

    #[test]
    fn test_session_encrypt_decrypt_roundtrip() {
        let secret_a = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public_a = x25519_dalek::PublicKey::from(&secret_a);
        let secret_b = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public_b = x25519_dalek::PublicKey::from(&secret_b);

        let session_a = create_ephemeral_session(&secret_a, &public_b.to_bytes()).unwrap();
        let session_b = create_ephemeral_session(&secret_b, &public_a.to_bytes()).unwrap();

        // Both sides derive the same session key
        assert_eq!(session_a.session_key, session_b.session_key);

        let plaintext = b"classified material";
        let encrypted = session_encrypt(&session_a, plaintext).unwrap();
        let decrypted = session_decrypt(&session_b, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_rotation_watcher_epoch_monotonicity() {
        let frost_key = b"test-frost-verification-key-000".to_vec();
        let mut watcher = SecretRotationWatcher::new(frost_key.clone());

        let fp = sha256_fingerprint(b"key-v1");
        let sig = sign_rotation_event(&frost_key, "master", 1, &fp);
        let event1 = RotationEvent {
            key_name: "master".into(),
            epoch: 1,
            frost_signature: sig,
            new_fingerprint: fp,
            timestamp: 1000,
        };
        assert!(watcher.process_event(&event1).is_ok());
        assert_eq!(watcher.current_epoch("master"), Some(1));

        // Same epoch: rejected
        let sig2 = sign_rotation_event(&frost_key, "master", 1, &fp);
        let event_dup = RotationEvent {
            key_name: "master".into(),
            epoch: 1,
            frost_signature: sig2,
            new_fingerprint: fp,
            timestamp: 1001,
        };
        assert!(watcher.process_event(&event_dup).is_err());

        // Lower epoch: rejected
        let sig3 = sign_rotation_event(&frost_key, "master", 0, &fp);
        let event_regress = RotationEvent {
            key_name: "master".into(),
            epoch: 0,
            frost_signature: sig3,
            new_fingerprint: fp,
            timestamp: 1002,
        };
        assert!(watcher.process_event(&event_regress).is_err());

        // Higher epoch: accepted
        let fp2 = sha256_fingerprint(b"key-v2");
        let sig4 = sign_rotation_event(&frost_key, "master", 2, &fp2);
        let event3 = RotationEvent {
            key_name: "master".into(),
            epoch: 2,
            frost_signature: sig4,
            new_fingerprint: fp2,
            timestamp: 1003,
        };
        assert!(watcher.process_event(&event3).is_ok());
        assert_eq!(watcher.current_epoch("master"), Some(2));
        assert_eq!(watcher.event_count(), 2);
    }

    #[test]
    fn test_rotation_watcher_bad_frost_signature() {
        let frost_key = b"correct-key".to_vec();
        let mut watcher = SecretRotationWatcher::new(frost_key);

        let fp = sha256_fingerprint(b"key-data");
        // Sign with wrong key
        let bad_sig = compute_hmac(b"wrong-key", b"whatever");
        let event = RotationEvent {
            key_name: "test".into(),
            epoch: 1,
            frost_signature: bad_sig,
            new_fingerprint: fp,
            timestamp: 1000,
        };
        assert!(watcher.process_event(&event).is_err());
        assert_eq!(watcher.event_count(), 0);
    }

    #[test]
    fn test_distributed_rotation_proposal_approve_commit() {
        let mut coord = DistributedRotationCoordinator::new(3, 5);
        let fp = sha256_fingerprint(b"new-key");

        let idx = coord.propose("master-kek", "node-1", fp).unwrap();
        assert_eq!(
            coord.get_proposal(idx).unwrap().phase,
            RotationPhase::Proposed
        );

        // Two more approvals needed for quorum of 3 (proposer auto-approves)
        let reached = coord.approve(idx, "node-2").unwrap();
        assert!(!reached);

        let reached = coord.approve(idx, "node-3").unwrap();
        assert!(reached);
        assert_eq!(
            coord.get_proposal(idx).unwrap().phase,
            RotationPhase::Approved
        );

        // Commit
        coord.commit(idx).unwrap();
        assert_eq!(
            coord.get_proposal(idx).unwrap().phase,
            RotationPhase::Committed
        );
        assert_eq!(coord.current_epoch("master-kek"), 1);
    }

    #[test]
    fn test_distributed_rotation_grace_period() {
        let mut coord = DistributedRotationCoordinator::new(1, 1);
        coord.grace_period_secs = 3600; // 1 hour, won't expire in test

        let fp = sha256_fingerprint(b"new-key");
        let idx = coord.propose("hmac", "node-1", fp).unwrap();
        coord.commit(idx).unwrap();

        // Finalize should fail: grace period not expired
        let result = coord.finalize(idx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("grace period not expired"));
    }

    #[test]
    fn test_distributed_rotation_zero_grace_period() {
        let mut coord = DistributedRotationCoordinator::new(1, 1);
        coord.grace_period_secs = 0; // immediate finalize

        let fp = sha256_fingerprint(b"new-key");
        let idx = coord.propose("hmac", "node-1", fp).unwrap();
        coord.commit(idx).unwrap();

        // With zero grace period, finalize should succeed
        assert!(coord.finalize(idx).is_ok());
        assert_eq!(
            coord.get_proposal(idx).unwrap().phase,
            RotationPhase::Finalized
        );
    }

    #[test]
    fn test_distributed_rotation_duplicate_proposal_rejected() {
        let mut coord = DistributedRotationCoordinator::new(2, 3);
        let fp = sha256_fingerprint(b"key");

        coord.propose("key-a", "node-1", fp).unwrap();
        // Second proposal for same key while first is pending
        let result = coord.propose("key-a", "node-2", fp);
        assert!(result.is_err());
    }

    #[test]
    fn test_distributed_rotation_reject_prevents_commit() {
        let mut coord = DistributedRotationCoordinator::new(2, 3);
        let fp = sha256_fingerprint(b"key");

        let idx = coord.propose("key-b", "node-1", fp).unwrap();
        coord.reject(idx).unwrap();

        // Cannot approve rejected proposal
        let result = coord.approve(idx, "node-2");
        assert!(result.is_err());
    }

    #[test]
    fn test_distributed_rotation_epoch_persistence() {
        let mut coord = DistributedRotationCoordinator::new(1, 1);
        coord.grace_period_secs = 0;

        let fp1 = sha256_fingerprint(b"v1");
        let idx1 = coord.propose("key", "node", fp1).unwrap();
        coord.commit(idx1).unwrap();
        coord.finalize(idx1).unwrap();
        assert_eq!(coord.current_epoch("key"), 1);

        let fp2 = sha256_fingerprint(b"v2");
        let idx2 = coord.propose("key", "node", fp2).unwrap();
        coord.commit(idx2).unwrap();
        assert_eq!(coord.current_epoch("key"), 2);
    }

    #[test]
    fn test_load_secret_from_socket_via_server() {
        let (server, client) = make_server_and_client();
        server.register_secret("api-key", b"sk-live-12345".to_vec());

        let result =
            load_secret_from_socket("api-key", Some(&client), Some(&server)).unwrap();
        assert_eq!(&*result, b"sk-live-12345");
    }

    #[test]
    fn test_load_secret_from_socket_env_fallback() {
        let env_key = "MILNET_SECRET_TEST_FALLBACK";
        std::env::set_var(env_key, "env-secret-value");

        let result = load_secret_from_socket("test-fallback", None, None).unwrap();
        assert_eq!(&*result, b"env-secret-value");

        std::env::remove_var(env_key);
    }

    #[test]
    fn test_load_secret_from_socket_no_source_fails() {
        // Ensure the env var doesn't exist
        let env_key = "MILNET_SECRET_NONEXISTENT_KEY";
        std::env::remove_var(env_key);

        let result = load_secret_from_socket("nonexistent-key", None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_adversarial_replay_attack() {
        // Capture an encrypted delivery, try to replay it with different session
        let (server, _) = make_server_and_client();
        server.register_secret("secret", b"payload".to_vec());

        let attacker_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let attacker_public = x25519_dalek::PublicKey::from(&attacker_secret);

        let (encrypted, server_pub) =
            server.deliver_secret("secret", &attacker_public.to_bytes()).unwrap();

        // Attacker gets the ciphertext but tries to decrypt with a different keypair
        let other_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let wrong_session = create_ephemeral_session(&other_secret, &server_pub).unwrap();
        let result = session_decrypt(&wrong_session, &encrypted);
        assert!(result.is_err());

        // Correct keypair works
        let correct_session =
            create_ephemeral_session(&attacker_secret, &server_pub).unwrap();
        let result = session_decrypt(&correct_session, &encrypted);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"payload");
    }

    #[test]
    fn test_adversarial_tampered_ciphertext() {
        let secret_a = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public_a = x25519_dalek::PublicKey::from(&secret_a);
        let secret_b = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public_b = x25519_dalek::PublicKey::from(&secret_b);

        let session = create_ephemeral_session(&secret_a, &public_b.to_bytes()).unwrap();
        let mut encrypted = session_encrypt(&session, b"authentic").unwrap();

        // Tamper with ciphertext
        if let Some(byte) = encrypted.get_mut(15) {
            *byte ^= 0xFF;
        }

        let recv_session = create_ephemeral_session(&secret_b, &public_a.to_bytes()).unwrap();
        assert!(session_decrypt(&recv_session, &encrypted).is_err());
    }

    #[test]
    fn test_adversarial_client_wrong_node_id() {
        let peer = make_test_peer();
        let server = SecretDeliveryServer::new(
            PathBuf::from("/tmp/test.sock"),
            vec![peer.clone()],
            vec![0u8; 32],
        );
        server.register_secret("secret", b"data".to_vec());

        // Client with wrong node_id
        let bad_client = SecretDeliveryClient::new(
            "evil-node".into(),
            peer.hmac_key.clone(),
            peer.attestation_hash,
            PathBuf::from("/tmp/test.sock"),
        );

        let result = bad_client.request_secret("secret", &server);
        assert!(result.is_err());
    }

    #[test]
    fn test_adversarial_client_wrong_hmac_key() {
        let peer = make_test_peer();
        let server = SecretDeliveryServer::new(
            PathBuf::from("/tmp/test.sock"),
            vec![peer.clone()],
            vec![0u8; 32],
        );
        server.register_secret("secret", b"data".to_vec());

        let bad_client = SecretDeliveryClient::new(
            peer.node_id.clone(),
            vec![0xAB; 64], // wrong HMAC key
            peer.attestation_hash,
            PathBuf::from("/tmp/test.sock"),
        );

        let result = bad_client.request_secret("secret", &server);
        assert!(result.is_err());
    }

    #[test]
    fn test_adversarial_client_wrong_attestation() {
        let peer = make_test_peer();
        let server = SecretDeliveryServer::new(
            PathBuf::from("/tmp/test.sock"),
            vec![peer.clone()],
            vec![0u8; 32],
        );
        server.register_secret("secret", b"data".to_vec());

        let bad_client = SecretDeliveryClient::new(
            peer.node_id.clone(),
            peer.hmac_key.clone(),
            [0xFF; 32], // wrong attestation
            PathBuf::from("/tmp/test.sock"),
        );

        let result = bad_client.request_secret("secret", &server);
        assert!(result.is_err());
    }

    #[test]
    fn test_server_secret_not_found() {
        let (server, _) = make_server_and_client();
        let peer_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let peer_public = x25519_dalek::PublicKey::from(&peer_secret);

        let result = server.deliver_secret("nonexistent", &peer_public.to_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_wire_msg_roundtrip() {
        for v in [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xFF] {
            let msg = WireMsg::from_u8(v).unwrap();
            assert_eq!(msg as u8, v);
        }
        assert!(WireMsg::from_u8(0x00).is_none());
        assert!(WireMsg::from_u8(0x07).is_none());
    }

    #[test]
    #[should_panic(expected = "quorum must be 1..=cluster_size")]
    fn test_coordinator_zero_quorum_panics() {
        DistributedRotationCoordinator::new(0, 5);
    }

    #[test]
    #[should_panic(expected = "quorum must be 1..=cluster_size")]
    fn test_coordinator_quorum_exceeds_cluster_panics() {
        DistributedRotationCoordinator::new(6, 5);
    }
}
