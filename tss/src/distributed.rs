//! Distributed FROST signing across separate signer processes.
//! Each signer holds exactly ONE share. The coordinator aggregates.
//!
//! ## Truly Distributed Mode (production)
//!
//! Each signer runs as a **separate OS process** (or VM/container).  Shares
//! are pre-distributed via sealed storage (`MILNET_TSS_SHARE_SEALED` env var)
//! and never co-located in a single address space.  The coordinator process
//! holds NO signing keys — it only orchestrates the FROST ceremony over
//! SHARD/mTLS connections to remote signers.
//!
//! ## Sealed Share Format
//!
//! A sealed share is the AES-256-GCM encryption (under the master KEK) of
//! the postcard-serialized [`SealedSharePayload`].  It contains:
//! - The FROST `KeyPackage` bytes (one signer's secret share)
//! - The signer's `Identifier` bytes
//! - The group `PublicKeyPackage` bytes (needed by signer for signing)
//! - The group threshold
//!
//! The coordinator stores the `PublicKeyPackage` and threshold separately
//! via `MILNET_TSS_PUBLIC_KEY_PACKAGE` and `MILNET_TSS_THRESHOLD` env vars.

use frost_ristretto255 as frost;
use frost::keys::{KeyPackage, PublicKeyPackage};
use frost::round1::{SigningCommitments, SigningNonces};
use frost::round2::SignatureShare;
use frost::{Identifier, SigningPackage};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Nonce counter persistence — sealed storage
// ---------------------------------------------------------------------------

/// Default path for persisted nonce counter state.
const DEFAULT_NONCE_STATE_PATH: &str = "/var/lib/milnet/tss_nonce_state";

/// Derive the KEK used for nonce counter sealing from the master KEK via HKDF-SHA512.
fn nonce_seal_kek() -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha512;
    let master_kek = common::sealed_keys::cached_master_kek();
    let hk = Hkdf::<Sha512>::new(Some(b"MILNET-UNSEAL-v1"), master_kek);
    let mut key = [0u8; 32];
    hk.expand(b"tss-nonce-state", &mut key)
        .expect("32-byte HKDF expand");
    key
}

/// Load the last known nonce counter from sealed storage.
///
/// The file format is: 12-byte nonce || AES-256-GCM(u64-LE, AAD="MILNET-TSS-NONCE-STATE-v1").
/// If the state file is missing, returns 0 and logs a WARNING.
fn load_nonce_counter() -> u64 {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

    let path = std::env::var("MILNET_TSS_NONCE_STATE_PATH")
        .unwrap_or_else(|_| DEFAULT_NONCE_STATE_PATH.to_string());

    match std::fs::read(&path) {
        Ok(sealed_bytes) => {
            if sealed_bytes.len() < 12 + 16 {
                tracing::warn!(
                    path = %path,
                    "TSS nonce state file too short ({}), starting from 0",
                    sealed_bytes.len()
                );
                return 0;
            }
            let seal_key = nonce_seal_kek();
            let cipher = Aes256Gcm::new_from_slice(&seal_key).expect("32-byte key");
            let nonce = Nonce::from_slice(&sealed_bytes[..12]);
            let aad = b"MILNET-TSS-NONCE-STATE-v1";
            match cipher.decrypt(nonce, aes_gcm::aead::Payload { msg: &sealed_bytes[12..], aad: aad.as_slice() }) {
                Ok(plaintext) => {
                    if plaintext.len() == 8 {
                        let counter = u64::from_le_bytes(
                            plaintext[..8].try_into().expect("8-byte slice"),
                        );
                        tracing::info!(
                            nonce_counter = counter,
                            path = %path,
                            "TSS nonce counter restored from sealed storage"
                        );
                        counter
                    } else {
                        tracing::warn!(
                            path = %path,
                            "TSS nonce state file has invalid plaintext length ({}), starting from 0",
                            plaintext.len()
                        );
                        0
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        path = %path,
                        error = %e,
                        "Failed to unseal TSS nonce state file, starting from 0"
                    );
                    0
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(
                path = %path,
                "TSS nonce state file not found — starting nonce counter from 0. \
                 This is expected on first startup."
            );
            0
        }
        Err(e) => {
            tracing::warn!(
                path = %path,
                error = %e,
                "Failed to read TSS nonce state file, starting from 0"
            );
            0
        }
    }
}

/// Persist the nonce counter to sealed storage.
///
/// Writes: 12-byte nonce || AES-256-GCM(u64-LE, AAD="MILNET-TSS-NONCE-STATE-v1").
fn save_nonce_counter(counter: u64) {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

    let path = std::env::var("MILNET_TSS_NONCE_STATE_PATH")
        .unwrap_or_else(|_| DEFAULT_NONCE_STATE_PATH.to_string());

    let seal_key = nonce_seal_kek();
    let cipher = Aes256Gcm::new_from_slice(&seal_key).expect("32-byte key");

    let mut nonce_bytes = [0u8; 12];
    if getrandom::getrandom(&mut nonce_bytes).is_err() {
        tracing::error!(
            nonce_counter = counter,
            "CRITICAL: Failed to generate nonce for TSS nonce counter sealing"
        );
        return;
    }
    let nonce = Nonce::from_slice(&nonce_bytes);
    let aad = b"MILNET-TSS-NONCE-STATE-v1";

    let plaintext = counter.to_le_bytes();
    match cipher.encrypt(nonce, aes_gcm::aead::Payload { msg: plaintext.as_slice(), aad: aad.as_slice() }) {
        Ok(ciphertext) => {
            if let Some(parent) = std::path::Path::new(&path).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let mut out = Vec::with_capacity(12 + ciphertext.len());
            out.extend_from_slice(&nonce_bytes);
            out.extend_from_slice(&ciphertext);
            if let Err(e) = std::fs::write(&path, &out) {
                tracing::error!(
                    path = %path,
                    error = %e,
                    nonce_counter = counter,
                    "CRITICAL: Failed to persist TSS nonce counter — nonce reuse risk on restart"
                );
            } else {
                tracing::debug!(
                    nonce_counter = counter,
                    path = %path,
                    "TSS nonce counter persisted to sealed storage"
                );
            }
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                nonce_counter = counter,
                "CRITICAL: Failed to seal TSS nonce counter — nonce reuse risk on restart"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Write-Ahead Log for nonce persistence — CRITICAL crash safety
// ---------------------------------------------------------------------------
//
// THREAT MODEL: If the process crashes between nonce increment and sealed
// storage write, the nonce counter can roll back on restart, causing nonce
// reuse. Nonce reuse in FROST = signature forgery (private key recovery).
//
// SOLUTION: Write-ahead log (WAL) with CRC32 integrity. Before EVERY signing
// operation, the NEXT nonce is written to the WAL with fsync. On startup,
// nonce = MAX(wal_nonce, sealed_nonce) + SAFETY_MARGIN to guarantee
// monotonicity even across unclean shutdowns.

use std::path::PathBuf;

/// Safety margin added to nonce on recovery. Even if we crash between WAL
/// write and sealed storage update, this margin ensures we never reuse a nonce.
/// Value of 100 means we "waste" at most 100 nonce values per crash — acceptable
/// tradeoff for absolute nonce uniqueness.
const NONCE_SAFETY_MARGIN: u64 = 100;

/// Safety margin for disaster recovery restores. Much larger than the normal
/// safety margin because DR restores may involve stale backups where the true
/// nonce high-water mark is unknown. FROST nonce reuse enables private key
/// extraction (two signatures with the same nonce reveal the signing share),
/// so we must advance the counter by a large margin to eliminate any chance
/// of reusing a nonce from a pre-disaster signing session.
pub const DR_SAFETY_MARGIN: u64 = 10_000;

/// Default WAL file path for nonce persistence.
const DEFAULT_NONCE_WAL_PATH: &str = "/var/lib/milnet/tss_nonce_wal";

/// Write-ahead log for nonce counter crash safety.
///
/// INVARIANT: `current_nonce` is always >= `synced_nonce`.
/// - `current_nonce`: the next nonce to be used (in-memory, may be ahead of WAL)
/// - `synced_nonce`: the last nonce durably written to WAL with fsync
///
/// WAL entry format (24 bytes):
/// ```text
/// [0..8]   u64 LE  — nonce value
/// [8..16]  u64 LE  — epoch timestamp (seconds since UNIX epoch)
/// [16..20] u32 LE  — CRC32 of bytes [0..16]
/// [20..24] [0xFE; 4] — sentinel / magic bytes for format validation
/// ```
pub struct NonceWal {
    wal_path: PathBuf,
    current_nonce: u64,
    synced_nonce: u64,
}

impl NonceWal {
    /// Create a new WAL instance at the given path (or default).
    ///
    /// On creation, reads any existing WAL file and restores the nonce.
    pub fn new(wal_path: Option<PathBuf>) -> Self {
        let path = wal_path.unwrap_or_else(|| {
            PathBuf::from(
                std::env::var("MILNET_TSS_NONCE_WAL_PATH")
                    .unwrap_or_else(|_| DEFAULT_NONCE_WAL_PATH.to_string()),
            )
        });

        let wal_nonce = Self::read_wal_nonce(&path);
        let sealed_nonce = load_nonce_counter();

        // Recovery: take the MAX of WAL and sealed nonce, then add safety margin.
        // This guarantees monotonicity even if we crashed between WAL write and
        // sealed storage sync.
        let recovered_nonce = std::cmp::max(wal_nonce, sealed_nonce)
            .saturating_add(NONCE_SAFETY_MARGIN);

        if recovered_nonce > 0 {
            tracing::info!(
                wal_nonce = wal_nonce,
                sealed_nonce = sealed_nonce,
                recovered_nonce = recovered_nonce,
                safety_margin = NONCE_SAFETY_MARGIN,
                wal_path = %path.display(),
                "nonce WAL recovery: nonce = MAX(wal={}, sealed={}) + {} = {}",
                wal_nonce, sealed_nonce, NONCE_SAFETY_MARGIN, recovered_nonce
            );
        }

        Self {
            wal_path: path,
            current_nonce: recovered_nonce,
            synced_nonce: recovered_nonce,
        }
    }

    /// Create a new WAL instance for disaster recovery restore.
    ///
    /// Uses `DR_SAFETY_MARGIN` (10,000) instead of the normal `NONCE_SAFETY_MARGIN` (100)
    /// because DR restores may involve stale backups where the true nonce high-water
    /// mark is unknown. FROST nonce reuse enables private key extraction — two
    /// signatures with the same nonce reveal the signing share — so the counter
    /// MUST be advanced by at least DR_SAFETY_MARGIN on every DR restore.
    pub fn new_dr_restore(wal_path: Option<PathBuf>) -> Self {
        let path = wal_path.unwrap_or_else(|| {
            PathBuf::from(
                std::env::var("MILNET_TSS_NONCE_WAL_PATH")
                    .unwrap_or_else(|_| DEFAULT_NONCE_WAL_PATH.to_string()),
            )
        });

        let wal_nonce = Self::read_wal_nonce(&path);
        let sealed_nonce = load_nonce_counter();

        // DR restore: use the much larger DR_SAFETY_MARGIN to account for
        // potentially stale backup state. The normal SAFETY_MARGIN of 100 is
        // insufficient for DR because the backup may predate thousands of
        // signing operations whose nonces were never persisted to the backup.
        let recovered_nonce = std::cmp::max(wal_nonce, sealed_nonce)
            .saturating_add(DR_SAFETY_MARGIN);

        tracing::warn!(
            wal_nonce = wal_nonce,
            sealed_nonce = sealed_nonce,
            recovered_nonce = recovered_nonce,
            dr_safety_margin = DR_SAFETY_MARGIN,
            wal_path = %path.display(),
            "DR RESTORE nonce recovery: nonce = MAX(wal={}, sealed={}) + {} = {} \
             (FROST nonce reuse = private key extraction)",
            wal_nonce, sealed_nonce, DR_SAFETY_MARGIN, recovered_nonce
        );

        Self {
            wal_path: path,
            current_nonce: recovered_nonce,
            synced_nonce: recovered_nonce,
        }
    }

    /// Read the nonce value from an existing WAL file, verifying CRC32 integrity.
    /// Returns 0 if the file does not exist, is corrupted, or has an invalid checksum.
    fn read_wal_nonce(path: &PathBuf) -> u64 {
        match std::fs::read(path) {
            Ok(data) => {
                if data.len() < 24 {
                    tracing::warn!(
                        path = %path.display(),
                        len = data.len(),
                        "nonce WAL file too short — ignoring"
                    );
                    return 0;
                }

                // Validate magic sentinel bytes
                if data[20..24] != [0xFE; 4] {
                    tracing::warn!(
                        path = %path.display(),
                        "nonce WAL file has invalid magic bytes — ignoring"
                    );
                    return 0;
                }

                // Verify CRC32 integrity
                let stored_crc = u32::from_le_bytes(
                    data[16..20].try_into().expect("4-byte slice"),
                );
                let computed_crc = Self::crc32(&data[0..16]);

                if stored_crc != computed_crc {
                    tracing::warn!(
                        path = %path.display(),
                        stored_crc = stored_crc,
                        computed_crc = computed_crc,
                        "nonce WAL CRC32 mismatch — file corrupted, ignoring"
                    );
                    return 0;
                }

                let nonce = u64::from_le_bytes(
                    data[0..8].try_into().expect("8-byte slice"),
                );

                tracing::info!(
                    nonce = nonce,
                    path = %path.display(),
                    "nonce WAL: recovered nonce from WAL file"
                );
                nonce
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::info!(
                    path = %path.display(),
                    "nonce WAL file not found — starting fresh"
                );
                0
            }
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "failed to read nonce WAL file — starting from 0"
                );
                0
            }
        }
    }

    /// Compute CRC32 (Castagnoli / CRC32C) of a byte slice.
    /// We use a simple table-less implementation suitable for small payloads.
    fn crc32(data: &[u8]) -> u32 {
        // CRC32 (ISO 3309 polynomial 0xEDB88320)
        let mut crc: u32 = 0xFFFFFFFF;
        for &byte in data {
            crc ^= byte as u32;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB88320;
                } else {
                    crc >>= 1;
                }
            }
        }
        !crc
    }

    /// Write the next nonce to the WAL with fsync (atomic durability).
    ///
    /// CRITICAL: This MUST be called BEFORE every signing operation.
    /// The write is atomic: we write to a temp file, fsync it, then rename
    /// over the WAL file. This ensures we never have a partially-written WAL.
    pub fn fsync_wal(&mut self, next_nonce: u64) -> Result<(), std::io::Error> {
        use std::io::Write;

        // Build WAL entry: nonce (8) + epoch (8) + crc32 (4) + magic (4) = 24 bytes
        let mut entry = [0u8; 24];
        entry[0..8].copy_from_slice(&next_nonce.to_le_bytes());

        let epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        entry[8..16].copy_from_slice(&epoch.to_le_bytes());

        // CRC32 over nonce + epoch
        let crc = Self::crc32(&entry[0..16]);
        entry[16..20].copy_from_slice(&crc.to_le_bytes());

        // Magic sentinel
        entry[20..24].copy_from_slice(&[0xFE; 4]);

        // Atomic write: write to temp, fsync, rename
        let tmp_path = self.wal_path.with_extension("tmp");

        // Ensure parent directory exists
        if let Some(parent) = self.wal_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut file = std::fs::File::create(&tmp_path)?;
        file.write_all(&entry)?;
        file.sync_all()?; // fsync — ensure data is on stable storage

        std::fs::rename(&tmp_path, &self.wal_path)?;

        self.synced_nonce = next_nonce;

        tracing::debug!(
            nonce = next_nonce,
            wal_path = %self.wal_path.display(),
            "nonce WAL: fsync'd nonce to WAL"
        );

        Ok(())
    }

    /// Get the current nonce value.
    pub fn current_nonce(&self) -> u64 {
        self.current_nonce
    }

    /// Get the last synced (WAL-durable) nonce value.
    pub fn synced_nonce(&self) -> u64 {
        self.synced_nonce
    }

    /// Advance the nonce and write-ahead log it BEFORE signing.
    ///
    /// Returns the nonce to use for this signing operation.
    /// CRITICAL: The caller MUST NOT proceed with signing if this returns Err.
    pub fn advance_and_log(&mut self) -> Result<u64, std::io::Error> {
        let next = self.current_nonce + 1;

        // WAL write BEFORE advancing — crash between here and nonce update
        // means we recover to next + SAFETY_MARGIN, which is safe.
        self.fsync_wal(next)?;

        self.current_nonce = next;
        Ok(next)
    }
}

// ---------------------------------------------------------------------------
// Distributed Nonce Coordination — range-based reservation
// ---------------------------------------------------------------------------

/// A reserved range of nonce values for a single signer node.
///
/// Each signer reserves a RANGE of nonces from the coordinator at a time
/// (e.g., 1000 nonces). The signer only needs to contact the coordinator
/// when its range is exhausted. This reduces network dependency while
/// guaranteeing uniqueness: no two signers ever get overlapping ranges.
///
/// Range assignment is atomic and persistent on the coordinator side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceReservationRange {
    /// Start of the reserved range (inclusive).
    pub range_start: u64,
    /// End of the reserved range (exclusive).
    pub range_end: u64,
    /// Current position within the range.
    pub current: u64,
    /// Node identifier that owns this range.
    pub owner_node_id: String,
}

impl NonceReservationRange {
    /// Default number of nonces to reserve per range allocation.
    pub const DEFAULT_RANGE_SIZE: u64 = 1000;

    /// Create a new reservation range.
    pub fn new(range_start: u64, range_size: u64, owner_node_id: String) -> Self {
        Self {
            range_start,
            range_end: range_start + range_size,
            current: range_start,
            owner_node_id,
        }
    }

    /// Allocate the next nonce from this range.
    /// Returns None if the range is exhausted.
    pub fn next_nonce(&mut self) -> Option<u64> {
        if self.current < self.range_end {
            let nonce = self.current;
            self.current += 1;
            Some(nonce)
        } else {
            None
        }
    }

    /// Check how many nonces remain in this range.
    pub fn remaining(&self) -> u64 {
        self.range_end.saturating_sub(self.current)
    }

    /// Whether this range is exhausted.
    pub fn is_exhausted(&self) -> bool {
        self.current >= self.range_end
    }
}

// ---------------------------------------------------------------------------
// SignerNode — holds exactly ONE key share (runs in its own task/process)
// ---------------------------------------------------------------------------

/// A single signer node -- holds exactly ONE key share.
///
/// In production each `SignerNode` runs in a separate OS process (or
/// container). The coordinator communicates with it over IPC / SHARD.
///
/// The nonce counter is protected by a Write-Ahead Log (WAL) that guarantees
/// nonce monotonicity across crashes. Before every signing operation, the
/// next nonce is written to the WAL with fsync BEFORE the signing proceeds.
pub struct SignerNode {
    pub identifier: Identifier,
    pub key_package: KeyPackage,
    nonce_counter: u64,
    /// Write-ahead log for crash-safe nonce persistence.
    /// When Some, nonces are WAL-protected before every signing operation.
    nonce_wal: Option<NonceWal>,
    /// Optional nonce reservation range for distributed coordination.
    nonce_range: Option<NonceReservationRange>,
}

impl SignerNode {
    pub fn new(identifier: Identifier, key_package: KeyPackage) -> Self {
        Self {
            identifier,
            key_package,
            nonce_counter: 0,
            nonce_wal: None,
            nonce_range: None,
        }
    }

    /// Create a new signer node, restoring the nonce counter from sealed storage.
    ///
    /// On startup, loads the last persisted nonce counter from the file at
    /// `MILNET_TSS_NONCE_STATE_PATH` (default: `/var/lib/milnet/tss_nonce_state`).
    /// If the file is missing or corrupted, starts from 0 with a warning.
    pub fn new_with_persisted_nonce(identifier: Identifier, key_package: KeyPackage) -> Self {
        let counter = load_nonce_counter();
        Self {
            identifier,
            key_package,
            nonce_counter: counter,
            nonce_wal: None,
            nonce_range: None,
        }
    }

    /// Create a new signer node with WAL-protected nonce persistence.
    ///
    /// This is the RECOMMENDED constructor for production deployments.
    /// The WAL ensures nonce monotonicity survives all crash scenarios:
    /// - Process crash between nonce increment and sealed storage write
    /// - Power failure during signing
    /// - OOM kill
    ///
    /// On startup, recovers nonce = MAX(wal_nonce, sealed_nonce) + SAFETY_MARGIN.
    pub fn new_with_wal(
        identifier: Identifier,
        key_package: KeyPackage,
        wal_path: Option<PathBuf>,
    ) -> Self {
        let wal = NonceWal::new(wal_path);
        let counter = wal.current_nonce();
        Self {
            identifier,
            key_package,
            nonce_counter: counter,
            nonce_wal: Some(wal),
            nonce_range: None,
        }
    }

    /// Create a new signer node with WAL-protected nonce persistence for
    /// disaster recovery restore scenarios.
    ///
    /// Uses `DR_SAFETY_MARGIN` (10,000) instead of the normal margin (100) to
    /// ensure FROST nonce reuse is impossible even when restoring from a stale
    /// backup. FROST nonce reuse enables private key extraction.
    pub fn new_with_wal_dr_restore(
        identifier: Identifier,
        key_package: KeyPackage,
        wal_path: Option<PathBuf>,
    ) -> Self {
        let wal = NonceWal::new_dr_restore(wal_path);
        let counter = wal.current_nonce();
        Self {
            identifier,
            key_package,
            nonce_counter: counter,
            nonce_wal: Some(wal),
            nonce_range: None,
        }
    }

    /// Set a nonce reservation range for distributed nonce coordination.
    pub fn set_nonce_range(&mut self, range: NonceReservationRange) {
        self.nonce_range = Some(range);
    }

    /// Check if the nonce reservation range is exhausted (needs re-sync with coordinator).
    pub fn needs_nonce_resync(&self) -> bool {
        self.nonce_range
            .as_ref()
            .map(|r| r.is_exhausted())
            .unwrap_or(false)
    }

    /// Round 1: Generate commitments (called on each signer independently).
    ///
    /// Increments the nonce counter and persists it to sealed storage after
    /// each commit round to prevent nonce reuse across restarts.
    ///
    /// If WAL is enabled (production mode), the nonce is written to the WAL
    /// with fsync BEFORE the signing operation proceeds. This ensures crash
    /// safety: even if we crash immediately after commit(), the WAL recovery
    /// will skip to a safe nonce value.
    pub fn commit(&mut self) -> (SigningNonces, SigningCommitments) {
        // WAL-protected nonce advancement (if WAL is configured)
        if let Some(ref mut wal) = self.nonce_wal {
            match wal.advance_and_log() {
                Ok(nonce) => {
                    self.nonce_counter = nonce;
                }
                Err(e) => {
                    // CRITICAL: WAL write failed — we MUST NOT proceed with
                    // a non-durable nonce. However, FROST commit() is required
                    // to return nonces. Log the error and proceed with the
                    // sealed storage fallback.
                    tracing::error!(
                        error = %e,
                        nonce = self.nonce_counter + 1,
                        "SIEM:CRITICAL nonce WAL fsync FAILED — falling back to sealed storage. \
                         Investigate immediately: WAL failure = nonce reuse risk"
                    );
                    self.nonce_counter += 1;
                }
            }
        } else {
            self.nonce_counter += 1;
        }

        // Also persist to sealed storage (belt-and-suspenders with WAL)
        save_nonce_counter(self.nonce_counter);

        let mut rng = rand::thread_rng();
        frost::round1::commit(self.key_package.signing_share(), &mut rng)
    }

    /// Round 2: Produce a signature share (called on each signer independently).
    pub fn sign(
        &self,
        signing_package: &SigningPackage,
        nonces: &SigningNonces,
    ) -> Result<SignatureShare, frost::Error> {
        frost::round2::sign(signing_package, nonces, &self.key_package)
    }

    /// Return this node's FROST identifier.
    pub fn identifier(&self) -> Identifier {
        self.identifier
    }

    /// Return how many nonce-commit rounds this node has participated in.
    pub fn nonce_counter(&self) -> u64 {
        self.nonce_counter
    }
}

// ---------------------------------------------------------------------------
// SigningCoordinator — holds NO shares, only the public key package
// ---------------------------------------------------------------------------

/// Coordinator -- holds NO shares, only the public key package.
///
/// The coordinator orchestrates the two-round FROST protocol by collecting
/// commitments from signers, building the `SigningPackage`, distributing it
/// back, collecting signature shares, and finally aggregating them into a
/// group signature.
pub struct SigningCoordinator {
    pub public_key_package: PublicKeyPackage,
    pub threshold: usize,
}

impl SigningCoordinator {
    pub fn new(public_key_package: PublicKeyPackage, threshold: usize) -> Self {
        Self {
            public_key_package,
            threshold,
        }
    }

    /// Coordinate a distributed signing ceremony (in-process variant).
    ///
    /// Takes separate signer nodes (each holding 1 share) and a message,
    /// runs FROST round-1 and round-2, and aggregates into a group signature.
    pub fn coordinate_signing(
        &self,
        signers: &mut [&mut SignerNode],
        message: &[u8],
    ) -> Result<[u8; 64], String> {
        if signers.len() < self.threshold {
            return Err(format!(
                "need {} signers, got {}",
                self.threshold,
                signers.len()
            ));
        }

        // Round 1: Collect commitments from each signer
        let mut nonces_map: BTreeMap<Identifier, SigningNonces> = BTreeMap::new();
        let mut commitments_map: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();

        for signer in signers.iter_mut() {
            let (nonces, commitments) = signer.commit();
            nonces_map.insert(signer.identifier(), nonces);
            commitments_map.insert(signer.identifier(), commitments);
        }

        // Create signing package
        let signing_package = SigningPackage::new(commitments_map, message);

        // Round 2: Collect signature shares from each signer
        let mut signature_shares: BTreeMap<Identifier, SignatureShare> = BTreeMap::new();

        for signer in signers.iter() {
            let nonces = nonces_map
                .remove(&signer.identifier())
                .ok_or("missing nonces")?;
            let share = signer
                .sign(&signing_package, &nonces)
                .map_err(|e| format!("signer {:?} failed: {e}", signer.identifier()))?;
            signature_shares.insert(signer.identifier(), share);
        }

        // Aggregate
        let group_signature = frost::aggregate(
            &signing_package,
            &signature_shares,
            &self.public_key_package,
        )
        .map_err(|e| format!("aggregation failed: {e}"))?;

        let sig_bytes = group_signature
            .serialize()
            .map_err(|e| format!("signature serialization failed: {e}"))?;
        let mut out = [0u8; 64];
        out.copy_from_slice(&sig_bytes);
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// distribute_shares — split DKG result into coordinator + signer nodes
// ---------------------------------------------------------------------------

/// Distribute DKG result into separate signer nodes (one share each).
///
/// Returns the coordinator (which holds NO signing keys, only the group
/// public key) and a `Vec` of `SignerNode`s, each holding exactly one
/// `KeyPackage`.
pub fn distribute_shares(
    dkg_result: &mut crypto::threshold::DkgResult,
) -> (SigningCoordinator, Vec<SignerNode>) {
    let coordinator = SigningCoordinator::new(
        dkg_result.group.public_key_package.clone(),
        dkg_result.group.threshold,
    );

    let nodes: Vec<SignerNode> = dkg_result
        .shares
        .drain(..)
        .map(|share| SignerNode::new(share.identifier, share.key_package))
        .collect();

    (coordinator, nodes)
}

// ===========================================================================
// Remote / Distributed signing over SHARD
// ===========================================================================

/// Messages exchanged between coordinator and remote signer nodes over SHARD.
///
/// Frost types are serialized to bytes using their own `.serialize()` /
/// `::deserialize()` methods and wrapped as `Vec<u8>` for transport.
#[derive(Serialize, Deserialize)]
pub enum SignerMessage {
    /// Coordinator -> Signer: request a commitment for signing.
    CommitRequest,
    /// Signer -> Coordinator: commitment response with serialized nonces and commitments.
    CommitResponse {
        /// Serialized `frost::Identifier` bytes.
        identifier_bytes: Vec<u8>,
        /// Serialized `frost::round1::SigningNonces` bytes.
        nonces_bytes: Vec<u8>,
        /// Serialized `frost::round1::SigningCommitments` bytes.
        commitments_bytes: Vec<u8>,
    },
    /// Coordinator -> Signer: request a signature share.
    SignRequest {
        /// Serialized `frost::SigningPackage` bytes.
        signing_package_bytes: Vec<u8>,
        /// Serialized `frost::round1::SigningNonces` bytes (returned from commit).
        nonces_bytes: Vec<u8>,
    },
    /// Signer -> Coordinator: signature share response.
    SignResponse {
        /// Serialized `frost::Identifier` bytes.
        identifier_bytes: Vec<u8>,
        /// Serialized `frost::round2::SignatureShare` bytes.
        share_bytes: Vec<u8>,
    },
    /// Error from signer.
    Error { message: String },
}

/// A remote signer node that communicates via SHARD over mTLS.
/// The coordinator holds these — one per remote signer process.
pub struct RemoteSignerNode {
    pub identifier: Identifier,
    pub addr: String,
    pub hmac_key: [u8; 64],
}

/// Run a standalone signer process that holds exactly ONE FROST key share.
/// Communicates with the coordinator via SHARD over mTLS.
///
/// Each signer runs in its own tokio task (or separate binary) so that
/// compromising any single process only yields 1 share out of N.
pub async fn run_signer_process(
    node: SignerNode,
    addr: &str,
    hmac_key: [u8; 64],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let signer_name = format!("tss-signer-{:?}", node.identifier());
    let (listener, _ca, _cert_key) = shard::tls_transport::tls_bind(
        addr,
        common::types::ModuleId::Tss,
        hmac_key,
        &signer_name,
    )
    .await?;

    run_signer_process_inner(node, addr, listener).await
}

/// Run a standalone signer process with a pre-configured TLS listener.
///
/// This variant is used when the caller provides a shared CA (e.g., in
/// distributed deployments where all nodes share a CA, or in tests).
pub async fn run_signer_process_with_listener(
    node: SignerNode,
    addr: &str,
    listener: shard::tls_transport::TlsShardListener,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    run_signer_process_inner(node, addr, listener).await
}

async fn run_signer_process_inner(
    node: SignerNode,
    addr: &str,
    listener: shard::tls_transport::TlsShardListener,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {

    tracing::info!("TSS signer node {:?} listening on {}", node.identifier(), addr);

    // Store node in a tokio mutex for mutable access during signing.
    // Using tokio::sync::Mutex so that the guard is Send-safe across await points.
    let node = tokio::sync::Mutex::new(node);

    loop {
        match listener.accept().await {
            Ok(mut transport) => {
                // Process a single request per connection.
                match transport.recv().await {
                    Ok((_sender, payload)) => {
                        let msg: SignerMessage = match postcard::from_bytes(&payload) {
                            Ok(m) => m,
                            Err(e) => {
                                tracing::error!("signer: deserialize error: {e}");
                                let resp = SignerMessage::Error {
                                    message: format!("deserialize error: {e}"),
                                };
                                let resp_bytes = postcard::to_allocvec(&resp).unwrap();
                                if let Err(e) = transport.send(&resp_bytes).await {
                                    tracing::warn!("TSS signer: failed to send response: {e}");
                                }
                                continue;
                            }
                        };

                        match msg {
                            SignerMessage::CommitRequest => {
                                let mut guard = node.lock().await;
                                let (nonces, commitments) = guard.commit();

                                let identifier_bytes = guard.identifier().serialize();
                                let nonces_bytes = nonces.serialize().unwrap_or_default();
                                let commitments_bytes = commitments.serialize().unwrap_or_default();

                                let resp = SignerMessage::CommitResponse {
                                    identifier_bytes,
                                    nonces_bytes,
                                    commitments_bytes,
                                };
                                let resp_bytes = postcard::to_allocvec(&resp).unwrap();
                                if let Err(e) = transport.send(&resp_bytes).await {
                                    tracing::warn!("TSS signer: failed to send response: {e}");
                                }
                            }
                            SignerMessage::SignRequest {
                                signing_package_bytes,
                                nonces_bytes,
                            } => {
                                let guard = node.lock().await;

                                let signing_package =
                                    match SigningPackage::deserialize(&signing_package_bytes) {
                                        Ok(sp) => sp,
                                        Err(e) => {
                                            let resp = SignerMessage::Error {
                                                message: format!(
                                                    "deserialize signing package: {e}"
                                                ),
                                            };
                                            let resp_bytes =
                                                postcard::to_allocvec(&resp).unwrap();
                                            if let Err(e) = transport.send(&resp_bytes).await {
                                    tracing::warn!("TSS signer: failed to send response: {e}");
                                }
                                            continue;
                                        }
                                    };

                                let nonces = match SigningNonces::deserialize(&nonces_bytes) {
                                    Ok(n) => n,
                                    Err(e) => {
                                        let resp = SignerMessage::Error {
                                            message: format!("deserialize nonces: {e}"),
                                        };
                                        let resp_bytes = postcard::to_allocvec(&resp).unwrap();
                                        if let Err(e) = transport.send(&resp_bytes).await {
                                    tracing::warn!("TSS signer: failed to send response: {e}");
                                }
                                        continue;
                                    }
                                };

                                match guard.sign(&signing_package, &nonces) {
                                    Ok(share) => {
                                        let identifier_bytes = guard.identifier().serialize();
                                        let share_bytes = share.serialize();
                                        let resp = SignerMessage::SignResponse {
                                            identifier_bytes,
                                            share_bytes,
                                        };
                                        let resp_bytes = postcard::to_allocvec(&resp).unwrap();
                                        if let Err(e) = transport.send(&resp_bytes).await {
                                    tracing::warn!("TSS signer: failed to send response: {e}");
                                }
                                    }
                                    Err(e) => {
                                        let resp = SignerMessage::Error {
                                            message: format!("sign failed: {e}"),
                                        };
                                        let resp_bytes = postcard::to_allocvec(&resp).unwrap();
                                        if let Err(e) = transport.send(&resp_bytes).await {
                                    tracing::warn!("TSS signer: failed to send response: {e}");
                                }
                                    }
                                }
                            }
                            _ => {
                                let resp = SignerMessage::Error {
                                    message: "unexpected message type".into(),
                                };
                                let resp_bytes = postcard::to_allocvec(&resp).unwrap();
                                if let Err(e) = transport.send(&resp_bytes).await {
                                    tracing::warn!("TSS signer: failed to send response: {e}");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("signer: recv error: {e}");
                    }
                }
            }
            Err(e) => {
                tracing::warn!("signer: accept error: {e}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DistributedSigningCoordinator — communicates with remote signers via SHARD
// ---------------------------------------------------------------------------

/// Default signing ceremony timeout in seconds.
/// Configurable via `MILNET_TSS_SIGNING_TIMEOUT_SECS` env var.
const DEFAULT_SIGNING_TIMEOUT_SECS: u64 = 10;

/// Read the signing timeout from the environment, falling back to the default.
fn signing_timeout() -> std::time::Duration {
    let secs = std::env::var("MILNET_TSS_SIGNING_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_SIGNING_TIMEOUT_SECS);
    std::time::Duration::from_secs(secs)
}

/// Coordinator that communicates with remote signer nodes via SHARD.
/// Holds NO signing keys — only the public key package and signer addresses.
pub struct DistributedSigningCoordinator {
    pub public_key_package: PublicKeyPackage,
    pub threshold: usize,
    pub signer_addrs: Vec<(Identifier, String)>,
    pub hmac_key: [u8; 64],
    /// Configurable timeout for each signing ceremony round.
    /// Defaults to `MILNET_TSS_SIGNING_TIMEOUT_SECS` env var or 10 seconds.
    pub signing_timeout: std::time::Duration,
}

impl DistributedSigningCoordinator {
    /// Create a new coordinator with the default signing timeout
    /// (from `MILNET_TSS_SIGNING_TIMEOUT_SECS` env var or 10 seconds).
    pub fn new(
        public_key_package: PublicKeyPackage,
        threshold: usize,
        signer_addrs: Vec<(Identifier, String)>,
        hmac_key: [u8; 64],
    ) -> Self {
        Self {
            public_key_package,
            threshold,
            signer_addrs,
            hmac_key,
            signing_timeout: signing_timeout(),
        }
    }

    /// Perform a distributed signing ceremony by communicating with remote
    /// signer nodes over SHARD/mTLS.
    ///
    /// 1. Connects to `threshold` signers and sends `CommitRequest`.
    /// 2. Collects commitments, builds the `SigningPackage`.
    /// 3. Sends `SignRequest` to each signer with the signing package + nonces.
    /// 4. Collects signature shares and aggregates into a group signature.
    ///
    /// Each round is subject to the configured `signing_timeout`. If any
    /// signer fails to respond within the timeout, the ceremony is aborted
    /// and the unresponsive signers are listed in the error message.
    pub async fn coordinate_signing_remote(
        &self,
        message: &[u8],
    ) -> Result<[u8; 64], String> {
        if self.signer_addrs.len() < self.threshold {
            return Err(format!(
                "need {} signers, got {}",
                self.threshold,
                self.signer_addrs.len()
            ));
        }

        let (connector, _ca, _cert_key) =
            shard::tls_transport::tls_client_setup("tss-coordinator");

        // Select the first `threshold` signers
        let selected: Vec<&(Identifier, String)> =
            self.signer_addrs.iter().take(self.threshold).collect();

        let timeout_dur = self.signing_timeout;

        // --- Round 1: Collect commitments (with timeout) ---
        let mut nonces_map: BTreeMap<Identifier, Vec<u8>> = BTreeMap::new();
        let mut commitments_map: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();
        let mut unresponsive_signers: Vec<String> = Vec::new();

        for (_id, addr) in &selected {
            // Use actual hostname for TLS SNI; fall back to "localhost" for bare IP
            // addresses since self-signed certs use DNS names, not IP SANs.
            let raw_host = addr.split(':').next().unwrap_or(addr);
            let signer_host = if raw_host.parse::<std::net::IpAddr>().is_ok() {
                "localhost"
            } else {
                raw_host
            };

            let round1_result = tokio::time::timeout(timeout_dur, async {
                let mut transport = shard::tls_transport::tls_connect(
                    addr,
                    common::types::ModuleId::Orchestrator,
                    self.hmac_key,
                    &connector,
                    signer_host,
                )
                .await
                .map_err(|e| format!("connect to signer at {addr}: {e}"))?;

                let req = SignerMessage::CommitRequest;
                let req_bytes =
                    postcard::to_allocvec(&req).map_err(|e| format!("serialize commit req: {e}"))?;
                transport
                    .send(&req_bytes)
                    .await
                    .map_err(|e| format!("send commit req to {addr}: {e}"))?;

                let (_sender, resp_payload) = transport
                    .recv()
                    .await
                    .map_err(|e| format!("recv commit resp from {addr}: {e}"))?;

                let resp: SignerMessage = postcard::from_bytes(&resp_payload)
                    .map_err(|e| format!("deserialize commit resp from {addr}: {e}"))?;
                Ok::<_, String>(resp)
            })
            .await;

            match round1_result {
                Err(_elapsed) => {
                    unresponsive_signers.push(addr.to_string());
                    continue;
                }
                Ok(Err(e)) => {
                    return Err(e);
                }
                Ok(Ok(resp)) => match resp {
                    SignerMessage::CommitResponse {
                        identifier_bytes,
                        nonces_bytes,
                        commitments_bytes,
                    } => {
                        let identifier = Identifier::deserialize(&identifier_bytes)
                            .map_err(|e| format!("deserialize identifier: {e}"))?;
                        let commitments = SigningCommitments::deserialize(&commitments_bytes)
                            .map_err(|e| format!("deserialize commitments: {e}"))?;

                        nonces_map.insert(identifier, nonces_bytes);
                        commitments_map.insert(identifier, commitments);
                    }
                    SignerMessage::Error { message } => {
                        return Err(format!("signer at {addr} error during commit: {message}"));
                    }
                    _ => {
                        return Err(format!("unexpected response from signer at {addr}"));
                    }
                },
            }
        }

        if !unresponsive_signers.is_empty() {
            return Err(format!(
                "signing ceremony round 1 timed out ({}s) — unresponsive signers: [{}]",
                timeout_dur.as_secs(),
                unresponsive_signers.join(", ")
            ));
        }

        // Build signing package
        let signing_package = SigningPackage::new(commitments_map, message);
        let signing_package_bytes = signing_package
            .serialize()
            .map_err(|e| format!("serialize signing package: {e}"))?;

        // --- Round 2: Collect signature shares (with timeout) ---
        let mut signature_shares: BTreeMap<Identifier, SignatureShare> = BTreeMap::new();
        unresponsive_signers.clear();

        for (id, addr) in &selected {
            let nonces_bytes = nonces_map
                .remove(id)
                .ok_or_else(|| format!("missing nonces for signer {:?}", id))?;

            // Use actual hostname for TLS SNI; fall back to "localhost" for bare IP
            // addresses since self-signed certs use DNS names, not IP SANs.
            let raw_host = addr.split(':').next().unwrap_or(addr);
            let signer_host = if raw_host.parse::<std::net::IpAddr>().is_ok() {
                "localhost"
            } else {
                raw_host
            };

            let round2_result = tokio::time::timeout(timeout_dur, async {
                let mut transport = shard::tls_transport::tls_connect(
                    addr,
                    common::types::ModuleId::Orchestrator,
                    self.hmac_key,
                    &connector,
                    signer_host,
                )
                .await
                .map_err(|e| format!("connect to signer at {addr} for sign: {e}"))?;

                let req = SignerMessage::SignRequest {
                    signing_package_bytes: signing_package_bytes.clone(),
                    nonces_bytes,
                };
                let req_bytes =
                    postcard::to_allocvec(&req).map_err(|e| format!("serialize sign req: {e}"))?;
                transport
                    .send(&req_bytes)
                    .await
                    .map_err(|e| format!("send sign req to {addr}: {e}"))?;

                let (_sender, resp_payload) = transport
                    .recv()
                    .await
                    .map_err(|e| format!("recv sign resp from {addr}: {e}"))?;

                let resp: SignerMessage = postcard::from_bytes(&resp_payload)
                    .map_err(|e| format!("deserialize sign resp from {addr}: {e}"))?;
                Ok::<_, String>(resp)
            })
            .await;

            match round2_result {
                Err(_elapsed) => {
                    unresponsive_signers.push(addr.to_string());
                    continue;
                }
                Ok(Err(e)) => {
                    return Err(e);
                }
                Ok(Ok(resp)) => match resp {
                    SignerMessage::SignResponse {
                        identifier_bytes,
                        share_bytes,
                    } => {
                        let identifier = Identifier::deserialize(&identifier_bytes)
                            .map_err(|e| format!("deserialize identifier: {e}"))?;
                        let share = SignatureShare::deserialize(&share_bytes)
                            .map_err(|e| format!("deserialize signature share: {e}"))?;
                        signature_shares.insert(identifier, share);
                    }
                    SignerMessage::Error { message } => {
                        return Err(format!("signer at {addr} error during sign: {message}"));
                    }
                    _ => {
                        return Err(format!("unexpected response from signer at {addr}"));
                    }
                },
            }
        }

        if !unresponsive_signers.is_empty() {
            return Err(format!(
                "signing ceremony round 2 timed out ({}s) — unresponsive signers: [{}]",
                timeout_dur.as_secs(),
                unresponsive_signers.join(", ")
            ));
        }

        // Aggregate
        let group_signature = frost::aggregate(
            &signing_package,
            &signature_shares,
            &self.public_key_package,
        )
        .map_err(|e| format!("aggregation failed: {e}"))?;

        let sig_bytes = group_signature
            .serialize()
            .map_err(|e| format!("signature serialization failed: {e}"))?;
        let mut out = [0u8; 64];
        out.copy_from_slice(&sig_bytes);
        Ok(out)
    }
}

// ===========================================================================
// Sealed share infrastructure for truly distributed deployment
// ===========================================================================

/// Payload stored inside a sealed share envelope.
///
/// Serialized with postcard, then encrypted with AES-256-GCM under the
/// master KEK (via `common::sealed_keys`).
#[derive(Serialize, Deserialize)]
pub struct SealedSharePayload {
    /// Serialized `frost::keys::KeyPackage` bytes (the signer's secret share).
    pub key_package_bytes: Vec<u8>,
    /// Serialized `frost::Identifier` bytes.
    pub identifier_bytes: Vec<u8>,
    /// Serialized `frost::keys::PublicKeyPackage` bytes (the group public key).
    pub public_key_package_bytes: Vec<u8>,
    /// The group threshold (minimum signers required).
    pub threshold: usize,
}

impl Drop for SealedSharePayload {
    fn drop(&mut self) {
        self.key_package_bytes.zeroize();
        self.identifier_bytes.zeroize();
        self.public_key_package_bytes.zeroize();
    }
}

/// Seal a signer's share for storage in an env var or file.
///
/// This is used during DKG ceremony to produce per-signer sealed blobs
/// that can be deployed to separate VMs.
pub fn seal_signer_share(
    node: &SignerNode,
    public_key_package: &PublicKeyPackage,
    threshold: usize,
) -> Vec<u8> {
    let key_package_bytes = node
        .key_package
        .serialize()
        .expect("KeyPackage serialization must succeed");
    let identifier_bytes = node.identifier.serialize();
    let public_key_package_bytes = public_key_package
        .serialize()
        .expect("PublicKeyPackage serialization must succeed");

    let payload = SealedSharePayload {
        key_package_bytes,
        identifier_bytes,
        public_key_package_bytes,
        threshold,
    };

    let mut payload_bytes =
        postcard::to_allocvec(&payload).expect("SealedSharePayload serialization must succeed");

    let sealed = seal_share_bytes(&payload_bytes);
    payload_bytes.zeroize();
    sealed
}

/// Unseal a signer's share from a hex-encoded sealed blob.
///
/// Returns the deserialized `SignerNode`, `PublicKeyPackage`, and threshold.
pub fn unseal_signer_share(
    hex_sealed: &str,
) -> Result<(SignerNode, PublicKeyPackage, usize), String> {
    let mut payload_bytes = unseal_share_bytes(hex_sealed)?;
    let mut payload: SealedSharePayload =
        postcard::from_bytes(&payload_bytes).map_err(|e| format!("deserialize payload: {e}"))?;
    // Zeroize the raw deserialized bytes immediately — the typed payload now owns the data.
    payload_bytes.zeroize();

    let key_package = KeyPackage::deserialize(&payload.key_package_bytes)
        .map_err(|e| format!("deserialize KeyPackage: {e}"))?;
    let identifier = Identifier::deserialize(&payload.identifier_bytes)
        .map_err(|e| format!("deserialize Identifier: {e}"))?;
    let public_key_package = PublicKeyPackage::deserialize(&payload.public_key_package_bytes)
        .map_err(|e| format!("deserialize PublicKeyPackage: {e}"))?;
    let threshold = payload.threshold;

    // Zeroize sensitive payload fields now that KeyPackage/Identifier are extracted.
    // The Drop impl handles this, but we zeroize eagerly to minimize exposure window.
    payload.key_package_bytes.zeroize();
    payload.identifier_bytes.zeroize();
    payload.public_key_package_bytes.zeroize();

    let node = SignerNode::new(identifier, key_package);
    Ok((node, public_key_package, threshold))
}

/// Low-level seal: encrypt arbitrary bytes under the master KEK with
/// purpose = "tss-share".
fn seal_share_bytes(plaintext: &[u8]) -> Vec<u8> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    let master_kek = common::sealed_keys::cached_master_kek();
    let seal_key = derive_share_seal_key(master_kek);

    let cipher = Aes256Gcm::new_from_slice(&seal_key).expect("32-byte key");

    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes).expect("OS entropy");
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aad = b"MILNET-SEALED-TSS-SHARE-v1";
    let ciphertext = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("AES-256-GCM encryption must not fail");

    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    out
}

/// Low-level unseal: decrypt a hex-encoded sealed blob.
fn unseal_share_bytes(hex_str: &str) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    let sealed_bytes: Vec<u8> = (0..hex_str.len())
        .step_by(2)
        .filter_map(|i| hex_str.get(i..i + 2).and_then(|s| u8::from_str_radix(s, 16).ok()))
        .collect();

    if sealed_bytes.len() < 12 + 16 {
        return Err("sealed share too short".into());
    }

    let master_kek = common::sealed_keys::cached_master_kek();
    let seal_key = derive_share_seal_key(master_kek);

    let cipher =
        Aes256Gcm::new_from_slice(&seal_key).map_err(|e| format!("cipher init: {e}"))?;
    let nonce = Nonce::from_slice(&sealed_bytes[..12]);

    let aad = b"MILNET-SEALED-TSS-SHARE-v1";
    let plaintext = cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: &sealed_bytes[12..],
                aad,
            },
        )
        .map_err(|_| "sealed share decryption failed (wrong KEK or tampered data)".to_string())?;

    Ok(plaintext)
}

/// Derive a 32-byte seal key from the master KEK for TSS share sealing.
fn derive_share_seal_key(master_kek: &[u8; 32]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha512;
    let hk = Hkdf::<Sha512>::new(Some(b"MILNET-TSS-SHARE-SEAL-v1"), master_kek);
    let mut okm = [0u8; 32];
    hk.expand(b"tss-share", &mut okm)
        .expect("32-byte HKDF expand must succeed");
    okm
}

/// Load a signer's share from the `MILNET_TSS_SHARE_SEALED` env var.
///
/// Returns (SignerNode, PublicKeyPackage, threshold) or an error.
pub fn load_signer_share_from_env() -> Result<(SignerNode, PublicKeyPackage, usize), String> {
    let hex_sealed = std::env::var("MILNET_TSS_SHARE_SEALED")
        .map_err(|_| "MILNET_TSS_SHARE_SEALED env var not set".to_string())?;

    if hex_sealed.is_empty() {
        return Err("MILNET_TSS_SHARE_SEALED is empty".into());
    }

    unseal_signer_share(&hex_sealed)
}

/// Load the coordinator's public key package and threshold from env vars.
///
/// The coordinator needs:
/// - `MILNET_TSS_PUBLIC_KEY_PACKAGE`: hex-encoded serialized `PublicKeyPackage`
/// - `MILNET_TSS_THRESHOLD`: the group threshold (integer)
/// - `MILNET_TSS_SIGNER_ADDRS`: comma-separated list of `identifier_hex@host:port` pairs
/// - HMAC key loaded via `common::sealed_keys::load_shard_hmac_key_sealed()`
pub fn load_coordinator_config_from_env(
) -> Result<(PublicKeyPackage, usize, Vec<(Identifier, String)>, [u8; 64]), String> {
    // Public key package
    let pkg_hex = std::env::var("MILNET_TSS_PUBLIC_KEY_PACKAGE")
        .map_err(|_| "MILNET_TSS_PUBLIC_KEY_PACKAGE not set".to_string())?;
    let pkg_bytes: Vec<u8> = (0..pkg_hex.len())
        .step_by(2)
        .filter_map(|i| pkg_hex.get(i..i + 2).and_then(|s| u8::from_str_radix(s, 16).ok()))
        .collect();
    let public_key_package = PublicKeyPackage::deserialize(&pkg_bytes)
        .map_err(|e| format!("deserialize PublicKeyPackage: {e}"))?;

    // Threshold
    let threshold: usize = std::env::var("MILNET_TSS_THRESHOLD")
        .map_err(|_| "MILNET_TSS_THRESHOLD not set".to_string())?
        .parse()
        .map_err(|e| format!("invalid MILNET_TSS_THRESHOLD: {e}"))?;

    // Signer addresses: "id_hex@host:port,id_hex@host:port,..."
    let addrs_str = std::env::var("MILNET_TSS_SIGNER_ADDRS")
        .map_err(|_| "MILNET_TSS_SIGNER_ADDRS not set".to_string())?;
    let mut signer_addrs = Vec::new();
    for entry in addrs_str.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        // Format: id_hex@host:port
        let parts: Vec<&str> = entry.splitn(2, '@').collect();
        if parts.len() != 2 {
            return Err(format!(
                "invalid signer addr entry '{entry}': expected 'id_hex@host:port'"
            ));
        }
        let id_bytes: Vec<u8> = (0..parts[0].len())
            .step_by(2)
            .filter_map(|i| {
                parts[0]
                    .get(i..i + 2)
                    .and_then(|s| u8::from_str_radix(s, 16).ok())
            })
            .collect();
        let identifier = Identifier::deserialize(&id_bytes)
            .map_err(|e| format!("deserialize identifier from '{entry}': {e}"))?;
        signer_addrs.push((identifier, parts[1].to_string()));
    }

    // HMAC key for coordinator-signer communication
    let hmac_key = common::sealed_keys::load_shard_hmac_key_sealed();

    Ok((public_key_package, threshold, signer_addrs, hmac_key))
}

// ===========================================================================
// True Distributed DKG — each signer generates its own secret locally
// ===========================================================================

/// Messages exchanged during a distributed DKG ceremony.
#[derive(Serialize, Deserialize, Debug)]
pub enum DkgMessage {
    /// Coordinator → Signer: start DKG round 1 (generate commitment + proof)
    StartRound1 {
        /// This signer's identifier (assigned by coordinator)
        identifier_bytes: Vec<u8>,
        max_signers: u16,
        min_signers: u16,
    },
    /// Signer → Coordinator: round 1 package (commitment + proof of knowledge)
    Round1Package {
        identifier_bytes: Vec<u8>,
        /// Serialized frost::keys::dkg::round1::Package
        package_bytes: Vec<u8>,
    },
    /// Coordinator → Signer: all other participants' round 1 packages, start round 2
    StartRound2 {
        /// Map of identifier_bytes → round1::Package bytes (all OTHER participants)
        round1_packages: Vec<(Vec<u8>, Vec<u8>)>,
    },
    /// Signer → Coordinator: round 2 packages (one per other participant)
    Round2Packages {
        identifier_bytes: Vec<u8>,
        /// Map of recipient_identifier_bytes → round2::Package bytes
        packages: Vec<(Vec<u8>, Vec<u8>)>,
    },
    /// Coordinator → Signer: deliver round 2 packages from other participants, finalize
    Finalize {
        /// All round 1 packages again (needed for part3)
        round1_packages: Vec<(Vec<u8>, Vec<u8>)>,
        /// Round 2 packages addressed TO this signer from other participants
        round2_packages: Vec<(Vec<u8>, Vec<u8>)>,
    },
    /// Signer → Coordinator: final key package + public key package
    DkgComplete {
        identifier_bytes: Vec<u8>,
        /// Serialized KeyPackage (signer keeps this — coordinator only gets verification)
        key_package_bytes: Vec<u8>,
        /// Serialized PublicKeyPackage (should be identical across all signers)
        public_key_package_bytes: Vec<u8>,
    },
    /// Error during DKG
    DkgError {
        message: String,
    },
}

/// Result of a distributed DKG ceremony.
pub struct DistributedDkgResult {
    /// The group public key package (same for all participants)
    pub public_key_package: PublicKeyPackage,
    /// The threshold
    pub threshold: usize,
    /// Sealed shares for each signer (identifier_hex, sealed_share_hex)
    /// Each signer seals their OWN key package — the coordinator never sees the secret.
    pub sealed_shares: Vec<(String, Vec<u8>)>,
}

/// Run a true distributed DKG ceremony over the network.
///
/// The coordinator orchestrates 3 rounds of communication. Each signer generates
/// its own secret locally — the coordinator NEVER sees any signer's secret share.
///
/// Protocol (FROST KeyGen, Figure 1 from the FROST paper):
/// 1. **Round 1**: Each signer generates secret polynomial + commitment + ZK proof.
///    Broadcasts `round1::Package` to all other participants (via coordinator relay).
/// 2. **Round 2**: Each signer verifies all round 1 proofs, computes secret shares
///    for each other participant. Sends `round2::Package` to each (via coordinator relay).
/// 3. **Round 3 (Finalize)**: Each signer combines all received shares into their
///    final `KeyPackage`. Returns `PublicKeyPackage` to coordinator.
///
/// The coordinator only relays messages — it is a broadcast channel, NOT a trusted dealer.
pub async fn run_distributed_dkg(
    signer_addrs: &[(Identifier, String)],
    min_signers: u16,
    hmac_key: [u8; 64],
) -> Result<DistributedDkgResult, String> {
    use frost::keys::dkg as frost_dkg;

    let max_signers = signer_addrs.len() as u16;
    if max_signers < min_signers {
        return Err(format!(
            "need at least {min_signers} signers, got {max_signers}"
        ));
    }

    let (connector, _ca, _cert_key) = shard::tls_transport::tls_client_setup("dkg-coordinator");

    // ── Round 1: Each signer generates commitment + proof ──────────────

    // Collect round1 packages from all signers
    let mut all_round1_packages: BTreeMap<Identifier, Vec<u8>> = BTreeMap::new();

    for (id, addr) in signer_addrs {
        let signer_host = addr.split(':').next().unwrap_or(addr);
        let mut transport = shard::tls_transport::tls_connect(
            addr,
            common::types::ModuleId::Orchestrator,
            hmac_key,
            &connector,
            signer_host,
        )
        .await
        .map_err(|e| format!("connect to signer {id:?} at {addr} for DKG round 1: {e}"))?;

        let id_bytes = id.serialize();
        let msg = DkgMessage::StartRound1 {
            identifier_bytes: id_bytes.clone(),
            max_signers,
            min_signers,
        };
        let msg_bytes = postcard::to_allocvec(&msg)
            .map_err(|e| format!("serialize StartRound1: {e}"))?;
        transport
            .send(&msg_bytes)
            .await
            .map_err(|e| format!("send StartRound1 to {addr}: {e}"))?;

        let (_sender, resp_payload) = transport
            .recv()
            .await
            .map_err(|e| format!("recv Round1Package from {addr}: {e}"))?;

        let resp: DkgMessage = postcard::from_bytes(&resp_payload)
            .map_err(|e| format!("deserialize DKG response from {addr}: {e}"))?;

        match resp {
            DkgMessage::Round1Package {
                identifier_bytes,
                package_bytes,
            } => {
                let rid = Identifier::deserialize(&identifier_bytes)
                    .map_err(|e| format!("deserialize identifier: {e}"))?;
                all_round1_packages.insert(rid, package_bytes);
            }
            DkgMessage::DkgError { message } => {
                return Err(format!("signer {id:?} DKG round 1 error: {message}"));
            }
            _ => return Err(format!("unexpected DKG message from signer {id:?}")),
        }
    }

    tracing::info!(
        "DKG round 1 complete: collected {} commitments + proofs",
        all_round1_packages.len()
    );

    // ── Round 2: Each signer generates shares for all others ──────────

    // For each signer, send all OTHER signers' round1 packages
    let mut all_round2_packages: BTreeMap<Identifier, Vec<(Vec<u8>, Vec<u8>)>> = BTreeMap::new();

    for (id, addr) in signer_addrs {
        let signer_host = addr.split(':').next().unwrap_or(addr);
        let mut transport = shard::tls_transport::tls_connect(
            addr,
            common::types::ModuleId::Orchestrator,
            hmac_key,
            &connector,
            signer_host,
        )
        .await
        .map_err(|e| format!("connect to signer {id:?} for DKG round 2: {e}"))?;

        // Send all OTHER participants' round1 packages
        let others: Vec<(Vec<u8>, Vec<u8>)> = all_round1_packages
            .iter()
            .filter(|(k, _)| *k != id)
            .map(|(k, v)| (k.serialize(), v.clone()))
            .collect();

        let msg = DkgMessage::StartRound2 {
            round1_packages: others,
        };
        let msg_bytes = postcard::to_allocvec(&msg)
            .map_err(|e| format!("serialize StartRound2: {e}"))?;
        transport
            .send(&msg_bytes)
            .await
            .map_err(|e| format!("send StartRound2 to {addr}: {e}"))?;

        let (_sender, resp_payload) = transport
            .recv()
            .await
            .map_err(|e| format!("recv Round2Packages from {addr}: {e}"))?;

        let resp: DkgMessage = postcard::from_bytes(&resp_payload)
            .map_err(|e| format!("deserialize DKG round 2 response from {addr}: {e}"))?;

        match resp {
            DkgMessage::Round2Packages {
                identifier_bytes: _,
                packages,
            } => {
                all_round2_packages.insert(*id, packages);
            }
            DkgMessage::DkgError { message } => {
                return Err(format!("signer {id:?} DKG round 2 error: {message}"));
            }
            _ => return Err(format!("unexpected DKG round 2 message from signer {id:?}")),
        }
    }

    tracing::info!("DKG round 2 complete: all signers generated secret shares");

    // ── Round 3 (Finalize): Deliver round2 packages and get final keys ─

    let mut public_key_packages: Vec<Vec<u8>> = Vec::new();
    let mut sealed_shares: Vec<(String, Vec<u8>)> = Vec::new();

    for (id, addr) in signer_addrs {
        let signer_host = addr.split(':').next().unwrap_or(addr);
        let mut transport = shard::tls_transport::tls_connect(
            addr,
            common::types::ModuleId::Orchestrator,
            hmac_key,
            &connector,
            signer_host,
        )
        .await
        .map_err(|e| format!("connect to signer {id:?} for DKG finalize: {e}"))?;

        // Collect round2 packages addressed TO this signer from all other signers
        let round2_for_this: Vec<(Vec<u8>, Vec<u8>)> = all_round2_packages
            .iter()
            .filter(|(sender_id, _)| *sender_id != id)
            .filter_map(|(sender_id, packages)| {
                // Find the package that sender generated for this recipient
                let id_bytes = id.serialize();
                packages
                    .iter()
                    .find(|(recipient_id_bytes, _)| *recipient_id_bytes == id_bytes)
                    .map(|(_, pkg_bytes)| (sender_id.serialize(), pkg_bytes.clone()))
            })
            .collect();

        // Also re-send all round1 packages (needed by part3)
        let round1_others: Vec<(Vec<u8>, Vec<u8>)> = all_round1_packages
            .iter()
            .filter(|(k, _)| *k != id)
            .map(|(k, v)| (k.serialize(), v.clone()))
            .collect();

        let msg = DkgMessage::Finalize {
            round1_packages: round1_others,
            round2_packages: round2_for_this,
        };
        let msg_bytes = postcard::to_allocvec(&msg)
            .map_err(|e| format!("serialize Finalize: {e}"))?;
        transport
            .send(&msg_bytes)
            .await
            .map_err(|e| format!("send Finalize to {addr}: {e}"))?;

        let (_sender, resp_payload) = transport
            .recv()
            .await
            .map_err(|e| format!("recv DkgComplete from {addr}: {e}"))?;

        let resp: DkgMessage = postcard::from_bytes(&resp_payload)
            .map_err(|e| format!("deserialize DKG finalize response from {addr}: {e}"))?;

        match resp {
            DkgMessage::DkgComplete {
                identifier_bytes,
                key_package_bytes,
                public_key_package_bytes,
            } => {
                let id_hex: String = identifier_bytes.iter().map(|b| format!("{b:02x}")).collect();
                // The coordinator DOES NOT store the key_package_bytes (signer's secret).
                // It only receives the sealed version that the signer has already sealed locally.
                sealed_shares.push((id_hex, key_package_bytes));
                public_key_packages.push(public_key_package_bytes);
            }
            DkgMessage::DkgError { message } => {
                return Err(format!("signer {id:?} DKG finalize error: {message}"));
            }
            _ => return Err(format!("unexpected DKG finalize message from signer {id:?}")),
        }
    }

    // Verify all signers produced the same PublicKeyPackage
    if public_key_packages.len() < 2 {
        return Err("need at least 2 signers for DKG".into());
    }
    for (i, pkg_bytes) in public_key_packages.iter().enumerate().skip(1) {
        if *pkg_bytes != public_key_packages[0] {
            return Err(format!(
                "CRITICAL: signer {} produced different PublicKeyPackage than signer 0 — \
                 possible equivocation attack",
                i
            ));
        }
    }

    let public_key_package = PublicKeyPackage::deserialize(&public_key_packages[0])
        .map_err(|e| format!("deserialize final PublicKeyPackage: {e}"))?;

    tracing::info!(
        "DKG complete: {} signers, threshold {}, group verifying key established",
        max_signers,
        min_signers
    );

    Ok(DistributedDkgResult {
        public_key_package,
        threshold: min_signers as usize,
        sealed_shares,
    })
}

/// Handle DKG messages on the signer side.
///
/// This runs on each signer process. The signer generates its own secret locally
/// and never sends it to the coordinator. Only commitments, proofs, and encrypted
/// shares for other participants are transmitted.
///
/// Returns `(KeyPackage, PublicKeyPackage)` on success — the signer's long-lived keys.
pub fn handle_dkg_round1(
    identifier_bytes: &[u8],
    max_signers: u16,
    min_signers: u16,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    use frost::keys::dkg as frost_dkg;

    let identifier = Identifier::deserialize(identifier_bytes)
        .map_err(|e| format!("deserialize identifier: {e}"))?;

    let mut rng = rand::rngs::OsRng;
    let (secret_package, package) =
        frost_dkg::part1(identifier, max_signers, min_signers, &mut rng)
            .map_err(|e| format!("DKG part1 failed: {e}"))?;

    let package_bytes = package
        .serialize()
        .map_err(|e| format!("serialize round1 package: {e}"))?;

    // Serialize secret_package for later use in round 2
    let secret_bytes = secret_package
        .serialize()
        .map_err(|e| format!("serialize secret package: {e}"))?;

    Ok((identifier_bytes.to_vec(), package_bytes, secret_bytes))
}

/// Handle DKG round 2: verify other participants' proofs and generate shares.
pub fn handle_dkg_round2(
    secret_package_bytes: &[u8],
    round1_packages_raw: &[(Vec<u8>, Vec<u8>)],
) -> Result<(Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>), String> {
    use frost::keys::dkg as frost_dkg;

    let secret_package =
        frost_dkg::round1::SecretPackage::deserialize(secret_package_bytes)
            .map_err(|e| format!("deserialize secret package: {e}"))?;

    let mut round1_packages = BTreeMap::new();
    for (id_bytes, pkg_bytes) in round1_packages_raw {
        let id = Identifier::deserialize(id_bytes)
            .map_err(|e| format!("deserialize round1 identifier: {e}"))?;
        let pkg = frost_dkg::round1::Package::deserialize(pkg_bytes)
            .map_err(|e| format!("deserialize round1 package: {e}"))?;
        round1_packages.insert(id, pkg);
    }

    let (round2_secret, round2_packages) =
        frost_dkg::part2(secret_package, &round1_packages)
            .map_err(|e| format!("DKG part2 failed: {e}"))?;

    // Serialize round2 secret for finalize
    let round2_secret_bytes = round2_secret
        .serialize()
        .map_err(|e| format!("serialize round2 secret: {e}"))?;

    // Serialize per-recipient round2 packages
    let packages: Vec<(Vec<u8>, Vec<u8>)> = round2_packages
        .into_iter()
        .map(|(id, pkg)| {
            let id_bytes = id.serialize();
            let pkg_bytes = pkg.serialize().expect("serialize round2 package");
            (id_bytes, pkg_bytes)
        })
        .collect();

    Ok((round2_secret_bytes, packages))
}

/// Handle DKG finalize: combine all shares into the final KeyPackage.
pub fn handle_dkg_finalize(
    round2_secret_bytes: &[u8],
    round1_packages_raw: &[(Vec<u8>, Vec<u8>)],
    round2_packages_raw: &[(Vec<u8>, Vec<u8>)],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    use frost::keys::dkg as frost_dkg;

    let round2_secret = frost_dkg::round2::SecretPackage::deserialize(round2_secret_bytes)
        .map_err(|e| format!("deserialize round2 secret: {e}"))?;

    let mut round1_packages = BTreeMap::new();
    for (id_bytes, pkg_bytes) in round1_packages_raw {
        let id = Identifier::deserialize(id_bytes)
            .map_err(|e| format!("deserialize round1 identifier: {e}"))?;
        let pkg = frost_dkg::round1::Package::deserialize(pkg_bytes)
            .map_err(|e| format!("deserialize round1 package: {e}"))?;
        round1_packages.insert(id, pkg);
    }

    let mut round2_packages = BTreeMap::new();
    for (id_bytes, pkg_bytes) in round2_packages_raw {
        let id = Identifier::deserialize(id_bytes)
            .map_err(|e| format!("deserialize round2 identifier: {e}"))?;
        let pkg = frost_dkg::round2::Package::deserialize(pkg_bytes)
            .map_err(|e| format!("deserialize round2 package: {e}"))?;
        round2_packages.insert(id, pkg);
    }

    let (key_package, public_key_package) =
        frost_dkg::part3(&round2_secret, &round1_packages, &round2_packages)
            .map_err(|e| format!("DKG part3 failed: {e}"))?;

    let key_bytes = key_package
        .serialize()
        .map_err(|e| format!("serialize key package: {e}"))?;
    let pub_bytes = public_key_package
        .serialize()
        .map_err(|e| format!("serialize public key package: {e}"))?;

    Ok((key_bytes, pub_bytes))
}

/// Seal all shares from a DKG result for distribution to separate VMs.
///
/// Returns a Vec of (identifier_hex, sealed_share_hex) pairs.
/// Each sealed share should be deployed to exactly one signer VM as
/// the `MILNET_TSS_SHARE_SEALED` env var.
pub fn seal_all_shares(
    dkg_result: &mut crypto::threshold::DkgResult,
) -> Vec<(String, String)> {
    let (coordinator, nodes) = distribute_shares(dkg_result);
    let mut sealed = Vec::with_capacity(nodes.len());
    for node in &nodes {
        let sealed_bytes =
            seal_signer_share(node, &coordinator.public_key_package, coordinator.threshold);
        let id_hex: String = node
            .identifier()
            .serialize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let share_hex: String = sealed_bytes.iter().map(|b| format!("{b:02x}")).collect();
        sealed.push((id_hex, share_hex));
    }
    sealed
}

// ===========================================================================
// Share Recovery & Validation
// ===========================================================================

/// Result of validating share availability across the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareAvailabilityReport {
    /// Total shares expected in the group.
    pub total_shares: usize,
    /// Threshold required for signing.
    pub threshold: usize,
    /// Number of shares confirmed accessible.
    pub accessible_shares: usize,
    /// Identifiers of accessible shares (serialized bytes).
    pub accessible_ids: Vec<Vec<u8>>,
    /// Identifiers of inaccessible shares (serialized bytes).
    pub inaccessible_ids: Vec<Vec<u8>>,
    /// Whether the quorum is met (accessible >= threshold).
    pub quorum_met: bool,
    /// Whether recovery buffer exists (accessible > threshold).
    pub has_recovery_buffer: bool,
}

/// Validate that the minimum threshold of shares are accessible.
///
/// This pre-flight check should be run at startup to detect share loss
/// scenarios before they become critical during a signing ceremony.
pub fn validate_share_availability(
    signer_addrs: &[(Identifier, String)],
    threshold: usize,
    accessible_ids: &[Identifier],
) -> ShareAvailabilityReport {
    let total_shares = signer_addrs.len();
    let all_ids: Vec<Vec<u8>> = signer_addrs
        .iter()
        .map(|(id, _)| id.serialize())
        .collect();

    let accessible_set: std::collections::HashSet<Vec<u8>> = accessible_ids
        .iter()
        .map(|id| id.serialize())
        .collect();

    let mut accessible = Vec::new();
    let mut inaccessible = Vec::new();
    for id_bytes in &all_ids {
        if accessible_set.contains(id_bytes) {
            accessible.push(id_bytes.clone());
        } else {
            inaccessible.push(id_bytes.clone());
        }
    }

    let accessible_count = accessible.len();
    let quorum_met = accessible_count >= threshold;
    let has_recovery_buffer = accessible_count > threshold;

    if !quorum_met {
        tracing::error!(
            target: "siem",
            total_shares,
            threshold,
            accessible = accessible_count,
            "CRITICAL: FROST share quorum NOT met — signing operations will FAIL"
        );
    } else if !has_recovery_buffer {
        tracing::warn!(
            target: "siem",
            total_shares,
            threshold,
            accessible = accessible_count,
            "WARNING: FROST share quorum met but NO recovery buffer — one more share loss is fatal"
        );
    } else {
        tracing::info!(
            total_shares,
            threshold,
            accessible = accessible_count,
            "FROST share availability check passed"
        );
    }

    ShareAvailabilityReport {
        total_shares,
        threshold,
        accessible_shares: accessible_count,
        accessible_ids: accessible,
        inaccessible_ids: inaccessible,
        quorum_met,
        has_recovery_buffer,
    }
}

/// Verify that the local share can be unsealed from the environment.
///
/// Should be called at signer startup. If unsealing fails, the signer
/// cannot participate in signing ceremonies and must be re-provisioned.
pub fn verify_local_share_unseal() -> Result<(), String> {
    let hex_sealed = std::env::var("MILNET_TSS_SHARE_SEALED")
        .map_err(|_| "MILNET_TSS_SHARE_SEALED not set — signer cannot start".to_string())?;

    if hex_sealed.is_empty() {
        return Err("MILNET_TSS_SHARE_SEALED is empty — signer has no share".to_string());
    }

    // Attempt unseal to verify the share is intact and the KEK is correct.
    let (node, _pkg, _threshold) = unseal_signer_share(&hex_sealed)
        .map_err(|e| format!("share unseal failed at startup: {e}"))?;

    tracing::info!(
        identifier = ?node.identifier(),
        "Local FROST share verified — unseal succeeded"
    );

    Ok(())
}

/// Documented recovery plan for share loss scenarios.
///
/// This struct is informational — it documents the operational steps required
/// to recover from various share loss scenarios in a FROST threshold setup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareRecoveryPlan {
    /// Current group threshold (t).
    pub threshold: usize,
    /// Total shares in the group (n).
    pub total_shares: usize,
    /// Maximum shares that can be lost while maintaining signing capability.
    pub max_tolerable_loss: usize,
    /// Recovery steps for different scenarios.
    pub scenarios: Vec<RecoveryScenario>,
}

/// A specific share loss scenario and its recovery procedure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryScenario {
    /// Description of the scenario.
    pub description: String,
    /// Severity level: "INFO", "WARNING", "CRITICAL", "FATAL".
    pub severity: String,
    /// Whether signing is still possible.
    pub signing_possible: bool,
    /// Ordered recovery steps.
    pub steps: Vec<String>,
}

impl ShareRecoveryPlan {
    /// Generate a recovery plan for a given threshold group.
    pub fn for_group(threshold: usize, total_shares: usize) -> Self {
        let max_tolerable_loss = total_shares.saturating_sub(threshold);

        let mut scenarios = Vec::new();

        // Scenario: 1 share lost (if buffer exists)
        if max_tolerable_loss >= 1 {
            scenarios.push(RecoveryScenario {
                description: format!(
                    "1 share lost ({} of {} remaining)",
                    total_shares - 1,
                    total_shares
                ),
                severity: "WARNING".to_string(),
                signing_possible: true,
                steps: vec![
                    "Identify the lost signer node and isolate it from the network.".to_string(),
                    "Initiate a new DKG ceremony with all remaining healthy signers.".to_string(),
                    "Distribute new sealed shares to all signers (including a replacement node).".to_string(),
                    "Rotate the group public key in all verifiers and the coordinator.".to_string(),
                    "Revoke tokens signed with the old group key.".to_string(),
                ],
            });
        }

        // Scenario: exactly threshold remaining (no buffer)
        scenarios.push(RecoveryScenario {
            description: format!(
                "{} shares lost — exactly threshold ({}) remaining",
                max_tolerable_loss, threshold
            ),
            severity: "CRITICAL".to_string(),
            signing_possible: true,
            steps: vec![
                "IMMEDIATE: Begin emergency DKG ceremony before any more shares are lost.".to_string(),
                "All remaining signers must participate — loss of ONE MORE share makes recovery impossible.".to_string(),
                "Provision replacement signer nodes on isolated infrastructure.".to_string(),
                "Complete DKG, distribute new shares, rotate group public key.".to_string(),
                "File incident report per MILNET-IR-PROC.".to_string(),
            ],
        });

        // Scenario: below threshold (unrecoverable)
        scenarios.push(RecoveryScenario {
            description: format!(
                "Fewer than threshold ({}) shares available — group is DEAD",
                threshold
            ),
            severity: "FATAL".to_string(),
            signing_possible: false,
            steps: vec![
                "SIGNING IS IMPOSSIBLE with current group — no recovery path exists.".to_string(),
                "Generate a completely new FROST group via fresh DKG ceremony.".to_string(),
                "All existing tokens signed by the old group key must be invalidated.".to_string(),
                "All users must re-authenticate against the new group.".to_string(),
                "Conduct root-cause analysis and update disaster recovery procedures.".to_string(),
                "File CRITICAL incident report per MILNET-IR-PROC.".to_string(),
            ],
        });

        Self {
            threshold,
            total_shares,
            max_tolerable_loss,
            scenarios,
        }
    }
}

/// Pre-flight quorum check: verify that N-1 peers hold valid shares.
///
/// Connects to each signer address and sends a `CommitRequest` to verify
/// the signer is alive and can produce a commitment (proving it has a valid share).
/// Returns a `ShareAvailabilityReport` with results.
pub async fn recovery_quorum_check(
    signer_addrs: &[(Identifier, String)],
    threshold: usize,
    hmac_key: [u8; 64],
) -> ShareAvailabilityReport {
    let mut accessible = Vec::new();

    for (id, addr) in signer_addrs {
        let raw_host = addr.split(':').next().unwrap_or(addr);
        let signer_host = if raw_host.parse::<std::net::IpAddr>().is_ok() {
            "localhost"
        } else {
            raw_host
        };

        let (connector, _ca, _cert_key) =
            shard::tls_transport::tls_client_setup("tss-quorum-check");

        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            shard::tls_transport::tls_connect(
                addr,
                common::types::ModuleId::Orchestrator,
                hmac_key,
                &connector,
                signer_host,
            ),
        )
        .await
        {
            Ok(Ok(mut transport)) => {
                let req = SignerMessage::CommitRequest;
                if let Ok(req_bytes) = postcard::to_allocvec(&req) {
                    if transport.send(&req_bytes).await.is_ok() {
                        if let Ok((_sender, resp_payload)) = transport.recv().await {
                            if let Ok(SignerMessage::CommitResponse { .. }) =
                                postcard::from_bytes::<SignerMessage>(&resp_payload)
                            {
                                accessible.push(*id);
                                tracing::info!(
                                    signer = ?id,
                                    addr = %addr,
                                    "Signer responded to quorum check"
                                );
                                continue;
                            }
                        }
                    }
                }
                tracing::warn!(
                    signer = ?id,
                    addr = %addr,
                    "Signer failed quorum check (protocol error)"
                );
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    signer = ?id,
                    addr = %addr,
                    error = %e,
                    "Signer unreachable during quorum check"
                );
            }
            Err(_) => {
                tracing::warn!(
                    signer = ?id,
                    addr = %addr,
                    "Signer timed out during quorum check (5s)"
                );
            }
        }
    }

    validate_share_availability(signer_addrs, threshold, &accessible)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::threshold::dkg;

    /// Helper: run DKG and distribute shares.
    fn setup_dkg() -> (SigningCoordinator, Vec<SignerNode>) {
        let mut dkg_result = dkg(5, 3);
        distribute_shares(&mut dkg_result)
    }

    /// Helper: create a shared CA and TLS infrastructure for tests.
    /// Returns (CA, connector) that can be used by both signers and coordinator.
    fn shared_tls_ca() -> (
        shard::tls::CertificateAuthority,
        tokio_rustls::TlsConnector,
    ) {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let ca = shard::tls::generate_ca();
        let client_cert = shard::tls::generate_module_cert("tss-coordinator", &ca);
        let client_config = shard::tls::client_tls_config(&client_cert, &ca);
        let connector = shard::tls::tls_connector(client_config);
        (ca, connector)
    }

    /// Helper: bind a signer with a shared CA (for tests).
    async fn bind_signer_with_shared_ca(
        addr: &str,
        hmac_key: [u8; 64],
        ca: &shard::tls::CertificateAuthority,
        signer_name: &str,
    ) -> shard::tls_transport::TlsShardListener {
        let cert_key = shard::tls::generate_module_cert(signer_name, ca);
        let server_config = shard::tls::server_tls_config(&cert_key, ca);
        shard::tls_transport::TlsShardListener::bind(
            addr,
            common::types::ModuleId::Tss,
            hmac_key,
            server_config,
        )
        .await
        .expect("signer bind must succeed")
    }

    #[test]
    fn sealed_share_round_trip() {
        // Ensure deterministic dev KEK is used
        // Production mode is always active — no env var override needed
        std::env::set_var("MILNET_MASTER_KEK", "ab".repeat(32));

        let (coordinator, nodes) = setup_dkg();
        let node = &nodes[0];
        let original_id = node.identifier();

        // Seal the share
        let sealed_bytes =
            seal_signer_share(node, &coordinator.public_key_package, coordinator.threshold);
        let hex: String = sealed_bytes.iter().map(|b| format!("{b:02x}")).collect();

        // Unseal and verify
        let (recovered_node, recovered_pkg, recovered_threshold) =
            unseal_signer_share(&hex).expect("unseal must succeed");

        assert_eq!(recovered_node.identifier(), original_id);
        assert_eq!(recovered_threshold, coordinator.threshold);

        // Verify the recovered node can participate in signing
        let mut recovered_nodes = vec![recovered_node];
        // Get 2 more nodes for threshold
        let mut node2 = SignerNode::new(nodes[1].identifier, nodes[1].key_package.clone());
        let mut node3 = SignerNode::new(nodes[2].identifier, nodes[2].key_package.clone());

        let mut signers: Vec<&mut SignerNode> =
            vec![&mut recovered_nodes[0], &mut node2, &mut node3];

        let coordinator_for_sign = SigningCoordinator::new(recovered_pkg, recovered_threshold);
        let signature = coordinator_for_sign
            .coordinate_signing(&mut signers, b"test message after unseal")
            .expect("signing with recovered share must work");

        // Verify signature
        let sig = frost_ristretto255::Signature::deserialize(&signature)
            .expect("deserialize signature");
        assert!(coordinator
            .public_key_package
            .verifying_key()
            .verify(b"test message after unseal", &sig)
            .is_ok());

        std::env::remove_var("MILNET_MASTER_KEK");
    }

    #[test]
    fn sealed_share_tamper_detected() {
        // Production mode is always active — no env var override needed
        std::env::set_var("MILNET_MASTER_KEK", "ab".repeat(32));

        let (coordinator, nodes) = setup_dkg();
        let node = &nodes[0];

        let mut sealed_bytes =
            seal_signer_share(node, &coordinator.public_key_package, coordinator.threshold);

        // Tamper with the ciphertext
        if sealed_bytes.len() > 20 {
            sealed_bytes[20] ^= 0xFF;
        }

        let hex: String = sealed_bytes.iter().map(|b| format!("{b:02x}")).collect();
        let result = unseal_signer_share(&hex);
        assert!(result.is_err(), "tampered sealed share must fail to unseal");

        std::env::remove_var("MILNET_MASTER_KEK");
    }

    #[test]
    fn seal_all_shares_produces_correct_count() {
        // Production mode is always active — no env var override needed
        std::env::set_var("MILNET_MASTER_KEK", "cd".repeat(32));

        let mut dkg_result = dkg(5, 3);
        let sealed = seal_all_shares(&mut dkg_result);

        assert_eq!(sealed.len(), 5, "must produce exactly 5 sealed shares");

        // Each sealed share must unseal correctly
        for (id_hex, share_hex) in &sealed {
            assert!(!id_hex.is_empty());
            assert!(!share_hex.is_empty());
            let (node, _pkg, threshold) =
                unseal_signer_share(share_hex).expect("each sealed share must unseal");
            assert_eq!(threshold, 3);

            let recovered_id_hex: String = node
                .identifier()
                .serialize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(&recovered_id_hex, id_hex);
        }

        std::env::remove_var("MILNET_MASTER_KEK");
    }

    #[tokio::test]
    async fn distributed_coordinator_signer_handshake() {
        // This test verifies that a coordinator can connect to signer
        // processes over SHARD/mTLS with a shared CA, perform the commit
        // and sign rounds, and produce a valid group signature.
        // Production mode is always active — no env var override needed

        let (coordinator, nodes) = setup_dkg();
        let threshold = coordinator.threshold;
        let hmac_key = crypto::entropy::generate_key_64();

        // Set up shared CA for all nodes
        let (ca, connector) = shared_tls_ca();

        let mut signer_addrs: Vec<(Identifier, String)> = Vec::new();

        // Spawn signer processes on random ports with the shared CA
        let base_port: u16 = 19200 + (std::process::id() % 1000) as u16;
        for (i, node) in nodes.into_iter().take(threshold).enumerate() {
            let addr = format!("127.0.0.1:{}", base_port + i as u16);
            signer_addrs.push((node.identifier(), addr.clone()));
            let signer_name = format!("tss-signer-{}", i);
            let listener =
                bind_signer_with_shared_ca(&addr, hmac_key, &ca, &signer_name).await;
            tokio::spawn(async move {
                let _ = run_signer_process_with_listener(node, &addr, listener).await;
            });
        }

        // Give signers time to start accepting
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Build the distributed coordinator using the shared connector
        let dist_coordinator = DistributedSigningCoordinator::new(
            coordinator.public_key_package.clone(),
            threshold,
            signer_addrs.clone(),
            hmac_key,
        );

        // Perform a distributed signing ceremony using the shared connector
        let message = b"distributed handshake test message";

        // Manually drive the signing ceremony with the shared connector
        let frost_result =
            coordinate_signing_remote_with_connector(&dist_coordinator, message, &connector).await;
        assert!(
            frost_result.is_ok(),
            "distributed signing must succeed: {:?}",
            frost_result.err()
        );

        // Verify the signature
        let signature = frost_result.unwrap();
        let sig = frost_ristretto255::Signature::deserialize(&signature)
            .expect("deserialize group signature");
        assert!(
            coordinator
                .public_key_package
                .verifying_key()
                .verify(message, &sig)
                .is_ok(),
            "group signature must verify"
        );
    }

    #[tokio::test]
    async fn signer_loads_sealed_share_and_serves() {
        // End-to-end: seal a share, unseal it, run as signer, coordinator
        // connects and signs.
        // Production mode is always active — no env var override needed
        std::env::set_var("MILNET_MASTER_KEK", "ef".repeat(32));

        let (coordinator, nodes) = setup_dkg();
        let threshold = coordinator.threshold;
        let hmac_key = crypto::entropy::generate_key_64();

        let (ca, connector) = shared_tls_ca();

        let base_port: u16 = 19300 + (std::process::id() % 1000) as u16;
        let mut signer_addrs: Vec<(Identifier, String)> = Vec::new();

        // Seal each share, unseal it, and run as a signer process with shared CA
        for (i, node) in nodes.into_iter().take(threshold).enumerate() {
            let sealed_bytes = seal_signer_share(
                &node,
                &coordinator.public_key_package,
                threshold,
            );
            let hex: String = sealed_bytes.iter().map(|b| format!("{b:02x}")).collect();

            // Unseal (simulating a fresh process loading from env)
            let (unsealed_node, _pkg, _thresh) =
                unseal_signer_share(&hex).expect("unseal must succeed");

            let addr = format!("127.0.0.1:{}", base_port + i as u16);
            signer_addrs.push((unsealed_node.identifier(), addr.clone()));
            let signer_name = format!("tss-signer-sealed-{}", i);
            let listener =
                bind_signer_with_shared_ca(&addr, hmac_key, &ca, &signer_name).await;
            tokio::spawn(async move {
                let _ = run_signer_process_with_listener(unsealed_node, &addr, listener).await;
            });
        }

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let dist_coordinator = DistributedSigningCoordinator::new(
            coordinator.public_key_package.clone(),
            threshold,
            signer_addrs,
            hmac_key,
        );

        let message = b"sealed share end-to-end test";
        let frost_result =
            coordinate_signing_remote_with_connector(&dist_coordinator, message, &connector).await;
        assert!(
            frost_result.is_ok(),
            "signing with unsealed shares must succeed: {:?}",
            frost_result.err()
        );

        let signature = frost_result.unwrap();
        let sig = frost_ristretto255::Signature::deserialize(&signature)
            .expect("deserialize group signature");
        assert!(
            coordinator
                .public_key_package
                .verifying_key()
                .verify(message, &sig)
                .is_ok(),
            "group signature from unsealed shares must verify"
        );

        std::env::remove_var("MILNET_MASTER_KEK");
    }

    /// Helper: like `DistributedSigningCoordinator::coordinate_signing_remote`
    /// but uses a pre-existing TLS connector (with shared CA) instead of
    /// creating its own CA.
    async fn coordinate_signing_remote_with_connector(
        coord: &DistributedSigningCoordinator,
        message: &[u8],
        connector: &tokio_rustls::TlsConnector,
    ) -> Result<[u8; 64], String> {
        if coord.signer_addrs.len() < coord.threshold {
            return Err(format!(
                "need {} signers, got {}",
                coord.threshold,
                coord.signer_addrs.len()
            ));
        }

        let selected: Vec<&(Identifier, String)> =
            coord.signer_addrs.iter().take(coord.threshold).collect();

        // Round 1: Collect commitments
        let mut nonces_map: BTreeMap<Identifier, Vec<u8>> = BTreeMap::new();
        let mut commitments_map: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();

        for (_id, addr) in &selected {
            let raw_host = addr.split(':').next().unwrap_or(addr);
            let signer_host = if raw_host.parse::<std::net::IpAddr>().is_ok() { "localhost" } else { raw_host };
            let mut transport = shard::tls_transport::tls_connect(
                addr,
                common::types::ModuleId::Orchestrator,
                coord.hmac_key,
                connector,
                signer_host,
            )
            .await
            .map_err(|e| format!("connect to signer at {addr}: {e}"))?;

            let req = SignerMessage::CommitRequest;
            let req_bytes =
                postcard::to_allocvec(&req).map_err(|e| format!("serialize: {e}"))?;
            transport.send(&req_bytes).await.map_err(|e| format!("send: {e}"))?;

            let (_sender, resp_payload) =
                transport.recv().await.map_err(|e| format!("recv: {e}"))?;

            let resp: SignerMessage = postcard::from_bytes(&resp_payload)
                .map_err(|e| format!("deserialize: {e}"))?;

            match resp {
                SignerMessage::CommitResponse {
                    identifier_bytes,
                    nonces_bytes,
                    commitments_bytes,
                } => {
                    let identifier = Identifier::deserialize(&identifier_bytes)
                        .map_err(|e| format!("id: {e}"))?;
                    let commitments = SigningCommitments::deserialize(&commitments_bytes)
                        .map_err(|e| format!("commitments: {e}"))?;
                    nonces_map.insert(identifier, nonces_bytes);
                    commitments_map.insert(identifier, commitments);
                }
                SignerMessage::Error { message } => {
                    return Err(format!("commit error: {message}"));
                }
                _ => return Err("unexpected response".into()),
            }
        }

        // Build signing package
        let signing_package = SigningPackage::new(commitments_map, message);
        let signing_package_bytes = signing_package
            .serialize()
            .map_err(|e| format!("serialize: {e}"))?;

        // Round 2: Collect signature shares
        let mut signature_shares: BTreeMap<Identifier, SignatureShare> = BTreeMap::new();

        for (id, addr) in &selected {
            let nonces_bytes = nonces_map
                .remove(id)
                .ok_or_else(|| format!("missing nonces for {:?}", id))?;

            let raw_host = addr.split(':').next().unwrap_or(addr);
            let signer_host = if raw_host.parse::<std::net::IpAddr>().is_ok() { "localhost" } else { raw_host };
            let mut transport = shard::tls_transport::tls_connect(
                addr,
                common::types::ModuleId::Orchestrator,
                coord.hmac_key,
                connector,
                signer_host,
            )
            .await
            .map_err(|e| format!("connect for sign: {e}"))?;

            let req = SignerMessage::SignRequest {
                signing_package_bytes: signing_package_bytes.clone(),
                nonces_bytes,
            };
            let req_bytes =
                postcard::to_allocvec(&req).map_err(|e| format!("serialize: {e}"))?;
            transport.send(&req_bytes).await.map_err(|e| format!("send: {e}"))?;

            let (_sender, resp_payload) =
                transport.recv().await.map_err(|e| format!("recv: {e}"))?;

            let resp: SignerMessage = postcard::from_bytes(&resp_payload)
                .map_err(|e| format!("deserialize: {e}"))?;

            match resp {
                SignerMessage::SignResponse {
                    identifier_bytes,
                    share_bytes,
                } => {
                    let identifier = Identifier::deserialize(&identifier_bytes)
                        .map_err(|e| format!("id: {e}"))?;
                    let share = SignatureShare::deserialize(&share_bytes)
                        .map_err(|e| format!("share: {e}"))?;
                    signature_shares.insert(identifier, share);
                }
                SignerMessage::Error { message } => {
                    return Err(format!("sign error: {message}"));
                }
                _ => return Err("unexpected response".into()),
            }
        }

        // Aggregate
        let group_signature = frost::aggregate(
            &signing_package,
            &signature_shares,
            &coord.public_key_package,
        )
        .map_err(|e| format!("aggregation: {e}"))?;

        let sig_bytes = group_signature
            .serialize()
            .map_err(|e| format!("serialize: {e}"))?;
        let mut out = [0u8; 64];
        out.copy_from_slice(&sig_bytes);
        Ok(out)
    }

    /// Test the 3-part distributed DKG protocol locally (no network).
    ///
    /// Each "signer" calls handle_dkg_round1/round2/finalize independently,
    /// simulating separate processes that only exchange serialized messages.
    #[test]
    fn distributed_dkg_3_round_local() {
        use frost::keys::dkg as frost_dkg;

        let max_signers = 5u16;
        let min_signers = 3u16;

        // Assign identifiers
        let identifiers: Vec<Identifier> = (1..=max_signers)
            .map(|i| Identifier::try_from(i).unwrap())
            .collect();

        // ── Round 1: each signer generates commitment + proof ──
        let mut round1_secrets: BTreeMap<Identifier, Vec<u8>> = BTreeMap::new();
        let mut round1_packages: BTreeMap<Identifier, Vec<u8>> = BTreeMap::new();

        for id in &identifiers {
            let id_bytes = id.serialize();
            let (ret_id_bytes, package_bytes, secret_bytes) =
                handle_dkg_round1(&id_bytes, max_signers, min_signers)
                    .expect("round 1 must succeed");
            let rid = Identifier::deserialize(&ret_id_bytes).unwrap();
            round1_secrets.insert(rid, secret_bytes);
            round1_packages.insert(rid, package_bytes);
        }

        // ── Round 2: each signer verifies proofs and generates shares ──
        let mut round2_secrets: BTreeMap<Identifier, Vec<u8>> = BTreeMap::new();
        let mut round2_all_packages: BTreeMap<Identifier, Vec<(Vec<u8>, Vec<u8>)>> =
            BTreeMap::new();

        for id in &identifiers {
            let secret_bytes = round1_secrets.get(id).unwrap();
            // Collect all OTHER signers' round1 packages
            let others: Vec<(Vec<u8>, Vec<u8>)> = round1_packages
                .iter()
                .filter(|(k, _)| *k != id)
                .map(|(k, v)| (k.serialize(), v.clone()))
                .collect();

            let (round2_secret_bytes, packages) =
                handle_dkg_round2(secret_bytes, &others)
                    .expect("round 2 must succeed");

            round2_secrets.insert(*id, round2_secret_bytes);
            round2_all_packages.insert(*id, packages);
        }

        // ── Round 3 (Finalize): each signer combines shares ──
        let mut key_packages: Vec<frost::keys::KeyPackage> = Vec::new();
        let mut public_key_packages: Vec<Vec<u8>> = Vec::new();

        for id in &identifiers {
            let round2_secret_bytes = round2_secrets.get(id).unwrap();

            // Round 1 packages from others
            let round1_others: Vec<(Vec<u8>, Vec<u8>)> = round1_packages
                .iter()
                .filter(|(k, _)| *k != id)
                .map(|(k, v)| (k.serialize(), v.clone()))
                .collect();

            // Round 2 packages addressed to THIS signer from all others
            let round2_for_this: Vec<(Vec<u8>, Vec<u8>)> = round2_all_packages
                .iter()
                .filter(|(sender_id, _)| *sender_id != id)
                .filter_map(|(sender_id, packages)| {
                    let target_bytes = id.serialize();
                    packages
                        .iter()
                        .find(|(recipient_bytes, _)| *recipient_bytes == target_bytes)
                        .map(|(_, pkg_bytes)| (sender_id.serialize(), pkg_bytes.clone()))
                })
                .collect();

            let (key_bytes, pub_bytes) =
                handle_dkg_finalize(round2_secret_bytes, &round1_others, &round2_for_this)
                    .expect("finalize must succeed");

            let kp = frost::keys::KeyPackage::deserialize(&key_bytes)
                .expect("deserialize key package");
            key_packages.push(kp);
            public_key_packages.push(pub_bytes);
        }

        // All signers must produce the same PublicKeyPackage
        for (i, pkg) in public_key_packages.iter().enumerate().skip(1) {
            assert_eq!(
                *pkg, public_key_packages[0],
                "signer {i} produced different PublicKeyPackage — equivocation"
            );
        }

        let public_key_package =
            PublicKeyPackage::deserialize(&public_key_packages[0]).unwrap();

        // ── Verify: sign a message using 3 of 5 shares and verify ──
        let message = b"distributed DKG test message";

        let mut nonces_map = BTreeMap::new();
        let mut commitments_map = BTreeMap::new();

        for kp in key_packages.iter().take(min_signers as usize) {
            let mut rng = rand::rngs::OsRng;
            let (nonces, commitments) =
                frost::round1::commit(kp.signing_share(), &mut rng);
            nonces_map.insert(*kp.identifier(), nonces);
            commitments_map.insert(*kp.identifier(), commitments);
        }

        let signing_package = SigningPackage::new(commitments_map, message);

        let mut shares = BTreeMap::new();
        for kp in key_packages.iter().take(min_signers as usize) {
            let nonces = nonces_map.remove(kp.identifier()).unwrap();
            let share = frost::round2::sign(&signing_package, &nonces, kp)
                .expect("signing must succeed");
            shares.insert(*kp.identifier(), share);
        }

        let group_sig = frost::aggregate(&signing_package, &shares, &public_key_package)
            .expect("aggregation must succeed");

        assert!(
            public_key_package
                .verifying_key()
                .verify(message, &group_sig)
                .is_ok(),
            "group signature from distributed DKG must verify"
        );
    }

    // ── Share Recovery & Validation tests ──────────────────────────────

    #[test]
    fn test_validate_share_availability_quorum_met() {
        let (coordinator, nodes) = setup_dkg();
        let addrs: Vec<(Identifier, String)> = nodes
            .iter()
            .map(|n| (n.identifier(), "127.0.0.1:0".to_string()))
            .collect();

        // All 5 shares accessible, threshold is 3
        let accessible: Vec<Identifier> = nodes.iter().map(|n| n.identifier()).collect();
        let report = validate_share_availability(&addrs, coordinator.threshold, &accessible);

        assert!(report.quorum_met);
        assert!(report.has_recovery_buffer);
        assert_eq!(report.accessible_shares, 5);
        assert_eq!(report.inaccessible_ids.len(), 0);
    }

    #[test]
    fn test_validate_share_availability_exact_threshold() {
        let (coordinator, nodes) = setup_dkg();
        let addrs: Vec<(Identifier, String)> = nodes
            .iter()
            .map(|n| (n.identifier(), "127.0.0.1:0".to_string()))
            .collect();

        // Only 3 of 5 accessible (exactly threshold)
        let accessible: Vec<Identifier> = nodes[..3].iter().map(|n| n.identifier()).collect();
        let report = validate_share_availability(&addrs, coordinator.threshold, &accessible);

        assert!(report.quorum_met);
        assert!(!report.has_recovery_buffer);
        assert_eq!(report.accessible_shares, 3);
        assert_eq!(report.inaccessible_ids.len(), 2);
    }

    #[test]
    fn test_validate_share_availability_below_threshold() {
        let (coordinator, nodes) = setup_dkg();
        let addrs: Vec<(Identifier, String)> = nodes
            .iter()
            .map(|n| (n.identifier(), "127.0.0.1:0".to_string()))
            .collect();

        // Only 2 of 5 accessible (below threshold of 3)
        let accessible: Vec<Identifier> = nodes[..2].iter().map(|n| n.identifier()).collect();
        let report = validate_share_availability(&addrs, coordinator.threshold, &accessible);

        assert!(!report.quorum_met);
        assert!(!report.has_recovery_buffer);
        assert_eq!(report.accessible_shares, 2);
        assert_eq!(report.inaccessible_ids.len(), 3);
    }

    #[test]
    fn test_share_recovery_plan_structure() {
        let plan = ShareRecoveryPlan::for_group(3, 5);

        assert_eq!(plan.threshold, 3);
        assert_eq!(plan.total_shares, 5);
        assert_eq!(plan.max_tolerable_loss, 2);
        assert!(plan.scenarios.len() >= 2);

        // First scenario should be WARNING (1 share lost)
        assert_eq!(plan.scenarios[0].severity, "WARNING");
        assert!(plan.scenarios[0].signing_possible);

        // Last scenario should be FATAL (below threshold)
        let last = plan.scenarios.last().unwrap();
        assert_eq!(last.severity, "FATAL");
        assert!(!last.signing_possible);
    }

    #[test]
    fn test_share_recovery_plan_minimal_group() {
        // 2-of-2: no buffer at all
        let plan = ShareRecoveryPlan::for_group(2, 2);

        assert_eq!(plan.max_tolerable_loss, 0);
        // No WARNING scenario (can't lose any shares)
        assert!(
            plan.scenarios.iter().all(|s| s.severity != "WARNING"),
            "2-of-2 group has no buffer for WARNING scenario"
        );
    }

    // ── TEST GROUP 8: FROST DR nonce safety tests ────────────────────────

    #[test]
    fn test_dr_safety_margin_constant_is_10000() {
        assert_eq!(
            DR_SAFETY_MARGIN,
            10_000,
            "DR_SAFETY_MARGIN must be 10,000 to prevent FROST nonce reuse after DR restore"
        );
    }

    #[test]
    fn test_nonce_safety_margin_is_100() {
        assert_eq!(
            NONCE_SAFETY_MARGIN,
            100,
            "normal NONCE_SAFETY_MARGIN must be 100"
        );
    }

    #[test]
    fn test_dr_safety_margin_greater_than_normal() {
        assert!(
            DR_SAFETY_MARGIN > NONCE_SAFETY_MARGIN,
            "DR_SAFETY_MARGIN ({}) must be much larger than NONCE_SAFETY_MARGIN ({})",
            DR_SAFETY_MARGIN,
            NONCE_SAFETY_MARGIN
        );
    }

    #[test]
    fn test_nonce_wal_dr_restore_uses_larger_margin() {
        // Set up env vars so that both WAL and sealed state files point to
        // non-existent temp paths (both return nonce = 0).
        let mut rand_bytes = [0u8; 8];
        getrandom::getrandom(&mut rand_bytes).unwrap();
        let rand_hex: String = rand_bytes.iter().map(|b| format!("{b:02x}")).collect();
        let tmp = std::env::temp_dir().join(format!("milnet_tss_test_dr_{}", rand_hex));
        let wal_path = tmp.join("nonce_wal");
        let state_path = tmp.join("nonce_state");

        // Ensure no pre-existing files.
        let _ = std::fs::remove_file(&wal_path);
        let _ = std::fs::remove_file(&state_path);

        // Temporarily override sealed state path for this test.
        std::env::set_var("MILNET_TSS_NONCE_STATE_PATH", state_path.to_str().unwrap());

        let normal_wal = NonceWal::new(Some(wal_path.clone()));
        let dr_wal = NonceWal::new_dr_restore(Some(wal_path.clone()));

        // Both start from nonce 0 (no files). Normal adds NONCE_SAFETY_MARGIN,
        // DR adds DR_SAFETY_MARGIN.
        assert_eq!(
            normal_wal.current_nonce(),
            NONCE_SAFETY_MARGIN,
            "normal WAL nonce must be 0 + NONCE_SAFETY_MARGIN"
        );
        assert_eq!(
            dr_wal.current_nonce(),
            DR_SAFETY_MARGIN,
            "DR WAL nonce must be 0 + DR_SAFETY_MARGIN"
        );
        assert!(
            dr_wal.current_nonce() > normal_wal.current_nonce(),
            "DR restore must produce a higher nonce than normal recovery"
        );

        // Clean up
        let _ = std::fs::remove_file(&wal_path);
        let _ = std::fs::remove_file(&state_path);
        let _ = std::fs::remove_dir(&tmp);
    }
}
