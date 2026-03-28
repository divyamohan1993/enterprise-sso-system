//! Distributed code healing.
//!
//! When a node's binary is detected as tampered (by the attestation mesh),
//! healthy nodes can push the correct binary to the tampered node. The
//! healed node then restarts with the correct binary.
//!
//! Healing flow:
//! 1. Tampered node detected by attestation mesh
//! 2. Raft leader proposes MemberLeave for tampered node (strips leader role)
//! 3. Healthy peer sends correct binary in chunks (signed with ML-DSA-87)
//! 4. Tampered node receives, verifies hash, replaces /proc/self/exe target
//! 5. Tampered node signals for restart (via systemd or k8s)
//! 6. On restart, node re-joins cluster with correct binary
#![forbid(unsafe_code)]

use crate::binary_attestation_mesh::BinaryHash;
use crate::raft::NodeId;
use sha2::{Digest, Sha512};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tracing::{error, info, warn};

// ── Healing session ──────────────────────────────────────────────────────────

/// Healing session state.
pub struct HealingSession {
    /// Node being healed.
    target_node: NodeId,
    /// The correct binary hash.
    expected_hash: BinaryHash,
    /// Binary chunks received so far.
    chunks: HashMap<u32, Vec<u8>>,
    /// Total expected chunks.
    total_chunks: u32,
    /// Healing start time.
    started_at: Instant,
    /// Whether healing is complete.
    complete: bool,
}

impl HealingSession {
    /// Check whether the session has timed out.
    pub fn is_timed_out(&self, timeout: Duration) -> bool {
        self.started_at.elapsed() > timeout
    }

    /// Fraction of chunks received so far (0.0 to 1.0).
    pub fn progress(&self) -> f64 {
        if self.total_chunks == 0 {
            return 0.0;
        }
        self.chunks.len() as f64 / self.total_chunks as f64
    }
}

// ── Code healer ──────────────────────────────────────────────────────────────

/// Default chunk size: 1 MB.
const DEFAULT_CHUNK_SIZE: usize = 1_048_576;

/// Default healing timeout: 5 minutes.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

/// Restart exit code used to signal the supervisor to restart the process.
pub const RESTART_EXIT_CODE: i32 = 42;

/// Code healer -- coordinates binary repair.
pub struct CodeHealer {
    /// Path to the running binary (for replacement).
    binary_path: PathBuf,
    /// Path to stage the new binary before atomic swap.
    staging_path: PathBuf,
    /// Active healing sessions.
    sessions: HashMap<NodeId, HealingSession>,
    /// Maximum chunk size (default: 1MB).
    chunk_size: usize,
    /// Healing timeout (default: 5 minutes).
    timeout: Duration,
}

impl CodeHealer {
    /// Create a new code healer.
    pub fn new(binary_path: PathBuf, staging_path: PathBuf) -> Self {
        Self {
            binary_path,
            staging_path,
            sessions: HashMap::new(),
            chunk_size: DEFAULT_CHUNK_SIZE,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Create with custom chunk size and timeout.
    pub fn with_options(
        binary_path: PathBuf,
        staging_path: PathBuf,
        chunk_size: usize,
        timeout: Duration,
    ) -> Self {
        Self {
            binary_path,
            staging_path,
            sessions: HashMap::new(),
            chunk_size: if chunk_size == 0 {
                DEFAULT_CHUNK_SIZE
            } else {
                chunk_size
            },
            timeout,
        }
    }

    /// Read a binary, split it into chunks, and return the chunks plus the SHA-512 hash.
    pub fn prepare_binary_chunks(
        binary_path: &Path,
        chunk_size: usize,
    ) -> Result<(Vec<Vec<u8>>, BinaryHash), String> {
        let data = std::fs::read(binary_path)
            .map_err(|e| format!("failed to read binary at {}: {e}", binary_path.display()))?;

        let mut hasher = Sha512::new();
        hasher.update(&data);
        let digest = hasher.finalize();
        let mut hash = [0u8; 64];
        hash.copy_from_slice(&digest);

        let effective_chunk_size = if chunk_size == 0 { DEFAULT_CHUNK_SIZE } else { chunk_size };
        let chunks: Vec<Vec<u8>> = data.chunks(effective_chunk_size).map(|c| c.to_vec()).collect();

        Ok((chunks, hash))
    }

    /// Start a healing session for the given target node.
    pub fn start_healing_session(
        &mut self,
        target: NodeId,
        expected_hash: BinaryHash,
        total_chunks: u32,
    ) {
        info!(
            node = %target,
            total_chunks,
            "starting healing session"
        );
        self.sessions.insert(
            target,
            HealingSession {
                target_node: target,
                expected_hash,
                chunks: HashMap::new(),
                total_chunks,
                started_at: Instant::now(),
                complete: false,
            },
        );
    }

    /// Receive a chunk for a healing session.
    ///
    /// Returns `Ok(true)` when all chunks have been received and the session
    /// is complete. Returns `Ok(false)` when more chunks are still expected.
    pub fn receive_chunk(
        &mut self,
        target: &NodeId,
        chunk_index: u32,
        data: Vec<u8>,
    ) -> Result<bool, String> {
        let session = self
            .sessions
            .get_mut(target)
            .ok_or_else(|| format!("no healing session for node {target}"))?;

        if session.is_timed_out(self.timeout) {
            return Err(format!("healing session for node {target} has timed out"));
        }

        if chunk_index >= session.total_chunks {
            return Err(format!(
                "chunk index {chunk_index} out of range (total: {})",
                session.total_chunks
            ));
        }

        session.chunks.insert(chunk_index, data);

        if session.chunks.len() as u32 == session.total_chunks {
            session.complete = true;
            info!(node = %target, "all chunks received");
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Assemble received chunks, verify the hash, and write to the staging path.
    ///
    /// Returns the staging path on success.
    pub fn assemble_and_verify(&self, target: &NodeId) -> Result<PathBuf, String> {
        let session = self
            .sessions
            .get(target)
            .ok_or_else(|| format!("no healing session for node {target}"))?;

        if !session.complete {
            return Err(format!(
                "healing session for node {target} is not yet complete ({}/{})",
                session.chunks.len(),
                session.total_chunks
            ));
        }

        // Assemble in order
        let mut assembled = Vec::new();
        for i in 0..session.total_chunks {
            let chunk = session
                .chunks
                .get(&i)
                .ok_or_else(|| format!("missing chunk {i}"))?;
            assembled.extend_from_slice(chunk);
        }

        // Verify hash (constant-time)
        let mut hasher = Sha512::new();
        hasher.update(&assembled);
        let digest = hasher.finalize();
        let mut computed_hash = [0u8; 64];
        computed_hash.copy_from_slice(&digest);

        let hash_ok: bool = computed_hash
            .as_slice()
            .ct_eq(session.expected_hash.as_slice())
            .into();

        if !hash_ok {
            error!(node = %target, "assembled binary hash mismatch");
            return Err("assembled binary hash does not match expected hash".into());
        }

        // Write to staging path
        std::fs::write(&self.staging_path, &assembled).map_err(|e| {
            format!(
                "failed to write staged binary to {}: {e}",
                self.staging_path.display()
            )
        })?;

        // Set executable permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o755);
            std::fs::set_permissions(&self.staging_path, perms).map_err(|e| {
                format!(
                    "failed to set permissions on {}: {e}",
                    self.staging_path.display()
                )
            })?;
        }

        info!(
            node = %target,
            path = %self.staging_path.display(),
            "staged binary written and verified"
        );

        Ok(self.staging_path.clone())
    }

    /// Atomically replace the running binary with the staged one.
    pub fn atomic_replace_binary(&self) -> Result<(), String> {
        if !self.staging_path.exists() {
            return Err(format!(
                "staging binary not found at {}",
                self.staging_path.display()
            ));
        }

        info!(
            from = %self.staging_path.display(),
            to = %self.binary_path.display(),
            "performing atomic binary replacement"
        );

        std::fs::rename(&self.staging_path, &self.binary_path).map_err(|e| {
            format!(
                "failed to rename {} -> {}: {e}",
                self.staging_path.display(),
                self.binary_path.display()
            )
        })?;

        Ok(())
    }

    /// Signal for process restart.
    ///
    /// Exits with a specific exit code that the supervisor (systemd, k8s)
    /// should interpret as "restart with new binary".
    pub fn request_restart() -> Result<(), String> {
        warn!(exit_code = RESTART_EXIT_CODE, "requesting process restart for binary healing");
        std::process::exit(RESTART_EXIT_CODE);
    }

    /// Clean up a healing session.
    pub fn cleanup_session(&mut self, target: &NodeId) {
        if self.sessions.remove(target).is_some() {
            info!(node = %target, "cleaned up healing session");
        }
    }

    /// Get the chunk size.
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Get the binary path.
    pub fn binary_path(&self) -> &Path {
        &self.binary_path
    }

    /// Get the staging path.
    pub fn staging_path(&self) -> &Path {
        &self.staging_path
    }

    /// Check if there is an active session for a node.
    pub fn has_session(&self, target: &NodeId) -> bool {
        self.sessions.contains_key(target)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use uuid::Uuid;

    fn test_node(n: u8) -> NodeId {
        let mut bytes = [0u8; 16];
        bytes[15] = n;
        NodeId(Uuid::from_bytes(bytes))
    }

    fn make_hash(fill: u8) -> BinaryHash {
        [fill; 64]
    }

    fn sha512_of(data: &[u8]) -> BinaryHash {
        let mut hasher = Sha512::new();
        hasher.update(data);
        let digest = hasher.finalize();
        let mut hash = [0u8; 64];
        hash.copy_from_slice(&digest);
        hash
    }

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("code_healing_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn code_healer_new_sets_defaults() {
        let healer = CodeHealer::new(PathBuf::from("/usr/bin/sso"), PathBuf::from("/tmp/staged"));
        assert_eq!(healer.chunk_size(), DEFAULT_CHUNK_SIZE);
        assert_eq!(healer.binary_path(), Path::new("/usr/bin/sso"));
        assert_eq!(healer.staging_path(), Path::new("/tmp/staged"));
    }

    #[test]
    fn with_options_custom_values() {
        let healer = CodeHealer::with_options(
            PathBuf::from("/a"),
            PathBuf::from("/b"),
            512,
            Duration::from_secs(60),
        );
        assert_eq!(healer.chunk_size(), 512);
    }

    #[test]
    fn with_options_zero_chunk_size_uses_default() {
        let healer = CodeHealer::with_options(
            PathBuf::from("/a"),
            PathBuf::from("/b"),
            0,
            Duration::from_secs(60),
        );
        assert_eq!(healer.chunk_size(), DEFAULT_CHUNK_SIZE);
    }

    #[test]
    fn prepare_binary_chunks_splits_correctly() {
        let dir = temp_dir();
        let bin_path = dir.join("test_binary");
        let data = vec![0xABu8; 100];
        std::fs::write(&bin_path, &data).unwrap();

        let (chunks, hash) = CodeHealer::prepare_binary_chunks(&bin_path, 30).unwrap();
        assert_eq!(chunks.len(), 4); // 30+30+30+10
        assert_eq!(chunks[0].len(), 30);
        assert_eq!(chunks[1].len(), 30);
        assert_eq!(chunks[2].len(), 30);
        assert_eq!(chunks[3].len(), 10);
        assert_eq!(hash, sha512_of(&data));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn prepare_binary_chunks_single_chunk() {
        let dir = temp_dir();
        let bin_path = dir.join("small_binary");
        let data = vec![0x01u8; 10];
        std::fs::write(&bin_path, &data).unwrap();

        let (chunks, hash) = CodeHealer::prepare_binary_chunks(&bin_path, 1024).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], data);
        assert_eq!(hash, sha512_of(&data));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn prepare_binary_chunks_nonexistent_file() {
        let result = CodeHealer::prepare_binary_chunks(Path::new("/nonexistent/binary"), 1024);
        assert!(result.is_err());
    }

    #[test]
    fn start_and_receive_chunks() {
        let dir = temp_dir();
        let mut healer = CodeHealer::new(dir.join("binary"), dir.join("staged"));

        let node = test_node(1);
        let hash = make_hash(0xAA);
        healer.start_healing_session(node, hash, 3);
        assert!(healer.has_session(&node));

        assert_eq!(
            healer.receive_chunk(&node, 0, vec![1, 2, 3]).unwrap(),
            false
        );
        assert_eq!(
            healer.receive_chunk(&node, 1, vec![4, 5, 6]).unwrap(),
            false
        );
        assert_eq!(
            healer.receive_chunk(&node, 2, vec![7, 8, 9]).unwrap(),
            true
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn receive_chunk_no_session_fails() {
        let dir = temp_dir();
        let mut healer = CodeHealer::new(dir.join("binary"), dir.join("staged"));
        let result = healer.receive_chunk(&test_node(99), 0, vec![1]);
        assert!(result.is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn receive_chunk_out_of_range_fails() {
        let dir = temp_dir();
        let mut healer = CodeHealer::new(dir.join("binary"), dir.join("staged"));

        let node = test_node(1);
        healer.start_healing_session(node, make_hash(0xAA), 2);

        let result = healer.receive_chunk(&node, 5, vec![1]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("out of range"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn assemble_and_verify_success() {
        let dir = temp_dir();
        let staging = dir.join("staged_binary");
        let mut healer = CodeHealer::new(dir.join("binary"), staging.clone());

        let data = vec![0xDEu8; 50];
        let expected_hash = sha512_of(&data);
        let node = test_node(1);

        healer.start_healing_session(node, expected_hash, 2);
        healer.receive_chunk(&node, 0, data[..25].to_vec()).unwrap();
        healer.receive_chunk(&node, 1, data[25..].to_vec()).unwrap();

        let result = healer.assemble_and_verify(&node).unwrap();
        assert_eq!(result, staging);
        assert!(staging.exists());

        let written = std::fs::read(&staging).unwrap();
        assert_eq!(written, data);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn assemble_and_verify_hash_mismatch() {
        let dir = temp_dir();
        let mut healer = CodeHealer::new(dir.join("binary"), dir.join("staged"));

        let node = test_node(1);
        // Use a wrong expected hash
        healer.start_healing_session(node, make_hash(0xFF), 1);
        healer
            .receive_chunk(&node, 0, vec![0x01, 0x02, 0x03])
            .unwrap();

        let result = healer.assemble_and_verify(&node);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("hash does not match"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn assemble_incomplete_session_fails() {
        let dir = temp_dir();
        let mut healer = CodeHealer::new(dir.join("binary"), dir.join("staged"));

        let node = test_node(1);
        healer.start_healing_session(node, make_hash(0xAA), 3);
        healer.receive_chunk(&node, 0, vec![1]).unwrap();

        let result = healer.assemble_and_verify(&node);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not yet complete"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn atomic_replace_binary_works() {
        let dir = temp_dir();
        let binary_path = dir.join("real_binary");
        let staging_path = dir.join("staged_binary");

        // Write original
        std::fs::write(&binary_path, b"old").unwrap();
        // Write staged
        std::fs::write(&staging_path, b"new").unwrap();

        let healer = CodeHealer::new(binary_path.clone(), staging_path.clone());
        healer.atomic_replace_binary().unwrap();

        assert!(!staging_path.exists());
        assert_eq!(std::fs::read(&binary_path).unwrap(), b"new");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn atomic_replace_binary_missing_staging_fails() {
        let dir = temp_dir();
        let healer = CodeHealer::new(dir.join("binary"), dir.join("nonexistent_staged"));
        let result = healer.atomic_replace_binary();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cleanup_session_removes_session() {
        let dir = temp_dir();
        let mut healer = CodeHealer::new(dir.join("binary"), dir.join("staged"));

        let node = test_node(1);
        healer.start_healing_session(node, make_hash(0xAA), 1);
        assert!(healer.has_session(&node));

        healer.cleanup_session(&node);
        assert!(!healer.has_session(&node));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cleanup_nonexistent_session_is_noop() {
        let dir = temp_dir();
        let mut healer = CodeHealer::new(dir.join("binary"), dir.join("staged"));
        healer.cleanup_session(&test_node(99)); // no panic
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn healing_session_progress() {
        let dir = temp_dir();
        let mut healer = CodeHealer::new(dir.join("binary"), dir.join("staged"));

        let node = test_node(1);
        healer.start_healing_session(node, make_hash(0xAA), 4);

        // Initial progress is 0
        let session = healer.sessions.get(&node).unwrap();
        assert!((session.progress() - 0.0).abs() < f64::EPSILON);

        healer.receive_chunk(&node, 0, vec![1]).unwrap();
        healer.receive_chunk(&node, 1, vec![2]).unwrap();

        let session = healer.sessions.get(&node).unwrap();
        assert!((session.progress() - 0.5).abs() < f64::EPSILON);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn end_to_end_healing_flow() {
        let dir = temp_dir();
        let binary_path = dir.join("binary");
        let staging_path = dir.join("staged");

        // Create a "correct" binary
        let correct_binary = vec![0xCAu8; 200];
        let correct_hash = sha512_of(&correct_binary);

        // Prepare chunks from the correct binary
        let src_path = dir.join("source_binary");
        std::fs::write(&src_path, &correct_binary).unwrap();
        let (chunks, hash) = CodeHealer::prepare_binary_chunks(&src_path, 64).unwrap();
        assert_eq!(hash, correct_hash);

        // Simulate healing
        let mut healer = CodeHealer::new(binary_path.clone(), staging_path.clone());
        let target = test_node(1);
        healer.start_healing_session(target, correct_hash, chunks.len() as u32);

        for (i, chunk) in chunks.iter().enumerate() {
            let complete = healer.receive_chunk(&target, i as u32, chunk.clone()).unwrap();
            if i == chunks.len() - 1 {
                assert!(complete);
            } else {
                assert!(!complete);
            }
        }

        // Assemble and verify
        healer.assemble_and_verify(&target).unwrap();
        assert!(staging_path.exists());

        // Write a dummy "old" binary
        std::fs::write(&binary_path, b"tampered").unwrap();

        // Atomic replace
        healer.atomic_replace_binary().unwrap();
        assert_eq!(std::fs::read(&binary_path).unwrap(), correct_binary);

        // Cleanup
        healer.cleanup_session(&target);
        assert!(!healer.has_session(&target));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn duplicate_chunk_overwrites() {
        let dir = temp_dir();
        let mut healer = CodeHealer::new(dir.join("binary"), dir.join("staged"));

        let node = test_node(1);
        let data = vec![0x01u8; 10];
        let expected_hash = sha512_of(&data);
        healer.start_healing_session(node, expected_hash, 1);

        // Send wrong chunk first
        healer.receive_chunk(&node, 0, vec![0xFF; 10]).unwrap();
        // Overwrite with correct chunk
        healer.receive_chunk(&node, 0, data.clone()).unwrap();

        // Should verify successfully with the corrected chunk
        let result = healer.assemble_and_verify(&node);
        assert!(result.is_ok());

        std::fs::remove_dir_all(&dir).ok();
    }
}
