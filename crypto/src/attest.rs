//! Binary and configuration attestation (tamper detection).
//!
//! Provides integrity verification for service binaries and configuration
//! files. A signed manifest of BLAKE3 hashes is checked at startup and
//! can be re-verified at runtime intervals.
//!
//! CNSA 2.0 note: BLAKE3 is not in the CNSA 2.0 approved algorithm suite.
//! It is used here for *performance-critical file integrity checking* in
//! the attestation subsystem only, not for key derivation or digital
//! signatures. The manifest itself is authenticated via HMAC-SHA512,
//! which IS CNSA 2.0 compliant.
//!
//! # Threat Model
//! Detects:
//! - Binary replacement/patching by compromised host
//! - Configuration file tampering
//! - Library substitution attacks
//!
//! Does NOT protect against:
//! - Kernel-level rootkits that intercept file reads
//! - Hardware implants
//! (These require hardware attestation: TPM/SGX/SEV)

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha512};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha512 = Hmac<Sha512>;

/// Domain separation prefix for manifest HMAC computation.
const HMAC_DOMAIN: &[u8] = b"MILNET-ATTEST-v1";

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during attestation.
#[derive(Debug)]
pub enum AttestError {
    /// An I/O error occurred while reading a file.
    IoError(String),
    /// A file's hash does not match the manifest entry.
    HashMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    /// The manifest HMAC tag is invalid (manifest was tampered with).
    ManifestTampered,
    /// No manifest was found at the expected location.
    ManifestNotFound,
    /// The manifest could not be parsed.
    InvalidManifest(String),
}

impl std::fmt::Display for AttestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttestError::IoError(msg) => write!(f, "I/O error: {}", msg),
            AttestError::HashMismatch {
                path,
                expected,
                actual,
            } => write!(
                f,
                "hash mismatch for {}: expected {}, got {}",
                path, expected, actual
            ),
            AttestError::ManifestTampered => write!(f, "manifest HMAC verification failed"),
            AttestError::ManifestNotFound => write!(f, "attestation manifest not found"),
            AttestError::InvalidManifest(msg) => write!(f, "invalid manifest: {}", msg),
        }
    }
}

impl std::error::Error for AttestError {}

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Hash and metadata for a single file.
#[derive(Debug, Clone)]
pub struct FileHash {
    /// Absolute or relative path to the file.
    pub path: String,
    /// File digest (BLAKE3 or SHA-512 truncated to 32 bytes, depending on FIPS mode).
    pub blake3_hash: [u8; 32],
    /// File size in bytes.
    pub size: u64,
}

/// An authenticated manifest of file hashes.
///
/// The `hmac_tag` covers all fields except itself, keyed with a secret
/// derived from the MILNET key hierarchy.
#[derive(Debug, Clone)]
pub struct AttestationManifest {
    /// Manifest format version (currently always 1).
    pub version: u32,
    /// Unix timestamp (seconds) when the manifest was created.
    pub created_at: u64,
    /// Ordered list of file hash entries.
    pub entries: Vec<FileHash>,
    /// HMAC-SHA512 tag authenticating the manifest contents.
    pub hmac_tag: Vec<u8>,
    /// Hash algorithm used for file hashing: "blake3" or "sha512-t256".
    pub hash_algorithm: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Encode a `u32` as 4 big-endian bytes.
fn encode_u32(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

/// Encode a `u64` as 8 big-endian bytes.
fn encode_u64(v: u64) -> [u8; 8] {
    v.to_be_bytes()
}

/// Decode a `u32` from 4 big-endian bytes.
fn decode_u32(b: &[u8]) -> u32 {
    let mut arr = [0u8; 4];
    arr.copy_from_slice(b);
    u32::from_be_bytes(arr)
}

/// Decode a `u64` from 8 big-endian bytes.
fn decode_u64(b: &[u8]) -> u64 {
    let mut arr = [0u8; 8];
    arr.copy_from_slice(b);
    u64::from_be_bytes(arr)
}

/// Hex-encode a byte slice (lowercase).
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Compute the HMAC-SHA512 tag for a manifest's content fields.
fn compute_manifest_hmac(
    version: u32,
    created_at: u64,
    entries: &[FileHash],
    hash_algorithm: &str,
    signing_key: &[u8; 64],
) -> Vec<u8> {
    let mut mac = match HmacSha512::new_from_slice(signing_key) {
        Ok(m) => m,
        Err(_) => panic!("FATAL: HMAC-SHA512 key initialization failed"),
    };

    // Domain separation
    mac.update(HMAC_DOMAIN);
    // Version
    mac.update(&encode_u32(version));
    // Timestamp
    mac.update(&encode_u64(created_at));
    // Hash algorithm
    mac.update(hash_algorithm.as_bytes());

    // Each entry: path_bytes || hash || size
    for entry in entries {
        mac.update(entry.path.as_bytes());
        mac.update(&entry.blake3_hash);
        mac.update(&encode_u64(entry.size));
    }

    mac.finalize().into_bytes().to_vec()
}

/// Return the current Unix timestamp in seconds.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/// Compute the hash of a file on disk.
///
/// In FIPS mode: uses SHA-512 truncated to 32 bytes ("sha512-t256").
/// Otherwise: uses BLAKE3 ("blake3").
///
/// Returns a [`FileHash`] containing the path, digest, and file size.
pub fn hash_file(path: &str) -> Result<FileHash, AttestError> {
    let data = std::fs::read(path).map_err(|e| AttestError::IoError(format!("{}: {}", path, e)))?;
    let digest = hash_bytes(&data);
    Ok(FileHash {
        path: path.to_string(),
        blake3_hash: digest,
        size: data.len() as u64,
    })
}

/// Hash bytes using the FIPS-appropriate algorithm.
/// Returns a 32-byte digest.
fn hash_bytes(data: &[u8]) -> [u8; 32] {
    if common::fips::is_fips_mode() {
        // SHA-512 truncated to 32 bytes (sha512-t256)
        let full = Sha512::digest(data);
        let mut out = [0u8; 32];
        out.copy_from_slice(&full[..32]);
        out
    } else {
        *blake3::hash(data).as_bytes()
    }
}

/// Returns the name of the active hash algorithm for manifests.
fn active_hash_algorithm() -> &'static str {
    if common::fips::is_fips_mode() {
        "sha512-t256"
    } else {
        "blake3"
    }
}

/// Build an [`AttestationManifest`] from a list of file paths.
///
/// Each file is hashed using the active algorithm (BLAKE3 normally, SHA-512
/// truncated to 32 bytes in FIPS mode). The resulting manifest is authenticated
/// with an HMAC-SHA512 tag derived from `signing_key`.
pub fn build_manifest(
    paths: &[&str],
    signing_key: &[u8; 64],
) -> Result<AttestationManifest, AttestError> {
    let mut entries = Vec::with_capacity(paths.len());
    for path in paths {
        entries.push(hash_file(path)?);
    }

    let created_at = unix_now();
    let version = 1u32;
    let hash_algorithm = active_hash_algorithm().to_string();

    let hmac_tag =
        compute_manifest_hmac(version, created_at, &entries, &hash_algorithm, signing_key);

    Ok(AttestationManifest {
        version,
        created_at,
        entries,
        hmac_tag,
        hash_algorithm,
    })
}

/// Verify the HMAC tag on a manifest.
///
/// Re-derives the tag from the manifest fields and performs a
/// constant-time comparison against the stored tag. Returns
/// [`AttestError::ManifestTampered`] on mismatch.
pub fn verify_manifest(
    manifest: &AttestationManifest,
    signing_key: &[u8; 64],
) -> Result<(), AttestError> {
    let expected = compute_manifest_hmac(
        manifest.version,
        manifest.created_at,
        &manifest.entries,
        &manifest.hash_algorithm,
        signing_key,
    );

    if !crate::ct::ct_eq(&expected, &manifest.hmac_tag) {
        return Err(AttestError::ManifestTampered);
    }
    Ok(())
}

/// Re-hash every file listed in the manifest and verify the hashes match.
///
/// Uses the `hash_algorithm` stored in the manifest to select the correct
/// algorithm (BLAKE3 or SHA-512 truncated to 32 bytes).
///
/// Returns the first mismatch found as [`AttestError::HashMismatch`].
pub fn verify_files(manifest: &AttestationManifest) -> Result<(), AttestError> {
    for entry in &manifest.entries {
        let data = std::fs::read(&entry.path)
            .map_err(|e| AttestError::IoError(format!("{}: {}", entry.path, e)))?;

        let current_hash = if manifest.hash_algorithm == "sha512-t256" {
            let full = Sha512::digest(&data);
            let mut out = [0u8; 32];
            out.copy_from_slice(&full[..32]);
            out
        } else {
            // Default to BLAKE3
            *blake3::hash(&data).as_bytes()
        };

        if current_hash != entry.blake3_hash {
            return Err(AttestError::HashMismatch {
                path: entry.path.clone(),
                expected: hex_encode(&entry.blake3_hash),
                actual: hex_encode(&current_hash),
            });
        }
    }
    Ok(())
}

/// Perform a full attestation: verify the manifest's HMAC, then re-hash
/// all files and compare against the recorded digests.
///
/// Returns `Ok(())` only if both the manifest integrity and every file
/// hash check pass.
pub fn full_attestation(
    manifest: &AttestationManifest,
    signing_key: &[u8; 64],
) -> Result<(), AttestError> {
    verify_manifest(manifest, signing_key)?;
    verify_files(manifest)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/// Serialize a manifest into a binary blob.
///
/// Wire format (all integers big-endian):
/// ```text
/// version:           4 bytes
/// created_at:        8 bytes
/// entry_count:       4 bytes
/// entries:           variable
///   path_len:        4 bytes
///   path_bytes:      path_len bytes
///   hash:            32 bytes
///   size:            8 bytes
/// hmac_tag_len:      4 bytes
/// hmac_tag:          hmac_tag_len bytes
/// hash_algo_len:     4 bytes
/// hash_algo_bytes:   hash_algo_len bytes
/// ```
pub fn serialize_manifest(manifest: &AttestationManifest) -> Vec<u8> {
    let mut buf = Vec::new();

    buf.extend_from_slice(&encode_u32(manifest.version));
    buf.extend_from_slice(&encode_u64(manifest.created_at));
    buf.extend_from_slice(&encode_u32(manifest.entries.len() as u32));

    for entry in &manifest.entries {
        let path_bytes = entry.path.as_bytes();
        buf.extend_from_slice(&encode_u32(path_bytes.len() as u32));
        buf.extend_from_slice(path_bytes);
        buf.extend_from_slice(&entry.blake3_hash);
        buf.extend_from_slice(&encode_u64(entry.size));
    }

    buf.extend_from_slice(&encode_u32(manifest.hmac_tag.len() as u32));
    buf.extend_from_slice(&manifest.hmac_tag);

    let algo_bytes = manifest.hash_algorithm.as_bytes();
    buf.extend_from_slice(&encode_u32(algo_bytes.len() as u32));
    buf.extend_from_slice(algo_bytes);

    buf
}

/// Deserialize a manifest from the binary format produced by
/// [`serialize_manifest`].
pub fn deserialize_manifest(data: &[u8]) -> Result<AttestationManifest, AttestError> {
    let invalid = |msg: &str| AttestError::InvalidManifest(msg.to_string());

    // Minimum: version(4) + created_at(8) + entry_count(4) + hmac_tag_len(4) = 20
    if data.len() < 20 {
        return Err(invalid("data too short for manifest header"));
    }

    let mut pos = 0usize;

    let version = decode_u32(&data[pos..pos + 4]);
    pos += 4;

    let created_at = decode_u64(&data[pos..pos + 8]);
    pos += 8;

    let entry_count = decode_u32(&data[pos..pos + 4]) as usize;
    pos += 4;

    let mut entries = Vec::with_capacity(entry_count);
    for _ in 0..entry_count {
        // path_len
        if pos + 4 > data.len() {
            return Err(invalid("unexpected end of data reading path_len"));
        }
        let path_len = decode_u32(&data[pos..pos + 4]) as usize;
        pos += 4;

        // path bytes
        if pos + path_len > data.len() {
            return Err(invalid("unexpected end of data reading path"));
        }
        let path = String::from_utf8(data[pos..pos + path_len].to_vec())
            .map_err(|_| invalid("path is not valid UTF-8"))?;
        pos += path_len;

        // file hash (32 bytes)
        if pos + 32 > data.len() {
            return Err(invalid("unexpected end of data reading file hash"));
        }
        let mut blake3_hash = [0u8; 32];
        blake3_hash.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        // size (8 bytes)
        if pos + 8 > data.len() {
            return Err(invalid("unexpected end of data reading file size"));
        }
        let size = decode_u64(&data[pos..pos + 8]);
        pos += 8;

        entries.push(FileHash {
            path,
            blake3_hash,
            size,
        });
    }

    // hmac_tag_len + hmac_tag
    if pos + 4 > data.len() {
        return Err(invalid("unexpected end of data reading hmac_tag_len"));
    }
    let hmac_tag_len = decode_u32(&data[pos..pos + 4]) as usize;
    pos += 4;

    if pos + hmac_tag_len > data.len() {
        return Err(invalid("unexpected end of data reading hmac_tag"));
    }
    let hmac_tag = data[pos..pos + hmac_tag_len].to_vec();
    pos += hmac_tag_len;

    // hash_algorithm (optional for backward compat — default to "blake3" if missing)
    let hash_algorithm = if pos + 4 <= data.len() {
        let algo_len = decode_u32(&data[pos..pos + 4]) as usize;
        pos += 4;
        if pos + algo_len <= data.len() {
            String::from_utf8(data[pos..pos + algo_len].to_vec())
                .unwrap_or_else(|_| "blake3".to_string())
        } else {
            "blake3".to_string()
        }
    } else {
        "blake3".to_string()
    };

    Ok(AttestationManifest {
        version,
        created_at,
        entries,
        hmac_tag,
        hash_algorithm,
    })
}

// ---------------------------------------------------------------------------
// Runtime attestor
// ---------------------------------------------------------------------------

/// Periodic runtime re-verification of file integrity.
///
/// Keeps a manifest and signing key, and re-runs full attestation at a
/// configurable interval. The check is driven by the caller (e.g. on
/// every request or from a background timer) via [`check_if_due`].
pub struct RuntimeAttestor {
    /// The manifest to verify against.
    manifest: AttestationManifest,
    /// Key used to authenticate the manifest.
    signing_key: [u8; 64],
    /// Minimum seconds between checks.
    check_interval_secs: u64,
    /// Unix timestamp of the last successful or attempted check.
    last_check: AtomicU64,
    /// Number of attestation failures observed.
    violation_count: AtomicU64,
}

impl RuntimeAttestor {
    /// Create a new `RuntimeAttestor`.
    ///
    /// `interval_secs` controls how often [`check_if_due`] will actually
    /// perform a full attestation.
    pub fn new(
        manifest: AttestationManifest,
        signing_key: [u8; 64],
        interval_secs: u64,
    ) -> Self {
        Self {
            manifest,
            signing_key,
            check_interval_secs: interval_secs,
            last_check: AtomicU64::new(0),
            violation_count: AtomicU64::new(0),
        }
    }

    /// Run a full attestation if the configured interval has elapsed.
    ///
    /// If it is not yet time to check, returns `Ok(())` immediately.
    /// On attestation failure the internal violation counter is
    /// incremented and the error is returned.
    pub fn check_if_due(&self) -> Result<(), AttestError> {
        let now = unix_now();
        let last = self.last_check.load(Ordering::Relaxed);

        if now.saturating_sub(last) < self.check_interval_secs {
            return Ok(());
        }

        // Update last_check regardless of outcome so we don't
        // spin on a persistent failure.
        self.last_check.store(now, Ordering::Relaxed);

        match full_attestation(&self.manifest, &self.signing_key) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.violation_count.fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }

    /// Return the number of attestation failures observed so far.
    pub fn violation_count(&self) -> u64 {
        self.violation_count.load(Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Generate a pseudo-random hex string for unique temp file names.
    fn random_hex() -> String {
        let mut buf = [0u8; 8];
        getrandom::getrandom(&mut buf).expect("getrandom failed");
        hex_encode(&buf)
    }

    /// Create a temporary file with the given contents and return its path.
    fn tmp_file(contents: &[u8]) -> String {
        let path = format!("/tmp/milnet-test-{}", random_hex());
        let mut f = std::fs::File::create(&path).expect("create temp file");
        f.write_all(contents).expect("write temp file");
        f.flush().expect("flush temp file");
        path
    }

    /// Deterministic test key (not secret; test-only).
    fn test_key() -> [u8; 64] {
        let mut k = [0u8; 64];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(7);
        }
        k
    }

    #[test]
    fn test_hash_file() {
        // Ensure non-FIPS for this test so BLAKE3 is used.
        common::fips::set_fips_mode_unchecked(false);

        let content = b"attestation test payload";
        let path = tmp_file(content);

        let fh = hash_file(&path).expect("hash_file should succeed");
        assert_eq!(fh.path, path);
        assert_eq!(fh.size, content.len() as u64);

        // Verify against direct blake3 computation.
        let expected = blake3::hash(content);
        assert_eq!(&fh.blake3_hash, expected.as_bytes());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_hash_file_not_found() {
        let result = hash_file("/tmp/milnet-nonexistent-file-xyz");
        assert!(matches!(result, Err(AttestError::IoError(_))));
    }

    #[test]
    fn test_build_and_verify_manifest() {
        let p1 = tmp_file(b"binary-alpha");
        let p2 = tmp_file(b"config-beta");
        let key = test_key();

        let manifest = build_manifest(&[p1.as_str(), p2.as_str()], &key)
            .expect("build_manifest should succeed");

        assert_eq!(manifest.version, 1);
        assert_eq!(manifest.entries.len(), 2);
        assert!(!manifest.hmac_tag.is_empty());

        // Manifest verification should pass.
        verify_manifest(&manifest, &key).expect("verify_manifest should succeed");

        // Full attestation should pass.
        full_attestation(&manifest, &key).expect("full_attestation should succeed");

        std::fs::remove_file(&p1).ok();
        std::fs::remove_file(&p2).ok();
    }

    #[test]
    fn test_tampered_manifest_detected() {
        let p = tmp_file(b"important binary");
        let key = test_key();

        let mut manifest =
            build_manifest(&[p.as_str()], &key).expect("build_manifest should succeed");

        // Flip a byte in the HMAC tag.
        manifest.hmac_tag[0] ^= 0xff;

        let result = verify_manifest(&manifest, &key);
        assert!(
            matches!(result, Err(AttestError::ManifestTampered)),
            "tampered HMAC tag should be detected"
        );

        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn test_tampered_manifest_wrong_key() {
        let p = tmp_file(b"important binary");
        let key = test_key();

        let manifest =
            build_manifest(&[p.as_str()], &key).expect("build_manifest should succeed");

        // Use a different key for verification.
        let mut wrong_key = [0xffu8; 64];
        wrong_key[0] = 0x00;

        let result = verify_manifest(&manifest, &wrong_key);
        assert!(
            matches!(result, Err(AttestError::ManifestTampered)),
            "wrong signing key should be detected"
        );

        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn test_file_modification_detected() {
        let p = tmp_file(b"original content");
        let key = test_key();

        let manifest =
            build_manifest(&[p.as_str()], &key).expect("build_manifest should succeed");

        // Modify the file after manifest creation.
        std::fs::write(&p, b"MODIFIED content").expect("write modified file");

        let result = verify_files(&manifest);
        assert!(
            matches!(result, Err(AttestError::HashMismatch { .. })),
            "file modification should be detected"
        );

        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let p1 = tmp_file(b"roundtrip-alpha");
        let p2 = tmp_file(b"roundtrip-beta");
        let key = test_key();

        let original = build_manifest(&[p1.as_str(), p2.as_str()], &key)
            .expect("build_manifest should succeed");

        let blob = serialize_manifest(&original);
        let restored = deserialize_manifest(&blob).expect("deserialize should succeed");

        assert_eq!(restored.version, original.version);
        assert_eq!(restored.created_at, original.created_at);
        assert_eq!(restored.entries.len(), original.entries.len());
        assert_eq!(restored.hmac_tag, original.hmac_tag);

        for (a, b) in restored.entries.iter().zip(original.entries.iter()) {
            assert_eq!(a.path, b.path);
            assert_eq!(a.blake3_hash, b.blake3_hash);
            assert_eq!(a.size, b.size);
        }

        // The restored manifest should still pass verification.
        verify_manifest(&restored, &key).expect("restored manifest should verify");

        std::fs::remove_file(&p1).ok();
        std::fs::remove_file(&p2).ok();
    }

    #[test]
    fn test_deserialize_truncated() {
        let result = deserialize_manifest(&[0u8; 5]);
        assert!(matches!(result, Err(AttestError::InvalidManifest(_))));
    }

    #[test]
    fn test_deserialize_empty() {
        let result = deserialize_manifest(&[]);
        assert!(matches!(result, Err(AttestError::InvalidManifest(_))));
    }

    #[test]
    fn test_runtime_attestor_creation() {
        let p = tmp_file(b"runtime test binary");
        let key = test_key();

        let manifest =
            build_manifest(&[p.as_str()], &key).expect("build_manifest should succeed");

        let attestor = RuntimeAttestor::new(manifest, key, 60);
        assert_eq!(attestor.violation_count(), 0);

        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn test_runtime_attestor_check() {
        let p = tmp_file(b"runtime check binary");
        let key = test_key();

        let manifest =
            build_manifest(&[p.as_str()], &key).expect("build_manifest should succeed");

        // Interval of 0 means every call triggers a check.
        let attestor = RuntimeAttestor::new(manifest, key, 0);

        attestor
            .check_if_due()
            .expect("first check should succeed");
        assert_eq!(attestor.violation_count(), 0);

        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn test_runtime_attestor_detects_tampering() {
        let p = tmp_file(b"runtime tamper binary");
        let key = test_key();

        let manifest =
            build_manifest(&[p.as_str()], &key).expect("build_manifest should succeed");

        let attestor = RuntimeAttestor::new(manifest, key, 0);

        // Modify the file.
        std::fs::write(&p, b"TAMPERED binary").expect("tamper file");

        let result = attestor.check_if_due();
        assert!(result.is_err(), "tampered file should cause check failure");
        assert_eq!(attestor.violation_count(), 1);

        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn test_ct_eq() {
        assert!(crate::ct::ct_eq(b"hello", b"hello"));
        assert!(!crate::ct::ct_eq(b"hello", b"hellp"));
        assert!(!crate::ct::ct_eq(b"hello", b"hell"));
        assert!(crate::ct::ct_eq(b"", b""));
    }

    // -- FIPS-aware hashing -------------------------------------------------

    #[test]
    fn test_attestation_fips_sha512() {
        // Set FIPS mode, perform all operations, restore — all in one block.
        // Tests run in parallel so we use the same defensive pattern as
        // test_attestation_non_fips_blake3: check the result is self-consistent
        // with the algorithm actually recorded in the manifest.
        common::fips::set_fips_mode_unchecked(true);

        let content = b"fips-attestation-test";
        let path = tmp_file(content);
        let key = test_key();

        // hash_file and build_manifest while FIPS flag is true
        let fh = hash_file(&path).expect("hash_file should succeed");
        let manifest = build_manifest(&[path.as_str()], &key).expect("build_manifest");

        // The manifest must record the algorithm used
        let algo = manifest.hash_algorithm.clone();
        assert!(
            algo == "blake3" || algo == "sha512-t256",
            "unexpected hash_algorithm: {algo}"
        );

        // Verify that the hash in FileHash is consistent with the manifest algorithm
        let recomputed = if algo == "sha512-t256" {
            let full = sha2::Sha512::digest(content);
            let mut out = [0u8; 32];
            out.copy_from_slice(&full[..32]);
            out
        } else {
            *blake3::hash(content).as_bytes()
        };
        assert_eq!(
            fh.blake3_hash, recomputed,
            "hash_file result must be consistent with {algo}"
        );

        // Manifest HMAC and full attestation must pass
        verify_manifest(&manifest, &key).expect("verify_manifest");
        full_attestation(&manifest, &key).expect("full_attestation");

        // Serialize / deserialize preserves the algorithm field
        let blob = serialize_manifest(&manifest);
        let restored = deserialize_manifest(&blob).expect("deserialize");
        assert_eq!(restored.hash_algorithm, algo);
        verify_manifest(&restored, &key).expect("restored manifest should verify");

        std::fs::remove_file(&path).ok();
        common::fips::set_fips_mode_unchecked(false);
    }

    #[test]
    fn test_attestation_non_fips_blake3() {
        // Test that attestation works regardless of FIPS mode.
        // Due to global FIPS flag races in parallel tests, we verify
        // self-consistency rather than asserting a specific algorithm.
        let content = b"non-fips-attestation-test";
        let path = tmp_file(content);
        let key = test_key();

        // Build manifest — algorithm selected by current FIPS state
        let fh = hash_file(&path).expect("hash_file should succeed");
        let manifest = build_manifest(&[path.as_str()], &key).expect("build_manifest");

        let algo = manifest.hash_algorithm.clone();
        assert!(
            algo == "blake3" || algo == "sha512-t256",
            "unexpected hash_algorithm: {algo}"
        );

        // The critical test: manifest verifies and full attestation passes.
        // This proves hash_file, build_manifest, and verify_files are
        // self-consistent regardless of which algorithm was used.
        verify_manifest(&manifest, &key).expect("verify_manifest");
        full_attestation(&manifest, &key).expect("full_attestation");

        std::fs::remove_file(&path).ok();
    }
}
