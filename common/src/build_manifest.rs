//! Reproducible build manifest and binary integrity verification.
//!
//! Provides types and utilities for embedding build-time metadata into
//! compiled binaries and verifying binary integrity at runtime. Used by
//! the reproducible build verification pipeline (`deploy/verify-reproducible-build.sh`).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::path::Path;

/// Build metadata captured at compile time and embedded in the binary.
///
/// This struct is typically populated via environment variables set by
/// the build system or CI pipeline, then serialised into the binary using
/// the [`embed_build_info`] macro.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BuildManifest {
    /// Git commit hash (full SHA-1) at build time.
    pub git_commit: String,
    /// `rustc --version` output.
    pub rustc_version: String,
    /// `cargo --version` output.
    pub cargo_version: String,
    /// The target triple (e.g., `x86_64-unknown-linux-gnu`).
    pub target: String,
    /// Comma-separated list of enabled Cargo features.
    pub features: String,
    /// SHA-256 hash of the compiled binary (hex-encoded).
    pub binary_hash: String,
    /// ISO 8601 build timestamp.
    pub build_time: String,
    /// Whether this build was verified as reproducible.
    pub reproducible_verified: bool,
}

impl BuildManifest {
    /// Create a new BuildManifest with the given fields.
    pub fn new(
        git_commit: impl Into<String>,
        rustc_version: impl Into<String>,
        cargo_version: impl Into<String>,
        target: impl Into<String>,
        features: impl Into<String>,
        binary_hash: impl Into<String>,
        build_time: impl Into<String>,
        reproducible_verified: bool,
    ) -> Self {
        Self {
            git_commit: git_commit.into(),
            rustc_version: rustc_version.into(),
            cargo_version: cargo_version.into(),
            target: target.into(),
            features: features.into(),
            binary_hash: binary_hash.into(),
            build_time: build_time.into(),
            reproducible_verified,
        }
    }

    /// Serialise this manifest to a JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialise a manifest from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Load a manifest from a JSON file on disk.
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read manifest file: {}", e))?;
        Self::from_json(&contents)
            .map_err(|e| format!("Failed to parse manifest JSON: {}", e))
    }

    /// Write this manifest to a JSON file on disk.
    pub fn to_file(&self, path: &Path) -> Result<(), String> {
        let json = self.to_json()
            .map_err(|e| format!("Failed to serialise manifest: {}", e))?;
        std::fs::write(path, json)
            .map_err(|e| format!("Failed to write manifest file: {}", e))
    }
}

/// Compute the SHA-512 hash of a file and return it as a hex string (CNSA 2.0).
///
/// Used to hash compiled binaries for the build manifest.
pub fn sha512_file(path: &Path) -> Result<String, String> {
    let data = std::fs::read(path)
        .map_err(|e| format!("Failed to read file '{}': {}", path.display(), e))?;
    let hash = Sha512::digest(&data);
    Ok(hex::encode(hash))
}

/// Compute the SHA-512 hash of a byte slice and return it as a hex string (CNSA 2.0).
pub fn sha512_bytes(data: &[u8]) -> String {
    let hash = Sha512::digest(data);
    hex::encode(hash)
}

/// Deprecated: use [`sha512_file`] instead. This was misnamed; it computes SHA-512.
#[deprecated(since = "0.2.0", note = "renamed to sha512_file (computes SHA-512, not SHA-256)")]
pub fn sha256_file(path: &Path) -> Result<String, String> {
    sha512_file(path)
}

/// Deprecated: use [`sha512_bytes`] instead. This was misnamed; it computes SHA-512.
#[deprecated(since = "0.2.0", note = "renamed to sha512_bytes (computes SHA-512, not SHA-256)")]
pub fn sha256_bytes(data: &[u8]) -> String {
    sha512_bytes(data)
}

/// Verify that a binary file on disk matches the hash recorded in a manifest.
///
/// Returns `Ok(true)` if the hash matches, `Ok(false)` if it does not,
/// or `Err` if the file cannot be read.
pub fn verify_binary_integrity(binary_path: &Path, manifest: &BuildManifest) -> Result<bool, String> {
    let actual_hash = sha512_file(binary_path)?;
    Ok({
        use subtle::ConstantTimeEq;
        bool::from(actual_hash.as_bytes().ct_eq(manifest.binary_hash.as_bytes()))
    })
}

/// Verify the integrity of the currently running binary against a manifest.
///
/// Uses `/proc/self/exe` on Linux to locate the running binary. On other
/// platforms, falls back to `std::env::current_exe()`.
pub fn verify_running_binary_integrity(manifest: &BuildManifest) -> Result<bool, String> {
    let exe_path = get_current_exe_path()?;
    verify_binary_integrity(&exe_path, manifest)
}

/// Get the path to the currently running executable.
fn get_current_exe_path() -> Result<std::path::PathBuf, String> {
    // On Linux, /proc/self/exe is a symlink to the actual binary, which avoids
    // issues with PATH lookups.
    #[cfg(target_os = "linux")]
    {
        let proc_path = Path::new("/proc/self/exe");
        if proc_path.exists() {
            return std::fs::read_link(proc_path)
                .map_err(|e| format!("Failed to read /proc/self/exe: {}", e));
        }
    }

    std::env::current_exe()
        .map_err(|e| format!("Failed to determine current executable path: {}", e))
}

/// Build information embedded at compile time via environment variables.
///
/// Use the [`embed_build_info`] macro to populate this struct from
/// environment variables that the build system sets (e.g., in a build.rs
/// or CI script).
#[derive(Debug, Clone)]
pub struct EmbeddedBuildInfo {
    /// Git commit hash, from `BUILD_GIT_COMMIT` env var.
    pub git_commit: &'static str,
    /// Rust compiler version, from `BUILD_RUSTC_VERSION` env var.
    pub rustc_version: &'static str,
    /// Cargo version, from `BUILD_CARGO_VERSION` env var.
    pub cargo_version: &'static str,
    /// Target triple, from `BUILD_TARGET` env var.
    pub target: &'static str,
    /// Build timestamp, from `BUILD_TIMESTAMP` env var.
    pub build_time: &'static str,
}

/// Embed build information into the binary using compile-time environment variables.
///
/// The build system or CI pipeline must set these environment variables before
/// invoking `cargo build`:
///
/// - `BUILD_GIT_COMMIT` -- the git commit hash
/// - `BUILD_RUSTC_VERSION` -- output of `rustc --version`
/// - `BUILD_CARGO_VERSION` -- output of `cargo --version`
/// - `BUILD_TARGET` -- the target triple
/// - `BUILD_TIMESTAMP` -- ISO 8601 build timestamp
///
/// If any variable is not set, the macro substitutes `"unknown"`.
///
/// # Example
///
/// ```text
/// use common::build_manifest::embed_build_info;
///
/// let info = embed_build_info!();
/// println!("Built from commit: {}", info.git_commit);
/// ```
#[macro_export]
macro_rules! embed_build_info {
    () => {
        $crate::build_manifest::EmbeddedBuildInfo {
            git_commit: option_env!("BUILD_GIT_COMMIT").unwrap_or("unknown"),
            rustc_version: option_env!("BUILD_RUSTC_VERSION").unwrap_or("unknown"),
            cargo_version: option_env!("BUILD_CARGO_VERSION").unwrap_or("unknown"),
            target: option_env!("BUILD_TARGET").unwrap_or("unknown"),
            build_time: option_env!("BUILD_TIMESTAMP").unwrap_or("unknown"),
        }
    };
}

/// Validate that build manifest fields are not "unknown".
///
/// If the `MILNET_MILITARY_DEPLOYMENT` environment variable is set at runtime
/// and any field in the embedded build info is "unknown", this emits a CRITICAL
/// SIEM event. Call this at startup to catch misconfigured builds early.
///
/// Returns true if all fields are populated, false if any is "unknown".
pub fn validate_build_manifest(info: &EmbeddedBuildInfo) -> bool {
    let fields = [
        ("git_commit", info.git_commit),
        ("rustc_version", info.rustc_version),
        ("cargo_version", info.cargo_version),
        ("target", info.target),
        ("build_time", info.build_time),
    ];

    let mut all_valid = true;
    let mut unknown_fields = Vec::new();

    for (name, value) in &fields {
        if *value == "unknown" {
            all_valid = false;
            unknown_fields.push(*name);
        }
    }

    if !all_valid {
        if std::env::var("MILNET_MILITARY_DEPLOYMENT").is_ok() {
            let siem_event = serde_json::json!({
                "event_type": "build_manifest_incomplete",
                "severity": "CRITICAL",
                "source_module": "build_manifest",
                "detail": format!(
                    "Build manifest has unknown fields in military deployment: {:?}",
                    unknown_fields
                )
            });
            tracing::error!(target: "siem", "{}", siem_event);
        } else {
            tracing::warn!(
                target: "build_manifest",
                "Build manifest has unknown fields: {:?} (non-military deployment, continuing)",
                unknown_fields
            );
        }
    }

    all_valid
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_build_manifest_new() {
        let m = BuildManifest::new(
            "abc123", "rustc 1.75.0", "cargo 1.75.0",
            "x86_64-unknown-linux-gnu", "default",
            "deadbeef", "2026-03-25T00:00:00Z", true,
        );
        assert_eq!(m.git_commit, "abc123");
        assert_eq!(m.rustc_version, "rustc 1.75.0");
        assert!(m.reproducible_verified);
    }

    #[test]
    fn test_build_manifest_json_roundtrip() {
        let m = BuildManifest::new(
            "abc123def456", "rustc 1.75.0", "cargo 1.75.0",
            "x86_64-unknown-linux-gnu", "default,fips",
            "0123456789abcdef", "2026-03-25T12:00:00Z", false,
        );
        let json = m.to_json().unwrap();
        let m2 = BuildManifest::from_json(&json).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn test_build_manifest_file_roundtrip() {
        let m = BuildManifest::new(
            "deadbeef", "rustc 1.80.0", "cargo 1.80.0",
            "aarch64-unknown-linux-gnu", "",
            "aabbccdd", "2026-01-01T00:00:00Z", true,
        );
        let dir = std::env::temp_dir().join("build_manifest_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("manifest.json");

        m.to_file(&path).unwrap();
        let m2 = BuildManifest::from_file(&path).unwrap();
        assert_eq!(m, m2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sha512_bytes() {
        let hash = sha512_bytes(b"hello world");
        assert_eq!(
            hash,
            "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f"
        );
    }

    #[test]
    fn test_sha512_file() {
        let dir = std::env::temp_dir().join("sha512_file_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("testfile.bin");

        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"hello world").unwrap();
        drop(f);

        let hash = sha512_file(&path).unwrap();
        assert_eq!(
            hash,
            "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_verify_binary_integrity_match() {
        let dir = std::env::temp_dir().join("verify_integrity_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("binary.bin");

        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"test binary content").unwrap();
        drop(f);

        let expected_hash = sha512_file(&path).unwrap();
        let manifest = BuildManifest::new(
            "abc", "rustc 1.75.0", "cargo 1.75.0",
            "x86_64-unknown-linux-gnu", "",
            &expected_hash, "2026-01-01T00:00:00Z", true,
        );

        assert!(verify_binary_integrity(&path, &manifest).unwrap());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_verify_binary_integrity_mismatch() {
        let dir = std::env::temp_dir().join("verify_integrity_mismatch_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("binary.bin");

        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"test binary content").unwrap();
        drop(f);

        let manifest = BuildManifest::new(
            "abc", "rustc 1.75.0", "cargo 1.75.0",
            "x86_64-unknown-linux-gnu", "",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "2026-01-01T00:00:00Z", true,
        );

        assert!(!verify_binary_integrity(&path, &manifest).unwrap());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_verify_binary_integrity_file_not_found() {
        let manifest = BuildManifest::new(
            "abc", "rustc 1.75.0", "cargo 1.75.0",
            "x86_64-unknown-linux-gnu", "",
            "deadbeef", "2026-01-01T00:00:00Z", true,
        );

        let result = verify_binary_integrity(
            Path::new("/nonexistent/binary"),
            &manifest,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_embed_build_info_macro() {
        let info = embed_build_info!();
        // Without env vars set, all fields default to "unknown"
        assert_eq!(info.git_commit, "unknown");
        assert_eq!(info.rustc_version, "unknown");
        assert_eq!(info.cargo_version, "unknown");
        assert_eq!(info.target, "unknown");
        assert_eq!(info.build_time, "unknown");
    }

    #[test]
    fn test_build_manifest_from_invalid_json() {
        let result = BuildManifest::from_json("not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_build_manifest_from_nonexistent_file() {
        let result = BuildManifest::from_file(Path::new("/nonexistent/manifest.json"));
        assert!(result.is_err());
    }

    #[test]
    fn test_sha512_output_length_is_64_bytes() {
        let hash = sha512_bytes(b"test data");
        // SHA-512 produces 64 bytes = 128 hex characters
        let raw_bytes = hex::decode(&hash).expect("hash should be valid hex");
        assert_eq!(raw_bytes.len(), 64, "SHA-512 output must be 64 bytes");
    }
}
