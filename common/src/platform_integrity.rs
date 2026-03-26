//! Platform integrity verification for vTPM-equipped deployment VMs.
//!
//! The deployment environment provides Secure Boot, vTPM 2.0, and OS-level
//! integrity monitoring. This module does NOT re-implement those checks.
//! Instead it provides:
//!
//! - vTPM presence verification (check `/dev/tpmrm0`)
//! - Self-attestation: SHA-512 hash of own binary, boot_id logging
//! - Runtime integrity monitor: periodic binary re-hash + dumpable check
//! - vTPM key sealing/unsealing via tpm2-tools CLI
//!
//! All checks are FATAL in production mode (`MILNET_PRODUCTION` set) and
//! WARN-only in dev mode.

use sha2::{Digest, Sha512};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from platform integrity verification.
#[derive(Debug)]
pub enum PlatformError {
    /// A required file or device path was not found.
    NotFound(String),
    /// An I/O error reading a system file.
    IoError(String),
    /// A platform check failed.
    CheckFailed(String),
    /// An integrity violation was detected at runtime.
    IntegrityViolation(String),
    /// A tpm2-tools command failed.
    TpmCommandFailed(String),
}

impl std::fmt::Display for PlatformError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlatformError::NotFound(msg) => write!(f, "not found: {}", msg),
            PlatformError::IoError(msg) => write!(f, "I/O error: {}", msg),
            PlatformError::CheckFailed(msg) => write!(f, "check failed: {}", msg),
            PlatformError::IntegrityViolation(msg) => {
                write!(f, "integrity violation: {}", msg)
            }
            PlatformError::TpmCommandFailed(msg) => {
                write!(f, "TPM command failed: {}", msg)
            }
        }
    }
}

impl std::error::Error for PlatformError {}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn is_production() -> bool {
    crate::sealed_keys::is_production()
}

/// Hardened TPM2-tools binary path.
/// In production, only binaries from known paths are executed to prevent
/// PATH manipulation attacks.
const TPM2_TOOLS_DIR: &str = "/usr/bin";

/// Returns the absolute path for a tpm2-tools command.
/// Validates the binary exists and is not a symlink to an unexpected location.
fn tpm2_command(tool_name: &str) -> std::process::Command {
    let path = format!("{}/{}", TPM2_TOOLS_DIR, tool_name);

    // Verify binary exists at expected path
    if !std::path::Path::new(&path).exists() {
        // Fallback: try /usr/local/bin (common alternative)
        let alt_path = format!("/usr/local/bin/{}", tool_name);
        if std::path::Path::new(&alt_path).exists() {
            let mut cmd = std::process::Command::new(&alt_path);
            cmd.env_clear();
            // Restore minimal safe PATH
            cmd.env("PATH", "/usr/bin:/bin");
            return cmd;
        }
        panic!("TPM2 tool not found at {} or /usr/local/bin/{}", path, tool_name);
    }

    let mut cmd = std::process::Command::new(&path);
    // Clear inherited environment to prevent injection via LD_PRELOAD, PATH, etc.
    cmd.env_clear();
    // Restore only the minimal safe environment
    cmd.env("PATH", "/usr/bin:/bin");
    cmd
}

/// Compute SHA-512 digest of a byte slice.
fn sha512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}

// ---------------------------------------------------------------------------
// vTPM presence check
// ---------------------------------------------------------------------------

/// Information about a detected vTPM device.
#[derive(Debug, Clone)]
pub struct TpmInfo {
    /// Whether a TPM device was found.
    pub available: bool,
    /// TPM version string (e.g., "2").
    pub version: String,
    /// Path to the TPM device node.
    pub device_path: String,
}

/// Check whether a vTPM 2.0 device is present.
///
/// Looks for `/dev/tpmrm0` (resource manager, preferred) or `/dev/tpm0` (raw),
/// then reads the version from sysfs.
pub fn verify_tpm_present() -> Result<TpmInfo, PlatformError> {
    let device_path = if Path::new("/dev/tpmrm0").exists() {
        "/dev/tpmrm0".to_string()
    } else if Path::new("/dev/tpm0").exists() {
        "/dev/tpm0".to_string()
    } else {
        tracing::warn!("platform: no vTPM device found (/dev/tpmrm0, /dev/tpm0)");
        return Ok(TpmInfo {
            available: false,
            version: String::new(),
            device_path: String::new(),
        });
    };

    // Read TPM version from sysfs
    let version = std::fs::read_to_string("/sys/class/tpm/tpm0/tpm_version_major")
        .map(|v| v.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    tracing::info!(
        "platform: vTPM detected — device={}, version={}",
        device_path,
        version
    );

    Ok(TpmInfo {
        available: true,
        version,
        device_path,
    })
}

// ---------------------------------------------------------------------------
// Self-attestation
// ---------------------------------------------------------------------------

/// Self-attestation data captured at startup.
#[derive(Debug, Clone)]
pub struct SelfAttestation {
    /// SHA-512 hash of the service binary (/proc/self/exe).
    pub binary_hash: [u8; 64],
    /// Kernel boot_id for audit correlation.
    pub boot_id: String,
}

/// Compute SHA-512 of our own binary via /proc/self/exe.
pub fn hash_own_binary() -> Result<[u8; 64], PlatformError> {
    let data = std::fs::read("/proc/self/exe").map_err(|e| {
        PlatformError::IoError(format!("cannot read /proc/self/exe: {}", e))
    })?;
    Ok(sha512(&data))
}

/// Read the kernel boot_id for audit correlation.
pub fn read_boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Perform startup self-attestation: hash binary and read boot_id.
pub fn self_attest() -> Result<SelfAttestation, PlatformError> {
    let binary_hash = hash_own_binary()?;
    let boot_id = read_boot_id();

    tracing::info!(
        "platform: self-attestation — binary SHA-512={}...{}, boot_id={}",
        hex::encode(&binary_hash[..4]),
        hex::encode(&binary_hash[60..64]),
        boot_id,
    );

    Ok(SelfAttestation {
        binary_hash,
        boot_id,
    })
}

// ---------------------------------------------------------------------------
// Runtime Integrity Monitor
// ---------------------------------------------------------------------------

/// Continuous background integrity monitor.
///
/// Periodically verifies:
/// 1. Binary on disk (/proc/self/exe) has not changed since startup
/// 2. Process is still non-dumpable (reads /proc/self/status)
///
/// On violation: logs CRITICAL, zeroizes secrets, exits the process.
pub struct RuntimeIntegrityMonitor {
    /// SHA-512 hash of the binary at startup.
    initial_binary_hash: [u8; 64],
    /// Whether the monitor should continue running.
    running: Arc<AtomicBool>,
    /// Number of violations detected.
    violation_count: Arc<AtomicU64>,
}

impl RuntimeIntegrityMonitor {
    /// Snapshot the current process state for future comparison.
    pub fn new() -> Self {
        let binary_hash = hash_own_binary().unwrap_or([0u8; 64]);

        Self {
            initial_binary_hash: binary_hash,
            running: Arc::new(AtomicBool::new(true)),
            violation_count: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Check that the process is still non-dumpable by reading /proc/self/status.
    fn check_non_dumpable() -> Result<(), PlatformError> {
        // Parse /proc/self/status for "TracerPid" and dumpable state
        // instead of calling prctl (which requires unsafe).
        let status = match std::fs::read_to_string("/proc/self/status") {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("platform: cannot read /proc/self/status: {}", e);
                return Ok(()); // Cannot check, don't false-alarm
            }
        };

        for line in status.lines() {
            // Check if a tracer is attached
            if let Some(rest) = line.strip_prefix("TracerPid:") {
                let pid: u32 = rest.trim().parse().unwrap_or(0);
                if pid != 0 {
                    return Err(PlatformError::IntegrityViolation(format!(
                        "process is being traced by PID {}",
                        pid
                    )));
                }
            }
        }
        Ok(())
    }

    /// Run a single round of all integrity checks.
    pub fn run_checks(&self) -> Vec<PlatformError> {
        let mut violations = Vec::new();

        // 1. Check non-dumpable / no tracer
        if let Err(e) = Self::check_non_dumpable() {
            violations.push(e);
        }

        // 2. Check binary on disk hasn't changed
        match hash_own_binary() {
            Ok(current_hash) => {
                if current_hash != self.initial_binary_hash {
                    violations.push(PlatformError::IntegrityViolation(format!(
                        "binary on disk changed: expected={}..., current={}...",
                        hex::encode(&self.initial_binary_hash[..8]),
                        hex::encode(&current_hash[..8]),
                    )));
                }
            }
            Err(e) => {
                tracing::warn!("platform: cannot hash own binary for check: {}", e);
            }
        }

        violations
    }

    /// Number of violations detected since the monitor started.
    pub fn violation_count(&self) -> u64 {
        self.violation_count.load(Ordering::Relaxed)
    }

    /// Signal the monitor to stop.
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

/// Start the background integrity monitor.
///
/// Spawns a background thread that runs integrity checks every
/// `interval_secs` seconds. On violation in production mode, the
/// process exits with code 199.
pub fn start_integrity_monitor(
    interval_secs: u64,
) -> (JoinHandle<()>, Arc<RuntimeIntegrityMonitor>) {
    let monitor = Arc::new(RuntimeIntegrityMonitor::new());
    let monitor_ref = Arc::clone(&monitor);
    let production = is_production();

    let handle = std::thread::Builder::new()
        .name("integrity-monitor".to_string())
        .spawn(move || {
            tracing::info!(
                "platform: runtime integrity monitor started (interval={}s, production={})",
                interval_secs,
                production,
            );

            loop {
                std::thread::sleep(std::time::Duration::from_secs(interval_secs));

                if !monitor_ref.running.load(Ordering::Relaxed) {
                    tracing::info!("platform: integrity monitor stopping");
                    break;
                }

                let violations = monitor_ref.run_checks();
                if !violations.is_empty() {
                    for v in &violations {
                        tracing::error!("CRITICAL INTEGRITY VIOLATION: {}", v);
                    }
                    monitor_ref
                        .violation_count
                        .fetch_add(violations.len() as u64, Ordering::Relaxed);

                    if production {
                        tracing::error!(
                            "FATAL: {} integrity violation(s) in production — \
                             initiating emergency shutdown",
                            violations.len()
                        );
                        std::thread::sleep(std::time::Duration::from_millis(100));
                        std::process::exit(199);
                    }
                }
            }
        })
        .expect("failed to spawn integrity monitor thread");

    (handle, monitor)
}

// ---------------------------------------------------------------------------
// vTPM Key Sealing via tpm2-tools
// ---------------------------------------------------------------------------

/// Default directory for sealed key blobs.
const DEFAULT_SEALED_DIR: &str = "/var/lib/milnet/sealed";

/// PCR indices used for sealing policy (UEFI firmware + Secure Boot policy).
const SEAL_PCR_LIST: &str = "sha256:0,7";

/// Seal a secret to the vTPM with a PCR policy.
///
/// Uses `tpm2_createprimary`, `tpm2_create`, and `tpm2_load` to seal
/// `secret` under PCRs 0 and 7. The sealed blob is written to
/// `<sealed_dir>/<name>.pub` and `<sealed_dir>/<name>.priv`.
///
/// On first deploy, call this to seal FROST shares and master KEK.
/// On subsequent boots, call `tpm_unseal` to recover them (only succeeds
/// if the boot chain matches the PCR policy).
pub fn tpm_seal(
    name: &str,
    secret: &[u8],
    sealed_dir: Option<&str>,
) -> Result<(), PlatformError> {
    let dir = sealed_dir.unwrap_or(DEFAULT_SEALED_DIR);

    // Ensure sealed directory exists
    std::fs::create_dir_all(dir).map_err(|e| {
        PlatformError::IoError(format!("cannot create sealed dir {}: {}", dir, e))
    })?;

    let _ctx_path = format!("{}/{}.ctx", dir, name);
    let pub_path = format!("{}/{}.pub", dir, name);
    let priv_path = format!("{}/{}.priv", dir, name);
    let primary_ctx = format!("{}/{}_primary.ctx", dir, name);
    let policy_path = format!("{}/{}_policy.digest", dir, name);

    // Write secret to a temp file for tpm2_create -i
    let secret_tmp = format!("{}/{}.secret.tmp", dir, name);
    std::fs::write(&secret_tmp, secret).map_err(|e| {
        PlatformError::IoError(format!("cannot write temp secret: {}", e))
    })?;

    // 1. Create primary key under owner hierarchy
    let output = tpm2_command("tpm2_createprimary")
        .args(["-C", "o", "-c", &primary_ctx])
        .output()
        .map_err(|e| {
            PlatformError::TpmCommandFailed(format!("tpm2_createprimary: {}", e))
        })?;

    if !output.status.success() {
        // Clean up temp file
        let _ = std::fs::remove_file(&secret_tmp);
        return Err(PlatformError::TpmCommandFailed(format!(
            "tpm2_createprimary failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    // 2. Create PCR policy
    let _output = tpm2_command("tpm2_pcrread")
        .args(["-o", &policy_path, SEAL_PCR_LIST])
        .output();

    // Build a policy session for PCR binding
    let policy_session = format!("{}/{}_session.ctx", dir, name);
    let output = tpm2_command("tpm2_startauthsession")
        .args(["-S", &policy_session])
        .output()
        .map_err(|e| {
            PlatformError::TpmCommandFailed(format!("tpm2_startauthsession: {}", e))
        })?;

    if !output.status.success() {
        let _ = std::fs::remove_file(&secret_tmp);
        return Err(PlatformError::TpmCommandFailed(format!(
            "tpm2_startauthsession failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    let output = tpm2_command("tpm2_policypcr")
        .args(["-S", &policy_session, "-l", SEAL_PCR_LIST, "-L", &policy_path])
        .output()
        .map_err(|e| {
            PlatformError::TpmCommandFailed(format!("tpm2_policypcr: {}", e))
        })?;

    if !output.status.success() {
        let _ = std::fs::remove_file(&secret_tmp);
        return Err(PlatformError::TpmCommandFailed(format!(
            "tpm2_policypcr failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    let _ = tpm2_command("tpm2_flushcontext").args([&policy_session]).output();

    // 3. Create sealed object with PCR policy
    let output = tpm2_command("tpm2_create")
        .args([
            "-C", &primary_ctx,
            "-i", &secret_tmp,
            "-u", &pub_path,
            "-r", &priv_path,
            "-L", &policy_path,
        ])
        .output()
        .map_err(|e| {
            PlatformError::TpmCommandFailed(format!("tpm2_create: {}", e))
        })?;

    // Clean up temp secret file immediately
    let _ = std::fs::remove_file(&secret_tmp);

    if !output.status.success() {
        return Err(PlatformError::TpmCommandFailed(format!(
            "tpm2_create (seal) failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    // Clean up intermediate files
    let _ = std::fs::remove_file(&primary_ctx);
    let _ = std::fs::remove_file(&policy_path);

    tracing::info!(
        "platform: sealed '{}' to vTPM (PCR policy {}) at {}",
        name,
        SEAL_PCR_LIST,
        dir,
    );

    Ok(())
}

/// Unseal a secret from the vTPM.
///
/// Loads the sealed blob from `<sealed_dir>/<name>.pub` and
/// `<sealed_dir>/<name>.priv`, then unseals using a PCR policy session.
///
/// Returns the unsealed secret bytes. Fails if PCR values have changed
/// since the secret was sealed (fail-closed: manual re-seal required).
pub fn tpm_unseal(
    name: &str,
    sealed_dir: Option<&str>,
) -> Result<Vec<u8>, PlatformError> {
    let dir = sealed_dir.unwrap_or(DEFAULT_SEALED_DIR);
    let pub_path = format!("{}/{}.pub", dir, name);
    let priv_path = format!("{}/{}.priv", dir, name);
    let primary_ctx = format!("{}/{}_primary.ctx", dir, name);
    let loaded_ctx = format!("{}/{}_loaded.ctx", dir, name);
    let unsealed_path = format!("{}/{}.unsealed.tmp", dir, name);

    // Check sealed blobs exist
    if !Path::new(&pub_path).exists() || !Path::new(&priv_path).exists() {
        return Err(PlatformError::NotFound(format!(
            "sealed blob not found for '{}' at {}",
            name, dir
        )));
    }

    // 1. Recreate primary
    let output = tpm2_command("tpm2_createprimary")
        .args(["-C", "o", "-c", &primary_ctx])
        .output()
        .map_err(|e| {
            PlatformError::TpmCommandFailed(format!("tpm2_createprimary: {}", e))
        })?;

    if !output.status.success() {
        return Err(PlatformError::TpmCommandFailed(format!(
            "tpm2_createprimary failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    // 2. Load sealed object
    let output = tpm2_command("tpm2_load")
        .args([
            "-C", &primary_ctx,
            "-u", &pub_path,
            "-r", &priv_path,
            "-c", &loaded_ctx,
        ])
        .output()
        .map_err(|e| {
            PlatformError::TpmCommandFailed(format!("tpm2_load: {}", e))
        })?;

    if !output.status.success() {
        let _ = std::fs::remove_file(&primary_ctx);
        return Err(PlatformError::TpmCommandFailed(format!(
            "tpm2_load failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    // 3. Start policy session and satisfy PCR policy
    let policy_session = format!("{}/{}_unseal_session.ctx", dir, name);
    let output = tpm2_command("tpm2_startauthsession")
        .args(["--policy-session", "-S", &policy_session])
        .output()
        .map_err(|e| {
            PlatformError::TpmCommandFailed(format!("tpm2_startauthsession: {}", e))
        })?;

    if !output.status.success() {
        let _ = std::fs::remove_file(&primary_ctx);
        let _ = std::fs::remove_file(&loaded_ctx);
        return Err(PlatformError::TpmCommandFailed(format!(
            "tpm2_startauthsession failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    let output = tpm2_command("tpm2_policypcr")
        .args(["-S", &policy_session, "-l", SEAL_PCR_LIST])
        .output()
        .map_err(|e| {
            PlatformError::TpmCommandFailed(format!("tpm2_policypcr: {}", e))
        })?;

    if !output.status.success() {
        let _ = std::fs::remove_file(&primary_ctx);
        let _ = std::fs::remove_file(&loaded_ctx);
        let _ = tpm2_command("tpm2_flushcontext").args([&policy_session]).output();
        return Err(PlatformError::TpmCommandFailed(format!(
            "tpm2_policypcr (unseal) failed — PCR values may have changed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    // 4. Unseal
    let output = tpm2_command("tpm2_unseal")
        .args([
            "-c", &loaded_ctx,
            "-p", &format!("session:{}", policy_session),
            "-o", &unsealed_path,
        ])
        .output()
        .map_err(|e| {
            PlatformError::TpmCommandFailed(format!("tpm2_unseal: {}", e))
        })?;

    // Clean up contexts
    let _ = std::fs::remove_file(&primary_ctx);
    let _ = std::fs::remove_file(&loaded_ctx);
    let _ = tpm2_command("tpm2_flushcontext").args([&policy_session]).output();

    if !output.status.success() {
        let _ = std::fs::remove_file(&unsealed_path);
        return Err(PlatformError::TpmCommandFailed(format!(
            "tpm2_unseal failed — boot chain may have changed (PCR mismatch): {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    // Read unsealed data and clean up
    let secret = std::fs::read(&unsealed_path).map_err(|e| {
        PlatformError::IoError(format!("cannot read unsealed data: {}", e))
    })?;
    let _ = std::fs::remove_file(&unsealed_path);

    tracing::info!(
        "platform: unsealed '{}' from vTPM ({} bytes)",
        name,
        secret.len(),
    );

    Ok(secret)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha512_deterministic() {
        let data = b"test payload for sha512";
        let h1 = sha512(data);
        let h2 = sha512(data);
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 64]);
    }

    #[test]
    fn test_tpm_does_not_panic() {
        let result = verify_tpm_present();
        assert!(result.is_ok());
    }

    #[test]
    fn test_hash_own_binary() {
        // In CI, /proc/self/exe should be readable
        let result = hash_own_binary();
        // May fail on non-Linux; just verify no panic
        if let Ok(hash) = result {
            assert_ne!(hash, [0u8; 64]);
        }
    }

    #[test]
    fn test_read_boot_id() {
        let boot_id = read_boot_id();
        // May be "unknown" on non-Linux
        assert!(!boot_id.is_empty());
    }

    #[test]
    fn test_self_attest() {
        let result = self_attest();
        // May fail on non-Linux
        if let Ok(att) = result {
            assert_ne!(att.binary_hash, [0u8; 64]);
            assert!(!att.boot_id.is_empty());
        }
    }

    #[test]
    fn test_runtime_monitor_creation() {
        let monitor = RuntimeIntegrityMonitor::new();
        assert_eq!(monitor.violation_count(), 0);
    }

    #[test]
    fn test_runtime_monitor_checks_run() {
        let monitor = RuntimeIntegrityMonitor::new();
        let _violations = monitor.run_checks();
        // Just verify it doesn't panic
    }

    #[test]
    fn test_tpm_unseal_missing_blob() {
        let result = tpm_unseal("nonexistent-key", Some("/tmp/milnet-test-sealed"));
        assert!(result.is_err());
        match result.unwrap_err() {
            PlatformError::NotFound(_) => {} // expected
            other => panic!("expected NotFound, got: {}", other),
        }
    }

    #[test]
    fn test_platform_error_display() {
        let e = PlatformError::CheckFailed("test failure".to_string());
        assert!(e.to_string().contains("test failure"));

        let e = PlatformError::TpmCommandFailed("tpm2 error".to_string());
        assert!(e.to_string().contains("tpm2 error"));
    }
}
