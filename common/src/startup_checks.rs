//! Platform startup checks — called by every service before initialization.
//!
//! Orchestrates platform verification in the correct order:
//! 1. Verify vTPM present (`/dev/tpmrm0`)
//! 2. Process hardening (memguard: PR_SET_DUMPABLE, PR_SET_NO_NEW_PRIVS)
//! 3. Self-attestation: SHA-512(/proc/self/exe) + boot_id logging
//! 4. Start background integrity monitor (re-hash binary + tracer check)
//!
//! In production mode (`MILNET_PRODUCTION` set), failed checks are FATAL.
//! In dev mode, they produce warnings.

use crate::measured_boot::BootAttestation;
use crate::platform_integrity::{self, RuntimeIntegrityMonitor, TpmInfo};
use std::sync::Arc;
use std::thread::JoinHandle;

// ---------------------------------------------------------------------------
// Report structure
// ---------------------------------------------------------------------------

/// Summary of all platform attestation checks performed at startup.
#[derive(Debug)]
pub struct PlatformAttestationReport {
    /// vTPM device information (if available).
    pub tpm_info: TpmInfo,
    /// Whether process hardening succeeded.
    pub process_hardened: bool,
    /// SHA-512 hash of the service binary at startup.
    pub binary_hash: [u8; 64],
    /// Kernel boot_id for audit correlation.
    pub boot_id: String,
    /// Boot attestation (for SHARD registration).
    pub boot_attestation: BootAttestation,
    /// Whether all checks passed.
    pub all_passed: bool,
    /// Human-readable summary of check results.
    pub summary: String,
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/// Run all platform integrity checks.
///
/// This function should be called by every service's `main()` **before**
/// any other initialization (key loading, network binding, etc.).
///
/// `harden_fn` is a closure that performs process hardening (e.g., calling
/// `crypto::memguard::harden_process()`). It must return `true` on success.
/// This indirection avoids a circular dependency (common cannot depend on crypto).
///
/// In production mode (`MILNET_PRODUCTION` set), any critical failure
/// causes an immediate panic. In dev mode, failures are logged as warnings.
///
/// Returns:
/// - `PlatformAttestationReport` with results of all checks
/// - `JoinHandle` for the background integrity monitor thread
/// - `Arc<RuntimeIntegrityMonitor>` for querying violation counts
///
/// # Panics
/// In production mode, panics if:
/// - vTPM is not available
/// - Process hardening fails
pub fn run_platform_checks<F: FnOnce() -> bool>(harden_fn: F) -> (
    PlatformAttestationReport,
    JoinHandle<()>,
    Arc<RuntimeIntegrityMonitor>,
) {
    let production = crate::sealed_keys::is_production();
    let mut all_passed = true;
    let mut summary_parts: Vec<String> = Vec::new();

    // -----------------------------------------------------------------------
    // 1. Verify vTPM present
    // -----------------------------------------------------------------------
    let tpm_info = match platform_integrity::verify_tpm_present() {
        Ok(info) => {
            if info.available {
                tracing::info!(
                    "platform check [1/4]: vTPM {} detected at {}",
                    info.version,
                    info.device_path,
                );
                summary_parts.push(format!("vTPM=v{}", info.version));
            } else {
                if production {
                    panic!(
                        "FATAL: vTPM not available (/dev/tpmrm0, /dev/tpm0). \
                         Production deployment requires vTPM 2.0."
                    );
                }
                tracing::warn!(
                    "platform check [1/4]: vTPM not available (dev mode — continuing)"
                );
                summary_parts.push("vTPM=ABSENT(dev)".to_string());
                all_passed = false;
            }
            info
        }
        Err(e) => {
            if production {
                panic!("FATAL: vTPM check error: {}", e);
            }
            tracing::warn!(
                "platform check [1/4]: vTPM check error: {} (dev mode — continuing)",
                e
            );
            summary_parts.push(format!("vTPM=ERROR({})", e));
            all_passed = false;
            TpmInfo {
                available: false,
                version: String::new(),
                device_path: String::new(),
            }
        }
    };

    // -----------------------------------------------------------------------
    // 2. Harden process (PR_SET_DUMPABLE, PR_SET_NO_NEW_PRIVS)
    // -----------------------------------------------------------------------
    let process_hardened = harden_fn();
    if process_hardened {
        tracing::info!("platform check [2/4]: process hardened (non-dumpable, no-new-privs)");
        summary_parts.push("hardened=OK".to_string());
    } else {
        if production {
            panic!(
                "FATAL: process hardening failed. \
                 Cannot disable core dumps or set no-new-privs in production."
            );
        }
        tracing::warn!(
            "platform check [2/4]: process hardening partially failed (dev mode — continuing)"
        );
        summary_parts.push("hardened=PARTIAL(dev)".to_string());
        all_passed = false;
    }

    // -----------------------------------------------------------------------
    // 3. Self-attestation: hash binary + read boot_id
    // -----------------------------------------------------------------------
    let self_att = match platform_integrity::self_attest() {
        Ok(att) => {
            tracing::info!(
                "platform check [3/4]: binary SHA-512={}...{}, boot_id={}",
                hex::encode(&att.binary_hash[..4]),
                hex::encode(&att.binary_hash[60..64]),
                att.boot_id,
            );
            summary_parts.push(format!(
                "binary=SHA512:{}...",
                hex::encode(&att.binary_hash[..8])
            ));
            summary_parts.push(format!("boot_id={}", &att.boot_id[..8.min(att.boot_id.len())]));
            att
        }
        Err(e) => {
            tracing::warn!(
                "platform check [3/4]: self-attestation failed: {} (non-Linux?)",
                e
            );
            summary_parts.push("binary=UNREADABLE".to_string());
            all_passed = false;
            platform_integrity::SelfAttestation {
                binary_hash: [0u8; 64],
                boot_id: "unknown".to_string(),
            }
        }
    };

    // -----------------------------------------------------------------------
    // 4. Start background integrity monitor
    // -----------------------------------------------------------------------
    let monitor_interval = 60; // seconds
    let (monitor_handle, monitor_ref) =
        platform_integrity::start_integrity_monitor(monitor_interval);

    tracing::info!(
        "platform check [4/4]: runtime integrity monitor started (interval={}s)",
        monitor_interval,
    );
    summary_parts.push(format!("monitor={}s", monitor_interval));

    // -----------------------------------------------------------------------
    // Build attestation report
    // -----------------------------------------------------------------------
    let boot_attestation = BootAttestation::from_checks(&tpm_info, &self_att);
    let summary = summary_parts.join(", ");

    tracing::info!(
        "platform attestation complete: all_passed={}, {}",
        all_passed,
        summary,
    );

    let report = PlatformAttestationReport {
        tpm_info,
        process_hardened,
        binary_hash: self_att.binary_hash,
        boot_id: self_att.boot_id,
        boot_attestation,
        all_passed,
        summary,
    };

    (report, monitor_handle, monitor_ref)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_attestation_report_fields() {
        let report = PlatformAttestationReport {
            tpm_info: TpmInfo {
                available: false,
                version: String::new(),
                device_path: String::new(),
            },
            process_hardened: true,
            binary_hash: [0u8; 64],
            boot_id: "test".to_string(),
            boot_attestation: BootAttestation {
                tpm_available: false,
                tpm_version: String::new(),
                binary_hash: [0u8; 64],
                boot_id: "test".to_string(),
                attestation_time: 0,
            },
            all_passed: false,
            summary: "test".to_string(),
        };
        assert!(!report.all_passed);
    }
}
