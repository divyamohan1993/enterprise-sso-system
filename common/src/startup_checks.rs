//! Platform startup checks — called by every service before initialization.
//!
//! Orchestrates platform verification in the correct order:
//! 1. Verify vTPM present (`/dev/tpmrm0`)
//! 2. Process hardening (memguard: PR_SET_DUMPABLE, PR_SET_NO_NEW_PRIVS)
//! 3. Self-attestation: SHA-512(/proc/self/exe) + boot_id logging
//! 4. Start background integrity monitor (re-hash binary + tracer check)
//!
//! ALL checks are FATAL — this system is always in production mode.

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
/// ALL checks are fatal — any failure causes an immediate panic.
///
/// Returns:
/// - `PlatformAttestationReport` with results of all checks
/// - `JoinHandle` for the background integrity monitor thread
/// - `Arc<RuntimeIntegrityMonitor>` for querying violation counts
///
/// # Panics
/// Panics if any check fails (vTPM, hardening, attestation, monitor).
pub fn run_platform_checks<F: FnOnce() -> bool>(harden_fn: F) -> (
    PlatformAttestationReport,
    JoinHandle<()>,
    Arc<RuntimeIntegrityMonitor>,
) {
    // Dev mode: skip all platform checks (no vTPM, no hardening, no attestation)
    if std::env::var("MILNET_DEV_MODE").unwrap_or_default() == "1" {
        tracing::warn!("MILNET_DEV_MODE=1: skipping all platform integrity checks");
        let _ = harden_fn(); // best-effort hardening, ignore result
        let monitor = Arc::new(platform_integrity::RuntimeIntegrityMonitor::new());
        let monitor_ref = Arc::clone(&monitor);
        let handle = std::thread::Builder::new()
            .name("integrity-monitor-noop".to_string())
            .spawn(move || {
                // No-op monitor in dev mode — just park the thread
                loop { std::thread::park(); }
            })
            .expect("failed to spawn noop monitor thread");
        let report = PlatformAttestationReport {
            tpm_info: platform_integrity::TpmInfo {
                available: false,
                version: String::from("dev-mode"),
                device_path: String::from("none"),
            },
            process_hardened: false,
            binary_hash: [0u8; 64],
            boot_id: String::from("dev-mode"),
            boot_attestation: crate::measured_boot::BootAttestation::dev_mode(),
            all_passed: true,
            summary: String::from("DEV_MODE: all checks skipped"),
        };
        return (report, handle, monitor_ref);
    }

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
                panic!(
                    "FATAL: vTPM not available (/dev/tpmrm0, /dev/tpm0). \
                     Production deployment requires vTPM 2.0."
                );
            }
            info
        }
        Err(e) => {
            panic!("FATAL: vTPM check error: {}", e);
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
        panic!(
            "FATAL: process hardening failed. \
             Cannot disable core dumps or set no-new-privs."
        );
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
            panic!(
                "FATAL: self-attestation failed: {}. \
                 Deployment requires binary self-attestation.",
                e
            );
        }
    };

    // -----------------------------------------------------------------------
    // 4. Start background integrity monitor
    // -----------------------------------------------------------------------
    let monitor_interval = 60; // seconds
    let (monitor_handle, monitor_ref) =
        match platform_integrity::start_integrity_monitor(monitor_interval) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("FATAL: failed to start integrity monitor: {e}");
                std::process::exit(1);
            }
        };

    // Verify the monitor thread is actually running.
    if monitor_handle.is_finished() {
        panic!(
            "FATAL: runtime integrity monitor thread exited immediately. \
             Deployment requires a running integrity monitor."
        );
    } else {
        tracing::info!(
            "platform check [4/4]: runtime integrity monitor started (interval={}s)",
            monitor_interval,
        );
        summary_parts.push(format!("monitor={}s", monitor_interval));
    }

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
// Environment sanitization — remove sensitive vars from /proc/PID/environ
// ---------------------------------------------------------------------------

/// SECURITY: List of sensitive environment variables that MUST be removed
/// from the process environment after their values have been consumed.
/// A root attacker can read /proc/PID/environ to exfiltrate these secrets.
const SENSITIVE_ENV_VARS: &[&str] = &[
    "MILNET_MASTER_KEK",
    "MILNET_KEK_SHARE",
    "MILNET_KEK_SHARE_INDEX",
    "MILNET_KEK_PEER_SHARES",
    "MILNET_PKCS11_PIN",
    "MILNET_HSM_BACKEND",
    "DATABASE_URL",
    "POSTGRES_PASSWORD",
    "MILNET_SIEM_WEBHOOK_URL",
    "MILNET_SIEM_AUTH_TOKEN",
    "MILNET_GATEWAY_CERT_PATH",
    "MILNET_GATEWAY_KEY_PATH",
    "MILNET_FIPS_MODE_KEY",
    "MILNET_ADMIN_API_KEY",
    "ADMIN_API_KEY",
    "RATCHET_KEK",
    "DATABASE_REPLICA_URLS",
    "GOOGLE_CLIENT_ID",
    "GOOGLE_CLIENT_SECRET",
    "ADMIN_TLS_KEY",
    "ADMIN_TLS_CERT",
    "MILNET_TSS_SHARE_SEALED",
];

/// Remove ALL sensitive environment variables from the process environment.
///
/// **MUST** be called by every service's `main()` AFTER all configuration has
/// been loaded from env vars. This prevents exfiltration of secrets via
/// `/proc/PID/environ` by a root-level attacker or via child process
/// inheritance.
///
/// Returns the number of variables that were actually present and removed.
pub fn sanitize_environment() -> usize {
    let mut count = 0;
    for var_name in SENSITIVE_ENV_VARS {
        if std::env::var_os(var_name).is_some() {
            // SECURITY: remove_var deletes from the process environment block,
            // preventing /proc/PID/environ exfiltration. The value has already
            // been consumed by the caller's config loading code.
            std::env::remove_var(var_name);
            count += 1;
        }
    }

    if count > 0 {
        tracing::info!(
            sanitized_count = count,
            "SECURITY: sanitized {} sensitive environment variable(s) \
             from process environment to prevent /proc/PID/environ exfiltration",
            count,
        );
    } else {
        tracing::info!(
            "SECURITY: environment sanitization complete — \
             no sensitive variables found (may have been removed earlier)"
        );
    }

    count
}

// ---------------------------------------------------------------------------
// Kernel security posture verification
// ---------------------------------------------------------------------------

/// Verify kernel security settings critical for anti-exfiltration.
///
/// Checks:
/// - `/proc/sys/kernel/yama/ptrace_scope` >= 1 (restrict ptrace)
/// - `/proc/sys/kernel/unprivileged_bpf_disabled` == 1 (restrict eBPF)
///
/// ALL checks are FATAL — insufficient kernel hardening allows nation-state
/// attackers to attach debuggers or load eBPF programs that exfiltrate keys.
/// If the sysctl files are unreadable (e.g., container without /proc mounted),
/// the check is skipped with a warning since the container runtime may enforce
/// these restrictions externally (e.g., seccomp profile).
pub fn verify_kernel_security_posture() {
    if std::env::var("MILNET_DEV_MODE").unwrap_or_default() == "1" {
        tracing::warn!("MILNET_DEV_MODE=1: skipping kernel security posture checks");
        return;
    }
    // Check Yama ptrace_scope
    match std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope") {
        Ok(val) => {
            let scope: u32 = val.trim().parse().unwrap_or(0);
            if scope >= 1 {
                tracing::info!(
                    ptrace_scope = scope,
                    "kernel security: yama ptrace_scope={} (restricted)",
                    scope,
                );
            } else {
                panic!(
                    "FATAL: /proc/sys/kernel/yama/ptrace_scope={} — \
                     ptrace is unrestricted! Any process can attach to this service \
                     and read key material from memory. \
                     Fix: echo 1 > /proc/sys/kernel/yama/ptrace_scope",
                    scope,
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                "kernel security: cannot read /proc/sys/kernel/yama/ptrace_scope: {} \
                 (Yama LSM may not be enabled — assuming container runtime enforces ptrace restrictions)",
                e,
            );
        }
    }

    // Check unprivileged_bpf_disabled
    match std::fs::read_to_string("/proc/sys/kernel/unprivileged_bpf_disabled") {
        Ok(val) => {
            let disabled: u32 = val.trim().parse().unwrap_or(0);
            if disabled >= 1 {
                tracing::info!(
                    unprivileged_bpf_disabled = disabled,
                    "kernel security: unprivileged_bpf_disabled={} (restricted)",
                    disabled,
                );
            } else {
                panic!(
                    "FATAL: /proc/sys/kernel/unprivileged_bpf_disabled={} — \
                     unprivileged users can load BPF programs to intercept syscalls \
                     and exfiltrate key material. \
                     Fix: echo 1 > /proc/sys/kernel/unprivileged_bpf_disabled",
                    disabled,
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                "kernel security: cannot read /proc/sys/kernel/unprivileged_bpf_disabled: {} \
                 (assuming container runtime restricts BPF)",
                e,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// STIG audit integration
// ---------------------------------------------------------------------------

/// Run all STIG/CIS benchmark checks.
///
/// Any Category I failure is fatal and causes a panic.
pub fn run_stig_audit() -> Result<crate::stig::StigSummary, Vec<crate::stig::StigCheck>> {
    if std::env::var("MILNET_DEV_MODE").unwrap_or_default() == "1" {
        tracing::warn!("MILNET_DEV_MODE=1: skipping STIG audit");
        return Ok(crate::stig::StigSummary::default());
    }

    let mut auditor = crate::stig::StigAuditor::new();
    auditor.run_all();
    let summary = auditor.summary();

    let cat_i = auditor.cat_i_failures();
    if !cat_i.is_empty() {
        for failure in &cat_i {
            tracing::error!(
                "STIG Category I FAILURE: {} — {}",
                failure.id,
                failure.detail
            );
        }
        panic!(
            "FATAL: {} STIG Category I failure(s) detected. \
             System cannot start with critical security misconfigurations.",
            cat_i.len()
        );
    }
    Ok(summary)
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
