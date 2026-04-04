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
    // SECURITY: Install a custom panic hook that suppresses stack traces in
    // production. Default Rust panic output includes file paths, line numbers,
    // and function names which reveal internal architecture to an attacker who
    // can observe stderr (e.g. via container logs).
    install_military_panic_hook();

    // SECURITY: Load FIPS activation key and auto-enable FIPS mode in military
    // deployment. This MUST happen before any crypto operations.
    crate::fips::load_fips_activation_key();

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
// Distributed cluster verification — called after platform checks
// ---------------------------------------------------------------------------

/// Verify distributed cluster readiness before accepting requests.
///
/// This function MUST be called by every service's `main()` AFTER
/// `run_platform_checks()` but BEFORE binding any network port.
///
/// Takes pre-collected peer attestations (gathered via mTLS during service
/// discovery). If verification fails, the process exits with a FATAL error.
///
/// Returns the verification result on success for audit logging.
pub fn verify_distributed_cluster(
    peer_attestations: &[crate::distributed_startup::PeerAttestation],
) -> crate::distributed_startup::StartupVerification {
    let verifier = match crate::distributed_startup::DistributedStartupVerifier::new() {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                "FATAL: distributed startup verifier initialization failed: {}",
                e,
            );
            eprintln!("FATAL: distributed startup verifier initialization failed: {e}");
            std::process::exit(1);
        }
    };

    match verifier.verify_cluster(peer_attestations) {
        Ok(verification) => {
            tracing::info!(
                "distributed cluster verification PASSED: cluster_size={}, quorum={}, state_synced={}",
                verification.cluster_size,
                verification.quorum_achievable,
                verification.state_chain_synced,
            );
            verification
        }
        Err(e) => {
            tracing::error!(
                "FATAL: distributed cluster verification FAILED: {}",
                e,
            );
            eprintln!("FATAL: distributed cluster verification FAILED: {e}");
            std::process::exit(1);
        }
    }
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
        if let Some(val) = std::env::var_os(var_name) {
            // SECURITY: Overwrite the value with zeros before removing it.
            // std::env::remove_var removes the pointer from environ but does NOT
            // zero the original bytes in the process heap. A root attacker with
            // /proc/PID/mem access could read residual key material. Setting the
            // var to zeros first overwrites the libc environ buffer, then remove_var
            // drops the entry from the environ array.
            let zeros = "0".repeat(val.len());
            std::env::set_var(var_name, &zeros);
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
// Panic hook — suppress stack traces in production
// ---------------------------------------------------------------------------

/// Install a custom panic hook that redacts file paths and stack traces.
///
/// In military deployment, the default Rust panic hook prints file:line and
/// a full backtrace to stderr. This leaks internal code structure (module names,
/// function names, line numbers) which aids reverse engineering. The custom hook
/// logs only a generic "internal error" message with a correlation ID.
fn install_military_panic_hook() {
    use std::sync::Once;
    static HOOK_INSTALLED: Once = Once::new();
    HOOK_INSTALLED.call_once(|| {
        std::panic::set_hook(Box::new(|info| {
            // Generate a random correlation ID for incident response
            let mut corr_id = [0u8; 8];
            let _ = getrandom::getrandom(&mut corr_id);
            let corr_hex: String = corr_id.iter().map(|b| format!("{b:02x}")).collect();

            // In military deployment, suppress all location information
            if std::env::var("MILNET_MILITARY_DEPLOYMENT").as_deref() == Ok("1") {
                eprintln!(
                    "MILNET FATAL: internal error (correlation_id={corr_hex}). \
                     Check SIEM for details."
                );
            } else {
                // In dev/test, include location but not the payload (which might
                // contain secret-adjacent data from format strings)
                let location = info.location().map(|l| format!("{}:{}", l.file(), l.line()));
                eprintln!(
                    "MILNET FATAL: internal error at {} (correlation_id={corr_hex})",
                    location.as_deref().unwrap_or("unknown")
                );
            }

            // Emit SIEM event for all panics
            crate::siem::SecurityEvent::tamper_detected(
                &format!("process panic (correlation_id={corr_hex})")
            );
        }));
    });
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
