//! Adversarial tests for the runtime_defense module.
//!
//! Tests runtime_defense_sweep() with various simulated threat conditions
//! including TracerPid detection, LD_PRELOAD detection, capability escalation,
//! binary integrity verification, and VmLck verification.

use common::runtime_defense::{runtime_defense_sweep, RuntimeAlert};
use serial_test::serial;

// ---------------------------------------------------------------------------
// Helper: run sweep and find alerts by check name
// ---------------------------------------------------------------------------

fn alerts_by_check<'a>(alerts: &'a [RuntimeAlert], check: &str) -> Vec<&'a RuntimeAlert> {
    alerts.iter().filter(|a| a.check == check).collect()
}

// ---------------------------------------------------------------------------
// Binary integrity verification
// ---------------------------------------------------------------------------

#[test]
fn test_binary_integrity_with_wrong_hash() {
    // A hash of all zeros will never match the running binary.
    let fake_hash = [0u8; 64];
    let alerts = runtime_defense_sweep(&fake_hash);
    let binary_alerts = alerts_by_check(&alerts, "binary_integrity");
    assert!(
        !binary_alerts.is_empty(),
        "expected binary_integrity alert when expected hash is all zeros"
    );
    let a = binary_alerts[0];
    assert!(
        a.severity == "critical" || a.severity == "high",
        "binary_integrity alert should be critical or high, got: {}",
        a.severity
    );
}

#[test]
fn test_binary_integrity_with_matching_hash() {
    // Compute the actual hash of /proc/self/exe to prove that a correct
    // hash produces NO binary_integrity alert.
    if let Ok(binary) = std::fs::read("/proc/self/exe") {
        use sha2::{Digest, Sha512};
        let hash = Sha512::digest(&binary);
        let mut expected = [0u8; 64];
        expected.copy_from_slice(&hash);
        let alerts = runtime_defense_sweep(&expected);
        let binary_alerts = alerts_by_check(&alerts, "binary_integrity");
        assert!(
            binary_alerts.is_empty(),
            "no binary_integrity alert expected when hash matches, got: {:?}",
            binary_alerts
        );
    }
    // If /proc/self/exe is unreadable, the test environment doesn't
    // support this check; skip gracefully.
}

// ---------------------------------------------------------------------------
// LD_PRELOAD detection
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn test_ld_preload_detected_when_set() {
    // Save and restore LD_PRELOAD around the test.
    let saved = std::env::var("LD_PRELOAD").ok();

    std::env::set_var("LD_PRELOAD", "/tmp/evil.so");
    let fake_hash = [0xAA; 64]; // hash doesn't matter for this check
    let alerts = runtime_defense_sweep(&fake_hash);
    let injection_alerts = alerts_by_check(&alerts, "library_injection");
    assert!(
        !injection_alerts.is_empty(),
        "expected library_injection alert when LD_PRELOAD is set"
    );
    assert_eq!(injection_alerts[0].severity, "critical");
    assert!(
        injection_alerts[0].detail.contains("/tmp/evil.so"),
        "alert detail should contain the LD_PRELOAD value"
    );

    // Restore.
    match saved {
        Some(v) => std::env::set_var("LD_PRELOAD", v),
        None => std::env::remove_var("LD_PRELOAD"),
    }
}

#[test]
#[serial]
fn test_no_ld_preload_alert_when_unset() {
    let saved = std::env::var("LD_PRELOAD").ok();
    std::env::remove_var("LD_PRELOAD");

    let fake_hash = [0xAA; 64];
    let alerts = runtime_defense_sweep(&fake_hash);
    let injection_alerts = alerts_by_check(&alerts, "library_injection");
    assert!(
        injection_alerts.is_empty(),
        "no library_injection alert expected when LD_PRELOAD is not set"
    );

    if let Some(v) = saved {
        std::env::set_var("LD_PRELOAD", v);
    }
}

#[test]
#[serial]
fn test_empty_ld_preload_not_flagged() {
    let saved = std::env::var("LD_PRELOAD").ok();
    std::env::set_var("LD_PRELOAD", "");

    let fake_hash = [0xAA; 64];
    let alerts = runtime_defense_sweep(&fake_hash);
    let injection_alerts = alerts_by_check(&alerts, "library_injection");
    assert!(
        injection_alerts.is_empty(),
        "empty LD_PRELOAD should not trigger an alert"
    );

    match saved {
        Some(v) => std::env::set_var("LD_PRELOAD", v),
        None => std::env::remove_var("LD_PRELOAD"),
    }
}

// ---------------------------------------------------------------------------
// VmLck verification (memory canary)
// ---------------------------------------------------------------------------

#[test]
fn test_vmlck_zero_triggers_alert() {
    // In a test process we typically have VmLck: 0 because no pages
    // are mlock'd. The sweep should detect this.
    let fake_hash = [0xAA; 64];
    let alerts = runtime_defense_sweep(&fake_hash);
    let canary_alerts = alerts_by_check(&alerts, "memory_canary");
    // This will fire in CI/test where VmLck is 0.
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        let vmlck = status
            .lines()
            .find(|l| l.starts_with("VmLck:"))
            .and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok());
        if vmlck == Some(0) {
            assert!(
                !canary_alerts.is_empty(),
                "VmLck is 0 -- expected memory_canary alert"
            );
            assert_eq!(canary_alerts[0].severity, "high");
        }
    }
}

// ---------------------------------------------------------------------------
// Capability escalation detection
// ---------------------------------------------------------------------------

#[test]
fn test_capability_check_does_not_false_positive_in_test() {
    // A normal test process should NOT have full capabilities.
    let fake_hash = [0xAA; 64];
    let alerts = runtime_defense_sweep(&fake_hash);
    let cap_alerts = alerts_by_check(&alerts, "capability_escalation");
    // In a standard CI/test runner, full caps shouldn't be present.
    // If they are, the test environment itself is concerning.
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(val) = line.strip_prefix("CapEff:") {
                let caps = val.trim();
                if caps != "0000003fffffffff" && caps != "000001ffffffffff" {
                    assert!(
                        cap_alerts.is_empty(),
                        "non-root process should not trigger capability_escalation"
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Debugger detection (TracerPid)
// ---------------------------------------------------------------------------

#[test]
fn test_debugger_detection_no_false_positive() {
    // A test running without a debugger should NOT have TracerPid != 0.
    let fake_hash = [0xAA; 64];
    let alerts = runtime_defense_sweep(&fake_hash);
    let dbg_alerts = alerts_by_check(&alerts, "debugger_detection");
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(val) = line.strip_prefix("TracerPid:") {
                if let Ok(pid) = val.trim().parse::<u32>() {
                    if pid == 0 {
                        assert!(
                            dbg_alerts.is_empty(),
                            "TracerPid is 0, no debugger_detection alert expected"
                        );
                    } else {
                        assert!(
                            !dbg_alerts.is_empty(),
                            "TracerPid is {pid}, debugger_detection alert expected"
                        );
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Full sweep: all checks passing (correct hash, no LD_PRELOAD)
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn test_full_sweep_with_correct_hash() {
    let saved = std::env::var("LD_PRELOAD").ok();
    std::env::remove_var("LD_PRELOAD");

    if let Ok(binary) = std::fs::read("/proc/self/exe") {
        use sha2::{Digest, Sha512};
        let hash = Sha512::digest(&binary);
        let mut expected = [0u8; 64];
        expected.copy_from_slice(&hash);
        let alerts = runtime_defense_sweep(&expected);

        // With correct hash and no LD_PRELOAD, only environmental alerts
        // (VmLck, connection anomaly) should fire -- never binary_integrity
        // or library_injection.
        let binary_alerts = alerts_by_check(&alerts, "binary_integrity");
        let injection_alerts = alerts_by_check(&alerts, "library_injection");
        assert!(binary_alerts.is_empty(), "binary_integrity should not fire");
        assert!(injection_alerts.is_empty(), "library_injection should not fire");
    }

    if let Some(v) = saved {
        std::env::set_var("LD_PRELOAD", v);
    }
}

// ---------------------------------------------------------------------------
// Full sweep: each check failing individually
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn test_sweep_only_binary_integrity_fails() {
    let saved = std::env::var("LD_PRELOAD").ok();
    std::env::remove_var("LD_PRELOAD");

    let wrong_hash = [0xFF; 64];
    let alerts = runtime_defense_sweep(&wrong_hash);
    let binary_alerts = alerts_by_check(&alerts, "binary_integrity");
    // Binary integrity should fail (or report unable to read).
    assert!(
        !binary_alerts.is_empty(),
        "expected binary_integrity alert with wrong hash"
    );

    // library_injection should NOT fire since LD_PRELOAD is unset.
    let injection_alerts = alerts_by_check(&alerts, "library_injection");
    assert!(injection_alerts.is_empty());

    if let Some(v) = saved {
        std::env::set_var("LD_PRELOAD", v);
    }
}

#[test]
#[serial]
fn test_sweep_only_ld_preload_fails() {
    let saved = std::env::var("LD_PRELOAD").ok();
    std::env::set_var("LD_PRELOAD", "/usr/lib/evil_hook.so");

    // Use correct hash so binary_integrity doesn't fire.
    if let Ok(binary) = std::fs::read("/proc/self/exe") {
        use sha2::{Digest, Sha512};
        let hash = Sha512::digest(&binary);
        let mut expected = [0u8; 64];
        expected.copy_from_slice(&hash);
        let alerts = runtime_defense_sweep(&expected);

        let binary_alerts = alerts_by_check(&alerts, "binary_integrity");
        let injection_alerts = alerts_by_check(&alerts, "library_injection");
        assert!(binary_alerts.is_empty(), "binary_integrity should be clean");
        assert!(
            !injection_alerts.is_empty(),
            "library_injection should fire with LD_PRELOAD set"
        );
    }

    match saved {
        Some(v) => std::env::set_var("LD_PRELOAD", v),
        None => std::env::remove_var("LD_PRELOAD"),
    }
}

// ---------------------------------------------------------------------------
// Alert structure validation
// ---------------------------------------------------------------------------

#[test]
fn test_alert_severity_values_are_valid() {
    let valid_severities = ["critical", "high", "medium", "low"];
    let fake_hash = [0u8; 64];
    let alerts = runtime_defense_sweep(&fake_hash);
    for alert in &alerts {
        assert!(
            valid_severities.contains(&alert.severity),
            "invalid severity '{}' in alert check='{}' detail='{}'",
            alert.severity,
            alert.check,
            alert.detail,
        );
    }
}

#[test]
fn test_alert_check_names_are_nonempty() {
    let fake_hash = [0u8; 64];
    let alerts = runtime_defense_sweep(&fake_hash);
    for alert in &alerts {
        assert!(!alert.check.is_empty(), "alert check name must not be empty");
        assert!(!alert.detail.is_empty(), "alert detail must not be empty");
    }
}

// ---------------------------------------------------------------------------
// PID namespace isolation
// ---------------------------------------------------------------------------

#[test]
fn test_pid_namespace_isolation_returns_bool() {
    // Just verify it doesn't panic and returns a bool.
    let result = common::runtime_defense::verify_pid_namespace_isolation();
    let _ = result; // bool -- either true or false depending on environment
}
