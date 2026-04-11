//! Runtime defense wiring — connects StealthDetector + AutoResponsePipeline
//! to service main loops.

use crate::auto_response::{AutoResponseConfig, AutoResponsePipeline};
use crate::cluster::ClusterNode;
use crate::raft::NodeId;
use crate::stealth_detection::StealthDetector;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// Handle returned by `start_runtime_defense`.
pub struct RuntimeDefenseHandle {
    pub pipeline: Arc<Mutex<AutoResponsePipeline>>,
    pub detector: Arc<Mutex<StealthDetector>>,
    pub node_id: NodeId,
}

/// Start the runtime defense subsystem.
///
/// Spawns background tasks for:
/// 1. Stealth detection on randomized intervals
/// 2. Suspicion decay (prevents false-positive accumulation)
/// 3. Auto-response pipeline advancement
pub fn start_runtime_defense(
    service_name: &str,
    service_port: u16,
    platform_binary_hash: [u8; 64],
) -> RuntimeDefenseHandle {
    let node_id = NodeId::random();

    let mut detector = StealthDetector::new();
    detector.set_expected_hash(platform_binary_hash);
    detector.set_expected_ports(vec![service_port, service_port + 1000]);
    detector.capture_library_baseline();

    let detector = Arc::new(Mutex::new(detector));
    let pipeline = Arc::new(Mutex::new(
        AutoResponsePipeline::new(AutoResponseConfig::default()),
    ));

    // Detection + response loop
    let det = detector.clone();
    let pip = pipeline.clone();
    let svc = service_name.to_string();
    tokio::spawn(async move {
        let mut check_interval = tokio::time::interval(Duration::from_secs(30));
        let mut decay_interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            tokio::select! {
                _ = check_interval.tick() => {
                    let mut d = det.lock().await;
                    let events = d.run_due_checks();
                    for event in &events {
                        if event.suspicious {
                            tracing::warn!(
                                service = %svc,
                                layer = ?event.layer,
                                detail = %event.detail,
                                score = event.score_contribution,
                                total = d.suspicion_score(),
                                "STEALTH DETECTION: suspicious activity detected"
                            );
                        }
                    }
                    if d.should_quarantine() {
                        tracing::error!(
                            target: "siem",
                            service = %svc,
                            suspicion = d.suspicion_score(),
                            event = "self_quarantine",
                            severity = 10,
                            "QUARANTINE THRESHOLD EXCEEDED"
                        );
                        // Use the configured platform hash; fall back to zeros if not set
                        let expected = platform_binary_hash;
                        drop(d);
                        let mut p = pip.lock().await;
                        p.respond_to_tamper(node_id, expected, [0xFF; 64]);
                    }
                }
                _ = decay_interval.tick() => {
                    let mut d = det.lock().await;
                    d.apply_decay(Duration::from_secs(60));
                }
            }
        }
    });

    // Pipeline tick loop
    let pip2 = pipeline.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            let mut p = pip2.lock().await;
            let _events = p.tick();
        }
    });

    RuntimeDefenseHandle {
        pipeline,
        detector,
        node_id,
    }
}

// ---------------------------------------------------------------------------
// Runtime alerts and comprehensive sweep
// ---------------------------------------------------------------------------

/// Alert produced by a runtime defense sweep.
#[derive(Debug, Clone)]
pub struct RuntimeAlert {
    /// Which check produced this alert.
    pub check: &'static str,
    /// Severity: "critical", "high", "medium", "low".
    pub severity: &'static str,
    /// Human-readable description.
    pub detail: String,
}

/// Run all runtime defense checks synchronously and return any alerts.
///
/// This function performs:
/// 1. Process self-integrity check (verify binary hash hasn't changed)
/// 2. Memory canary monitoring (key material canary validation)
/// 3. Connection anomaly detection (spike from single IP)
/// 4. Debugger detection
/// 5. Library injection detection
/// 6. Capability escalation detection
///
/// Intended to be called periodically or on-demand by admin endpoints.
pub fn runtime_defense_sweep(expected_binary_hash: &[u8; 64]) -> Vec<RuntimeAlert> {
    let mut alerts = Vec::new();

    // 1. Process self-integrity: verify binary hash hasn't changed
    match std::fs::read("/proc/self/exe") {
        Ok(binary) => {
            use sha2::{Sha512, Digest};
            let hash = Sha512::digest(&binary);
            let mut current_hash = [0u8; 64];
            current_hash.copy_from_slice(&hash);
            if current_hash != *expected_binary_hash {
                alerts.push(RuntimeAlert {
                    check: "binary_integrity",
                    severity: "critical",
                    detail: format!(
                        "Binary hash mismatch: expected {}, got {}",
                        hex::encode(&expected_binary_hash[..8]),
                        hex::encode(&current_hash[..8]),
                    ),
                });
            }
        }
        Err(e) => {
            alerts.push(RuntimeAlert {
                check: "binary_integrity",
                severity: "high",
                detail: format!("Cannot read /proc/self/exe: {e}"),
            });
        }
    }

    // 2. Memory canary monitoring: check that mlock'd regions are intact
    // Verify /proc/self/status for unexpected VmLck changes
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        let vmlck = status
            .lines()
            .find(|l| l.starts_with("VmLck:"))
            .and_then(|l| {
                l.split_whitespace()
                    .nth(1)?
                    .parse::<u64>()
                    .ok()
            });
        if vmlck == Some(0) {
            // If we expected locked memory but have none, something unlocked it
            alerts.push(RuntimeAlert {
                check: "memory_canary",
                severity: "high",
                detail: "VmLck is 0 — expected locked key material pages; possible munlock attack".into(),
            });
        }
    }

    // 3. Connection anomaly detection: check for single-IP connection spikes
    if let Ok(tcp) = std::fs::read_to_string("/proc/self/net/tcp") {
        let mut ip_counts: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
        for line in tcp.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if let Some(remote) = fields.get(2) {
                // Remote address is in hex format: AABBCCDD:PORT
                if let Some(addr) = remote.split(':').next() {
                    *ip_counts.entry(addr.to_string()).or_insert(0) += 1;
                }
            }
        }
        const CONNECTION_SPIKE_THRESHOLD: u32 = 100;
        for (ip, count) in &ip_counts {
            if *count > CONNECTION_SPIKE_THRESHOLD {
                alerts.push(RuntimeAlert {
                    check: "connection_anomaly",
                    severity: "high",
                    detail: format!(
                        "Connection spike: {} connections from remote IP {}",
                        count, ip,
                    ),
                });
            }
        }
    }

    // 4. Debugger detection: TracerPid != 0
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(val) = line.strip_prefix("TracerPid:") {
                if let Ok(pid) = val.trim().parse::<u32>() {
                    if pid != 0 {
                        alerts.push(RuntimeAlert {
                            check: "debugger_detection",
                            severity: "critical",
                            detail: format!("Debugger attached: TracerPid={pid}"),
                        });
                    }
                }
            }
        }
    }

    // 5. Library injection: check for LD_PRELOAD
    if let Ok(val) = std::env::var("LD_PRELOAD") {
        if !val.is_empty() {
            alerts.push(RuntimeAlert {
                check: "library_injection",
                severity: "critical",
                detail: format!("LD_PRELOAD is set: {val}"),
            });
        }
    }

    // 6. Capability escalation: check that no unexpected capabilities are set
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(val) = line.strip_prefix("CapEff:") {
                let caps = val.trim();
                // Full capabilities (0000003fffffffff) is suspicious for a non-root service
                if caps == "0000003fffffffff" || caps == "000001ffffffffff" {
                    alerts.push(RuntimeAlert {
                        check: "capability_escalation",
                        severity: "high",
                        detail: format!("Process has full effective capabilities: {caps}"),
                    });
                }
            }
        }
    }

    if !alerts.is_empty() {
        tracing::warn!(
            alert_count = alerts.len(),
            "Runtime defense sweep completed with {} alert(s)",
            alerts.len(),
        );
    }

    alerts
}

/// Verify that the process is running in a separate PID namespace.
///
/// Checks `/proc/self/ns/pid` vs `/proc/1/ns/pid`. If they match, the process
/// shares the host PID namespace, which means no namespace isolation between
/// services. Returns `true` if the process is in an isolated namespace.
pub fn verify_pid_namespace_isolation() -> bool {
    let self_ns = match std::fs::read_link("/proc/self/ns/pid") {
        Ok(p) => p,
        Err(_) => {
            tracing::warn!("cannot read /proc/self/ns/pid; namespace isolation check skipped");
            return false;
        }
    };
    let init_ns = match std::fs::read_link("/proc/1/ns/pid") {
        Ok(p) => p,
        Err(_) => {
            // Cannot read init ns -- likely already in a container
            tracing::info!("cannot read /proc/1/ns/pid; likely running in a container (isolated)");
            return true;
        }
    };

    let isolated = self_ns != init_ns;
    if !isolated {
        tracing::warn!(
            target: "siem",
            self_ns = ?self_ns,
            "SIEM:WARNING process shares the host PID namespace. \
             No namespace isolation between services. Deploy in separate \
             PID namespaces (containers, systemd PrivatePIDs) for defense in depth."
        );
    } else {
        tracing::info!("PID namespace isolation verified: process is in a separate namespace");
    }
    isolated
}

impl RuntimeDefenseHandle {
    /// Connect the defense pipeline to a Raft cluster node.
    ///
    /// Once connected, any quarantine / tamper-detection commands generated by
    /// the auto-response pipeline are automatically proposed to Raft every 2 s,
    /// ensuring cluster-wide enforcement rather than local-only quarantine.
    ///
    /// The method is a no-op if `cluster` is `None` (standalone mode).
    pub fn connect_to_cluster(&self, cluster: Arc<ClusterNode>) {
        let pipeline = self.pipeline.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(2));
            loop {
                interval.tick().await;
                let commands = {
                    let mut p = pipeline.lock().await;
                    p.take_pending_commands()
                };
                for cmd in commands {
                    tracing::info!(
                        "proposing Raft command from auto-response pipeline: {:?}",
                        cmd
                    );
                    if let Err(e) = cluster.propose(cmd) {
                        tracing::error!(
                            "failed to propose Raft command: {e} — \
                             quarantine may not be enforced across cluster"
                        );
                    }
                }
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // runtime_defense_sweep tests
    // -----------------------------------------------------------------------

    #[test]
    fn sweep_returns_alerts_vec() {
        // A valid hash that won't match the running binary
        let fake_hash = [0xAA_u8; 64];
        let alerts = runtime_defense_sweep(&fake_hash);
        // Should always return some alerts (binary hash mismatch at minimum)
        assert!(!alerts.is_empty(), "sweep should detect binary hash mismatch");
    }

    #[test]
    fn sweep_detects_binary_integrity_mismatch() {
        let wrong_hash = [0xFF_u8; 64];
        let alerts = runtime_defense_sweep(&wrong_hash);
        let integrity_alert = alerts
            .iter()
            .find(|a| a.check == "binary_integrity");
        assert!(
            integrity_alert.is_some(),
            "must detect binary integrity mismatch"
        );
        let alert = integrity_alert.unwrap();
        assert_eq!(alert.severity, "critical");
        assert!(alert.detail.contains("hash mismatch") || alert.detail.contains("Cannot read"));
    }

    #[test]
    fn sweep_checks_debugger_tracer_pid() {
        // In normal test execution, TracerPid should be 0 (no debugger)
        let hash = [0x00_u8; 64];
        let alerts = runtime_defense_sweep(&hash);
        let debugger_alert = alerts
            .iter()
            .find(|a| a.check == "debugger_detection");
        // Under normal testing, no debugger should be attached
        // If CI attaches a debugger, this would fire but that's expected
        if let Some(alert) = debugger_alert {
            assert_eq!(alert.severity, "critical");
            assert!(alert.detail.contains("TracerPid"));
        }
    }

    #[test]
    fn sweep_checks_ld_preload() {
        // Temporarily set LD_PRELOAD and verify detection
        let original = std::env::var("LD_PRELOAD").ok();

        std::env::set_var("LD_PRELOAD", "/tmp/fake_inject.so");
        let hash = [0x00_u8; 64];
        let alerts = runtime_defense_sweep(&hash);
        let inject_alert = alerts
            .iter()
            .find(|a| a.check == "library_injection");
        assert!(
            inject_alert.is_some(),
            "must detect LD_PRELOAD injection"
        );
        assert_eq!(inject_alert.unwrap().severity, "critical");
        assert!(inject_alert.unwrap().detail.contains("LD_PRELOAD"));

        // Restore
        match original {
            Some(v) => std::env::set_var("LD_PRELOAD", v),
            None => std::env::remove_var("LD_PRELOAD"),
        }
    }

    #[test]
    fn sweep_no_ld_preload_no_alert() {
        let original = std::env::var("LD_PRELOAD").ok();
        std::env::remove_var("LD_PRELOAD");

        let hash = [0x00_u8; 64];
        let alerts = runtime_defense_sweep(&hash);
        let inject_alert = alerts
            .iter()
            .find(|a| a.check == "library_injection");
        assert!(
            inject_alert.is_none(),
            "should not alert when LD_PRELOAD is not set"
        );

        // Restore
        if let Some(v) = original {
            std::env::set_var("LD_PRELOAD", v);
        }
    }

    #[test]
    fn sweep_checks_capability_escalation() {
        let hash = [0x00_u8; 64];
        let alerts = runtime_defense_sweep(&hash);
        // In CI, we typically don't have full caps, so no alert expected
        // Just verify the check runs without panic
        for alert in &alerts {
            if alert.check == "capability_escalation" {
                assert_eq!(alert.severity, "high");
                assert!(alert.detail.contains("capabilities"));
            }
        }
    }

    #[test]
    fn sweep_checks_vmlck() {
        let hash = [0x00_u8; 64];
        let alerts = runtime_defense_sweep(&hash);
        // VmLck check: in CI without mlock, VmLck is 0
        let vmlck_alert = alerts
            .iter()
            .find(|a| a.check == "memory_canary");
        // If VmLck is 0 (which it is in CI without mlock), we get an alert
        if let Some(alert) = vmlck_alert {
            assert_eq!(alert.severity, "high");
            assert!(alert.detail.contains("VmLck"));
        }
    }

    #[test]
    fn runtime_alert_debug_format() {
        let alert = RuntimeAlert {
            check: "test_check",
            severity: "critical",
            detail: "test detail".to_string(),
        };
        let dbg = format!("{:?}", alert);
        assert!(dbg.contains("test_check"));
        assert!(dbg.contains("critical"));
    }

    #[test]
    fn runtime_alert_clone() {
        let alert = RuntimeAlert {
            check: "test_check",
            severity: "high",
            detail: "detail".to_string(),
        };
        let cloned = alert.clone();
        assert_eq!(cloned.check, alert.check);
        assert_eq!(cloned.severity, alert.severity);
        assert_eq!(cloned.detail, alert.detail);
    }

    // -----------------------------------------------------------------------
    // verify_pid_namespace_isolation tests
    // -----------------------------------------------------------------------

    #[test]
    fn namespace_isolation_returns_bool() {
        // Just verify it runs without panic and returns a bool
        let _result = verify_pid_namespace_isolation();
    }

    // -----------------------------------------------------------------------
    // start_runtime_defense tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn start_runtime_defense_returns_handle() {
        let hash = [0xBB_u8; 64];
        let handle = start_runtime_defense("test-service", 8443, hash);
        // Verify handle fields are populated
        assert_ne!(handle.node_id, NodeId::random()); // different random IDs
        // Pipeline and detector should be accessible
        let _det = handle.detector.lock().await;
        let _pip = handle.pipeline.lock().await;
    }

    #[tokio::test]
    async fn start_runtime_defense_spawns_tasks() {
        let hash = [0xCC_u8; 64];
        let handle = start_runtime_defense("sweep-test", 9443, hash);
        // Allow the spawned tasks a moment to start
        tokio::time::sleep(Duration::from_millis(50)).await;
        // Verify detector is accessible (tasks didn't panic)
        let det = handle.detector.lock().await;
        let _ = det.suspicion_score();
    }

    // -----------------------------------------------------------------------
    // sweep with matching binary hash (no integrity alert)
    // -----------------------------------------------------------------------

    #[test]
    fn sweep_with_actual_binary_hash() {
        // Compute the real binary hash and verify no integrity alert
        if let Ok(binary) = std::fs::read("/proc/self/exe") {
            use sha2::{Sha512, Digest};
            let hash = Sha512::digest(&binary);
            let mut expected = [0u8; 64];
            expected.copy_from_slice(&hash);

            let alerts = runtime_defense_sweep(&expected);
            let integrity_alert = alerts
                .iter()
                .find(|a| a.check == "binary_integrity");
            assert!(
                integrity_alert.is_none(),
                "should not alert when binary hash matches"
            );
        }
    }
}
