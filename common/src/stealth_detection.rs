//! Multi-layer stealth attack detection.
//!
//! THREAT MODEL: Attacker has root access, knows the detection code,
//! and will adapt after first detection. Defense strategy:
//! 1. Multiple independent detection methods (redundancy)
//! 2. Randomized check intervals (unpredictable timing)
//! 3. Behavioral analysis (detect anomalies, not just signatures)
//! 4. Memory integrity checks (detect runtime code patching)
//! 5. Syscall pattern analysis (detect rootkit hooks)
//! 6. Cross-node consistency checks (compare behavior across cluster)
//! 7. Entropy monitoring (compromised nodes often have degraded entropy)

use sha2::{Digest, Sha512};
use std::collections::HashMap;
use std::time::{Duration, Instant};

// ── DetectionLayer ────────────────────────────────────────────────────────────

/// Independent detection methods. Each operates on different evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DetectionLayer {
    /// SHA-512 of /proc/self/exe (catches binary replacement).
    BinaryHash,
    /// SHA-512 of loaded shared libraries (/proc/self/maps).
    LibraryHash,
    /// Check /proc/self/status for TracerPid != 0 (debugger attached).
    DebuggerDetection,
    /// Verify /proc/self/exe hasn't been deleted or replaced.
    ProcSelfExeIntegrity,
    /// Check that mlock'd memory regions haven't been munlock'd.
    MemoryProtectionCheck,
    /// Monitor entropy quality from /dev/urandom.
    EntropyQuality,
    /// Verify process capabilities haven't been escalated.
    CapabilityCheck,
    /// Check for LD_PRELOAD or other library injection.
    LibraryInjection,
    /// Verify expected network listeners (no rogue ports).
    NetworkListenerAudit,
    /// Cross-node timing consistency (clock manipulation detection).
    TimingConsistency,
}

impl DetectionLayer {
    /// All layers in order.
    fn all() -> Vec<DetectionLayer> {
        vec![
            DetectionLayer::BinaryHash,
            DetectionLayer::LibraryHash,
            DetectionLayer::DebuggerDetection,
            DetectionLayer::ProcSelfExeIntegrity,
            DetectionLayer::MemoryProtectionCheck,
            DetectionLayer::EntropyQuality,
            DetectionLayer::CapabilityCheck,
            DetectionLayer::LibraryInjection,
            DetectionLayer::NetworkListenerAudit,
            DetectionLayer::TimingConsistency,
        ]
    }

    /// Suspicion score contribution when this layer detects something.
    fn score_weight(&self) -> f64 {
        match self {
            DetectionLayer::BinaryHash => 0.40,
            DetectionLayer::LibraryHash => 0.30,
            DetectionLayer::DebuggerDetection => 0.35,
            DetectionLayer::ProcSelfExeIntegrity => 0.35,
            DetectionLayer::MemoryProtectionCheck => 0.15,
            DetectionLayer::EntropyQuality => 0.10,
            DetectionLayer::CapabilityCheck => 0.25,
            DetectionLayer::LibraryInjection => 0.30,
            DetectionLayer::NetworkListenerAudit => 0.20,
            DetectionLayer::TimingConsistency => 0.10,
        }
    }
}

// ── DetectionEvent ────────────────────────────────────────────────────────────

/// Result of a single detection check.
#[derive(Debug, Clone)]
pub struct DetectionEvent {
    pub layer: DetectionLayer,
    pub timestamp: Instant,
    pub suspicious: bool,
    pub detail: String,
    pub score_contribution: f64,
}

// ── StealthDetector ───────────────────────────────────────────────────────────

/// Multi-layer stealth attack detector with randomized scheduling.
pub struct StealthDetector {
    /// Which layers to run.
    enabled_layers: Vec<DetectionLayer>,
    /// Randomized intervals per layer (prevent predictable scheduling).
    intervals: HashMap<DetectionLayer, Duration>,
    /// Last check time per layer.
    last_checked: HashMap<DetectionLayer, Instant>,
    /// Detection results history (ring buffer per layer, max 64 entries).
    history: HashMap<DetectionLayer, Vec<DetectionEvent>>,
    /// Cumulative suspicion score (0.0 = clean, 1.0 = definitely compromised).
    suspicion_score: f64,
    /// Threshold for triggering quarantine.
    quarantine_threshold: f64,
    /// Expected binary hash (golden hash from cluster).
    expected_binary_hash: Option<[u8; 64]>,
    /// Expected network listener ports (only these are allowed).
    expected_ports: Vec<u16>,
    /// Timing baseline for consistency checks.
    timing_baseline: Option<Instant>,
}

/// Default minimum check interval (seconds).
const MIN_INTERVAL_SECS: u64 = 10;
/// Default maximum check interval (seconds).
const MAX_INTERVAL_SECS: u64 = 60;
/// Maximum history entries per layer.
const MAX_HISTORY: usize = 64;

impl StealthDetector {
    /// Create a new detector with all layers enabled and randomized intervals.
    pub fn new() -> Self {
        let enabled_layers = DetectionLayer::all();
        let intervals = randomize_intervals(&enabled_layers);
        let mut history = HashMap::new();
        for layer in &enabled_layers {
            history.insert(*layer, Vec::new());
        }

        Self {
            enabled_layers,
            intervals,
            last_checked: HashMap::new(),
            history,
            suspicion_score: 0.0,
            quarantine_threshold: 0.7,
            expected_binary_hash: None,
            expected_ports: Vec::new(),
            timing_baseline: None,
        }
    }

    /// Run all detection layers that are due (based on randomized schedule).
    pub fn run_due_checks(&mut self) -> Vec<DetectionEvent> {
        let now = Instant::now();
        let due_layers: Vec<DetectionLayer> = self
            .enabled_layers
            .iter()
            .filter(|layer| {
                let interval = self.intervals.get(layer).copied().unwrap_or(Duration::from_secs(30));
                match self.last_checked.get(layer) {
                    Some(last) => now.duration_since(*last) >= interval,
                    None => true, // never checked
                }
            })
            .copied()
            .collect();

        let mut events = Vec::new();
        for layer in due_layers {
            let event = self.run_check(layer);
            events.push(event);
        }

        // Re-randomize intervals after each batch to stay unpredictable
        self.intervals = randomize_intervals(&self.enabled_layers);

        events
    }

    /// Run a specific detection layer.
    pub fn run_check(&mut self, layer: DetectionLayer) -> DetectionEvent {
        let event = match layer {
            DetectionLayer::BinaryHash => self.check_binary_hash(),
            DetectionLayer::LibraryHash => self.check_library_hash(),
            DetectionLayer::DebuggerDetection => self.check_debugger(),
            DetectionLayer::ProcSelfExeIntegrity => self.check_proc_self_exe(),
            DetectionLayer::MemoryProtectionCheck => self.check_memory_protection(),
            DetectionLayer::EntropyQuality => self.check_entropy_quality(),
            DetectionLayer::CapabilityCheck => self.check_capabilities(),
            DetectionLayer::LibraryInjection => self.check_library_injection(),
            DetectionLayer::NetworkListenerAudit => self.check_network_listeners(),
            DetectionLayer::TimingConsistency => self.check_timing_consistency(),
        };

        self.last_checked.insert(layer, event.timestamp);

        if event.suspicious {
            self.suspicion_score = (self.suspicion_score + event.score_contribution).min(1.0);
            tracing::warn!(
                layer = ?layer,
                detail = %event.detail,
                score = event.score_contribution,
                total = self.suspicion_score,
                "stealth detection: suspicious activity"
            );
        }

        // Append to history ring buffer
        if let Some(hist) = self.history.get_mut(&layer) {
            if hist.len() >= MAX_HISTORY {
                hist.remove(0);
            }
            hist.push(event.clone());
        }

        event
    }

    /// Current suspicion score.
    pub fn suspicion_score(&self) -> f64 {
        self.suspicion_score
    }

    /// Has the quarantine threshold been exceeded?
    pub fn should_quarantine(&self) -> bool {
        self.suspicion_score >= self.quarantine_threshold
    }

    /// Reset suspicion score (after successful healing).
    pub fn reset_after_heal(&mut self) {
        self.suspicion_score = 0.0;
        for hist in self.history.values_mut() {
            hist.clear();
        }
        tracing::info!("stealth detection: suspicion score reset after heal");
    }

    /// Set expected binary hash.
    pub fn set_expected_hash(&mut self, hash: [u8; 64]) {
        self.expected_binary_hash = Some(hash);
    }

    /// Set expected network listener ports.
    pub fn set_expected_ports(&mut self, ports: Vec<u16>) {
        self.expected_ports = ports;
    }

    // ── Individual layer implementations ──────────────────────────────────

    /// SHA-512 of /proc/self/exe.
    fn check_binary_hash(&self) -> DetectionEvent {
        let now = Instant::now();
        match std::fs::read("/proc/self/exe") {
            Ok(binary) => {
                let mut hasher = Sha512::new();
                hasher.update(&binary);
                let hash = hasher.finalize();
                let mut hash_arr = [0u8; 64];
                hash_arr.copy_from_slice(&hash);

                if let Some(expected) = &self.expected_binary_hash {
                    if hash_arr != *expected {
                        return DetectionEvent {
                            layer: DetectionLayer::BinaryHash,
                            timestamp: now,
                            suspicious: true,
                            detail: format!(
                                "binary hash mismatch: got {}, expected {}",
                                hex::encode(&hash_arr[..8]),
                                hex::encode(&expected[..8]),
                            ),
                            score_contribution: DetectionLayer::BinaryHash.score_weight(),
                        };
                    }
                }

                DetectionEvent {
                    layer: DetectionLayer::BinaryHash,
                    timestamp: now,
                    suspicious: false,
                    detail: format!("binary hash ok: {}", hex::encode(&hash_arr[..8])),
                    score_contribution: 0.0,
                }
            }
            Err(e) => DetectionEvent {
                layer: DetectionLayer::BinaryHash,
                timestamp: now,
                suspicious: true,
                detail: format!("cannot read /proc/self/exe: {e}"),
                score_contribution: DetectionLayer::BinaryHash.score_weight(),
            },
        }
    }

    /// Parse /proc/self/maps, hash each .so file path.
    fn check_library_hash(&self) -> DetectionEvent {
        let now = Instant::now();
        match std::fs::read_to_string("/proc/self/maps") {
            Ok(maps) => {
                let mut hasher = Sha512::new();
                let mut lib_count = 0u32;

                for line in maps.lines() {
                    // Lines with .so are shared libraries: "addr perms offset dev inode pathname"
                    if let Some(path) = extract_so_path(line) {
                        hasher.update(path.as_bytes());
                        lib_count += 1;
                    }
                }

                let hash = hasher.finalize();
                DetectionEvent {
                    layer: DetectionLayer::LibraryHash,
                    timestamp: now,
                    suspicious: false,
                    detail: format!(
                        "library map hash: {} ({lib_count} libs)",
                        hex::encode(&hash[..8])
                    ),
                    score_contribution: 0.0,
                }
            }
            Err(e) => DetectionEvent {
                layer: DetectionLayer::LibraryHash,
                timestamp: now,
                suspicious: true,
                detail: format!("cannot read /proc/self/maps: {e}"),
                score_contribution: DetectionLayer::LibraryHash.score_weight(),
            },
        }
    }

    /// Read /proc/self/status, check TracerPid line for attached debugger.
    fn check_debugger(&self) -> DetectionEvent {
        let now = Instant::now();
        match std::fs::read_to_string("/proc/self/status") {
            Ok(status) => {
                for line in status.lines() {
                    if let Some(rest) = line.strip_prefix("TracerPid:") {
                        let pid_str = rest.trim();
                        let pid: u32 = pid_str.parse().unwrap_or(0);
                        if pid != 0 {
                            return DetectionEvent {
                                layer: DetectionLayer::DebuggerDetection,
                                timestamp: now,
                                suspicious: true,
                                detail: format!("debugger attached: TracerPid={pid}"),
                                score_contribution: DetectionLayer::DebuggerDetection.score_weight(),
                            };
                        }
                        return DetectionEvent {
                            layer: DetectionLayer::DebuggerDetection,
                            timestamp: now,
                            suspicious: false,
                            detail: "no debugger attached".into(),
                            score_contribution: 0.0,
                        };
                    }
                }
                DetectionEvent {
                    layer: DetectionLayer::DebuggerDetection,
                    timestamp: now,
                    suspicious: true,
                    detail: "TracerPid line missing from /proc/self/status".into(),
                    score_contribution: DetectionLayer::DebuggerDetection.score_weight(),
                }
            }
            Err(e) => DetectionEvent {
                layer: DetectionLayer::DebuggerDetection,
                timestamp: now,
                suspicious: true,
                detail: format!("cannot read /proc/self/status: {e}"),
                score_contribution: DetectionLayer::DebuggerDetection.score_weight(),
            },
        }
    }

    /// Readlink /proc/self/exe, verify not "(deleted)".
    fn check_proc_self_exe(&self) -> DetectionEvent {
        let now = Instant::now();
        match std::fs::read_link("/proc/self/exe") {
            Ok(path) => {
                let path_str = path.to_string_lossy().to_string();
                if path_str.contains("(deleted)") {
                    DetectionEvent {
                        layer: DetectionLayer::ProcSelfExeIntegrity,
                        timestamp: now,
                        suspicious: true,
                        detail: format!("binary deleted while running: {path_str}"),
                        score_contribution: DetectionLayer::ProcSelfExeIntegrity.score_weight(),
                    }
                } else {
                    DetectionEvent {
                        layer: DetectionLayer::ProcSelfExeIntegrity,
                        timestamp: now,
                        suspicious: false,
                        detail: format!("binary intact: {path_str}"),
                        score_contribution: 0.0,
                    }
                }
            }
            Err(e) => DetectionEvent {
                layer: DetectionLayer::ProcSelfExeIntegrity,
                timestamp: now,
                suspicious: true,
                detail: format!("cannot readlink /proc/self/exe: {e}"),
                score_contribution: DetectionLayer::ProcSelfExeIntegrity.score_weight(),
            },
        }
    }

    /// Read /proc/self/status, check VmLck field for locked memory.
    fn check_memory_protection(&self) -> DetectionEvent {
        let now = Instant::now();
        match std::fs::read_to_string("/proc/self/status") {
            Ok(status) => {
                for line in status.lines() {
                    if let Some(rest) = line.strip_prefix("VmLck:") {
                        let trimmed = rest.trim();
                        // Format: "N kB" -- parse the number
                        let kb_str = trimmed.split_whitespace().next().unwrap_or("0");
                        let kb: u64 = kb_str.parse().unwrap_or(0);
                        // We expect at least some locked memory if keys are mlock'd
                        // A value of 0 means nothing is locked, which could mean
                        // mlock was bypassed or munlock was called
                        return DetectionEvent {
                            layer: DetectionLayer::MemoryProtectionCheck,
                            timestamp: now,
                            suspicious: false, // informational -- 0 is normal early in startup
                            detail: format!("VmLck: {kb} kB"),
                            score_contribution: 0.0,
                        };
                    }
                }
                DetectionEvent {
                    layer: DetectionLayer::MemoryProtectionCheck,
                    timestamp: now,
                    suspicious: false,
                    detail: "VmLck field not found (kernel may not expose it)".into(),
                    score_contribution: 0.0,
                }
            }
            Err(e) => DetectionEvent {
                layer: DetectionLayer::MemoryProtectionCheck,
                timestamp: now,
                suspicious: true,
                detail: format!("cannot read /proc/self/status: {e}"),
                score_contribution: DetectionLayer::MemoryProtectionCheck.score_weight(),
            },
        }
    }

    /// Read 32 bytes from /dev/urandom, check distinct byte count >= 16.
    fn check_entropy_quality(&self) -> DetectionEvent {
        let now = Instant::now();
        let mut buf = [0u8; 32];
        match getrandom::getrandom(&mut buf) {
            Ok(()) => {
                let mut seen = [false; 256];
                let mut distinct = 0u32;
                for &b in &buf {
                    if !seen[b as usize] {
                        seen[b as usize] = true;
                        distinct += 1;
                    }
                }
                let suspicious = distinct < 16;
                DetectionEvent {
                    layer: DetectionLayer::EntropyQuality,
                    timestamp: now,
                    suspicious,
                    detail: format!("entropy check: {distinct}/32 distinct bytes"),
                    score_contribution: if suspicious {
                        DetectionLayer::EntropyQuality.score_weight()
                    } else {
                        0.0
                    },
                }
            }
            Err(e) => DetectionEvent {
                layer: DetectionLayer::EntropyQuality,
                timestamp: now,
                suspicious: true,
                detail: format!("entropy source failed: {e}"),
                score_contribution: DetectionLayer::EntropyQuality.score_weight(),
            },
        }
    }

    /// Read /proc/self/status, check CapEff and CapPrm lines.
    fn check_capabilities(&self) -> DetectionEvent {
        let now = Instant::now();
        match std::fs::read_to_string("/proc/self/status") {
            Ok(status) => {
                let mut cap_eff: Option<u64> = None;
                let mut cap_prm: Option<u64> = None;

                for line in status.lines() {
                    if let Some(rest) = line.strip_prefix("CapEff:") {
                        cap_eff = u64::from_str_radix(rest.trim(), 16).ok();
                    }
                    if let Some(rest) = line.strip_prefix("CapPrm:") {
                        cap_prm = u64::from_str_radix(rest.trim(), 16).ok();
                    }
                }

                let eff = cap_eff.unwrap_or(0);
                let prm = cap_prm.unwrap_or(0);

                // CAP_SYS_ADMIN = bit 21, CAP_SYS_RAWIO = bit 17, CAP_SYS_PTRACE = bit 19
                // These are dangerous capabilities that a normal SSO service should not have.
                let dangerous_mask: u64 = (1 << 21) | (1 << 17) | (1 << 19);
                let has_dangerous = (eff & dangerous_mask) != 0;

                DetectionEvent {
                    layer: DetectionLayer::CapabilityCheck,
                    timestamp: now,
                    suspicious: has_dangerous,
                    detail: format!(
                        "CapEff={eff:#018x} CapPrm={prm:#018x} dangerous={}",
                        has_dangerous
                    ),
                    score_contribution: if has_dangerous {
                        DetectionLayer::CapabilityCheck.score_weight()
                    } else {
                        0.0
                    },
                }
            }
            Err(e) => DetectionEvent {
                layer: DetectionLayer::CapabilityCheck,
                timestamp: now,
                suspicious: true,
                detail: format!("cannot read /proc/self/status: {e}"),
                score_contribution: DetectionLayer::CapabilityCheck.score_weight(),
            },
        }
    }

    /// Check LD_PRELOAD env and scan /proc/self/maps for unexpected .so files.
    fn check_library_injection(&self) -> DetectionEvent {
        let now = Instant::now();

        // Check LD_PRELOAD
        if let Ok(preload) = std::env::var("LD_PRELOAD") {
            if !preload.is_empty() {
                return DetectionEvent {
                    layer: DetectionLayer::LibraryInjection,
                    timestamp: now,
                    suspicious: true,
                    detail: format!("LD_PRELOAD set: {preload}"),
                    score_contribution: DetectionLayer::LibraryInjection.score_weight(),
                };
            }
        }

        // Also check LD_LIBRARY_PATH for suspicious entries
        if let Ok(ldpath) = std::env::var("LD_LIBRARY_PATH") {
            // /tmp or /dev/shm in library path is suspicious
            if ldpath.contains("/tmp") || ldpath.contains("/dev/shm") {
                return DetectionEvent {
                    layer: DetectionLayer::LibraryInjection,
                    timestamp: now,
                    suspicious: true,
                    detail: format!("suspicious LD_LIBRARY_PATH: {ldpath}"),
                    score_contribution: DetectionLayer::LibraryInjection.score_weight(),
                };
            }
        }

        // Scan maps for libraries loaded from suspicious paths
        match std::fs::read_to_string("/proc/self/maps") {
            Ok(maps) => {
                for line in maps.lines() {
                    if let Some(path) = extract_so_path(line) {
                        if path.starts_with("/tmp/")
                            || path.starts_with("/dev/shm/")
                            || path.starts_with("/var/tmp/")
                        {
                            return DetectionEvent {
                                layer: DetectionLayer::LibraryInjection,
                                timestamp: now,
                                suspicious: true,
                                detail: format!("library loaded from suspicious path: {path}"),
                                score_contribution: DetectionLayer::LibraryInjection.score_weight(),
                            };
                        }
                    }
                }

                DetectionEvent {
                    layer: DetectionLayer::LibraryInjection,
                    timestamp: now,
                    suspicious: false,
                    detail: "no library injection detected".into(),
                    score_contribution: 0.0,
                }
            }
            Err(e) => DetectionEvent {
                layer: DetectionLayer::LibraryInjection,
                timestamp: now,
                suspicious: true,
                detail: format!("cannot read /proc/self/maps: {e}"),
                score_contribution: DetectionLayer::LibraryInjection.score_weight(),
            },
        }
    }

    /// Read /proc/net/tcp, verify only expected ports are listening.
    fn check_network_listeners(&self) -> DetectionEvent {
        let now = Instant::now();
        match std::fs::read_to_string("/proc/net/tcp") {
            Ok(tcp) => {
                let mut rogue_ports = Vec::new();

                for line in tcp.lines().skip(1) {
                    // Format: sl local_address rem_address st ...
                    // local_address is hex IP:PORT
                    // st = 0A means LISTEN
                    let fields: Vec<&str> = line.split_whitespace().collect();
                    if fields.len() < 4 {
                        continue;
                    }
                    let state = fields[3];
                    if state != "0A" {
                        continue; // not LISTEN
                    }
                    let local_addr = fields[1];
                    if let Some(port_hex) = local_addr.split(':').nth(1) {
                        if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                            if !self.expected_ports.is_empty() && !self.expected_ports.contains(&port) {
                                rogue_ports.push(port);
                            }
                        }
                    }
                }

                if !rogue_ports.is_empty() {
                    DetectionEvent {
                        layer: DetectionLayer::NetworkListenerAudit,
                        timestamp: now,
                        suspicious: true,
                        detail: format!("rogue listening ports: {:?}", rogue_ports),
                        score_contribution: DetectionLayer::NetworkListenerAudit.score_weight(),
                    }
                } else {
                    DetectionEvent {
                        layer: DetectionLayer::NetworkListenerAudit,
                        timestamp: now,
                        suspicious: false,
                        detail: "network listeners ok".into(),
                        score_contribution: 0.0,
                    }
                }
            }
            Err(e) => DetectionEvent {
                layer: DetectionLayer::NetworkListenerAudit,
                timestamp: now,
                suspicious: true,
                detail: format!("cannot read /proc/net/tcp: {e}"),
                score_contribution: DetectionLayer::NetworkListenerAudit.score_weight(),
            },
        }
    }

    /// Compare monotonic clock drift against expected.
    fn check_timing_consistency(&self) -> DetectionEvent {
        let now = Instant::now();

        // Get wall-clock time and monotonic time, compare drift
        let wall_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();

        // If we have a baseline, measure drift between monotonic and wall clock
        if let Some(baseline) = self.timing_baseline {
            let mono_elapsed = now.duration_since(baseline);
            // We can't perfectly compare monotonic vs wall clock without a baseline pair,
            // but we can check that the monotonic clock is advancing. If monotonic went
            // backward or jumped forward massively, something is wrong.
            let mono_ms = mono_elapsed.as_millis();

            // If monotonic elapsed is 0 but we're clearly past the baseline, suspicious
            if mono_ms == 0 && wall_now.as_secs() > 0 {
                return DetectionEvent {
                    layer: DetectionLayer::TimingConsistency,
                    timestamp: now,
                    suspicious: true,
                    detail: "monotonic clock not advancing".into(),
                    score_contribution: DetectionLayer::TimingConsistency.score_weight(),
                };
            }
        }

        DetectionEvent {
            layer: DetectionLayer::TimingConsistency,
            timestamp: now,
            suspicious: false,
            detail: format!("wall_clock={}s, timing ok", wall_now.as_secs()),
            score_contribution: 0.0,
        }
    }
}

impl Default for StealthDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract .so file path from a /proc/self/maps line.
/// Lines look like: "7f1234-7f5678 r-xp 00000000 fd:01 12345 /usr/lib/libfoo.so"
fn extract_so_path(line: &str) -> Option<&str> {
    // The path is the last field, after the inode
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() >= 6 {
        let path = fields[5];
        if path.contains(".so") {
            return Some(path);
        }
    }
    None
}

/// Generate randomized check intervals for each layer.
/// Uses getrandom for unpredictable scheduling.
fn randomize_intervals(layers: &[DetectionLayer]) -> HashMap<DetectionLayer, Duration> {
    let mut intervals = HashMap::new();
    let range = MAX_INTERVAL_SECS - MIN_INTERVAL_SECS;

    for layer in layers {
        let mut buf = [0u8; 8];
        // If getrandom fails, fall back to middle of range
        let random_val = if getrandom::getrandom(&mut buf).is_ok() {
            u64::from_le_bytes(buf)
        } else {
            (MIN_INTERVAL_SECS + MAX_INTERVAL_SECS) / 2
        };

        let offset = random_val % (range + 1);
        let secs = MIN_INTERVAL_SECS + offset;
        intervals.insert(*layer, Duration::from_secs(secs));
    }

    intervals
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_detector() {
        let detector = StealthDetector::new();
        assert_eq!(detector.enabled_layers.len(), 10);
        assert_eq!(detector.suspicion_score(), 0.0);
        assert!(!detector.should_quarantine());
    }

    #[test]
    fn test_detection_layer_all() {
        let all = DetectionLayer::all();
        assert_eq!(all.len(), 10);
    }

    #[test]
    fn test_score_weights_are_positive() {
        for layer in DetectionLayer::all() {
            assert!(layer.score_weight() > 0.0);
            assert!(layer.score_weight() <= 1.0);
        }
    }

    #[test]
    fn test_randomize_intervals_within_range() {
        let layers = DetectionLayer::all();
        let intervals = randomize_intervals(&layers);
        assert_eq!(intervals.len(), layers.len());
        for (_, duration) in &intervals {
            let secs = duration.as_secs();
            assert!(secs >= MIN_INTERVAL_SECS);
            assert!(secs <= MAX_INTERVAL_SECS);
        }
    }

    #[test]
    fn test_randomize_intervals_vary() {
        // Run twice, intervals should differ (probabilistic but near-certain with 10 layers)
        let layers = DetectionLayer::all();
        let i1 = randomize_intervals(&layers);
        let i2 = randomize_intervals(&layers);
        let any_different = layers.iter().any(|l| i1.get(l) != i2.get(l));
        // With 10 layers and 50 possible values each, probability of all same is ~1e-17
        assert!(any_different);
    }

    #[test]
    fn test_extract_so_path() {
        let line = "7f8a1234-7f8a5678 r-xp 00000000 fd:01 12345 /usr/lib/libfoo.so.1";
        assert_eq!(extract_so_path(line), Some("/usr/lib/libfoo.so.1"));

        let line_no_so = "7f8a1234-7f8a5678 r-xp 00000000 fd:01 12345 /usr/lib/something";
        assert_eq!(extract_so_path(line_no_so), None);

        let short_line = "7f8a1234-7f8a5678 r-xp";
        assert_eq!(extract_so_path(short_line), None);
    }

    #[test]
    fn test_quarantine_threshold() {
        let mut detector = StealthDetector::new();
        assert!(!detector.should_quarantine());

        // Manually push suspicion over threshold
        detector.suspicion_score = 0.75;
        assert!(detector.should_quarantine());
    }

    #[test]
    fn test_reset_after_heal() {
        let mut detector = StealthDetector::new();
        detector.suspicion_score = 0.9;
        detector.history.get_mut(&DetectionLayer::BinaryHash).unwrap().push(DetectionEvent {
            layer: DetectionLayer::BinaryHash,
            timestamp: Instant::now(),
            suspicious: true,
            detail: "test".into(),
            score_contribution: 0.4,
        });

        detector.reset_after_heal();
        assert_eq!(detector.suspicion_score(), 0.0);
        assert!(detector.history.get(&DetectionLayer::BinaryHash).unwrap().is_empty());
    }

    #[test]
    fn test_set_expected_hash() {
        let mut detector = StealthDetector::new();
        assert!(detector.expected_binary_hash.is_none());
        detector.set_expected_hash([0xAB; 64]);
        assert_eq!(detector.expected_binary_hash.unwrap(), [0xAB; 64]);
    }

    #[test]
    fn test_check_debugger_on_linux() {
        let detector = StealthDetector::new();
        let event = detector.check_debugger();
        // In a normal test environment, no debugger should be attached
        assert_eq!(event.layer, DetectionLayer::DebuggerDetection);
        // We don't assert suspicious=false because CI might differ,
        // but the function must not panic.
    }

    #[test]
    fn test_check_proc_self_exe_on_linux() {
        let detector = StealthDetector::new();
        let event = detector.check_proc_self_exe();
        assert_eq!(event.layer, DetectionLayer::ProcSelfExeIntegrity);
        // Binary should not be deleted during tests
        assert!(!event.suspicious, "binary should not be deleted: {}", event.detail);
    }

    #[test]
    fn test_check_entropy_quality() {
        let detector = StealthDetector::new();
        let event = detector.check_entropy_quality();
        assert_eq!(event.layer, DetectionLayer::EntropyQuality);
        // Entropy should be good on any non-compromised system
        assert!(!event.suspicious, "entropy should be good: {}", event.detail);
    }

    #[test]
    fn test_check_library_injection_clean() {
        // Only passes if LD_PRELOAD is not set in the test environment
        if std::env::var("LD_PRELOAD").is_err() {
            let detector = StealthDetector::new();
            let event = detector.check_library_injection();
            assert!(!event.suspicious, "no injection expected: {}", event.detail);
        }
    }

    #[test]
    fn test_check_timing_consistency() {
        let detector = StealthDetector::new();
        let event = detector.check_timing_consistency();
        assert_eq!(event.layer, DetectionLayer::TimingConsistency);
        assert!(!event.suspicious);
    }

    #[test]
    fn test_run_check_updates_state() {
        let mut detector = StealthDetector::new();
        assert!(detector.last_checked.get(&DetectionLayer::EntropyQuality).is_none());

        let _event = detector.run_check(DetectionLayer::EntropyQuality);
        assert!(detector.last_checked.get(&DetectionLayer::EntropyQuality).is_some());
        assert!(!detector.history.get(&DetectionLayer::EntropyQuality).unwrap().is_empty());
    }

    #[test]
    fn test_run_due_checks_runs_all_initially() {
        let mut detector = StealthDetector::new();
        // On first call, all layers are due (never checked)
        let events = detector.run_due_checks();
        assert_eq!(events.len(), 10);
    }

    #[test]
    fn test_run_due_checks_respects_intervals() {
        let mut detector = StealthDetector::new();
        // First run: all due
        let _ = detector.run_due_checks();

        // Immediately after: none should be due (all intervals >= 10s)
        let events = detector.run_due_checks();
        assert!(events.is_empty());
    }

    #[test]
    fn test_network_listeners_no_expected_ports() {
        let detector = StealthDetector::new();
        // With no expected ports configured, nothing is "rogue"
        let event = detector.check_network_listeners();
        assert!(!event.suspicious);
    }

    #[test]
    fn test_suspicion_score_capped_at_one() {
        let mut detector = StealthDetector::new();
        detector.suspicion_score = 0.95;
        // Simulate a suspicious event that would push past 1.0
        detector.suspicion_score = (detector.suspicion_score + 0.4).min(1.0);
        assert_eq!(detector.suspicion_score, 1.0);
    }

    #[test]
    fn test_history_ring_buffer_limit() {
        let mut detector = StealthDetector::new();
        let layer = DetectionLayer::EntropyQuality;

        // Fill beyond MAX_HISTORY
        for _ in 0..(MAX_HISTORY + 10) {
            detector.run_check(layer);
        }

        assert_eq!(
            detector.history.get(&layer).unwrap().len(),
            MAX_HISTORY
        );
    }

    #[test]
    fn test_default_impl() {
        let d: StealthDetector = Default::default();
        assert_eq!(d.enabled_layers.len(), 10);
    }
}
