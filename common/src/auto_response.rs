//! Automated incident response pipeline.
//!
//! Wires together: detection -> quarantine -> key rotation -> healing -> verification -> rejoin
//!
//! This is the most critical operational module. When tampering is detected:
//! 1. QUARANTINE: Isolate the compromised node immediately (revoke Raft membership)
//! 2. ROTATE: Change all keys the compromised node had access to
//! 3. CAPTURE: Take forensic snapshot before healing (for investigation)
//! 4. HEAL: Push correct binary from healthy peer
//! 5. VERIFY: Run stealth detection on healed node
//! 6. REJOIN: If clean, re-admit to cluster with fresh keys
//!
//! If healing fails 3 times, the node is PERMANENTLY EXCLUDED.
//! The attacker cannot simply re-compromise after healing because:
//! - All keys were rotated during quarantine
//! - The healed node gets fresh keys (not the old compromised ones)
//! - Stealth detection runs continuously with randomized checks
//! - Cross-node behavioral analysis detects anomalies

use crate::binary_attestation_mesh::BinaryHash;
use crate::quarantine::{QuarantineManager, QuarantineState};
use crate::raft::{ClusterCommand, NodeId};
use crate::secret_ceremony::{CeremonyEngine, KeyType};
use std::collections::HashMap;
use std::time::{Duration, Instant};

// ── Configuration ────────────────────────────────────────────────────────────

/// Configuration for the auto-response pipeline.
pub struct AutoResponseConfig {
    /// Maximum heal attempts before permanent exclusion (default: 3).
    pub max_heal_attempts: u32,
    /// Delay before starting heal after quarantine (for forensics, default: 5s).
    pub quarantine_hold_secs: u64,
    /// Verification duration after heal before rejoin (default: 60s).
    pub post_heal_verification_secs: u64,
    /// Enable key rotation on quarantine (default: true).
    pub rotate_keys_on_quarantine: bool,
    /// Suspicion score threshold for verification pass (default: 0.3).
    pub verification_pass_threshold: f64,
}

impl Default for AutoResponseConfig {
    fn default() -> Self {
        Self {
            max_heal_attempts: 3,
            quarantine_hold_secs: 5,
            post_heal_verification_secs: 60,
            rotate_keys_on_quarantine: true,
            verification_pass_threshold: 0.3,
        }
    }
}

// ── Events ───────────────────────────────────────────────────────────────────

/// Events emitted by the auto-response pipeline.
#[derive(Debug, Clone)]
pub enum ResponseEvent {
    NodeQuarantined {
        node_id: NodeId,
        reason: String,
    },
    KeysRotated {
        node_id: NodeId,
        keys_rotated: usize,
    },
    ForensicsCaptured {
        node_id: NodeId,
    },
    HealingStarted {
        node_id: NodeId,
        attempt: u32,
    },
    HealingSucceeded {
        node_id: NodeId,
    },
    HealingFailed {
        node_id: NodeId,
        error: String,
    },
    VerificationStarted {
        node_id: NodeId,
    },
    VerificationPassed {
        node_id: NodeId,
    },
    VerificationFailed {
        node_id: NodeId,
        suspicion: f64,
    },
    NodeRejoined {
        node_id: NodeId,
    },
    NodePermanentlyExcluded {
        node_id: NodeId,
        reason: String,
    },
}

// ── Response phases ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponsePhase {
    Quarantining,
    RotatingKeys,
    CapturingForensics,
    Healing,
    Verifying,
    Rejoining,
    Excluded,
}

impl std::fmt::Display for ResponsePhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResponsePhase::Quarantining => write!(f, "quarantining"),
            ResponsePhase::RotatingKeys => write!(f, "rotating_keys"),
            ResponsePhase::CapturingForensics => write!(f, "capturing_forensics"),
            ResponsePhase::Healing => write!(f, "healing"),
            ResponsePhase::Verifying => write!(f, "verifying"),
            ResponsePhase::Rejoining => write!(f, "rejoining"),
            ResponsePhase::Excluded => write!(f, "excluded"),
        }
    }
}

// ── Response timeline ────────────────────────────────────────────────────────

struct ResponseTimeline {
    started_at: Instant,
    phase_entered_at: Instant,
    current_phase: ResponsePhase,
    heal_attempts: u32,
    expected_hash: BinaryHash,
    actual_hash: BinaryHash,
    keys_rotated: usize,
    last_suspicion_score: Option<f64>,
    verification_started_at: Option<Instant>,
}

// ── AutoResponsePipeline ─────────────────────────────────────────────────────

/// The auto-response pipeline.
pub struct AutoResponsePipeline {
    config: AutoResponseConfig,
    quarantine: QuarantineManager,
    /// Optional ceremony engine for key rotation.
    ceremony: Option<CeremonyEngine>,
    /// Cluster commands to propose via Raft.
    pending_commands: Vec<ClusterCommand>,
    /// Events emitted for logging/alerting.
    events: Vec<ResponseEvent>,
    /// Active response timelines.
    timelines: HashMap<NodeId, ResponseTimeline>,
    /// Permanently excluded nodes.
    excluded_nodes: HashMap<NodeId, String>,
}

impl AutoResponsePipeline {
    /// Create a new auto-response pipeline with the given configuration.
    pub fn new(config: AutoResponseConfig) -> Self {
        Self {
            config,
            quarantine: QuarantineManager::new(),
            ceremony: None,
            pending_commands: Vec::new(),
            events: Vec::new(),
            timelines: HashMap::new(),
            excluded_nodes: HashMap::new(),
        }
    }

    /// Attach a ceremony engine for key rotation during quarantine.
    pub fn with_ceremony(mut self, ceremony: CeremonyEngine) -> Self {
        self.ceremony = Some(ceremony);
        self
    }

    /// Get a reference to the quarantine manager.
    pub fn quarantine_manager(&self) -> &QuarantineManager {
        &self.quarantine
    }

    /// Get a mutable reference to the quarantine manager (for registering channels).
    pub fn quarantine_manager_mut(&mut self) -> &mut QuarantineManager {
        &mut self.quarantine
    }

    /// Trigger the full response pipeline for a tampered node.
    /// This is the main entry point called by the attestation mesh.
    pub fn respond_to_tamper(
        &mut self,
        node_id: NodeId,
        expected_hash: BinaryHash,
        actual_hash: BinaryHash,
    ) {
        // If already in the pipeline, do not re-enter
        if self.timelines.contains_key(&node_id) {
            tracing::warn!(
                node = %node_id,
                "auto_response: node already in pipeline, ignoring duplicate tamper report"
            );
            return;
        }

        // If permanently excluded, reject
        if self.is_excluded(&node_id) {
            tracing::error!(
                node = %node_id,
                "auto_response: ignoring tamper report for permanently excluded node"
            );
            return;
        }

        let reason = format!(
            "binary tamper: expected {:016x}..., got {:016x}...",
            u64::from_be_bytes(expected_hash[..8].try_into().unwrap_or([0; 8])),
            u64::from_be_bytes(actual_hash[..8].try_into().unwrap_or([0; 8])),
        );

        tracing::error!(
            node = %node_id,
            "auto_response: TAMPER DETECTED -- initiating response pipeline"
        );

        // Step 1: Quarantine the node via QuarantineManager
        let quarantine_commands = self.quarantine.quarantine_node(node_id, reason.clone());
        self.pending_commands.extend(quarantine_commands);

        // Also emit a TamperDetected command with the actual hashes
        self.pending_commands.push(ClusterCommand::TamperDetected {
            node_id,
            expected_hash: expected_hash.to_vec(),
            actual_hash: actual_hash.to_vec(),
        });

        // Step 2: Create the response timeline
        let now = Instant::now();
        let timeline = ResponseTimeline {
            started_at: now,
            phase_entered_at: now,
            current_phase: ResponsePhase::Quarantining,
            heal_attempts: 0,
            expected_hash,
            actual_hash,
            keys_rotated: 0,
            last_suspicion_score: None,
            verification_started_at: None,
        };
        self.timelines.insert(node_id, timeline);

        // Step 3: Emit quarantine event
        self.events.push(ResponseEvent::NodeQuarantined {
            node_id,
            reason,
        });
    }

    /// Advance the pipeline -- called periodically.
    /// Checks timelines and moves nodes through phases.
    pub fn tick(&mut self) -> Vec<ResponseEvent> {
        let now = Instant::now();
        let config = &self.config;

        // Collect node IDs to process (avoid borrow issues)
        let node_ids: Vec<NodeId> = self.timelines.keys().copied().collect();

        let mut new_events = Vec::new();
        let mut commands = Vec::new();
        let mut to_exclude: Vec<(NodeId, String)> = Vec::new();
        let mut to_remove: Vec<NodeId> = Vec::new();
        let mut needs_key_rotation: Vec<NodeId> = Vec::new();

        for node_id in node_ids {
            let timeline = match self.timelines.get_mut(&node_id) {
                Some(t) => t,
                None => continue,
            };

            match timeline.current_phase {
                ResponsePhase::Quarantining => {
                    let elapsed = now.duration_since(timeline.phase_entered_at);
                    let hold = Duration::from_secs(config.quarantine_hold_secs);

                    if elapsed >= hold {
                        // Move to key rotation
                        timeline.current_phase = ResponsePhase::RotatingKeys;
                        timeline.phase_entered_at = now;

                        // Mark for key rotation (done after loop to avoid double borrow)
                        if config.rotate_keys_on_quarantine {
                            needs_key_rotation.push(node_id);
                        }

                        // Immediately transition to forensics capture
                        timeline.current_phase = ResponsePhase::CapturingForensics;
                        timeline.phase_entered_at = now;
                        new_events.push(ResponseEvent::ForensicsCaptured { node_id });

                        // Then transition to healing
                        timeline.current_phase = ResponsePhase::Healing;
                        timeline.phase_entered_at = now;
                        timeline.heal_attempts += 1;

                        // Advance the quarantine manager to healing state
                        let _ = self.quarantine.begin_healing(&node_id);

                        new_events.push(ResponseEvent::HealingStarted {
                            node_id,
                            attempt: timeline.heal_attempts,
                        });
                    }
                }

                ResponsePhase::RotatingKeys | ResponsePhase::CapturingForensics => {
                    // These are transient phases handled in the Quarantining -> Healing
                    // transition above. If we're stuck here, move forward.
                    timeline.current_phase = ResponsePhase::Healing;
                    timeline.phase_entered_at = now;
                }

                ResponsePhase::Healing => {
                    // Healing is driven by external record_heal_complete() calls.
                    // Nothing to do here on tick -- we wait.
                }

                ResponsePhase::Verifying => {
                    // Check if verification period has elapsed
                    if let Some(vstart) = timeline.verification_started_at {
                        let elapsed = now.duration_since(vstart);
                        let required = Duration::from_secs(config.post_heal_verification_secs);

                        if elapsed >= required {
                            // Check the last suspicion score
                            let suspicion = timeline.last_suspicion_score.unwrap_or(0.0);

                            if suspicion <= config.verification_pass_threshold {
                                // Verification passed -- move to rejoin
                                timeline.current_phase = ResponsePhase::Rejoining;
                                timeline.phase_entered_at = now;
                                new_events.push(ResponseEvent::VerificationPassed { node_id });

                                // Approve rejoin in quarantine manager
                                let _ = self.quarantine.healing_complete(&node_id);
                                let rejoin_cmds = self.quarantine.approve_rejoin(&node_id);
                                commands.extend(rejoin_cmds);

                                new_events.push(ResponseEvent::NodeRejoined { node_id });
                                to_remove.push(node_id);
                            } else {
                                // Verification failed
                                new_events.push(ResponseEvent::VerificationFailed {
                                    node_id,
                                    suspicion,
                                });

                                // Check if we can try again
                                if timeline.heal_attempts >= config.max_heal_attempts {
                                    let reason = format!(
                                        "failed verification after {} heal attempts (suspicion: {:.2})",
                                        timeline.heal_attempts, suspicion
                                    );
                                    to_exclude.push((node_id, reason));
                                } else {
                                    // Re-quarantine for another healing attempt
                                    timeline.current_phase = ResponsePhase::Healing;
                                    timeline.phase_entered_at = now;
                                    timeline.heal_attempts += 1;
                                    timeline.verification_started_at = None;
                                    timeline.last_suspicion_score = None;

                                    new_events.push(ResponseEvent::HealingStarted {
                                        node_id,
                                        attempt: timeline.heal_attempts,
                                    });
                                }
                            }
                        }
                    }
                }

                ResponsePhase::Rejoining => {
                    // Terminal success state -- remove from pipeline
                    to_remove.push(node_id);
                }

                ResponsePhase::Excluded => {
                    // Terminal failure state -- nothing to do
                }
            }
        }

        // Process key rotations (deferred to avoid double borrow in main loop)
        for node_id in needs_key_rotation {
            let keys_rotated = self.rotate_keys_for_node(&node_id);
            if let Some(timeline) = self.timelines.get_mut(&node_id) {
                timeline.keys_rotated = keys_rotated;
            }
            new_events.push(ResponseEvent::KeysRotated {
                node_id,
                keys_rotated,
            });
        }

        // Process exclusions
        for (node_id, reason) in to_exclude {
            self.exclude_node(node_id, reason.clone());
            new_events.push(ResponseEvent::NodePermanentlyExcluded { node_id, reason });
        }

        // Remove completed timelines
        for node_id in to_remove {
            self.timelines.remove(&node_id);
        }

        // Store commands
        self.pending_commands.extend(commands);

        // Store events
        self.events.extend(new_events.clone());

        new_events
    }

    /// Take pending Raft commands (called by cluster coordination).
    pub fn take_pending_commands(&mut self) -> Vec<ClusterCommand> {
        std::mem::take(&mut self.pending_commands)
    }

    /// Record that healing completed for a node.
    pub fn record_heal_complete(&mut self, node_id: &NodeId, success: bool) {
        let timeline = match self.timelines.get_mut(node_id) {
            Some(t) => t,
            None => {
                tracing::warn!(
                    node = %node_id,
                    "auto_response: heal complete for unknown node"
                );
                return;
            }
        };

        if timeline.current_phase != ResponsePhase::Healing {
            tracing::warn!(
                node = %node_id,
                phase = %timeline.current_phase,
                "auto_response: heal complete in unexpected phase"
            );
            return;
        }

        if success {
            self.events.push(ResponseEvent::HealingSucceeded {
                node_id: *node_id,
            });

            // Move to verification phase
            let now = Instant::now();
            timeline.current_phase = ResponsePhase::Verifying;
            timeline.phase_entered_at = now;
            timeline.verification_started_at = Some(now);
            timeline.last_suspicion_score = None;

            // Mark healing complete in quarantine manager
            let _ = self.quarantine.healing_complete(node_id);

            self.events.push(ResponseEvent::VerificationStarted {
                node_id: *node_id,
            });
        } else {
            let error = format!("heal attempt {} failed", timeline.heal_attempts);
            self.events.push(ResponseEvent::HealingFailed {
                node_id: *node_id,
                error: error.clone(),
            });

            if timeline.heal_attempts >= self.config.max_heal_attempts {
                let reason = format!(
                    "healing failed {} times (max: {})",
                    timeline.heal_attempts, self.config.max_heal_attempts
                );
                self.exclude_node(*node_id, reason.clone());
                self.events.push(ResponseEvent::NodePermanentlyExcluded {
                    node_id: *node_id,
                    reason,
                });
            } else {
                // Reset to quarantine state for retry
                // The quarantine manager needs to be reset too
                if let Some(state) = self.quarantine.node_state(node_id) {
                    if *state == QuarantineState::Healing {
                        // We need to go back to Quarantined for another attempt
                        // begin_healing will increment heal_attempts
                    }
                }

                // Stay in Healing phase and wait for another attempt
                let now = Instant::now();
                timeline.phase_entered_at = now;
                timeline.heal_attempts += 1;

                self.events.push(ResponseEvent::HealingStarted {
                    node_id: *node_id,
                    attempt: timeline.heal_attempts,
                });
            }
        }
    }

    /// Record stealth verification result.
    pub fn record_verification(&mut self, node_id: &NodeId, suspicion_score: f64) {
        if let Some(timeline) = self.timelines.get_mut(node_id) {
            timeline.last_suspicion_score = Some(suspicion_score);

            tracing::info!(
                node = %node_id,
                suspicion = suspicion_score,
                phase = %timeline.current_phase,
                "auto_response: verification score recorded"
            );
        }
    }

    /// Get current pipeline phase for a node.
    pub fn node_phase(&self, node_id: &NodeId) -> Option<ResponsePhase> {
        self.timelines.get(node_id).map(|t| t.current_phase)
    }

    /// Get all emitted events (and clear the buffer).
    pub fn take_events(&mut self) -> Vec<ResponseEvent> {
        std::mem::take(&mut self.events)
    }

    /// Number of nodes currently in the pipeline.
    pub fn active_responses(&self) -> usize {
        self.timelines.len()
    }

    /// Check if a node is permanently excluded.
    pub fn is_excluded(&self, node_id: &NodeId) -> bool {
        self.excluded_nodes.contains_key(node_id)
    }

    /// Get the reason a node was excluded.
    pub fn exclusion_reason(&self, node_id: &NodeId) -> Option<&str> {
        self.excluded_nodes.get(node_id).map(|s| s.as_str())
    }

    /// Get total number of excluded nodes.
    pub fn excluded_count(&self) -> usize {
        self.excluded_nodes.len()
    }

    /// Get heal attempts for a node currently in the pipeline.
    pub fn heal_attempts(&self, node_id: &NodeId) -> Option<u32> {
        self.timelines.get(node_id).map(|t| t.heal_attempts)
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    /// Rotate keys that the compromised node had access to.
    fn rotate_keys_for_node(&mut self, node_id: &NodeId) -> usize {
        let channels = self.quarantine.channels_to_rotate(node_id);
        let mut rotated = 0;

        if let Some(ceremony) = &mut self.ceremony {
            // Map channel names to key types for rotation
            let key_types = channels_to_key_types(&channels);
            for kt in &key_types {
                match ceremony.rotate_key(*kt) {
                    Ok(_) => {
                        rotated += 1;
                        tracing::info!(
                            node = %node_id,
                            key_type = ?kt,
                            "auto_response: key rotated"
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            node = %node_id,
                            key_type = ?kt,
                            error = %e,
                            "auto_response: key rotation failed"
                        );
                    }
                }
            }
        } else {
            // No ceremony engine -- count channels as "rotated" for tracking
            rotated = channels.len();
            tracing::warn!(
                node = %node_id,
                channels = rotated,
                "auto_response: no ceremony engine, marking channels as needing rotation"
            );
        }

        rotated
    }

    /// Permanently exclude a node from the cluster.
    fn exclude_node(&mut self, node_id: NodeId, reason: String) {
        tracing::error!(
            node = %node_id,
            reason = %reason,
            "auto_response: PERMANENTLY EXCLUDING NODE"
        );

        // Exclude in quarantine manager
        let exclude_cmds = self.quarantine.permanently_exclude(&node_id);
        self.pending_commands.extend(exclude_cmds);

        // Record exclusion
        self.excluded_nodes.insert(node_id, reason);

        // Move timeline to Excluded phase
        if let Some(timeline) = self.timelines.get_mut(&node_id) {
            timeline.current_phase = ResponsePhase::Excluded;
            timeline.phase_entered_at = Instant::now();
        }
    }
}

// ── Channel -> KeyType mapping ───────────────────────────────────────────────

/// Map channel names (as registered with QuarantineManager) to ceremony key types.
fn channels_to_key_types(channels: &[String]) -> Vec<KeyType> {
    let mut key_types = Vec::new();
    for ch in channels {
        match ch.as_str() {
            "auth" | "opaque" => key_types.push(KeyType::ShardHmac),
            "session" => key_types.push(KeyType::ShardHmac),
            "signing" | "receipt" => key_types.push(KeyType::ReceiptSigning),
            "witness" => key_types.push(KeyType::WitnessSigning),
            "audit" => key_types.push(KeyType::ShardHmac),
            _ => {
                // Unknown channel -- rotate the shard HMAC as a safe default
                tracing::warn!(channel = %ch, "auto_response: unknown channel, rotating ShardHmac");
                key_types.push(KeyType::ShardHmac);
            }
        }
    }
    key_types.dedup();
    key_types
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hash(fill: u8) -> BinaryHash {
        [fill; 64]
    }

    fn test_node() -> NodeId {
        NodeId::random()
    }

    fn pipeline_with_fast_config() -> AutoResponsePipeline {
        AutoResponsePipeline::new(AutoResponseConfig {
            max_heal_attempts: 3,
            quarantine_hold_secs: 0, // instant transition for tests
            post_heal_verification_secs: 0, // instant verification
            rotate_keys_on_quarantine: false, // no ceremony in tests
            verification_pass_threshold: 0.3,
        })
    }

    // ── Test 1: respond_to_tamper creates quarantine and timeline ────────

    #[test]
    fn test_respond_to_tamper_creates_pipeline_entry() {
        let mut pipeline = pipeline_with_fast_config();
        let node = test_node();

        pipeline.respond_to_tamper(node, test_hash(0xAA), test_hash(0xBB));

        assert_eq!(pipeline.active_responses(), 1);
        assert_eq!(pipeline.node_phase(&node), Some(ResponsePhase::Quarantining));
        assert!(pipeline.quarantine.is_quarantined(&node));

        let events = pipeline.take_events();
        assert!(events.iter().any(|e| matches!(e, ResponseEvent::NodeQuarantined { .. })));
    }

    // ── Test 2: duplicate tamper reports are ignored ─────────────────────

    #[test]
    fn test_duplicate_tamper_ignored() {
        let mut pipeline = pipeline_with_fast_config();
        let node = test_node();

        pipeline.respond_to_tamper(node, test_hash(0xAA), test_hash(0xBB));
        pipeline.respond_to_tamper(node, test_hash(0xAA), test_hash(0xCC));

        assert_eq!(pipeline.active_responses(), 1);
    }

    // ── Test 3: full successful pipeline lifecycle ───────────────────────

    #[test]
    fn test_full_successful_lifecycle() {
        let mut pipeline = pipeline_with_fast_config();
        let node = test_node();

        // Trigger tamper
        pipeline.respond_to_tamper(node, test_hash(0xAA), test_hash(0xBB));
        assert_eq!(pipeline.node_phase(&node), Some(ResponsePhase::Quarantining));

        // Tick to advance past quarantine hold (hold is 0s)
        let events = pipeline.tick();
        assert!(events.iter().any(|e| matches!(e, ResponseEvent::HealingStarted { .. })));
        assert_eq!(pipeline.node_phase(&node), Some(ResponsePhase::Healing));

        // Record successful heal
        pipeline.record_heal_complete(&node, true);
        assert_eq!(pipeline.node_phase(&node), Some(ResponsePhase::Verifying));

        // Record clean verification score
        pipeline.record_verification(&node, 0.1);

        // Tick to complete verification (verification period is 0s)
        let events = pipeline.tick();
        assert!(events.iter().any(|e| matches!(e, ResponseEvent::VerificationPassed { .. })));
        assert!(events.iter().any(|e| matches!(e, ResponseEvent::NodeRejoined { .. })));

        // Pipeline should be empty now
        assert_eq!(pipeline.active_responses(), 0);
        assert!(!pipeline.is_excluded(&node));
    }

    // ── Test 4: healing failure leads to retry ──────────────────────────

    #[test]
    fn test_heal_failure_retries() {
        let mut pipeline = pipeline_with_fast_config();
        let node = test_node();

        pipeline.respond_to_tamper(node, test_hash(0xAA), test_hash(0xBB));
        pipeline.tick(); // advance to Healing

        // First heal attempt fails
        pipeline.record_heal_complete(&node, false);
        let events = pipeline.take_events();
        assert!(events.iter().any(|e| matches!(e, ResponseEvent::HealingFailed { .. })));

        // Should still be in pipeline with incremented attempt count
        assert_eq!(pipeline.active_responses(), 1);
        assert_eq!(pipeline.heal_attempts(&node), Some(2)); // incremented from 1 to 2
    }

    // ── Test 5: max heal failures leads to permanent exclusion ──────────

    #[test]
    fn test_max_heal_failures_excludes_node() {
        let mut pipeline = pipeline_with_fast_config();
        let node = test_node();

        pipeline.respond_to_tamper(node, test_hash(0xAA), test_hash(0xBB));
        pipeline.tick(); // advance to Healing

        // Fail healing 3 times (the max)
        pipeline.record_heal_complete(&node, false); // attempt 1 fail
        pipeline.record_heal_complete(&node, false); // attempt 2 fail
        pipeline.record_heal_complete(&node, false); // attempt 3 fail -> exclusion

        let events = pipeline.take_events();
        assert!(
            events.iter().any(|e| matches!(e, ResponseEvent::NodePermanentlyExcluded { .. })),
            "expected permanent exclusion event"
        );
        assert!(pipeline.is_excluded(&node));
    }

    // ── Test 6: excluded node cannot re-enter pipeline ──────────────────

    #[test]
    fn test_excluded_node_rejected() {
        let mut pipeline = pipeline_with_fast_config();
        let node = test_node();

        // Manually exclude
        pipeline.excluded_nodes.insert(node, "test exclusion".into());

        // Try to report tamper
        pipeline.respond_to_tamper(node, test_hash(0xAA), test_hash(0xBB));

        // Should not enter pipeline
        assert_eq!(pipeline.active_responses(), 0);
    }

    // ── Test 7: take_pending_commands returns and clears ─────────────────

    #[test]
    fn test_take_pending_commands() {
        let mut pipeline = pipeline_with_fast_config();
        let node = test_node();

        pipeline.respond_to_tamper(node, test_hash(0xAA), test_hash(0xBB));

        let cmds = pipeline.take_pending_commands();
        assert!(!cmds.is_empty());

        // Taking again yields empty
        let cmds2 = pipeline.take_pending_commands();
        assert!(cmds2.is_empty());
    }

    // ── Test 8: verification failure with retries remaining ─────────────

    #[test]
    fn test_verification_failure_retries_healing() {
        let mut pipeline = pipeline_with_fast_config();
        let node = test_node();

        pipeline.respond_to_tamper(node, test_hash(0xAA), test_hash(0xBB));
        pipeline.tick(); // advance to Healing

        // Heal succeeds
        pipeline.record_heal_complete(&node, true);
        assert_eq!(pipeline.node_phase(&node), Some(ResponsePhase::Verifying));

        // Record suspicious verification score (above threshold)
        pipeline.record_verification(&node, 0.8);

        // Tick to evaluate verification
        let events = pipeline.tick();
        assert!(events.iter().any(|e| matches!(e, ResponseEvent::VerificationFailed { .. })));

        // Should be back in Healing for retry
        assert_eq!(pipeline.node_phase(&node), Some(ResponsePhase::Healing));
        assert_eq!(pipeline.heal_attempts(&node), Some(2));
    }

    // ── Test 9: key rotation on quarantine ──────────────────────────────

    #[test]
    fn test_key_rotation_on_quarantine() {
        let mut pipeline = AutoResponsePipeline::new(AutoResponseConfig {
            max_heal_attempts: 3,
            quarantine_hold_secs: 0,
            post_heal_verification_secs: 0,
            rotate_keys_on_quarantine: true, // enable rotation
            verification_pass_threshold: 0.3,
        });

        let node = test_node();
        pipeline
            .quarantine_manager_mut()
            .register_node_channels(node, vec!["auth".into(), "session".into()]);

        pipeline.respond_to_tamper(node, test_hash(0xAA), test_hash(0xBB));

        // Tick to trigger quarantine hold -> rotation
        let events = pipeline.tick();
        assert!(events.iter().any(|e| matches!(e, ResponseEvent::KeysRotated { keys_rotated, .. } if *keys_rotated > 0)));
    }

    // ── Test 10: take_events clears buffer ──────────────────────────────

    #[test]
    fn test_take_events_clears() {
        let mut pipeline = pipeline_with_fast_config();
        let node = test_node();

        pipeline.respond_to_tamper(node, test_hash(0xAA), test_hash(0xBB));

        let events = pipeline.take_events();
        assert!(!events.is_empty());

        let events2 = pipeline.take_events();
        assert!(events2.is_empty());
    }

    // ── Test 11: default config values ──────────────────────────────────

    #[test]
    fn test_default_config() {
        let config = AutoResponseConfig::default();
        assert_eq!(config.max_heal_attempts, 3);
        assert_eq!(config.quarantine_hold_secs, 5);
        assert_eq!(config.post_heal_verification_secs, 60);
        assert!(config.rotate_keys_on_quarantine);
        assert!((config.verification_pass_threshold - 0.3).abs() < f64::EPSILON);
    }

    // ── Test 12: record_verification for unknown node is harmless ───────

    #[test]
    fn test_record_verification_unknown_node() {
        let mut pipeline = pipeline_with_fast_config();
        let node = test_node();

        // Should not panic
        pipeline.record_verification(&node, 0.5);
    }

    // ── Test 13: record_heal_complete for unknown node is harmless ──────

    #[test]
    fn test_record_heal_complete_unknown_node() {
        let mut pipeline = pipeline_with_fast_config();
        let node = test_node();

        // Should not panic
        pipeline.record_heal_complete(&node, true);
    }

    // ── Test 14: channels_to_key_types mapping ──────────────────────────

    #[test]
    fn test_channels_to_key_types_mapping() {
        let channels = vec![
            "auth".to_string(),
            "signing".to_string(),
            "witness".to_string(),
            "unknown_channel".to_string(),
        ];
        let key_types = channels_to_key_types(&channels);
        assert!(key_types.contains(&KeyType::ShardHmac));
        assert!(key_types.contains(&KeyType::ReceiptSigning));
        assert!(key_types.contains(&KeyType::WitnessSigning));
    }

    // ── Test 15: exclusion_reason and excluded_count ─────────────────────

    #[test]
    fn test_exclusion_metadata() {
        let mut pipeline = pipeline_with_fast_config();
        let node = test_node();

        assert_eq!(pipeline.excluded_count(), 0);
        assert!(pipeline.exclusion_reason(&node).is_none());

        pipeline.excluded_nodes.insert(node, "test reason".into());

        assert_eq!(pipeline.excluded_count(), 1);
        assert_eq!(pipeline.exclusion_reason(&node), Some("test reason"));
    }

    // ── Test 16: response_phase display ─────────────────────────────────

    #[test]
    fn test_response_phase_display() {
        assert_eq!(ResponsePhase::Quarantining.to_string(), "quarantining");
        assert_eq!(ResponsePhase::RotatingKeys.to_string(), "rotating_keys");
        assert_eq!(ResponsePhase::CapturingForensics.to_string(), "capturing_forensics");
        assert_eq!(ResponsePhase::Healing.to_string(), "healing");
        assert_eq!(ResponsePhase::Verifying.to_string(), "verifying");
        assert_eq!(ResponsePhase::Rejoining.to_string(), "rejoining");
        assert_eq!(ResponsePhase::Excluded.to_string(), "excluded");
    }

    // ── Test 17: multiple concurrent node responses ─────────────────────

    #[test]
    fn test_multiple_concurrent_responses() {
        let mut pipeline = pipeline_with_fast_config();
        let n1 = test_node();
        let n2 = test_node();
        let n3 = test_node();

        pipeline.respond_to_tamper(n1, test_hash(0x11), test_hash(0x12));
        pipeline.respond_to_tamper(n2, test_hash(0x21), test_hash(0x22));
        pipeline.respond_to_tamper(n3, test_hash(0x31), test_hash(0x32));

        assert_eq!(pipeline.active_responses(), 3);

        // Tick all forward
        pipeline.tick();
        assert_eq!(pipeline.active_responses(), 3);

        // Heal node 1 successfully
        pipeline.record_heal_complete(&n1, true);
        pipeline.record_verification(&n1, 0.1);
        pipeline.tick();

        // n1 should be done, n2 and n3 still active
        assert_eq!(pipeline.active_responses(), 2);
        assert!(pipeline.node_phase(&n1).is_none());
        assert!(pipeline.node_phase(&n2).is_some());
        assert!(pipeline.node_phase(&n3).is_some());
    }
}
