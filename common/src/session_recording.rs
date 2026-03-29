//! Session Recording / Privileged Access Monitoring (PAM).
//!
//! Provides tamper-evident session recording with HMAC-SHA512 hash chains,
//! dual-control enforcement, and encrypted export for audit trails.
#![forbid(unsafe_code)]

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

type HmacSha512 = Hmac<Sha512>;

// ── Serde helpers for [u8; 64] ──────────────────────────────────────────────

fn serialize_hash_link<S: serde::Serializer>(data: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
    serde::Serialize::serialize(data.as_slice(), s)
}

fn deserialize_hash_link<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
    let v: Vec<u8> = serde::Deserialize::deserialize(d)?;
    v.try_into()
        .map_err(|_| serde::de::Error::custom("expected 64 bytes for hash chain link"))
}

// ── Domain types ────────────────────────────────────────────────────────────

/// Type of session being recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecordingType {
    /// Standard admin session.
    Admin,
    /// Elevated-privilege session (e.g. root-equivalent).
    Privileged,
    /// Break-glass / emergency access.
    Emergency,
    /// Sovereign-context session (data residency constrained).
    Sovereign,
}

/// Category of an individual event within a recorded session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionEventType {
    CommandExecuted,
    ResourceAccessed,
    ConfigurationChanged,
    PrivilegeEscalated,
    AuthenticationAttempt,
    DataExported,
    KeyAccessed,
    PolicyModified,
}

/// A single event inside a recorded session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEvent {
    /// Unix timestamp (seconds) when the event occurred.
    pub timestamp: i64,
    /// Category of the event.
    pub event_type: SessionEventType,
    /// Human-readable description of what happened.
    pub details: String,
    /// Source IP address of the actor.
    pub source_ip: String,
    /// HMAC-SHA512 hash-chain link binding this event to its predecessor.
    #[serde(
        serialize_with = "serialize_hash_link",
        deserialize_with = "deserialize_hash_link"
    )]
    pub hash_chain_link: [u8; 64],
}

/// A complete session recording.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecording {
    pub session_id: Uuid,
    pub user_id: Uuid,
    /// Unix timestamp when recording began.
    pub start_time: i64,
    /// Unix timestamp when recording ended (`None` while still active).
    pub end_time: Option<i64>,
    pub recording_type: RecordingType,
    /// Ordered sequence of events captured during the session.
    pub events: Vec<SessionEvent>,
    /// Running HMAC-SHA512 integrity hash over the full chain.
    pub integrity_hash: Vec<u8>,
}

/// Policy governing which sessions must be recorded and what requires approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PamPolicy {
    /// Device tiers that require session recording (e.g. tiers 1..=3).
    pub require_recording_for_tiers: Vec<u8>,
    /// Maximum allowed session duration in seconds.
    pub max_session_duration_secs: u64,
    /// Whether to raise an alert when privilege escalation is detected.
    pub alert_on_privilege_escalation: bool,
    /// Event types that require prior approval before execution.
    pub require_approval_for: Vec<SessionEventType>,
    /// Event types that require two-person (dual control) approval.
    pub dual_control_actions: Vec<SessionEventType>,
}

impl Default for PamPolicy {
    fn default() -> Self {
        Self {
            require_recording_for_tiers: vec![1, 2, 3],
            max_session_duration_secs: 28800, // 8 hours
            alert_on_privilege_escalation: true,
            require_approval_for: vec![
                SessionEventType::PrivilegeEscalated,
                SessionEventType::PolicyModified,
            ],
            dual_control_actions: vec![
                SessionEventType::KeyAccessed,
                SessionEventType::PolicyModified,
            ],
        }
    }
}

// ── Hash-chain helpers ──────────────────────────────────────────────────────

/// Deterministic seed used for the very first link in a new recording chain.
const GENESIS_SEED: [u8; 64] = [0u8; 64];

/// Compute the canonical byte representation of an event for hashing.
fn event_canonical_bytes(event_type: SessionEventType, timestamp: i64, details: &str, source_ip: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(&(event_type as u32).to_le_bytes());
    buf.extend_from_slice(&timestamp.to_le_bytes());
    buf.extend_from_slice(details.as_bytes());
    buf.extend_from_slice(source_ip.as_bytes());
    buf
}

/// Compute HMAC-SHA512(key = previous_hash, msg = event_data).
fn compute_chain_link(previous_hash: &[u8], event_data: &[u8]) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(previous_hash)
        .expect("HMAC-SHA512 accepts any key length");
    mac.update(event_data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}

// ── SessionRecorder ─────────────────────────────────────────────────────────

/// The main recording engine that manages session recordings with tamper-evident
/// HMAC-SHA512 hash chains.
pub struct SessionRecorder {
    recordings: Mutex<HashMap<Uuid, SessionRecording>>,
    policy: PamPolicy,
}

impl SessionRecorder {
    /// Create a new recorder with the given PAM policy.
    pub fn new(policy: PamPolicy) -> Self {
        Self {
            recordings: Mutex::new(HashMap::new()),
            policy,
        }
    }

    /// Create a new recorder with the default PAM policy.
    pub fn with_defaults() -> Self {
        Self::new(PamPolicy::default())
    }

    /// Return a reference to the active policy.
    pub fn policy(&self) -> &PamPolicy {
        &self.policy
    }

    // ── Recording lifecycle ─────────────────────────────────────────────

    /// Begin recording a new session. Returns an error if a recording for
    /// this session already exists.
    pub fn start_recording(
        &self,
        session_id: Uuid,
        user_id: Uuid,
        recording_type: RecordingType,
        now: i64,
    ) -> Result<(), RecordingError> {
        let mut map = self.lock_recordings();
        if map.contains_key(&session_id) {
            return Err(RecordingError::AlreadyExists(session_id));
        }

        let recording = SessionRecording {
            session_id,
            user_id,
            start_time: now,
            end_time: None,
            recording_type,
            events: Vec::new(),
            integrity_hash: GENESIS_SEED.to_vec(),
        };

        tracing::info!(
            session_id = %session_id,
            user_id = %user_id,
            recording_type = ?recording_type,
            "PAM: session recording started"
        );
        crate::siem::SecurityEvent::session_created(&session_id.to_string(), "0.0.0.0");

        map.insert(session_id, recording);
        Ok(())
    }

    /// Append an event to an active recording.  The hash chain link is computed
    /// automatically from the previous chain tail.
    pub fn record_event(
        &self,
        session_id: Uuid,
        event_type: SessionEventType,
        details: String,
        source_ip: String,
        timestamp: i64,
    ) -> Result<(), RecordingError> {
        let mut map = self.lock_recordings();
        let recording = map
            .get_mut(&session_id)
            .ok_or(RecordingError::NotFound(session_id))?;

        if recording.end_time.is_some() {
            return Err(RecordingError::AlreadyFinalized(session_id));
        }

        // Enforce max session duration.
        let elapsed = timestamp.saturating_sub(recording.start_time) as u64;
        if elapsed > self.policy.max_session_duration_secs {
            return Err(RecordingError::SessionExpired(session_id));
        }

        // Dual-control enforcement: event types that require 2-person approval
        // are BLOCKED until a second approver signs off.  The caller must
        // obtain a second approver signature and retry via a dual-control-aware
        // path before the operation can proceed.
        if self.policy.dual_control_actions.contains(&event_type) {
            tracing::error!(
                session_id = %session_id,
                event_type = ?event_type,
                "PAM: dual-control action BLOCKED — requires second approver signature"
            );
            crate::siem::SecurityEvent::tamper_detected(
                &format!("dual-control action {:?} blocked in session {} — no second approver", event_type, session_id),
            );
            return Err(RecordingError::DualControlRequired(event_type));
        }

        // Privilege escalation alerting.
        if self.policy.alert_on_privilege_escalation
            && event_type == SessionEventType::PrivilegeEscalated
        {
            tracing::warn!(
                session_id = %session_id,
                "PAM: privilege escalation detected in recorded session"
            );
            crate::siem::SecurityEvent::tamper_detected(
                &format!("privilege escalation in session {session_id}"),
            );
        }

        // Compute hash chain link.
        let previous_hash = &recording.integrity_hash;
        let event_data = event_canonical_bytes(event_type, timestamp, &details, &source_ip);
        let link = compute_chain_link(previous_hash, &event_data);

        let event = SessionEvent {
            timestamp,
            event_type,
            details,
            source_ip,
            hash_chain_link: link,
        };

        // Update the running integrity hash.
        recording.integrity_hash = link.to_vec();
        recording.events.push(event);

        Ok(())
    }

    /// Finalize a recording — sets end_time and computes final integrity hash.
    pub fn stop_recording(
        &self,
        session_id: Uuid,
        now: i64,
    ) -> Result<(), RecordingError> {
        let mut map = self.lock_recordings();
        let recording = map
            .get_mut(&session_id)
            .ok_or(RecordingError::NotFound(session_id))?;

        if recording.end_time.is_some() {
            return Err(RecordingError::AlreadyFinalized(session_id));
        }

        recording.end_time = Some(now);

        // Compute a final integrity hash over the entire event chain.
        let final_data = format!(
            "FINALIZE:{}:{}:{}",
            session_id,
            recording.start_time,
            now,
        );
        let final_hash = compute_chain_link(&recording.integrity_hash, final_data.as_bytes());
        recording.integrity_hash = final_hash.to_vec();

        tracing::info!(
            session_id = %session_id,
            events = recording.events.len(),
            "PAM: session recording finalized"
        );

        Ok(())
    }

    /// Retrieve a clone of the full recording.
    pub fn get_recording(&self, session_id: Uuid) -> Result<SessionRecording, RecordingError> {
        let map = self.lock_recordings();
        map.get(&session_id)
            .cloned()
            .ok_or(RecordingError::NotFound(session_id))
    }

    /// Verify that the HMAC hash chain of a recording is unbroken.
    ///
    /// Returns `Ok(true)` if every link is valid, `Ok(false)` if a tampered
    /// event is detected, or an error if the recording is not found.
    pub fn verify_integrity(recording: &SessionRecording) -> bool {
        let mut previous_hash: Vec<u8> = GENESIS_SEED.to_vec();

        for event in &recording.events {
            let event_data = event_canonical_bytes(
                event.event_type,
                event.timestamp,
                &event.details,
                &event.source_ip,
            );
            let expected = compute_chain_link(&previous_hash, &event_data);
            if expected != event.hash_chain_link {
                tracing::error!(
                    session_id = %recording.session_id,
                    timestamp = event.timestamp,
                    "PAM: hash chain integrity violation detected!"
                );
                return false;
            }
            previous_hash = expected.to_vec();
        }

        // If finalized, verify the final integrity hash too.
        if let Some(end_time) = recording.end_time {
            let final_data = format!(
                "FINALIZE:{}:{}:{}",
                recording.session_id,
                recording.start_time,
                end_time,
            );
            let expected_final = compute_chain_link(&previous_hash, final_data.as_bytes());
            if recording.integrity_hash != expected_final.to_vec() {
                tracing::error!(
                    session_id = %recording.session_id,
                    "PAM: final integrity hash mismatch!"
                );
                return false;
            }
        } else {
            // Still active — running hash should match last event's link.
            if recording.integrity_hash != previous_hash {
                return false;
            }
        }

        true
    }

    /// Export a recording as an encrypted blob (AES-256-GCM) suitable for
    /// off-site audit archival.
    pub fn export_recording(
        &self,
        session_id: Uuid,
        encryption_key: &[u8; 32],
    ) -> Result<Vec<u8>, RecordingError> {
        let recording = self.get_recording(session_id)?;

        // Serialize with postcard.
        let plaintext = postcard::to_allocvec(&recording)
            .map_err(|e| RecordingError::ExportFailed(e.to_string()))?;

        // Encrypt with AES-256-GCM.
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        let cipher = Aes256Gcm::new_from_slice(encryption_key)
            .map_err(|e| RecordingError::ExportFailed(e.to_string()))?;

        // Generate 96-bit nonce from getrandom.
        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| RecordingError::ExportFailed(e.to_string()))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| RecordingError::ExportFailed(e.to_string()))?;

        // Output format: nonce (12 bytes) || ciphertext.
        let mut output = Vec::with_capacity(12 + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        tracing::info!(
            session_id = %session_id,
            bytes = output.len(),
            "PAM: session recording exported (encrypted)"
        );

        Ok(output)
    }

    // ── Internal helpers ────────────────────────────────────────────────

    fn lock_recordings(&self) -> std::sync::MutexGuard<'_, HashMap<Uuid, SessionRecording>> {
        self.recordings.lock().unwrap_or_else(|e| {
            tracing::error!("PAM: recordings mutex poisoned — recovering");
            e.into_inner()
        })
    }
}

// ── Error type ──────────────────────────────────────────────────────────────

/// Errors that can occur during session recording operations.
#[derive(Debug, thiserror::Error)]
pub enum RecordingError {
    #[error("recording already exists for session {0}")]
    AlreadyExists(Uuid),
    #[error("no recording found for session {0}")]
    NotFound(Uuid),
    #[error("recording for session {0} has already been finalized")]
    AlreadyFinalized(Uuid),
    #[error("session {0} has exceeded maximum duration")]
    SessionExpired(Uuid),
    #[error("export failed: {0}")]
    ExportFailed(String),
    #[error("dual-control required: action {0:?} requires a second approver signature before execution")]
    DualControlRequired(SessionEventType),
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_recorder() -> SessionRecorder {
        SessionRecorder::with_defaults()
    }

    #[test]
    fn test_start_and_stop_recording() {
        let recorder = make_recorder();
        let sid = Uuid::new_v4();
        let uid = Uuid::new_v4();

        recorder
            .start_recording(sid, uid, RecordingType::Admin, 1000)
            .unwrap();

        // Duplicate start should fail.
        assert!(recorder
            .start_recording(sid, uid, RecordingType::Admin, 1001)
            .is_err());

        recorder.stop_recording(sid, 2000).unwrap();

        // Double stop should fail.
        assert!(recorder.stop_recording(sid, 2001).is_err());
    }

    #[test]
    fn test_record_events_and_verify_integrity() {
        let recorder = make_recorder();
        let sid = Uuid::new_v4();
        let uid = Uuid::new_v4();

        recorder
            .start_recording(sid, uid, RecordingType::Privileged, 1000)
            .unwrap();

        recorder
            .record_event(
                sid,
                SessionEventType::CommandExecuted,
                "ls -la /etc".into(),
                "10.0.0.1".into(),
                1001,
            )
            .unwrap();

        recorder
            .record_event(
                sid,
                SessionEventType::ResourceAccessed,
                "read /etc/shadow".into(),
                "10.0.0.1".into(),
                1002,
            )
            .unwrap();

        recorder.stop_recording(sid, 1100).unwrap();

        let recording = recorder.get_recording(sid).unwrap();
        assert_eq!(recording.events.len(), 2);
        assert!(SessionRecorder::verify_integrity(&recording));
    }

    #[test]
    fn test_tampered_event_fails_integrity() {
        let recorder = make_recorder();
        let sid = Uuid::new_v4();
        let uid = Uuid::new_v4();

        recorder
            .start_recording(sid, uid, RecordingType::Emergency, 1000)
            .unwrap();

        recorder
            .record_event(
                sid,
                SessionEventType::ConfigurationChanged,
                "original action".into(),
                "10.0.0.1".into(),
                1001,
            )
            .unwrap();

        recorder.stop_recording(sid, 1100).unwrap();

        let mut recording = recorder.get_recording(sid).unwrap();
        // Tamper with the event details.
        recording.events[0].details = "malicious action".into();

        assert!(!SessionRecorder::verify_integrity(&recording));
    }

    #[test]
    fn test_export_recording() {
        let recorder = make_recorder();
        let sid = Uuid::new_v4();
        let uid = Uuid::new_v4();

        recorder
            .start_recording(sid, uid, RecordingType::Sovereign, 1000)
            .unwrap();
        recorder
            .record_event(
                sid,
                SessionEventType::DataExported,
                "export classified report".into(),
                "10.0.0.5".into(),
                1010,
            )
            .unwrap();
        recorder.stop_recording(sid, 1100).unwrap();

        let key = [0xABu8; 32];
        let encrypted = recorder.export_recording(sid, &key).unwrap();
        // Nonce (12) + ciphertext (at least 16 for GCM tag).
        assert!(encrypted.len() > 28);
    }

    #[test]
    fn test_session_expired_enforcement() {
        let policy = PamPolicy {
            max_session_duration_secs: 60,
            ..PamPolicy::default()
        };
        let recorder = SessionRecorder::new(policy);
        let sid = Uuid::new_v4();
        let uid = Uuid::new_v4();

        recorder
            .start_recording(sid, uid, RecordingType::Admin, 1000)
            .unwrap();

        // Event within limit — ok.
        recorder
            .record_event(
                sid,
                SessionEventType::CommandExecuted,
                "ok".into(),
                "10.0.0.1".into(),
                1050,
            )
            .unwrap();

        // Event past limit — should fail.
        let result = recorder.record_event(
            sid,
            SessionEventType::CommandExecuted,
            "too late".into(),
            "10.0.0.1".into(),
            1061,
        );
        assert!(matches!(result, Err(RecordingError::SessionExpired(_))));
    }

    // ── TEST GROUP 4: Dual-control blocking tests ──────────────────────────

    #[test]
    fn test_dual_control_action_returns_error() {
        let recorder = make_recorder();
        let sid = Uuid::new_v4();
        let uid = Uuid::new_v4();

        recorder
            .start_recording(sid, uid, RecordingType::Admin, 1000)
            .unwrap();

        // KeyAccessed is a dual-control action in the default policy.
        let result = recorder.record_event(
            sid,
            SessionEventType::KeyAccessed,
            "access HSM key".into(),
            "10.0.0.1".into(),
            1001,
        );
        assert!(
            matches!(result, Err(RecordingError::DualControlRequired(SessionEventType::KeyAccessed))),
            "KeyAccessed must be blocked as dual-control action"
        );
    }

    #[test]
    fn test_dual_control_policy_modified_blocked() {
        let recorder = make_recorder();
        let sid = Uuid::new_v4();
        let uid = Uuid::new_v4();

        recorder
            .start_recording(sid, uid, RecordingType::Privileged, 1000)
            .unwrap();

        // PolicyModified is also a dual-control action in the default policy.
        let result = recorder.record_event(
            sid,
            SessionEventType::PolicyModified,
            "change firewall rules".into(),
            "10.0.0.2".into(),
            1001,
        );
        assert!(
            matches!(result, Err(RecordingError::DualControlRequired(SessionEventType::PolicyModified))),
            "PolicyModified must be blocked as dual-control action"
        );
    }

    #[test]
    fn test_non_dual_control_action_succeeds() {
        let recorder = make_recorder();
        let sid = Uuid::new_v4();
        let uid = Uuid::new_v4();

        recorder
            .start_recording(sid, uid, RecordingType::Admin, 1000)
            .unwrap();

        // CommandExecuted is NOT a dual-control action — should succeed.
        let result = recorder.record_event(
            sid,
            SessionEventType::CommandExecuted,
            "ls -la".into(),
            "10.0.0.1".into(),
            1001,
        );
        assert!(result.is_ok(), "non-dual-control action must succeed");

        // ResourceAccessed is also not dual-control.
        let result2 = recorder.record_event(
            sid,
            SessionEventType::ResourceAccessed,
            "read config".into(),
            "10.0.0.1".into(),
            1002,
        );
        assert!(result2.is_ok(), "ResourceAccessed must succeed");
    }

    #[test]
    fn test_dual_control_error_carries_correct_event_type() {
        let recorder = make_recorder();
        let sid = Uuid::new_v4();
        let uid = Uuid::new_v4();

        recorder
            .start_recording(sid, uid, RecordingType::Admin, 1000)
            .unwrap();

        let result = recorder.record_event(
            sid,
            SessionEventType::KeyAccessed,
            "attempt key access".into(),
            "10.0.0.1".into(),
            1001,
        );

        match result {
            Err(RecordingError::DualControlRequired(event_type)) => {
                assert_eq!(event_type, SessionEventType::KeyAccessed,
                    "error must carry the exact event type that was blocked");
            }
            other => panic!("expected DualControlRequired, got: {:?}", other),
        }
    }

    #[test]
    fn test_active_recording_integrity() {
        let recorder = make_recorder();
        let sid = Uuid::new_v4();
        let uid = Uuid::new_v4();

        recorder
            .start_recording(sid, uid, RecordingType::Admin, 1000)
            .unwrap();

        recorder
            .record_event(
                sid,
                SessionEventType::AuthenticationAttempt,
                "login".into(),
                "10.0.0.1".into(),
                1001,
            )
            .unwrap();

        // Verify integrity while still active (no end_time).
        let recording = recorder.get_recording(sid).unwrap();
        assert!(SessionRecorder::verify_integrity(&recording));
    }
}
