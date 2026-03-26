//! Device Lifecycle Management for the MILNET SSO system.
//!
//! Provides comprehensive device inventory tracking, health scoring,
//! remediation recommendations, and lifecycle state management with
//! full SIEM integration for all lifecycle transitions.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

// ── Domain types ────────────────────────────────────────────────────────────

/// Device status in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceStatus {
    /// Device is enrolled and actively communicating.
    Active,
    /// Device has been administratively suspended (pending investigation).
    Suspended,
    /// Device has been quarantined due to a compliance failure.
    Quarantined,
    /// Device has been permanently decommissioned.
    Decommissioned,
    /// Device has been reported lost or stolen.
    Lost,
}

impl std::fmt::Display for DeviceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceStatus::Active => write!(f, "Active"),
            DeviceStatus::Suspended => write!(f, "Suspended"),
            DeviceStatus::Quarantined => write!(f, "Quarantined"),
            DeviceStatus::Decommissioned => write!(f, "Decommissioned"),
            DeviceStatus::Lost => write!(f, "Lost"),
        }
    }
}

/// Operating system type for a managed device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OsType {
    /// Windows desktop/server.
    Windows,
    /// Linux distribution.
    Linux,
    /// macOS.
    MacOS,
    /// iOS mobile.
    IOS,
    /// Android mobile.
    Android,
    /// Other / unknown OS.
    Other(String),
}

impl std::fmt::Display for OsType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OsType::Windows => write!(f, "Windows"),
            OsType::Linux => write!(f, "Linux"),
            OsType::MacOS => write!(f, "macOS"),
            OsType::IOS => write!(f, "iOS"),
            OsType::Android => write!(f, "Android"),
            OsType::Other(s) => write!(f, "Other({})", s),
        }
    }
}

/// Geographic location of a device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceLocation {
    /// Latitude in decimal degrees.
    pub latitude: f64,
    /// Longitude in decimal degrees.
    pub longitude: f64,
}

/// Full device inventory record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInventory {
    /// Unique device identifier.
    pub device_id: Uuid,
    /// Human-readable device name.
    pub device_name: String,
    /// Operating system type.
    pub os_type: OsType,
    /// Operating system version string.
    pub os_version: String,
    /// Device hardware model.
    pub model: String,
    /// UUID of the device owner / assigned operator.
    pub owner_id: Uuid,
    /// Unix timestamp when the device was enrolled.
    pub enrolled_at: i64,
    /// Unix timestamp of the last communication from the device.
    pub last_seen: i64,
    /// Unix timestamp of the last health check.
    pub last_health_check: i64,
    /// Current lifecycle status.
    pub status: DeviceStatus,
    /// Device security tier (1=Sovereign, 2=Operational, 3=Sensor, 4=Emergency).
    pub tier: u8,
    /// Arbitrary tags for grouping and filtering.
    pub tags: Vec<String>,
    /// Optional geographic location.
    pub location: Option<DeviceLocation>,
    /// Computed compliance score (0.0 = non-compliant, 1.0 = fully compliant).
    pub compliance_score: f64,
}

/// Device health report submitted during a health check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceHealthReport {
    /// Days since the last OS patch was applied.
    pub os_patch_level: u32,
    /// Whether antivirus software is enabled.
    pub antivirus_enabled: bool,
    /// Whether antivirus definitions are up to date.
    pub antivirus_updated: bool,
    /// Whether full-disk encryption is enabled.
    pub disk_encryption_enabled: bool,
    /// Whether the host firewall is enabled.
    pub firewall_enabled: bool,
    /// Whether screen lock is enabled.
    pub screen_lock_enabled: bool,
    /// Whether the device is jailbroken or rooted.
    pub jailbroken_or_rooted: bool,
    /// Days since the last reboot.
    pub last_reboot_days: u32,
    /// Whether the device certificate is valid.
    pub certificate_valid: bool,
    /// Whether the platform attestation is fresh.
    pub attestation_fresh: bool,
}

/// Priority level for a remediation action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RemediationPriority {
    /// Low priority — informational.
    Low = 1,
    /// Medium priority — should be addressed soon.
    Medium = 2,
    /// High priority — must be addressed promptly.
    High = 3,
    /// Critical priority — immediate action required.
    Critical = 4,
}

/// A recommended remediation action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationAction {
    /// The type of remediation.
    pub action: RemediationType,
    /// Priority of this remediation.
    pub priority: RemediationPriority,
    /// Human-readable description of the remediation.
    pub description: String,
}

/// Types of remediation actions that can be recommended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemediationType {
    /// Force the device to apply pending OS/software updates.
    ForceUpdate,
    /// Quarantine the device (restrict network access).
    Quarantine,
    /// Suspend the device from the SSO system.
    Suspend,
    /// Remote wipe the device (lost/stolen scenario).
    Wipe,
    /// Require the device to re-enroll.
    ReEnroll,
    /// Send a notification to the device owner / administrator.
    Notify,
}

// ── Health scoring ──────────────────────────────────────────────────────────

/// Weight constants for health score computation.
const WEIGHT_DISK_ENCRYPTION: f64 = 0.20;
const WEIGHT_OS_PATCH: f64 = 0.15;
const WEIGHT_ANTIVIRUS: f64 = 0.15;
const WEIGHT_FIREWALL: f64 = 0.10;
const WEIGHT_SCREEN_LOCK: f64 = 0.05;
const WEIGHT_JAILBREAK: f64 = 0.15;
const WEIGHT_CERTIFICATE: f64 = 0.10;
const WEIGHT_ATTESTATION: f64 = 0.05;
const WEIGHT_REBOOT: f64 = 0.05;

/// Compute a compliance score from a device health report.
///
/// Returns a value in `[0.0, 1.0]` where 1.0 is fully compliant.
/// Each health factor is weighted according to its security impact.
pub fn compute_health_score(report: &DeviceHealthReport) -> f64 {
    let mut score = 0.0;

    // Disk encryption — binary pass/fail.
    if report.disk_encryption_enabled {
        score += WEIGHT_DISK_ENCRYPTION;
    }

    // OS patch level — full score if patched within 7 days, degrades linearly to 0 at 90 days.
    let patch_score = if report.os_patch_level <= 7 {
        1.0
    } else if report.os_patch_level >= 90 {
        0.0
    } else {
        1.0 - ((report.os_patch_level - 7) as f64 / 83.0)
    };
    score += WEIGHT_OS_PATCH * patch_score;

    // Antivirus — both enabled and updated required for full score.
    if report.antivirus_enabled && report.antivirus_updated {
        score += WEIGHT_ANTIVIRUS;
    } else if report.antivirus_enabled {
        score += WEIGHT_ANTIVIRUS * 0.5;
    }

    // Firewall — binary pass/fail.
    if report.firewall_enabled {
        score += WEIGHT_FIREWALL;
    }

    // Screen lock — binary pass/fail.
    if report.screen_lock_enabled {
        score += WEIGHT_SCREEN_LOCK;
    }

    // Jailbreak/root detection — immediate zero for this factor if compromised.
    if !report.jailbroken_or_rooted {
        score += WEIGHT_JAILBREAK;
    }

    // Certificate validity — binary pass/fail.
    if report.certificate_valid {
        score += WEIGHT_CERTIFICATE;
    }

    // Attestation freshness — binary pass/fail.
    if report.attestation_fresh {
        score += WEIGHT_ATTESTATION;
    }

    // Reboot freshness — full score if rebooted within 7 days, degrades to 0 at 30 days.
    let reboot_score = if report.last_reboot_days <= 7 {
        1.0
    } else if report.last_reboot_days >= 30 {
        0.0
    } else {
        1.0 - ((report.last_reboot_days - 7) as f64 / 23.0)
    };
    score += WEIGHT_REBOOT * reboot_score;

    // Clamp to [0.0, 1.0].
    score.clamp(0.0, 1.0)
}

/// Recommend remediation actions based on a health report.
///
/// Analyzes each health factor and generates appropriate remediation
/// actions sorted by priority (highest first).
pub fn recommend_remediation(report: &DeviceHealthReport) -> Vec<RemediationAction> {
    let mut actions = Vec::new();

    // Jailbroken/rooted — critical, must quarantine.
    if report.jailbroken_or_rooted {
        actions.push(RemediationAction {
            action: RemediationType::Quarantine,
            priority: RemediationPriority::Critical,
            description: "Device is jailbroken or rooted — quarantine immediately".into(),
        });
        actions.push(RemediationAction {
            action: RemediationType::ReEnroll,
            priority: RemediationPriority::Critical,
            description: "Jailbroken device must be wiped and re-enrolled".into(),
        });
    }

    // No disk encryption — high priority.
    if !report.disk_encryption_enabled {
        actions.push(RemediationAction {
            action: RemediationType::Notify,
            priority: RemediationPriority::High,
            description: "Full-disk encryption is not enabled".into(),
        });
        actions.push(RemediationAction {
            action: RemediationType::Suspend,
            priority: RemediationPriority::High,
            description: "Suspend until disk encryption is enabled".into(),
        });
    }

    // Certificate invalid — high priority.
    if !report.certificate_valid {
        actions.push(RemediationAction {
            action: RemediationType::ReEnroll,
            priority: RemediationPriority::High,
            description: "Device certificate is invalid — re-enrollment required".into(),
        });
    }

    // Attestation stale — high priority.
    if !report.attestation_fresh {
        actions.push(RemediationAction {
            action: RemediationType::Notify,
            priority: RemediationPriority::High,
            description: "Platform attestation is stale — re-attestation required".into(),
        });
    }

    // OS severely out of date (>= 30 days).
    if report.os_patch_level >= 30 {
        actions.push(RemediationAction {
            action: RemediationType::ForceUpdate,
            priority: RemediationPriority::High,
            description: format!(
                "OS is {} days behind on patches — force update required",
                report.os_patch_level
            ),
        });
    } else if report.os_patch_level > 7 {
        actions.push(RemediationAction {
            action: RemediationType::Notify,
            priority: RemediationPriority::Medium,
            description: format!(
                "OS is {} days behind on patches — update recommended",
                report.os_patch_level
            ),
        });
    }

    // Antivirus issues.
    if !report.antivirus_enabled {
        actions.push(RemediationAction {
            action: RemediationType::Quarantine,
            priority: RemediationPriority::High,
            description: "Antivirus is not enabled — quarantine until resolved".into(),
        });
    } else if !report.antivirus_updated {
        actions.push(RemediationAction {
            action: RemediationType::ForceUpdate,
            priority: RemediationPriority::Medium,
            description: "Antivirus definitions are out of date".into(),
        });
    }

    // Firewall disabled.
    if !report.firewall_enabled {
        actions.push(RemediationAction {
            action: RemediationType::Notify,
            priority: RemediationPriority::Medium,
            description: "Host firewall is disabled".into(),
        });
    }

    // Screen lock disabled.
    if !report.screen_lock_enabled {
        actions.push(RemediationAction {
            action: RemediationType::Notify,
            priority: RemediationPriority::Low,
            description: "Screen lock is not enabled".into(),
        });
    }

    // Reboot overdue (> 30 days).
    if report.last_reboot_days > 30 {
        actions.push(RemediationAction {
            action: RemediationType::Notify,
            priority: RemediationPriority::Low,
            description: format!(
                "Device has not been rebooted in {} days",
                report.last_reboot_days
            ),
        });
    }

    // Overall score-based recommendations.
    let score = compute_health_score(report);
    if score < 0.3 {
        // Only add suspend if not already present.
        if !actions.iter().any(|a| a.action == RemediationType::Suspend) {
            actions.push(RemediationAction {
                action: RemediationType::Suspend,
                priority: RemediationPriority::Critical,
                description: format!(
                    "Compliance score {:.2} is below 0.3 — suspend recommended",
                    score
                ),
            });
        }
    } else if score < 0.5 {
        if !actions.iter().any(|a| a.action == RemediationType::Quarantine) {
            actions.push(RemediationAction {
                action: RemediationType::Quarantine,
                priority: RemediationPriority::High,
                description: format!(
                    "Compliance score {:.2} is below 0.5 — quarantine recommended",
                    score
                ),
            });
        }
    }

    // Sort by priority descending (Critical first).
    actions.sort_by(|a, b| b.priority.cmp(&a.priority));
    actions
}

// ── Error type ──────────────────────────────────────────────────────────────

/// Errors from device lifecycle operations.
#[derive(Debug, thiserror::Error)]
pub enum DeviceLifecycleError {
    /// Device was not found in the inventory.
    #[error("device not found: {0}")]
    DeviceNotFound(Uuid),

    /// The requested state transition is not allowed.
    #[error("invalid state transition from {from} to {to} for device {device_id}")]
    InvalidTransition {
        device_id: Uuid,
        from: DeviceStatus,
        to: DeviceStatus,
    },

    /// Device tier is out of the valid range (1-4).
    #[error("invalid device tier: {0} (must be 1-4)")]
    InvalidTier(u8),

    /// Compliance score is out of range.
    #[error("invalid compliance score: {0} (must be 0.0-1.0)")]
    InvalidComplianceScore(f64),

    /// Inventory capacity exceeded.
    #[error("device inventory capacity exceeded (max {0})")]
    CapacityExceeded(usize),
}

// ── Lifecycle Manager ───────────────────────────────────────────────────────

/// Maximum number of devices that can be tracked in the inventory.
const MAX_DEVICE_INVENTORY: usize = 100_000;

/// The main device lifecycle management engine.
///
/// Tracks device inventory, health status, and lifecycle state transitions.
/// All state changes emit SIEM security events for audit compliance.
pub struct DeviceLifecycleManager {
    devices: Mutex<HashMap<Uuid, DeviceInventory>>,
}

impl DeviceLifecycleManager {
    /// Create a new empty device lifecycle manager.
    pub fn new() -> Self {
        Self {
            devices: Mutex::new(HashMap::new()),
        }
    }

    /// Enroll a new device into the inventory.
    ///
    /// Validates the device tier and compliance score, then stores the device
    /// and emits a SIEM enrollment event. Returns the device ID on success.
    pub fn enroll(&self, inventory: DeviceInventory) -> Result<Uuid, DeviceLifecycleError> {
        // Validate tier.
        if inventory.tier == 0 || inventory.tier > 4 {
            return Err(DeviceLifecycleError::InvalidTier(inventory.tier));
        }

        // Validate compliance score.
        if !(0.0..=1.0).contains(&inventory.compliance_score) {
            return Err(DeviceLifecycleError::InvalidComplianceScore(
                inventory.compliance_score,
            ));
        }

        let device_id = inventory.device_id;
        let device_name = inventory.device_name.clone();

        let mut map = self.lock_devices();

        // Check capacity.
        if map.len() >= MAX_DEVICE_INVENTORY {
            return Err(DeviceLifecycleError::CapacityExceeded(MAX_DEVICE_INVENTORY));
        }

        map.insert(device_id, inventory);
        drop(map);

        // Emit SIEM event.
        crate::siem::SecurityEvent::device_lifecycle(
            "enroll",
            device_id,
            &format!("Device '{}' enrolled", device_name),
        );

        tracing::info!(
            device_id = %device_id,
            device_name = %device_name,
            "Device enrolled"
        );

        Ok(device_id)
    }

    /// Update a device's health status and return recommended remediation actions.
    ///
    /// Computes a new compliance score, updates the inventory record, and
    /// returns any remediation actions that should be taken.
    pub fn update_health(
        &self,
        device_id: Uuid,
        report: DeviceHealthReport,
    ) -> Result<Vec<RemediationAction>, DeviceLifecycleError> {
        let score = compute_health_score(&report);
        let actions = recommend_remediation(&report);
        let now = current_unix_timestamp();

        let mut map = self.lock_devices();
        let device = map
            .get_mut(&device_id)
            .ok_or(DeviceLifecycleError::DeviceNotFound(device_id))?;

        device.compliance_score = score;
        device.last_health_check = now;
        device.last_seen = now;

        let device_name = device.device_name.clone();
        drop(map);

        tracing::info!(
            device_id = %device_id,
            device_name = %device_name,
            compliance_score = score,
            remediation_count = actions.len(),
            "Device health updated"
        );

        if score < 0.5 {
            crate::siem::SecurityEvent::device_lifecycle(
                "health_warning",
                device_id,
                &format!(
                    "Device '{}' compliance score {:.2} below threshold",
                    device_name, score
                ),
            );
        }

        Ok(actions)
    }

    /// Suspend a device, preventing it from authenticating.
    ///
    /// Valid from: Active, Quarantined.
    pub fn suspend(&self, device_id: Uuid, reason: &str) -> Result<(), DeviceLifecycleError> {
        self.transition(device_id, DeviceStatus::Suspended, reason)
    }

    /// Quarantine a device due to compliance failure.
    ///
    /// Valid from: Active.
    pub fn quarantine(&self, device_id: Uuid, reason: &str) -> Result<(), DeviceLifecycleError> {
        self.transition(device_id, DeviceStatus::Quarantined, reason)
    }

    /// Permanently decommission a device.
    ///
    /// Valid from: Active, Suspended, Quarantined.
    pub fn decommission(&self, device_id: Uuid, reason: &str) -> Result<(), DeviceLifecycleError> {
        self.transition(device_id, DeviceStatus::Decommissioned, reason)
    }

    /// Report a device as lost or stolen.
    ///
    /// Valid from: Active, Suspended, Quarantined.
    /// Triggers a CRITICAL SIEM event.
    pub fn report_lost(&self, device_id: Uuid) -> Result<(), DeviceLifecycleError> {
        self.transition(device_id, DeviceStatus::Lost, "device reported lost or stolen")
    }

    /// Reactivate a suspended or quarantined device.
    ///
    /// Valid from: Suspended, Quarantined.
    pub fn reactivate(&self, device_id: Uuid, reason: &str) -> Result<(), DeviceLifecycleError> {
        self.transition(device_id, DeviceStatus::Active, reason)
    }

    /// Retrieve a clone of a device inventory record.
    pub fn get_device(&self, device_id: Uuid) -> Option<DeviceInventory> {
        let map = self.lock_devices();
        map.get(&device_id).cloned()
    }

    /// List all devices with a given status.
    pub fn list_devices_by_status(&self, status: DeviceStatus) -> Vec<DeviceInventory> {
        let map = self.lock_devices();
        map.values()
            .filter(|d| d.status == status)
            .cloned()
            .collect()
    }

    /// Perform a bulk health audit across all active devices.
    ///
    /// Returns a list of `(device_id, compliance_score, remediation_actions)`
    /// for every active device in the inventory.
    pub fn bulk_health_audit(&self) -> Vec<(Uuid, f64, Vec<RemediationAction>)> {
        let map = self.lock_devices();
        map.values()
            .filter(|d| d.status == DeviceStatus::Active)
            .map(|d| {
                // Build a synthetic health report from the stored compliance score.
                // In production, this would re-query each device.
                let actions = if d.compliance_score < 0.3 {
                    vec![RemediationAction {
                        action: RemediationType::Suspend,
                        priority: RemediationPriority::Critical,
                        description: format!(
                            "Compliance score {:.2} is critically low",
                            d.compliance_score
                        ),
                    }]
                } else if d.compliance_score < 0.5 {
                    vec![RemediationAction {
                        action: RemediationType::Quarantine,
                        priority: RemediationPriority::High,
                        description: format!(
                            "Compliance score {:.2} is below threshold",
                            d.compliance_score
                        ),
                    }]
                } else {
                    vec![]
                };
                (d.device_id, d.compliance_score, actions)
            })
            .collect()
    }

    /// Return the total number of devices in the inventory.
    pub fn device_count(&self) -> usize {
        self.lock_devices().len()
    }

    // ── Internal helpers ────────────────────────────────────────────────

    /// Validate and execute a lifecycle state transition.
    fn transition(
        &self,
        device_id: Uuid,
        to: DeviceStatus,
        reason: &str,
    ) -> Result<(), DeviceLifecycleError> {
        let mut map = self.lock_devices();
        let device = map
            .get_mut(&device_id)
            .ok_or(DeviceLifecycleError::DeviceNotFound(device_id))?;

        let from = device.status;

        // Validate transition.
        if !is_valid_transition(from, to) {
            return Err(DeviceLifecycleError::InvalidTransition {
                device_id,
                from,
                to,
            });
        }

        device.status = to;
        device.last_seen = current_unix_timestamp();
        let device_name = device.device_name.clone();
        drop(map);

        // Emit SIEM event.
        let action = match to {
            DeviceStatus::Active => "reactivate",
            DeviceStatus::Suspended => "suspend",
            DeviceStatus::Quarantined => "quarantine",
            DeviceStatus::Decommissioned => "decommission",
            DeviceStatus::Lost => "report_lost",
        };

        crate::siem::SecurityEvent::device_lifecycle(
            action,
            device_id,
            &format!(
                "Device '{}' transitioned from {} to {}: {}",
                device_name, from, to, reason
            ),
        );

        tracing::info!(
            device_id = %device_id,
            device_name = %device_name,
            from = %from,
            to = %to,
            reason = %reason,
            "Device lifecycle transition"
        );

        Ok(())
    }

    fn lock_devices(&self) -> std::sync::MutexGuard<'_, HashMap<Uuid, DeviceInventory>> {
        self.devices.lock().unwrap_or_else(|e| {
            tracing::error!("device_lifecycle: mutex poisoned — recovering");
            crate::siem::SecurityEvent::mutex_poisoning("device_lifecycle inventory mutex");
            e.into_inner()
        })
    }
}

impl Default for DeviceLifecycleManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── State machine ───────────────────────────────────────────────────────────

/// Determine whether a lifecycle state transition is valid.
///
/// Allowed transitions:
/// - Active → Suspended, Quarantined, Decommissioned, Lost
/// - Suspended → Active, Decommissioned, Lost
/// - Quarantined → Active, Suspended, Decommissioned, Lost
/// - Decommissioned → (terminal, no transitions)
/// - Lost → Decommissioned (only after recovery/wipe)
fn is_valid_transition(from: DeviceStatus, to: DeviceStatus) -> bool {
    if from == to {
        return false;
    }
    matches!(
        (from, to),
        (DeviceStatus::Active, DeviceStatus::Suspended)
            | (DeviceStatus::Active, DeviceStatus::Quarantined)
            | (DeviceStatus::Active, DeviceStatus::Decommissioned)
            | (DeviceStatus::Active, DeviceStatus::Lost)
            | (DeviceStatus::Suspended, DeviceStatus::Active)
            | (DeviceStatus::Suspended, DeviceStatus::Decommissioned)
            | (DeviceStatus::Suspended, DeviceStatus::Lost)
            | (DeviceStatus::Quarantined, DeviceStatus::Active)
            | (DeviceStatus::Quarantined, DeviceStatus::Suspended)
            | (DeviceStatus::Quarantined, DeviceStatus::Decommissioned)
            | (DeviceStatus::Quarantined, DeviceStatus::Lost)
            | (DeviceStatus::Lost, DeviceStatus::Decommissioned)
    )
}

// ── SIEM extension ──────────────────────────────────────────────────────────

/// Extend `SecurityEvent` with device lifecycle event emission.
impl crate::siem::SecurityEvent {
    /// Emit a device lifecycle event.
    pub fn device_lifecycle(action: &str, device_id: Uuid, detail: &str) {
        let severity = match action {
            "report_lost" => crate::siem::Severity::Critical,
            "quarantine" | "suspend" | "decommission" => crate::siem::Severity::High,
            "health_warning" => crate::siem::Severity::Warning,
            "enroll" | "reactivate" => crate::siem::Severity::Info,
            _ => crate::siem::Severity::Medium,
        };

        let event = crate::siem::SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "device_lifecycle",
            action: match action {
                "enroll" => "device_enroll",
                "suspend" => "device_suspend",
                "quarantine" => "device_quarantine",
                "decommission" => "device_decommission",
                "report_lost" => "device_lost",
                "reactivate" => "device_reactivate",
                "health_warning" => "device_health_warning",
                _ => "device_lifecycle_unknown",
            },
            severity,
            outcome: "success",
            user_id: None,
            source_ip: None,
            detail: Some(format!("device_id={} {}", device_id, detail)),
        };
        event.emit();
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Get the current Unix timestamp in seconds.
fn current_unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Create a default healthy device health report.
/// Useful for tests and initial enrollment.
pub fn healthy_report() -> DeviceHealthReport {
    DeviceHealthReport {
        os_patch_level: 0,
        antivirus_enabled: true,
        antivirus_updated: true,
        disk_encryption_enabled: true,
        firewall_enabled: true,
        screen_lock_enabled: true,
        jailbroken_or_rooted: false,
        last_reboot_days: 1,
        certificate_valid: true,
        attestation_fresh: true,
    }
}

/// Create a new `DeviceInventory` with sensible defaults.
pub fn new_device(
    device_name: &str,
    os_type: OsType,
    os_version: &str,
    model: &str,
    owner_id: Uuid,
    tier: u8,
) -> DeviceInventory {
    let now = current_unix_timestamp();
    DeviceInventory {
        device_id: Uuid::new_v4(),
        device_name: device_name.to_string(),
        os_type,
        os_version: os_version.to_string(),
        model: model.to_string(),
        owner_id,
        enrolled_at: now,
        last_seen: now,
        last_health_check: 0,
        status: DeviceStatus::Active,
        tier,
        tags: Vec::new(),
        location: None,
        compliance_score: 1.0,
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manager() -> DeviceLifecycleManager {
        DeviceLifecycleManager::new()
    }

    fn make_device(name: &str, tier: u8) -> DeviceInventory {
        new_device(
            name,
            OsType::Linux,
            "6.1.0",
            "Dell PowerEdge R750",
            Uuid::new_v4(),
            tier,
        )
    }

    // ── Enrollment tests ────────────────────────────────────────────────

    #[test]
    fn test_enroll_device() {
        let mgr = make_manager();
        let device = make_device("milnet-node-01", 1);
        let device_id = device.device_id;

        let result = mgr.enroll(device);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), device_id);
        assert_eq!(mgr.device_count(), 1);
    }

    #[test]
    fn test_enroll_invalid_tier_zero() {
        let mgr = make_manager();
        let mut device = make_device("bad-tier", 1);
        device.tier = 0;

        let result = mgr.enroll(device);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DeviceLifecycleError::InvalidTier(0)
        ));
    }

    #[test]
    fn test_enroll_invalid_tier_five() {
        let mgr = make_manager();
        let mut device = make_device("bad-tier", 1);
        device.tier = 5;

        let result = mgr.enroll(device);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DeviceLifecycleError::InvalidTier(5)
        ));
    }

    #[test]
    fn test_enroll_invalid_compliance_score() {
        let mgr = make_manager();
        let mut device = make_device("bad-score", 1);
        device.compliance_score = 1.5;

        let result = mgr.enroll(device);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DeviceLifecycleError::InvalidComplianceScore(_)
        ));
    }

    #[test]
    fn test_get_device() {
        let mgr = make_manager();
        let device = make_device("lookup-test", 2);
        let device_id = device.device_id;

        mgr.enroll(device).unwrap();

        let found = mgr.get_device(device_id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().device_name, "lookup-test");

        // Nonexistent device.
        assert!(mgr.get_device(Uuid::new_v4()).is_none());
    }

    // ── Health scoring tests ────────────────────────────────────────────

    #[test]
    fn test_healthy_device_score() {
        let report = healthy_report();
        let score = compute_health_score(&report);
        assert!((score - 1.0).abs() < 0.01, "Healthy device should score ~1.0, got {}", score);
    }

    #[test]
    fn test_unhealthy_device_score() {
        let report = DeviceHealthReport {
            os_patch_level: 100,
            antivirus_enabled: false,
            antivirus_updated: false,
            disk_encryption_enabled: false,
            firewall_enabled: false,
            screen_lock_enabled: false,
            jailbroken_or_rooted: true,
            last_reboot_days: 60,
            certificate_valid: false,
            attestation_fresh: false,
        };
        let score = compute_health_score(&report);
        assert!(score < 0.01, "Totally unhealthy device should score ~0.0, got {}", score);
    }

    #[test]
    fn test_partial_health_score() {
        let report = DeviceHealthReport {
            os_patch_level: 3,
            antivirus_enabled: true,
            antivirus_updated: true,
            disk_encryption_enabled: true,
            firewall_enabled: true,
            screen_lock_enabled: true,
            jailbroken_or_rooted: false,
            last_reboot_days: 2,
            certificate_valid: false, // One factor missing.
            attestation_fresh: true,
        };
        let score = compute_health_score(&report);
        // Missing certificate_valid (0.10 weight), so score should be ~0.90.
        assert!(
            (score - 0.90).abs() < 0.02,
            "Score should be ~0.90, got {}",
            score
        );
    }

    #[test]
    fn test_os_patch_degradation() {
        // Freshly patched.
        let report_fresh = DeviceHealthReport {
            os_patch_level: 0,
            ..healthy_report()
        };
        let score_fresh = compute_health_score(&report_fresh);

        // 45 days behind.
        let report_mid = DeviceHealthReport {
            os_patch_level: 45,
            ..healthy_report()
        };
        let score_mid = compute_health_score(&report_mid);

        assert!(score_fresh > score_mid, "Fresh patches should score higher");
    }

    // ── Remediation tests ───────────────────────────────────────────────

    #[test]
    fn test_no_remediation_for_healthy_device() {
        let report = healthy_report();
        let actions = recommend_remediation(&report);
        assert!(actions.is_empty(), "Healthy device should have no remediations");
    }

    #[test]
    fn test_jailbreak_remediation() {
        let mut report = healthy_report();
        report.jailbroken_or_rooted = true;

        let actions = recommend_remediation(&report);
        assert!(!actions.is_empty());
        assert!(actions.iter().any(|a| a.action == RemediationType::Quarantine));
        assert!(actions.iter().any(|a| a.action == RemediationType::ReEnroll));
        assert_eq!(actions[0].priority, RemediationPriority::Critical);
    }

    #[test]
    fn test_no_encryption_remediation() {
        let mut report = healthy_report();
        report.disk_encryption_enabled = false;

        let actions = recommend_remediation(&report);
        assert!(actions.iter().any(|a| a.action == RemediationType::Suspend));
    }

    // ── Lifecycle transition tests ──────────────────────────────────────

    #[test]
    fn test_suspend_device() {
        let mgr = make_manager();
        let device = make_device("suspend-me", 2);
        let device_id = device.device_id;
        mgr.enroll(device).unwrap();

        let result = mgr.suspend(device_id, "policy violation");
        assert!(result.is_ok());

        let d = mgr.get_device(device_id).unwrap();
        assert_eq!(d.status, DeviceStatus::Suspended);
    }

    #[test]
    fn test_quarantine_device() {
        let mgr = make_manager();
        let device = make_device("quarantine-me", 3);
        let device_id = device.device_id;
        mgr.enroll(device).unwrap();

        let result = mgr.quarantine(device_id, "failed health check");
        assert!(result.is_ok());

        let d = mgr.get_device(device_id).unwrap();
        assert_eq!(d.status, DeviceStatus::Quarantined);
    }

    #[test]
    fn test_decommission_device() {
        let mgr = make_manager();
        let device = make_device("retire-me", 4);
        let device_id = device.device_id;
        mgr.enroll(device).unwrap();

        let result = mgr.decommission(device_id, "end of life");
        assert!(result.is_ok());

        let d = mgr.get_device(device_id).unwrap();
        assert_eq!(d.status, DeviceStatus::Decommissioned);
    }

    #[test]
    fn test_report_lost() {
        let mgr = make_manager();
        let device = make_device("lost-device", 1);
        let device_id = device.device_id;
        mgr.enroll(device).unwrap();

        let result = mgr.report_lost(device_id);
        assert!(result.is_ok());

        let d = mgr.get_device(device_id).unwrap();
        assert_eq!(d.status, DeviceStatus::Lost);
    }

    #[test]
    fn test_reactivate_suspended_device() {
        let mgr = make_manager();
        let device = make_device("reactivate-me", 2);
        let device_id = device.device_id;
        mgr.enroll(device).unwrap();

        mgr.suspend(device_id, "temp hold").unwrap();
        mgr.reactivate(device_id, "issue resolved").unwrap();

        let d = mgr.get_device(device_id).unwrap();
        assert_eq!(d.status, DeviceStatus::Active);
    }

    #[test]
    fn test_invalid_transition_decommissioned() {
        let mgr = make_manager();
        let device = make_device("terminal-device", 3);
        let device_id = device.device_id;
        mgr.enroll(device).unwrap();

        mgr.decommission(device_id, "EOL").unwrap();

        // Cannot reactivate a decommissioned device.
        let result = mgr.reactivate(device_id, "oops");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DeviceLifecycleError::InvalidTransition { .. }
        ));
    }

    #[test]
    fn test_transition_nonexistent_device() {
        let mgr = make_manager();
        let result = mgr.suspend(Uuid::new_v4(), "ghost");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DeviceLifecycleError::DeviceNotFound(_)
        ));
    }

    // ── Health update integration ───────────────────────────────────────

    #[test]
    fn test_update_health() {
        let mgr = make_manager();
        let device = make_device("health-check", 2);
        let device_id = device.device_id;
        mgr.enroll(device).unwrap();

        let report = healthy_report();
        let result = mgr.update_health(device_id, report);
        assert!(result.is_ok());

        let actions = result.unwrap();
        assert!(actions.is_empty(), "Healthy device should have no remediations");

        let d = mgr.get_device(device_id).unwrap();
        assert!(d.compliance_score > 0.9);
        assert!(d.last_health_check > 0);
    }

    #[test]
    fn test_update_health_nonexistent() {
        let mgr = make_manager();
        let result = mgr.update_health(Uuid::new_v4(), healthy_report());
        assert!(result.is_err());
    }

    // ── List and audit tests ────────────────────────────────────────────

    #[test]
    fn test_list_devices_by_status() {
        let mgr = make_manager();

        let d1 = make_device("active-1", 1);
        let d2 = make_device("active-2", 2);
        let d3 = make_device("will-suspend", 3);
        let d3_id = d3.device_id;

        mgr.enroll(d1).unwrap();
        mgr.enroll(d2).unwrap();
        mgr.enroll(d3).unwrap();

        mgr.suspend(d3_id, "test").unwrap();

        let active = mgr.list_devices_by_status(DeviceStatus::Active);
        assert_eq!(active.len(), 2);

        let suspended = mgr.list_devices_by_status(DeviceStatus::Suspended);
        assert_eq!(suspended.len(), 1);
        assert_eq!(suspended[0].device_id, d3_id);
    }

    #[test]
    fn test_bulk_health_audit() {
        let mgr = make_manager();

        let d1 = make_device("healthy-box", 1);
        let mut d2 = make_device("sick-box", 2);
        d2.compliance_score = 0.2;

        mgr.enroll(d1).unwrap();
        mgr.enroll(d2).unwrap();

        let audit = mgr.bulk_health_audit();
        assert_eq!(audit.len(), 2);

        // The sick box should have remediation actions.
        let sick = audit.iter().find(|(_, score, _)| *score < 0.3);
        assert!(sick.is_some());
        let (_, _, actions) = sick.unwrap();
        assert!(!actions.is_empty());
    }

    // ── State machine validation ────────────────────────────────────────

    #[test]
    fn test_valid_transitions() {
        // Active → everything except Active.
        assert!(is_valid_transition(DeviceStatus::Active, DeviceStatus::Suspended));
        assert!(is_valid_transition(DeviceStatus::Active, DeviceStatus::Quarantined));
        assert!(is_valid_transition(DeviceStatus::Active, DeviceStatus::Decommissioned));
        assert!(is_valid_transition(DeviceStatus::Active, DeviceStatus::Lost));

        // Suspended → Active, Decommissioned, Lost.
        assert!(is_valid_transition(DeviceStatus::Suspended, DeviceStatus::Active));
        assert!(is_valid_transition(DeviceStatus::Suspended, DeviceStatus::Decommissioned));

        // Quarantined → Active, Suspended, Decommissioned, Lost.
        assert!(is_valid_transition(DeviceStatus::Quarantined, DeviceStatus::Active));
        assert!(is_valid_transition(DeviceStatus::Quarantined, DeviceStatus::Suspended));

        // Lost → Decommissioned only.
        assert!(is_valid_transition(DeviceStatus::Lost, DeviceStatus::Decommissioned));

        // Invalid transitions.
        assert!(!is_valid_transition(DeviceStatus::Decommissioned, DeviceStatus::Active));
        assert!(!is_valid_transition(DeviceStatus::Lost, DeviceStatus::Active));
        assert!(!is_valid_transition(DeviceStatus::Active, DeviceStatus::Active));
    }

    // ── Display and serialization ───────────────────────────────────────

    #[test]
    fn test_device_status_display() {
        assert_eq!(DeviceStatus::Active.to_string(), "Active");
        assert_eq!(DeviceStatus::Suspended.to_string(), "Suspended");
        assert_eq!(DeviceStatus::Quarantined.to_string(), "Quarantined");
        assert_eq!(DeviceStatus::Decommissioned.to_string(), "Decommissioned");
        assert_eq!(DeviceStatus::Lost.to_string(), "Lost");
    }

    #[test]
    fn test_os_type_display() {
        assert_eq!(OsType::Windows.to_string(), "Windows");
        assert_eq!(OsType::Linux.to_string(), "Linux");
        assert_eq!(OsType::Other("FreeBSD".into()).to_string(), "Other(FreeBSD)");
    }

    #[test]
    fn test_device_serialization() {
        let device = make_device("serialize-test", 1);
        let json = serde_json::to_string(&device);
        assert!(json.is_ok());

        let json_str = json.unwrap();
        assert!(json_str.contains("serialize-test"));
        assert!(json_str.contains("Linux"));
    }

    #[test]
    fn test_health_report_serialization() {
        let report = healthy_report();
        let json = serde_json::to_string(&report);
        assert!(json.is_ok());

        let deserialized: DeviceHealthReport = serde_json::from_str(&json.unwrap()).unwrap();
        assert!(deserialized.antivirus_enabled);
        assert!(deserialized.disk_encryption_enabled);
    }

    #[test]
    fn test_remediation_action_serialization() {
        let action = RemediationAction {
            action: RemediationType::Quarantine,
            priority: RemediationPriority::Critical,
            description: "test quarantine".into(),
        };
        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains("Quarantine"));
        assert!(json.contains("Critical"));
    }
}
