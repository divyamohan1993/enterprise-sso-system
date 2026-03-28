use common::error::MilnetError;
use common::types::DeviceTier;

/// Check if a device tier can access a resource requiring a minimum tier.
/// Lower tier number = higher privilege: Sovereign(1) > Operational(2) > Sensor(3)
pub fn check_tier_access(
    device_tier: DeviceTier,
    required_tier: DeviceTier,
) -> Result<(), MilnetError> {
    if (device_tier as u8) <= (required_tier as u8) {
        Ok(())
    } else {
        Err(MilnetError::InsufficientTier {
            required: required_tier as u8,
            actual: device_tier as u8,
        })
    }
}

/// Device enrollment record
#[derive(Debug, Clone)]
pub struct DeviceEnrollment {
    pub device_id: uuid::Uuid,
    pub tier: DeviceTier,
    pub attestation_hash: [u8; 32],
    pub enrolled_by: uuid::Uuid,
    pub is_active: bool,
}

/// Device registry (in-memory for now)
pub struct DeviceRegistry {
    devices: std::collections::HashMap<uuid::Uuid, DeviceEnrollment>,
}

impl DeviceRegistry {
    pub fn new() -> Self {
        Self {
            devices: std::collections::HashMap::new(),
        }
    }

    pub fn enroll(&mut self, enrollment: DeviceEnrollment) {
        self.devices.insert(enrollment.device_id, enrollment);
    }

    pub fn lookup(&self, device_id: &uuid::Uuid) -> Option<&DeviceEnrollment> {
        self.devices.get(device_id)
    }

    /// Return the number of enrolled devices.
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Return references to all enrolled devices.
    pub fn all_devices(&self) -> Vec<&DeviceEnrollment> {
        self.devices.values().collect()
    }

    pub fn revoke(&mut self, device_id: &uuid::Uuid) -> bool {
        if let Some(device) = self.devices.get_mut(device_id) {
            device.is_active = false;
            true
        } else {
            false
        }
    }
}

impl Default for DeviceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate that a claimed tier matches the tier registered for a device.
///
/// Looks up `device_id` in the registry and checks:
/// 1. The device exists and is enrolled.
/// 2. The device is active (not revoked).
/// 3. The claimed tier matches the registered tier exactly.
/// 4. The attestation hash is non-zero (device has been properly attested).
///
/// SECURITY: This should be called by the orchestrator during authentication AND
/// by the CAE engine on every heartbeat re-evaluation. Tier claims must be
/// continuously validated — not just at login time — to prevent privilege
/// persistence after device compromise or tier downgrade.
pub fn validate_tier_claim(
    claimed_tier: u8,
    device_id: &uuid::Uuid,
    registry: &DeviceRegistry,
) -> bool {
    match registry.lookup(device_id) {
        Some(enrollment) => {
            // Device must be active
            if !enrollment.is_active {
                return false;
            }
            // Attestation hash must be non-zero (device properly attested)
            if enrollment.attestation_hash == [0u8; 32] {
                tracing::warn!(
                    "tier validation rejected: device {} has zero attestation hash",
                    device_id
                );
                return false;
            }
            // Claimed tier must match the registered tier exactly
            (enrollment.tier as u8) == claimed_tier
        }
        // Device not found in registry — claim is invalid
        None => false,
    }
}
