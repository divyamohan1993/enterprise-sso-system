//! Measured boot attestation via vTPM PCR-sealed keys.
//!
//! The deployment VMs have hardware/hypervisor-managed Secure Boot and vTPM.
//! The OS already enforces measured boot. This module provides the
//! **application-level** attestation pattern:
//!
//! - PCR-sealed key management: seal FROST shares and master KEK to vTPM
//!   so they can only be unsealed on a VM whose boot chain matches.
//! - Boot attestation reports (HMAC-SHA512 signed) for SHARD registration.
//! - Sealed key lifecycle: first-deploy seal, subsequent-boot unseal,
//!   PCR-change re-seal.
//!
//! Sealed blobs are stored at a configurable path
//! (default: `/var/lib/milnet/sealed/`).

use hmac::{Hmac, Mac};
use sha2::Sha512;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::platform_integrity::{self, PlatformError, SelfAttestation, TpmInfo};

type HmacSha512 = Hmac<Sha512>;

/// HMAC domain separation for boot attestation reports.
const ATTEST_HMAC_DOMAIN: &[u8] = b"MILNET-BOOT-ATTEST-v1";

// ---------------------------------------------------------------------------
// Boot attestation report
// ---------------------------------------------------------------------------

/// A boot attestation report that services include in SHARD registration.
#[derive(Debug, Clone)]
pub struct BootAttestation {
    /// Whether the vTPM is present.
    pub tpm_available: bool,
    /// vTPM version string.
    pub tpm_version: String,
    /// SHA-512 hash of the service binary at startup.
    pub binary_hash: [u8; 64],
    /// Kernel boot_id for audit correlation.
    pub boot_id: String,
    /// Unix timestamp when attestation was performed.
    pub attestation_time: i64,
}

impl BootAttestation {
    /// Create a boot attestation from the platform checks already performed.
    pub fn from_checks(tpm_info: &TpmInfo, self_att: &SelfAttestation) -> Self {
        Self {
            tpm_available: tpm_info.available,
            tpm_version: tpm_info.version.clone(),
            binary_hash: self_att.binary_hash,
            boot_id: self_att.boot_id.clone(),
            attestation_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
        }
    }

    /// Generate an HMAC-SHA512 signed attestation report.
    ///
    /// The report covers the binary hash, boot_id, TPM status, and
    /// timestamp, keyed with `signing_key`.
    pub fn to_signed_report(&self, signing_key: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha512::new_from_slice(signing_key)
            .expect("HMAC-SHA512 accepts any key length");

        mac.update(ATTEST_HMAC_DOMAIN);
        mac.update(&self.attestation_time.to_be_bytes());
        mac.update(&[self.tpm_available as u8]);
        mac.update(self.tpm_version.as_bytes());
        mac.update(&self.binary_hash);
        mac.update(self.boot_id.as_bytes());

        let tag = mac.finalize().into_bytes();

        // Report wire format:
        //   timestamp(8) + tpm_available(1) + tpm_version_len(4) + tpm_version +
        //   binary_hash(64) + boot_id_len(4) + boot_id + hmac_tag(64)
        let mut report = Vec::new();
        report.extend_from_slice(&self.attestation_time.to_be_bytes());
        report.push(self.tpm_available as u8);

        let ver_bytes = self.tpm_version.as_bytes();
        report.extend_from_slice(&(ver_bytes.len() as u32).to_be_bytes());
        report.extend_from_slice(ver_bytes);

        report.extend_from_slice(&self.binary_hash);

        let bid_bytes = self.boot_id.as_bytes();
        report.extend_from_slice(&(bid_bytes.len() as u32).to_be_bytes());
        report.extend_from_slice(bid_bytes);

        report.extend_from_slice(&tag);
        report
    }
}

// ---------------------------------------------------------------------------
// PCR-sealed key lifecycle
// ---------------------------------------------------------------------------

/// Well-known names for sealed key blobs.
pub const SEALED_MASTER_KEK: &str = "master-kek";
pub const SEALED_FROST_SHARES: &str = "frost-shares";

/// Seal a key to the vTPM. On first deploy, call this to protect
/// the master KEK and FROST shares.
///
/// The sealed blob can only be recovered on a VM whose PCR 0 (UEFI
/// firmware) and PCR 7 (Secure Boot policy) match the values at seal time.
pub fn seal_key(
    name: &str,
    secret: &[u8],
    sealed_dir: Option<&str>,
) -> Result<(), PlatformError> {
    platform_integrity::tpm_seal(name, secret, sealed_dir)
}

/// Unseal a key from the vTPM. Called on subsequent boots.
///
/// Fails if PCR values have changed since sealing (fail-closed).
/// On failure, manual re-seal is required after verifying the new
/// boot chain is authorized.
pub fn unseal_key(
    name: &str,
    sealed_dir: Option<&str>,
) -> Result<Vec<u8>, PlatformError> {
    platform_integrity::tpm_unseal(name, sealed_dir)
}

/// Check whether a sealed blob exists for the given key name.
pub fn sealed_blob_exists(name: &str, sealed_dir: Option<&str>) -> bool {
    let dir = sealed_dir.unwrap_or("/var/lib/milnet/sealed");
    let pub_path = format!("{}/{}.pub", dir, name);
    let priv_path = format!("{}/{}.priv", dir, name);
    Path::new(&pub_path).exists() && Path::new(&priv_path).exists()
}

/// Attempt to load a key: unseal from vTPM if sealed blob exists,
/// otherwise return None (caller should generate + seal on first deploy).
pub fn try_unseal_or_none(
    name: &str,
    sealed_dir: Option<&str>,
) -> Option<Vec<u8>> {
    if !sealed_blob_exists(name, sealed_dir) {
        tracing::info!(
            "platform: no sealed blob for '{}' — first deploy or re-seal needed",
            name,
        );
        return None;
    }

    match unseal_key(name, sealed_dir) {
        Ok(secret) => {
            tracing::info!(
                "platform: unsealed '{}' from vTPM ({} bytes)",
                name,
                secret.len(),
            );
            Some(secret)
        }
        Err(e) => {
            tracing::error!(
                "platform: failed to unseal '{}' — PCR values may have changed: {}",
                name,
                e,
            );
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boot_attestation_signed_report() {
        let att = BootAttestation {
            tpm_available: false,
            tpm_version: "2".to_string(),
            binary_hash: [0xAA; 64],
            boot_id: "test-boot-id".to_string(),
            attestation_time: 1000000,
        };

        let key = b"test-signing-key";
        let report1 = att.to_signed_report(key);
        let report2 = att.to_signed_report(key);
        assert_eq!(report1, report2);
        assert!(!report1.is_empty());
    }

    #[test]
    fn test_different_keys_produce_different_reports() {
        let att = BootAttestation {
            tpm_available: true,
            tpm_version: "2".to_string(),
            binary_hash: [0xBB; 64],
            boot_id: "abc".to_string(),
            attestation_time: 42,
        };

        let r1 = att.to_signed_report(b"key-a");
        let r2 = att.to_signed_report(b"key-b");
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_sealed_blob_exists_nonexistent() {
        assert!(!sealed_blob_exists(
            "nonexistent",
            Some("/tmp/milnet-test-nodir")
        ));
    }

    #[test]
    fn test_try_unseal_or_none_missing() {
        let result = try_unseal_or_none("missing-key", Some("/tmp/milnet-test-nodir"));
        assert!(result.is_none());
    }
}
