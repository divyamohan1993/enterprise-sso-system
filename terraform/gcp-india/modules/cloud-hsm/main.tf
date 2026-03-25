# ──────────────────────────────────────────────────────────────────────────────
# MILNET SSO — GCP India Cloud HSM Module
# ──────────────────────────────────────────────────────────────────────────────
# Cloud HSM keys are managed via Cloud KMS with protection_level = HSM.
# GCP Cloud HSM is FIPS 140-2 Level 3 certified.
# Keys are bound to the asia-south1 region keyring — never exported.
#
# This module creates HSM-protected keys in an existing keyring (from kms module).
# These are the operational keys loaded into HSM slots at runtime.
# ──────────────────────────────────────────────────────────────────────────────

variable "project_id" { type = string }
variable "region" { type = string }
variable "environment" { type = string }
variable "kms_keyring" {
  description = "Name of the Cloud KMS keyring to add HSM keys to"
  type        = string
}

locals {
  name_prefix  = "milnet-india-${var.environment}"
  keyring_path = "projects/${var.project_id}/locations/${var.region}/keyRings/${var.kms_keyring}"
}

# ── HSM Master Key ──
# Root-of-trust key stored in hardware security module.
# Used to protect key derivation material and bootstrap the key hierarchy.

resource "google_kms_crypto_key" "hsm_master" {
  name     = "${local.name_prefix}-hsm-master"
  key_ring = local.keyring_path
  purpose  = "ENCRYPT_DECRYPT"

  # No automatic rotation — HSM master key rotation is a controlled operation
  # requiring dual-control ceremony and audit trail.

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "HSM"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# ── HSM Token Signing Key ──
# Used to sign MILNET SSO tokens. EC P-384, HSM-backed.

resource "google_kms_crypto_key" "hsm_token_signing" {
  name     = "${local.name_prefix}-hsm-token-sign"
  key_ring = local.keyring_path
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm        = "EC_SIGN_P384_SHA384"
    protection_level = "HSM"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# ── HSM Key Agreement Key ──
# Used for ECDH key agreement in OPAQUE protocol handshakes.

resource "google_kms_crypto_key" "hsm_key_agreement" {
  name     = "${local.name_prefix}-hsm-key-agreement"
  key_ring = local.keyring_path
  purpose  = "ASYMMETRIC_DECRYPT"

  version_template {
    algorithm        = "RSA_DECRYPT_OAEP_4096_SHA256"
    protection_level = "HSM"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# ── HSM Attestation ──
# Cloud HSM provides attestation statements proving keys live in hardware.
# Attestation is checked at deployment time by deploy/bare-metal/security/vtpm-attest.sh.

# ── Outputs ──

output "hsm_master_key_id" {
  value = google_kms_crypto_key.hsm_master.id
}

output "hsm_token_signing_key_id" {
  value = google_kms_crypto_key.hsm_token_signing.id
}

output "hsm_key_agreement_key_id" {
  value = google_kms_crypto_key.hsm_key_agreement.id
}
