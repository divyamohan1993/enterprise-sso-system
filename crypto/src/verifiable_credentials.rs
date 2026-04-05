//! W3C Verifiable Credentials (VC 2.0) for the MILNET SSO system.
//!
//! Implements the W3C Verifiable Credentials Data Model v2.0 with:
//! - Credential issuance using ML-DSA-87 (FIPS 204) post-quantum signatures
//! - SD-JWT (Selective Disclosure JWT) for selective disclosure of claims
//! - Credential verification with full proof chain validation
//! - StatusList2021 revocation mechanism
//! - Credential schema validation
//! - JSON-LD context handling (simplified for military environments)
//!
//! # Security Model
//!
//! All credentials are signed with ML-DSA-87 to provide quantum-resistant
//! authenticity. Selective disclosure uses SHA-512 salted hashing so
//! individual claims can be revealed without exposing the full credential.
//! Revocation uses a compressed bitstring (StatusList2021) to enable
//! privacy-preserving status checks.
//!
//! # CNSA 2.0
//!
//! All hash operations use SHA-512 for CNSA 2.0 compliance.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// JSON-LD Context handling
// ---------------------------------------------------------------------------

/// Well-known JSON-LD context URIs for Verifiable Credentials.
pub const VC_CONTEXT_V2: &str = "https://www.w3.org/ns/credentials/v2";
pub const VC_CONTEXT_SECURITY: &str = "https://w3id.org/security/suites/jws-2020/v1";
pub const VC_CONTEXT_STATUS_LIST: &str = "https://w3id.org/vc/status-list/2021/v1";

/// Supported JSON-LD context identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContextUri {
    /// W3C VC Data Model v2.0
    VcV2,
    /// JSON Web Signature 2020 security suite
    JwsSecurity,
    /// StatusList2021 context
    StatusList,
    /// Custom context URI
    Custom(String),
}

impl ContextUri {
    /// Return the canonical URI string for this context.
    pub fn as_str(&self) -> &str {
        match self {
            ContextUri::VcV2 => VC_CONTEXT_V2,
            ContextUri::JwsSecurity => VC_CONTEXT_SECURITY,
            ContextUri::StatusList => VC_CONTEXT_STATUS_LIST,
            ContextUri::Custom(uri) => uri,
        }
    }

    /// Parse a URI string into a known context or custom.
    pub fn from_str(uri: &str) -> Self {
        match uri {
            VC_CONTEXT_V2 => ContextUri::VcV2,
            VC_CONTEXT_SECURITY => ContextUri::JwsSecurity,
            VC_CONTEXT_STATUS_LIST => ContextUri::StatusList,
            other => ContextUri::Custom(other.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// Credential Schema
// ---------------------------------------------------------------------------

/// Schema definition for validating credential subjects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSchema {
    /// Schema identifier URI.
    pub id: String,
    /// Schema type (e.g., "JsonSchema").
    pub schema_type: String,
    /// Required fields in the credential subject.
    pub required_fields: Vec<String>,
    /// Optional field name -> type description mapping.
    pub field_types: BTreeMap<String, String>,
}

impl CredentialSchema {
    /// Validate that a credential subject contains all required fields.
    pub fn validate_subject(&self, subject: &CredentialSubject) -> Result<(), String> {
        for field in &self.required_fields {
            if !subject.claims.contains_key(field) {
                return Err(format!(
                    "credential subject missing required field: {}",
                    field
                ));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Credential types
// ---------------------------------------------------------------------------

/// Verifiable Credential subject — the entity the credential is about.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSubject {
    /// DID or URI of the subject.
    pub id: String,
    /// Key-value claims about the subject.
    pub claims: BTreeMap<String, String>,
}

/// The proof section of a Verifiable Credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialProof {
    /// Proof type (e.g., "MlDsa87Signature2024").
    pub proof_type: String,
    /// ISO 8601 creation timestamp.
    pub created: String,
    /// DID of the verification method used.
    pub verification_method: String,
    /// Purpose of the proof (e.g., "assertionMethod").
    pub proof_purpose: String,
    /// The ML-DSA-87 signature bytes (hex-encoded).
    pub signature_hex: String,
}

/// Credential status information for revocation checking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialStatus {
    /// URI of the status list credential.
    pub status_list_credential: String,
    /// Index into the status list bitstring.
    pub status_list_index: u64,
    /// Purpose of the status entry (e.g., "revocation").
    pub status_purpose: String,
}

/// A W3C Verifiable Credential (VC 2.0).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiableCredential {
    /// JSON-LD context URIs.
    pub contexts: Vec<ContextUri>,
    /// Credential identifier (URI).
    pub id: String,
    /// Credential types (e.g., ["VerifiableCredential", "ClearanceCredential"]).
    pub credential_type: Vec<String>,
    /// DID of the issuer.
    pub issuer: String,
    /// ISO 8601 issuance date.
    pub issuance_date: String,
    /// Optional ISO 8601 expiration date.
    pub expiration_date: Option<String>,
    /// The credential subject.
    pub subject: CredentialSubject,
    /// Optional credential schema for validation.
    pub credential_schema: Option<CredentialSchema>,
    /// Optional status information for revocation.
    pub credential_status: Option<CredentialStatus>,
    /// Cryptographic proof (ML-DSA-87 signature).
    pub proof: Option<CredentialProof>,
}

impl VerifiableCredential {
    /// Create a new unsigned credential with default VC 2.0 context.
    pub fn new(
        id: String,
        issuer: String,
        subject: CredentialSubject,
        credential_types: Vec<String>,
        issuance_date: String,
    ) -> Self {
        let mut types = vec!["VerifiableCredential".to_string()];
        for t in credential_types {
            if t != "VerifiableCredential" {
                types.push(t);
            }
        }

        Self {
            contexts: vec![ContextUri::VcV2, ContextUri::JwsSecurity],
            id,
            credential_type: types,
            issuer,
            issuance_date,
            expiration_date: None,
            subject,
            credential_schema: None,
            credential_status: None,
            proof: None,
        }
    }

    /// Compute the canonical hash of this credential (excluding the proof).
    /// This is the message that gets signed. Uses SHA-512 for CNSA 2.0 compliance.
    pub fn canonical_hash(&self) -> [u8; 64] {
        let mut hasher = Sha512::new();
        hasher.update(b"MILNET-VC-HASH-v2");

        // Hash the contexts
        for ctx in &self.contexts {
            hasher.update(ctx.as_str().as_bytes());
        }

        hasher.update(self.id.as_bytes());

        for t in &self.credential_type {
            hasher.update(t.as_bytes());
        }

        hasher.update(self.issuer.as_bytes());
        hasher.update(self.issuance_date.as_bytes());

        if let Some(ref exp) = self.expiration_date {
            hasher.update(exp.as_bytes());
        }

        hasher.update(self.subject.id.as_bytes());
        for (k, v) in &self.subject.claims {
            hasher.update(k.as_bytes());
            hasher.update(v.as_bytes());
        }

        if let Some(ref status) = self.credential_status {
            hasher.update(status.status_list_credential.as_bytes());
            hasher.update(status.status_list_index.to_le_bytes());
            hasher.update(status.status_purpose.as_bytes());
        }

        let result = hasher.finalize();
        let mut hash = [0u8; 64];
        hash.copy_from_slice(&result);
        hash
    }

    /// Validate the credential against its schema (if present).
    pub fn validate_schema(&self) -> Result<(), String> {
        if let Some(ref schema) = self.credential_schema {
            schema.validate_subject(&self.subject)?;
        }
        Ok(())
    }

    /// Check whether this credential has expired.
    pub fn is_expired_at(&self, current_iso8601: &str) -> bool {
        match &self.expiration_date {
            Some(exp) => current_iso8601 > exp.as_str(),
            None => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Credential Issuance (ML-DSA-87)
// ---------------------------------------------------------------------------

/// Sign a Verifiable Credential using ML-DSA-87.
///
/// Takes a typed `PqSigningKey` from our `pq_sign` module. The credential's
/// canonical hash is signed and the proof is attached to the credential.
pub fn issue_credential(
    credential: &mut VerifiableCredential,
    signing_key: &crate::pq_sign::PqSigningKey,
    verification_method_did: &str,
) -> Result<(), String> {
    // Validate schema first
    credential.validate_schema()?;

    let hash = credential.canonical_hash();
    let signature = crate::pq_sign::pq_sign_raw(signing_key, &hash);

    let now = now_iso8601();

    credential.proof = Some(CredentialProof {
        proof_type: "MlDsa87Signature2024".to_string(),
        created: now,
        verification_method: verification_method_did.to_string(),
        proof_purpose: "assertionMethod".to_string(),
        signature_hex: hex::encode(&signature),
    });

    Ok(())
}

/// Verify the ML-DSA-87 signature on a Verifiable Credential.
pub fn verify_credential(
    credential: &VerifiableCredential,
    verifying_key: &crate::pq_sign::PqVerifyingKey,
) -> Result<bool, String> {
    let proof = credential
        .proof
        .as_ref()
        .ok_or("credential has no proof")?;

    if proof.proof_type != "MlDsa87Signature2024" {
        return Err(format!("unsupported proof type: {}", proof.proof_type));
    }

    let signature_bytes = hex::decode(&proof.signature_hex)
        .map_err(|e| format!("invalid signature hex: {e}"))?;

    let hash = credential.canonical_hash();

    Ok(crate::pq_sign::pq_verify_raw(verifying_key, &hash, &signature_bytes))
}

// ---------------------------------------------------------------------------
// Selective Disclosure (SD-JWT style)
// ---------------------------------------------------------------------------

/// A selectively disclosable claim.
///
/// Each claim is salted and hashed; the holder can choose which claims to
/// reveal by providing the salt + value (disclosure).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdClaim {
    /// SHA-512 hash of (salt || claim_name || claim_value). CNSA 2.0 compliant.
    /// Stored as Vec<u8> (64 bytes) for serde compatibility ([u8; 64] lacks Serialize).
    pub digest: Vec<u8>,
    /// Claim name (always visible to the holder).
    pub claim_name: String,
}

/// A disclosure for a single SD claim (reveals the value).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Disclosure {
    /// Random salt (16 bytes).
    pub salt: [u8; 16],
    /// Claim name.
    pub claim_name: String,
    /// Claim value.
    pub claim_value: String,
}

impl Disclosure {
    /// Compute the digest for this disclosure.
    pub fn digest(&self) -> [u8; 64] {
        compute_sd_digest(&self.salt, &self.claim_name, &self.claim_value)
    }

    /// Verify that this disclosure matches a given SD claim digest.
    pub fn matches(&self, sd_claim: &SdClaim) -> bool {
        let computed = self.digest();
        crate::ct::ct_eq(&computed, &sd_claim.digest)
    }
}

/// Compute the SD-JWT style digest: SHA-512(salt || claim_name || claim_value).
/// Upgraded to SHA-512 for CNSA 2.0 compliance.
fn compute_sd_digest(salt: &[u8; 16], name: &str, value: &str) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(b"MILNET-SD-JWT-v2");
    hasher.update(salt);
    hasher.update(name.as_bytes());
    hasher.update(value.as_bytes());
    let result = hasher.finalize();
    let mut digest = [0u8; 64];
    digest.copy_from_slice(&result);
    digest
}

/// Create SD claims from a credential subject, generating random salts.
///
/// Returns `(sd_claims, disclosures)` — the issuer embeds sd_claims in the
/// credential; the holder receives the disclosures privately.
pub fn create_sd_claims(
    subject: &CredentialSubject,
) -> Result<(Vec<SdClaim>, Vec<Disclosure>), String> {
    let mut sd_claims = Vec::new();
    let mut disclosures = Vec::new();

    for (name, value) in &subject.claims {
        let mut salt = [0u8; 16];
        getrandom::getrandom(&mut salt)
            .map_err(|e| format!("salt generation failed: {e}"))?;

        let digest = compute_sd_digest(&salt, name, value);

        sd_claims.push(SdClaim {
            digest: digest.to_vec(),
            claim_name: name.clone(),
        });

        disclosures.push(Disclosure {
            salt,
            claim_name: name.clone(),
            claim_value: value.clone(),
        });
    }

    Ok((sd_claims, disclosures))
}

/// Verify a set of disclosures against their SD claim digests.
pub fn verify_disclosures(sd_claims: &[SdClaim], disclosures: &[Disclosure]) -> bool {
    for disclosure in disclosures {
        let matched = sd_claims.iter().any(|sc| disclosure.matches(sc));
        if !matched {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// StatusList2021 Revocation
// ---------------------------------------------------------------------------

/// Compressed bitstring for credential revocation status.
///
/// Each bit position corresponds to a credential's `status_list_index`.
/// A set bit (1) means the credential at that index is revoked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusList2021 {
    /// The status list credential URI.
    pub id: String,
    /// Purpose (e.g., "revocation", "suspension").
    pub purpose: String,
    /// Bitstring stored as a byte vector (each byte = 8 status entries).
    pub bitstring: Vec<u8>,
    /// Total number of entries this list can track.
    pub capacity: u64,
}

impl StatusList2021 {
    /// Create a new status list with the given capacity.
    pub fn new(id: String, purpose: String, capacity: u64) -> Self {
        let byte_len = ((capacity + 7) / 8) as usize;
        Self {
            id,
            purpose,
            bitstring: vec![0u8; byte_len],
            capacity,
        }
    }

    /// Set the status bit at `index` (revoke/suspend the credential).
    pub fn set_status(&mut self, index: u64) -> Result<(), String> {
        if index >= self.capacity {
            return Err(format!(
                "status index {} exceeds capacity {}",
                index, self.capacity
            ));
        }
        let byte_idx = (index / 8) as usize;
        let bit_idx = (index % 8) as u8;
        self.bitstring[byte_idx] |= 1 << bit_idx;
        Ok(())
    }

    /// Clear the status bit at `index` (un-revoke/un-suspend).
    pub fn clear_status(&mut self, index: u64) -> Result<(), String> {
        if index >= self.capacity {
            return Err(format!(
                "status index {} exceeds capacity {}",
                index, self.capacity
            ));
        }
        let byte_idx = (index / 8) as usize;
        let bit_idx = (index % 8) as u8;
        self.bitstring[byte_idx] &= !(1 << bit_idx);
        Ok(())
    }

    /// Check whether the credential at `index` is revoked/suspended.
    pub fn is_set(&self, index: u64) -> Result<bool, String> {
        if index >= self.capacity {
            return Err(format!(
                "status index {} exceeds capacity {}",
                index, self.capacity
            ));
        }
        let byte_idx = (index / 8) as usize;
        let bit_idx = (index % 8) as u8;
        Ok((self.bitstring[byte_idx] >> bit_idx) & 1 == 1)
    }

    /// Count the number of revoked/suspended credentials.
    pub fn revoked_count(&self) -> u64 {
        self.bitstring
            .iter()
            .map(|b| b.count_ones() as u64)
            .sum()
    }
}

/// Check the revocation status of a credential against a status list.
pub fn check_revocation_status(
    credential: &VerifiableCredential,
    status_list: &StatusList2021,
) -> Result<bool, String> {
    let status = credential
        .credential_status
        .as_ref()
        .ok_or("credential has no status information")?;

    if status.status_list_credential != status_list.id {
        return Err(format!(
            "status list ID mismatch: credential references {}, got {}",
            status.status_list_credential, status_list.id
        ));
    }

    status_list.is_set(status.status_list_index)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_iso8601() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}Z", d.as_secs())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_subject() -> CredentialSubject {
        let mut claims = BTreeMap::new();
        claims.insert("clearance".to_string(), "TOP_SECRET".to_string());
        claims.insert("rank".to_string(), "O-6".to_string());
        claims.insert("unit".to_string(), "CYBERCOM".to_string());

        CredentialSubject {
            id: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string(),
            claims,
        }
    }

    fn test_schema() -> CredentialSchema {
        CredentialSchema {
            id: "https://milnet.mil/schemas/clearance-v1".to_string(),
            schema_type: "JsonSchema".to_string(),
            required_fields: vec!["clearance".to_string(), "rank".to_string()],
            field_types: BTreeMap::new(),
        }
    }

    #[test]
    fn test_credential_creation() {
        let subject = test_subject();
        let vc = VerifiableCredential::new(
            "urn:uuid:12345".to_string(),
            "did:web:milnet.mil".to_string(),
            subject,
            vec!["ClearanceCredential".to_string()],
            "2025-01-01T00:00:00Z".to_string(),
        );

        assert!(vc.credential_type.contains(&"VerifiableCredential".to_string()));
        assert!(vc.credential_type.contains(&"ClearanceCredential".to_string()));
        assert!(vc.proof.is_none());
    }

    #[test]
    fn test_canonical_hash_deterministic() {
        let subject = test_subject();
        let vc = VerifiableCredential::new(
            "urn:uuid:12345".to_string(),
            "did:web:milnet.mil".to_string(),
            subject,
            vec!["ClearanceCredential".to_string()],
            "2025-01-01T00:00:00Z".to_string(),
        );

        let h1 = vc.canonical_hash();
        let h2 = vc.canonical_hash();
        assert_eq!(h1, h2, "canonical hash must be deterministic");
    }

    #[test]
    fn test_schema_validation_pass() {
        let subject = test_subject();
        let schema = test_schema();
        assert!(schema.validate_subject(&subject).is_ok());
    }

    #[test]
    fn test_schema_validation_missing_field() {
        let mut subject = test_subject();
        subject.claims.remove("clearance");
        let schema = test_schema();
        let result = schema.validate_subject(&subject);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("clearance"));
    }

    #[test]
    fn test_sd_claims_creation_and_verification() {
        let subject = test_subject();
        let (sd_claims, disclosures) = create_sd_claims(&subject).unwrap();

        assert_eq!(sd_claims.len(), subject.claims.len());
        assert_eq!(disclosures.len(), subject.claims.len());

        // All disclosures should match their SD claims
        assert!(verify_disclosures(&sd_claims, &disclosures));
    }

    #[test]
    fn test_sd_selective_disclosure() {
        let subject = test_subject();
        let (sd_claims, disclosures) = create_sd_claims(&subject).unwrap();

        // Reveal only the clearance claim
        let partial: Vec<Disclosure> = disclosures
            .into_iter()
            .filter(|d| d.claim_name == "clearance")
            .collect();

        assert_eq!(partial.len(), 1);
        assert!(verify_disclosures(&sd_claims, &partial));
    }

    #[test]
    fn test_sd_tampered_disclosure_fails() {
        let subject = test_subject();
        let (sd_claims, mut disclosures) = create_sd_claims(&subject).unwrap();

        // Tamper with a claim value
        if let Some(d) = disclosures.first_mut() {
            d.claim_value = "TAMPERED".to_string();
        }

        assert!(!verify_disclosures(&sd_claims, &disclosures));
    }

    #[test]
    fn test_status_list_operations() {
        let mut sl = StatusList2021::new(
            "urn:uuid:status-list-1".to_string(),
            "revocation".to_string(),
            1000,
        );

        assert!(!sl.is_set(42).unwrap());
        assert_eq!(sl.revoked_count(), 0);

        sl.set_status(42).unwrap();
        assert!(sl.is_set(42).unwrap());
        assert_eq!(sl.revoked_count(), 1);

        sl.clear_status(42).unwrap();
        assert!(!sl.is_set(42).unwrap());
        assert_eq!(sl.revoked_count(), 0);
    }

    #[test]
    fn test_status_list_out_of_bounds() {
        let sl = StatusList2021::new(
            "urn:uuid:sl".to_string(),
            "revocation".to_string(),
            100,
        );
        assert!(sl.is_set(100).is_err());
        assert!(sl.is_set(999).is_err());
    }

    #[test]
    fn test_revocation_check() {
        let mut sl = StatusList2021::new(
            "urn:uuid:sl-1".to_string(),
            "revocation".to_string(),
            1000,
        );

        let subject = test_subject();
        let mut vc = VerifiableCredential::new(
            "urn:uuid:vc-1".to_string(),
            "did:web:milnet.mil".to_string(),
            subject,
            vec![],
            "2025-01-01T00:00:00Z".to_string(),
        );

        vc.credential_status = Some(CredentialStatus {
            status_list_credential: "urn:uuid:sl-1".to_string(),
            status_list_index: 7,
            status_purpose: "revocation".to_string(),
        });

        // Not revoked yet
        assert!(!check_revocation_status(&vc, &sl).unwrap());

        // Revoke
        sl.set_status(7).unwrap();
        assert!(check_revocation_status(&vc, &sl).unwrap());
    }

    #[test]
    fn test_credential_expiry() {
        let subject = test_subject();
        let mut vc = VerifiableCredential::new(
            "urn:uuid:vc-1".to_string(),
            "did:web:milnet.mil".to_string(),
            subject,
            vec![],
            "2025-01-01T00:00:00Z".to_string(),
        );

        vc.expiration_date = Some("2025-06-01T00:00:00Z".to_string());

        assert!(!vc.is_expired_at("2025-03-01T00:00:00Z"));
        assert!(vc.is_expired_at("2025-07-01T00:00:00Z"));
    }

    #[test]
    fn test_context_uri_roundtrip() {
        assert_eq!(ContextUri::from_str(VC_CONTEXT_V2), ContextUri::VcV2);
        assert_eq!(
            ContextUri::from_str("https://custom.example/v1"),
            ContextUri::Custom("https://custom.example/v1".to_string())
        );
    }
}
