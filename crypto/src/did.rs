//! Decentralized Identifier (W3C DID) support for the MILNET SSO system.
//!
//! Implements W3C DID Core specification with:
//! - DID methods: did:key (Ed25519, P-256), did:web
//! - DID Document resolution and verification
//! - DID-based authentication (DIDAuth)
//! - Key agreement for encrypted communication
//! - DID registration and rotation
//!
//! # Security Model
//!
//! DID documents are self-certifying (did:key) or domain-bound (did:web).
//! Authentication uses challenge-response with Ed25519 or P-256 signatures.
//! Key agreement uses X25519 Diffie-Hellman for establishing encrypted channels.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// DID Method types
// ---------------------------------------------------------------------------

/// Supported DID methods.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DidMethod {
    /// did:key — self-certifying, key material embedded in the identifier.
    Key,
    /// did:web — domain-bound, DID document hosted at a well-known URL.
    Web,
}

/// Key type used in a DID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    Ed25519,
    P256,
    X25519,
    MlDsa87,
}

impl KeyType {
    /// Return the multicodec prefix bytes for this key type.
    pub fn multicodec_prefix(&self) -> &[u8] {
        match self {
            KeyType::Ed25519 => &[0xed, 0x01],
            KeyType::P256 => &[0x80, 0x24],
            KeyType::X25519 => &[0xec, 0x01],
            KeyType::MlDsa87 => &[0xd4, 0x0d], // Provisional
        }
    }

    /// Return the JWK curve name.
    pub fn jwk_curve(&self) -> &str {
        match self {
            KeyType::Ed25519 => "Ed25519",
            KeyType::P256 => "P-256",
            KeyType::X25519 => "X25519",
            KeyType::MlDsa87 => "ML-DSA-87",
        }
    }
}

// ---------------------------------------------------------------------------
// DID Document types
// ---------------------------------------------------------------------------

/// A verification method within a DID Document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    /// Full identifier (e.g., "did:key:z6Mkh...#z6Mkh...").
    pub id: String,
    /// Type of the verification method.
    pub method_type: String,
    /// DID that controls this method.
    pub controller: String,
    /// Public key in multibase encoding (base58btc).
    pub public_key_multibase: String,
    /// Key type.
    pub key_type: KeyType,
    /// Raw public key bytes.
    pub public_key_bytes: Vec<u8>,
}

/// A service endpoint in a DID Document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    /// Service identifier.
    pub id: String,
    /// Service type (e.g., "LinkedDomains", "DIDCommMessaging").
    pub service_type: String,
    /// Service endpoint URI.
    pub endpoint: String,
}

/// A W3C DID Document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    /// The DID this document describes.
    pub id: String,
    /// DID method used.
    pub method: DidMethod,
    /// Verification methods (public keys).
    pub verification_method: Vec<VerificationMethod>,
    /// Authentication method references.
    pub authentication: Vec<String>,
    /// Assertion method references.
    pub assertion_method: Vec<String>,
    /// Key agreement method references.
    pub key_agreement: Vec<String>,
    /// Service endpoints.
    pub service: Vec<ServiceEndpoint>,
    /// Creation timestamp (ISO 8601).
    pub created: String,
    /// Last update timestamp (ISO 8601).
    pub updated: String,
    /// Optional deactivation flag.
    pub deactivated: bool,
    /// Additional metadata.
    pub metadata: BTreeMap<String, String>,
}

impl DidDocument {
    /// Find a verification method by its fragment ID.
    pub fn find_verification_method(&self, fragment: &str) -> Option<&VerificationMethod> {
        self.verification_method.iter().find(|vm| {
            vm.id.ends_with(fragment) || vm.id == fragment
        })
    }

    /// Check whether this DID document has been deactivated.
    pub fn is_active(&self) -> bool {
        !self.deactivated
    }

    /// Get the primary authentication method.
    pub fn primary_auth_method(&self) -> Option<&VerificationMethod> {
        self.authentication.first().and_then(|auth_ref| {
            self.find_verification_method(auth_ref)
        })
    }

    /// Get the primary key agreement method.
    pub fn primary_key_agreement(&self) -> Option<&VerificationMethod> {
        self.key_agreement.first().and_then(|ka_ref| {
            self.find_verification_method(ka_ref)
        })
    }
}

// ---------------------------------------------------------------------------
// did:key generation
// ---------------------------------------------------------------------------

/// Generate a did:key identifier from Ed25519 public key bytes.
///
/// Format: did:key:z<base58btc(multicodec_prefix + public_key)>
#[deprecated(note = "Use PQ-hybrid DID functions for quantum resistance")]
pub fn generate_did_key_ed25519(public_key: &[u8; 32]) -> String {
    let mut prefixed = Vec::with_capacity(2 + 32);
    prefixed.extend_from_slice(&[0xed, 0x01]);
    prefixed.extend_from_slice(public_key);
    let encoded = bs58::encode(&prefixed).into_string();
    format!("did:key:z{}", encoded)
}

/// Generate a did:key identifier from P-256 compressed public key bytes.
pub fn generate_did_key_p256(compressed_public_key: &[u8]) -> String {
    let mut prefixed = Vec::with_capacity(2 + compressed_public_key.len());
    prefixed.extend_from_slice(&[0x80, 0x24]);
    prefixed.extend_from_slice(compressed_public_key);
    let encoded = bs58::encode(&prefixed).into_string();
    format!("did:key:z{}", encoded)
}

/// Generate a did:web identifier from a domain name.
///
/// Format: did:web:<domain> (colons replace dots for path segments)
pub fn generate_did_web(domain: &str) -> String {
    format!("did:web:{}", domain.replace('.', ":"))
}

// ---------------------------------------------------------------------------
// DID Document resolution
// ---------------------------------------------------------------------------

/// Resolve a did:key to a DID Document.
///
/// For did:key, the document is entirely self-contained — the public key
/// is extracted from the DID itself.
pub fn resolve_did_key(did: &str) -> Result<DidDocument, String> {
    if !did.starts_with("did:key:z") {
        return Err(format!("not a did:key identifier: {}", did));
    }

    let multibase_str = &did["did:key:z".len()..];
    let decoded = bs58::decode(multibase_str)
        .into_vec()
        .map_err(|e| format!("base58 decode failed: {e}"))?;

    if decoded.len() < 3 {
        return Err("decoded key too short".to_string());
    }

    let (key_type, public_key_bytes) = match (decoded[0], decoded[1]) {
        (0xed, 0x01) => (KeyType::Ed25519, decoded[2..].to_vec()),
        (0x80, 0x24) => (KeyType::P256, decoded[2..].to_vec()),
        (0xec, 0x01) => (KeyType::X25519, decoded[2..].to_vec()),
        _ => return Err(format!("unknown multicodec prefix: {:02x}{:02x}", decoded[0], decoded[1])),
    };

    let method_type = match key_type {
        KeyType::Ed25519 => "Ed25519VerificationKey2020",
        KeyType::P256 => "EcdsaSecp256r1VerificationKey2019",
        KeyType::X25519 => "X25519KeyAgreementKey2020",
        KeyType::MlDsa87 => "MlDsa87VerificationKey2024",
    };

    let vm_id = format!("{}#{}", did, &did["did:key:".len()..]);
    let now = now_iso8601();

    let vm = VerificationMethod {
        id: vm_id.clone(),
        method_type: method_type.to_string(),
        controller: did.to_string(),
        public_key_multibase: format!("z{}", multibase_str),
        key_type: key_type.clone(),
        public_key_bytes,
    };

    let mut auth = Vec::new();
    let mut assertion = Vec::new();
    let mut key_agreement = Vec::new();

    match key_type {
        KeyType::X25519 => {
            key_agreement.push(vm_id.clone());
        }
        _ => {
            auth.push(vm_id.clone());
            assertion.push(vm_id.clone());
        }
    }

    Ok(DidDocument {
        id: did.to_string(),
        method: DidMethod::Key,
        verification_method: vec![vm],
        authentication: auth,
        assertion_method: assertion,
        key_agreement,
        service: Vec::new(),
        created: now.clone(),
        updated: now,
        deactivated: false,
        metadata: BTreeMap::new(),
    })
}

/// Create a did:web DID Document (typically fetched from the domain).
pub fn create_did_web_document(
    domain: &str,
    public_key: &[u8],
    key_type: KeyType,
) -> DidDocument {
    let did = generate_did_web(domain);
    let now = now_iso8601();

    let method_type = match key_type {
        KeyType::Ed25519 => "Ed25519VerificationKey2020",
        KeyType::P256 => "EcdsaSecp256r1VerificationKey2019",
        KeyType::X25519 => "X25519KeyAgreementKey2020",
        KeyType::MlDsa87 => "MlDsa87VerificationKey2024",
    };

    let vm_id = format!("{}#key-1", did);
    let vm = VerificationMethod {
        id: vm_id.clone(),
        method_type: method_type.to_string(),
        controller: did.clone(),
        public_key_multibase: format!("z{}", bs58::encode(public_key).into_string()),
        key_type,
        public_key_bytes: public_key.to_vec(),
    };

    DidDocument {
        id: did,
        method: DidMethod::Web,
        verification_method: vec![vm],
        authentication: vec![vm_id.clone()],
        assertion_method: vec![vm_id.clone()],
        key_agreement: Vec::new(),
        service: Vec::new(),
        created: now.clone(),
        updated: now,
        deactivated: false,
        metadata: BTreeMap::new(),
    }
}

// ---------------------------------------------------------------------------
// DIDAuth — Challenge-Response Authentication
// ---------------------------------------------------------------------------

/// A DIDAuth challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidAuthChallenge {
    /// Random challenge nonce (32 bytes).
    pub nonce: [u8; 32],
    /// DID of the challenger (verifier).
    pub verifier_did: String,
    /// Domain scope for the challenge.
    pub domain: String,
    /// Timestamp of challenge creation (ISO 8601).
    pub created: String,
}

/// A DIDAuth response (signed challenge).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidAuthResponse {
    /// The original challenge nonce.
    pub challenge_nonce: [u8; 32],
    /// DID of the prover (authenticated party).
    pub prover_did: String,
    /// Signature over the challenge (hex-encoded).
    pub signature_hex: String,
    /// Key type used for signing.
    pub key_type: KeyType,
}

/// Create a DIDAuth challenge.
pub fn create_did_auth_challenge(
    verifier_did: &str,
    domain: &str,
) -> Result<DidAuthChallenge, String> {
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| format!("nonce generation failed: {e}"))?;

    Ok(DidAuthChallenge {
        nonce,
        verifier_did: verifier_did.to_string(),
        domain: domain.to_string(),
        created: now_iso8601(),
    })
}

/// Compute the DIDAuth challenge digest (the message to sign).
/// Uses SHA-512 for CNSA 2.0 compliance.
pub fn did_auth_challenge_digest(challenge: &DidAuthChallenge) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(b"MILNET-DIDAUTH-v2");
    hasher.update(&challenge.nonce);
    hasher.update(challenge.verifier_did.as_bytes());
    hasher.update(challenge.domain.as_bytes());
    hasher.update(challenge.created.as_bytes());
    let result = hasher.finalize();
    let mut digest = [0u8; 64];
    digest.copy_from_slice(&result);
    digest
}

/// Sign a DIDAuth challenge with Ed25519.
#[deprecated(note = "Use PQ-hybrid sign_did_auth_hybrid for quantum resistance")]
pub fn sign_did_auth_ed25519(
    challenge: &DidAuthChallenge,
    prover_did: &str,
    signing_key: &ed25519_dalek::SigningKey,
) -> DidAuthResponse {
    use ed25519_dalek::Signer;
    let digest = did_auth_challenge_digest(challenge);
    let signature = signing_key.sign(&digest);

    DidAuthResponse {
        challenge_nonce: challenge.nonce,
        prover_did: prover_did.to_string(),
        signature_hex: hex::encode(signature.to_bytes()),
        key_type: KeyType::Ed25519,
    }
}

/// Sign a DIDAuth challenge with ML-DSA-87 (post-quantum).
pub fn sign_did_auth_ml_dsa87(
    challenge: &DidAuthChallenge,
    prover_did: &str,
    signing_key: &crate::pq_sign::PqSigningKey,
) -> DidAuthResponse {
    let digest = did_auth_challenge_digest(challenge);
    let signature = crate::pq_sign::pq_sign_raw(signing_key, &digest);

    DidAuthResponse {
        challenge_nonce: challenge.nonce,
        prover_did: prover_did.to_string(),
        signature_hex: hex::encode(&signature),
        key_type: KeyType::MlDsa87,
    }
}

/// A PQ-hybrid DIDAuth response containing both Ed25519 and ML-DSA-87 signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidAuthHybridResponse {
    /// The original challenge nonce.
    pub challenge_nonce: [u8; 32],
    /// DID of the prover (authenticated party).
    pub prover_did: String,
    /// Ed25519 signature over the challenge digest (hex-encoded).
    pub ed25519_signature_hex: String,
    /// ML-DSA-87 signature over (challenge_digest || ed25519_signature) (hex-encoded).
    pub ml_dsa87_signature_hex: String,
}

/// Sign a DIDAuth challenge with PQ-hybrid (Ed25519 + ML-DSA-87).
///
/// The ML-DSA-87 signature covers both the message and the Ed25519 signature,
/// binding the classical and post-quantum signatures together.
pub fn sign_did_auth_hybrid(
    challenge: &DidAuthChallenge,
    prover_did: &str,
    ed25519_key: &ed25519_dalek::SigningKey,
    pq_key: &crate::pq_sign::PqSigningKey,
) -> DidAuthHybridResponse {
    use ed25519_dalek::Signer;
    let digest = did_auth_challenge_digest(challenge);

    // Classical Ed25519 signature
    let ed25519_sig = ed25519_key.sign(&digest);
    let ed25519_sig_bytes = ed25519_sig.to_bytes();

    // PQ signature covers digest || ed25519_signature
    let mut pq_message = Vec::with_capacity(digest.len() + ed25519_sig_bytes.len());
    pq_message.extend_from_slice(&digest);
    pq_message.extend_from_slice(&ed25519_sig_bytes);
    let pq_sig = crate::pq_sign::pq_sign_raw(pq_key, &pq_message);

    DidAuthHybridResponse {
        challenge_nonce: challenge.nonce,
        prover_did: prover_did.to_string(),
        ed25519_signature_hex: hex::encode(ed25519_sig_bytes),
        ml_dsa87_signature_hex: hex::encode(&pq_sig),
    }
}

/// Verify a PQ-hybrid DIDAuth response. Both signatures must pass.
pub fn verify_did_auth_hybrid(
    challenge: &DidAuthChallenge,
    response: &DidAuthHybridResponse,
    ed25519_public_key: &[u8; 32],
    pq_verifying_key: &crate::pq_sign::PqVerifyingKey,
) -> Result<bool, String> {
    // Verify nonce matches
    if !crate::ct::ct_eq(&challenge.nonce, &response.challenge_nonce) {
        return Ok(false);
    }

    let digest = did_auth_challenge_digest(challenge);

    // Verify Ed25519 signature
    let ed25519_sig_bytes = hex::decode(&response.ed25519_signature_hex)
        .map_err(|e| format!("invalid Ed25519 signature hex: {e}"))?;
    if ed25519_sig_bytes.len() != 64 {
        return Err("invalid Ed25519 signature length".to_string());
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&ed25519_sig_bytes);

    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(ed25519_public_key)
        .map_err(|e| format!("invalid Ed25519 key: {e}"))?;
    let ed25519_sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    use ed25519_dalek::Verifier;
    if verifying_key.verify(&digest, &ed25519_sig).is_err() {
        return Ok(false);
    }

    // Verify ML-DSA-87 signature over (digest || ed25519_signature)
    let pq_sig_bytes = hex::decode(&response.ml_dsa87_signature_hex)
        .map_err(|e| format!("invalid ML-DSA-87 signature hex: {e}"))?;

    let mut pq_message = Vec::with_capacity(digest.len() + ed25519_sig_bytes.len());
    pq_message.extend_from_slice(&digest);
    pq_message.extend_from_slice(&ed25519_sig_bytes);

    Ok(crate::pq_sign::pq_verify_raw(pq_verifying_key, &pq_message, &pq_sig_bytes))
}

/// Verify a DIDAuth response using the public key from a DID Document.
pub fn verify_did_auth(
    challenge: &DidAuthChallenge,
    response: &DidAuthResponse,
    did_document: &DidDocument,
) -> Result<bool, String> {
    // Verify nonce matches
    if !crate::ct::ct_eq(&challenge.nonce, &response.challenge_nonce) {
        return Ok(false);
    }

    // Find the authentication method
    let vm = did_document
        .primary_auth_method()
        .ok_or("DID document has no authentication method")?;

    let digest = did_auth_challenge_digest(challenge);

    match response.key_type {
        KeyType::Ed25519 => {
            if vm.public_key_bytes.len() != 32 {
                return Err("invalid Ed25519 public key length".to_string());
            }
            let mut pk_bytes = [0u8; 32];
            pk_bytes.copy_from_slice(&vm.public_key_bytes);

            let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes)
                .map_err(|e| format!("invalid Ed25519 key: {e}"))?;

            let sig_bytes = hex::decode(&response.signature_hex)
                .map_err(|e| format!("invalid signature hex: {e}"))?;

            if sig_bytes.len() != 64 {
                return Err("invalid Ed25519 signature length".to_string());
            }
            let mut sig_arr = [0u8; 64];
            sig_arr.copy_from_slice(&sig_bytes);

            let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
            use ed25519_dalek::Verifier;
            Ok(verifying_key.verify(&digest, &signature).is_ok())
        }
        KeyType::MlDsa87 => {
            let sig_bytes = hex::decode(&response.signature_hex)
                .map_err(|e| format!("invalid signature hex: {e}"))?;

            let vk_bytes = &vm.public_key_bytes;
            let vk_enc = crate::pq_sign::PqEncodedVerifyingKey::try_from(vk_bytes.as_slice())
                .map_err(|e| format!("invalid ML-DSA-87 verifying key encoding: {e}"))?;
            let verifying_key = crate::pq_sign::PqVerifyingKey::decode(&vk_enc);

            Ok(crate::pq_sign::pq_verify_raw(&verifying_key, &digest, &sig_bytes))
        }
        _ => Err(format!(
            "DIDAuth verification not implemented for {:?}",
            response.key_type
        )),
    }
}

// ---------------------------------------------------------------------------
// Key Agreement
// ---------------------------------------------------------------------------

/// Derive a shared secret using X25519 Diffie-Hellman with HKDF-SHA512.
///
/// The raw DH output is passed through HKDF-SHA512 with a domain-specific
/// info string to produce a uniformly distributed key. Raw X25519 output
/// should never be used directly as key material.
pub fn did_key_agreement(
    our_secret: &[u8; 32],
    their_public: &[u8; 32],
) -> [u8; 32] {
    let our_secret = x25519_dalek::StaticSecret::from(*our_secret);
    let their_public = x25519_dalek::PublicKey::from(*their_public);
    let raw_dh = our_secret.diffie_hellman(&their_public);

    // Apply HKDF-SHA512 to extract a uniformly distributed key
    let hk = hkdf::Hkdf::<sha2::Sha512>::new(Some(b"MILNET-DID-KEYAGREE-SALT-v1"), raw_dh.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(b"MILNET-DID-KEY-AGREEMENT-v1", &mut okm)
        .expect("HKDF-SHA512 expand for 32 bytes cannot fail");
    okm
}

// ---------------------------------------------------------------------------
// DID Registration / Rotation
// ---------------------------------------------------------------------------

/// A DID rotation event — records the transition from an old key to a new key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidRotationEvent {
    /// The DID being rotated.
    pub did: String,
    /// Previous verification method ID.
    pub previous_method_id: String,
    /// New verification method ID.
    pub new_method_id: String,
    /// Timestamp of rotation (ISO 8601).
    pub rotated_at: String,
    /// Signature by the previous key authorizing the rotation (hex).
    pub authorization_signature_hex: String,
}

/// DID registry -- in-memory store for DID documents.
///
/// PERSISTENCE STATUS: In-memory only. A `PersistentDidRegistry` trait is
/// defined below for future database-backed implementations. This in-memory
/// registry emits a SIEM warning on construction to flag the lack of
/// persistence in operational dashboards.
///
/// BOUNDED RISK: DID documents are self-certifying (did:key) or domain-bound
/// (did:web). Loss of the registry on restart means DIDs must be re-registered,
/// but no security keys are lost (keys live in the DID itself or on the
/// domain's well-known endpoint). The primary impact is temporary inability
/// to resolve previously-registered DIDs until they are re-registered.
#[derive(Debug, Default)]
pub struct DidRegistry {
    documents: BTreeMap<String, DidDocument>,
    rotation_log: Vec<DidRotationEvent>,
}

impl DidRegistry {
    /// Create a new empty registry.
    ///
    /// Emits a SIEM warning that the DID registry is in-memory only and will
    /// not survive process restart. Production deployments should implement
    /// `PersistentDidRegistry` with a database backend.
    pub fn new() -> Self {
        tracing::warn!(
            target: "siem",
            "SIEM:WARNING DID registry initialized with in-memory backend only. \
             DID registrations will be lost on restart. Implement PersistentDidRegistry \
             with PostgreSQL backing for production deployments."
        );
        Self::default()
    }

    /// Register a new DID document.
    pub fn register(&mut self, document: DidDocument) -> Result<(), String> {
        if self.documents.contains_key(&document.id) {
            return Err(format!("DID already registered: {}", document.id));
        }
        self.documents.insert(document.id.clone(), document);
        Ok(())
    }

    /// Resolve a DID to its document.
    pub fn resolve(&self, did: &str) -> Option<&DidDocument> {
        self.documents.get(did)
    }

    /// Deactivate a DID.
    pub fn deactivate(&mut self, did: &str) -> Result<(), String> {
        let doc = self.documents.get_mut(did)
            .ok_or_else(|| format!("DID not found: {}", did))?;
        doc.deactivated = true;
        doc.updated = now_iso8601();
        Ok(())
    }

    /// Record a key rotation event.
    pub fn record_rotation(&mut self, event: DidRotationEvent) {
        if let Some(doc) = self.documents.get_mut(&event.did) {
            doc.updated = now_iso8601();
        }
        self.rotation_log.push(event);
    }

    /// Get the rotation history for a DID.
    pub fn rotation_history(&self, did: &str) -> Vec<&DidRotationEvent> {
        self.rotation_log.iter().filter(|e| e.did == did).collect()
    }

    /// Return the total number of registered DIDs.
    pub fn count(&self) -> usize {
        self.documents.len()
    }
}

// ---------------------------------------------------------------------------
// PersistentDidRegistry trait -- for future database-backed implementations
// ---------------------------------------------------------------------------

/// Trait for persistent DID registry backends.
///
/// Implementations should back the DID document store with PostgreSQL (or
/// equivalent persistent storage) and keep an in-memory cache for fast
/// resolution. The `DidRegistry` struct above serves as the in-memory
/// implementation; production deployments should wrap it with a persistent
/// backend that:
///   1. Loads all DID documents from DB on construction.
///   2. Writes through to DB on register/deactivate/rotate.
///   3. Uses `EncryptedPool` if DID documents contain sensitive metadata.
///   4. Emits SIEM events on DB unavailability (degrade to cache-only).
pub trait PersistentDidRegistry: Send + Sync {
    /// Register a new DID document, persisting to the backend.
    fn register(&mut self, document: DidDocument) -> Result<(), String>;
    /// Resolve a DID to its document.
    fn resolve(&self, did: &str) -> Option<&DidDocument>;
    /// Deactivate a DID.
    fn deactivate(&mut self, did: &str) -> Result<(), String>;
    /// Record a key rotation event.
    fn record_rotation(&mut self, event: DidRotationEvent);
    /// Return the total number of registered DIDs.
    fn count(&self) -> usize;
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
#[allow(deprecated)]
mod tests {
    use super::*;

    #[test]
    fn test_did_key_ed25519_generation() {
        let pk = [0x42u8; 32];
        let did = generate_did_key_ed25519(&pk);
        assert!(did.starts_with("did:key:z"));
    }

    #[test]
    fn test_did_key_ed25519_resolution() {
        let pk = [0x01u8; 32];
        let did = generate_did_key_ed25519(&pk);
        let doc = resolve_did_key(&did).expect("resolution must succeed");

        assert_eq!(doc.id, did);
        assert_eq!(doc.method, DidMethod::Key);
        assert!(!doc.verification_method.is_empty());
        assert_eq!(doc.verification_method[0].key_type, KeyType::Ed25519);
        assert_eq!(doc.verification_method[0].public_key_bytes, pk.to_vec());
    }

    #[test]
    fn test_did_web_generation() {
        let did = generate_did_web("milnet.mil");
        assert_eq!(did, "did:web:milnet:mil");
    }

    #[test]
    fn test_did_web_document() {
        let pk = [0x55u8; 32];
        let doc = create_did_web_document("milnet.mil", &pk, KeyType::Ed25519);

        assert_eq!(doc.id, "did:web:milnet:mil");
        assert_eq!(doc.method, DidMethod::Web);
        assert!(!doc.authentication.is_empty());
    }

    #[test]
    fn test_did_auth_challenge_response() {
        use ed25519_dalek::SigningKey;

        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).unwrap();
        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();

        let prover_did = generate_did_key_ed25519(verifying_key.as_bytes());
        let doc = resolve_did_key(&prover_did).unwrap();

        let challenge = create_did_auth_challenge("did:web:verifier:example", "milnet.mil")
            .expect("challenge creation must succeed");

        let response = sign_did_auth_ed25519(&challenge, &prover_did, &signing_key);

        let verified = verify_did_auth(&challenge, &response, &doc)
            .expect("verification must not error");
        assert!(verified, "valid DIDAuth response must verify");
    }

    #[test]
    fn test_did_auth_wrong_nonce_fails() {
        use ed25519_dalek::SigningKey;

        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).unwrap();
        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();

        let prover_did = generate_did_key_ed25519(verifying_key.as_bytes());
        let doc = resolve_did_key(&prover_did).unwrap();

        let challenge = create_did_auth_challenge("did:web:verifier:example", "milnet.mil").unwrap();
        let response = sign_did_auth_ed25519(&challenge, &prover_did, &signing_key);

        // Create a different challenge
        let challenge2 = create_did_auth_challenge("did:web:verifier:example", "milnet.mil").unwrap();

        // Nonce mismatch should fail
        let verified = verify_did_auth(&challenge2, &response, &doc).unwrap();
        assert!(!verified, "mismatched nonce must fail verification");
    }

    #[test]
    fn test_did_key_agreement() {
        let mut secret_a = [0u8; 32];
        let mut secret_b = [0u8; 32];
        getrandom::getrandom(&mut secret_a).unwrap();
        getrandom::getrandom(&mut secret_b).unwrap();

        let static_a = x25519_dalek::StaticSecret::from(secret_a);
        let static_b = x25519_dalek::StaticSecret::from(secret_b);

        let public_a = x25519_dalek::PublicKey::from(&static_a);
        let public_b = x25519_dalek::PublicKey::from(&static_b);

        let shared_ab = did_key_agreement(&secret_a, public_b.as_bytes());
        let shared_ba = did_key_agreement(&secret_b, public_a.as_bytes());

        assert_eq!(shared_ab, shared_ba, "DH shared secrets must match");
    }

    #[test]
    fn test_did_registry() {
        let mut registry = DidRegistry::new();

        let pk = [0x01u8; 32];
        let did = generate_did_key_ed25519(&pk);
        let doc = resolve_did_key(&did).unwrap();

        registry.register(doc).unwrap();
        assert_eq!(registry.count(), 1);
        assert!(registry.resolve(&did).is_some());

        // Duplicate registration fails
        let doc2 = resolve_did_key(&did).unwrap();
        assert!(registry.register(doc2).is_err());
    }

    #[test]
    fn test_did_deactivation() {
        let mut registry = DidRegistry::new();

        let pk = [0x02u8; 32];
        let did = generate_did_key_ed25519(&pk);
        let doc = resolve_did_key(&did).unwrap();

        registry.register(doc).unwrap();
        assert!(registry.resolve(&did).unwrap().is_active());

        registry.deactivate(&did).unwrap();
        assert!(!registry.resolve(&did).unwrap().is_active());
    }

    #[test]
    fn test_resolve_invalid_did_fails() {
        assert!(resolve_did_key("not-a-did").is_err());
        assert!(resolve_did_key("did:web:example.com").is_err());
    }

    #[test]
    fn test_did_auth_pq_hybrid_sign_verify() {
        use ed25519_dalek::SigningKey;

        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).unwrap();
        let ed25519_key = SigningKey::from_bytes(&secret);
        let ed25519_vk = ed25519_key.verifying_key();

        let (pq_sk, pq_vk) = crate::pq_sign::generate_pq_keypair();

        let prover_did = generate_did_key_ed25519(ed25519_vk.as_bytes());

        let challenge = create_did_auth_challenge("did:web:verifier:example", "milnet.mil")
            .expect("challenge creation must succeed");

        let response = sign_did_auth_hybrid(&challenge, &prover_did, &ed25519_key, &pq_sk);

        let verified = verify_did_auth_hybrid(
            &challenge,
            &response,
            ed25519_vk.as_bytes(),
            &pq_vk,
        )
        .expect("verification must not error");
        assert!(verified, "valid PQ-hybrid DIDAuth response must verify");
    }

    #[test]
    fn test_did_auth_pq_hybrid_wrong_nonce_fails() {
        use ed25519_dalek::SigningKey;

        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).unwrap();
        let ed25519_key = SigningKey::from_bytes(&secret);
        let ed25519_vk = ed25519_key.verifying_key();

        let (pq_sk, pq_vk) = crate::pq_sign::generate_pq_keypair();

        let prover_did = generate_did_key_ed25519(ed25519_vk.as_bytes());

        let challenge = create_did_auth_challenge("did:web:verifier:example", "milnet.mil").unwrap();
        let response = sign_did_auth_hybrid(&challenge, &prover_did, &ed25519_key, &pq_sk);

        let challenge2 = create_did_auth_challenge("did:web:verifier:example", "milnet.mil").unwrap();
        let verified = verify_did_auth_hybrid(&challenge2, &response, ed25519_vk.as_bytes(), &pq_vk).unwrap();
        assert!(!verified, "mismatched nonce must fail PQ-hybrid verification");
    }
}
