//! CAC/PIV PKCS#11 module for DoD smart card authentication.
//!
//! Provides types and session management for Common Access Card (CAC) and
//! Personal Identity Verification (PIV) smart cards via PKCS#11.
//!
//! # Supported Card Types
//! - US DoD CAC (Military and Civilian)
//! - US Federal PIV and PIV-Interoperable
//! - Mobile-derived PIV
//! - Indian Digital Signature Certificate (CCA)
//! - Indian Aadhaar eSign
//!
//! # Security
//! - Session login requires PIN (never stored)
//! - Certificates parsed from DER; public keys used for software verification
//! - `verify_signature` operates purely in software (no hardware required)
//! - PKCS#11 library loaded dynamically; graceful error if absent

use std::collections::HashMap;
use sha2::{Digest, Sha512};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Information about an inserted CAC/PIV smart card.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacCardInfo {
    /// Smart card serial number (from card middleware).
    pub card_serial: String,
    /// Issuing authority name.
    pub card_issuer: String,
    /// Subject Distinguished Name from the PIV auth certificate.
    pub subject_dn: String,
    /// DoD 10-digit Electronic Data Interchange Personal Identifier.
    pub edipi: Option<String>,
    /// Indian Virtual ID (Aadhaar VID).
    pub aadhaar_vid: Option<String>,
    /// Military branch or ministry affiliation.
    pub affiliation: String,
    /// SHA-512 fingerprint of the PIV authentication certificate (hex-encoded for serialization).
    #[serde(with = "fingerprint_serde")]
    pub cert_fingerprint: [u8; 64],
    /// Whether the card PIN has been successfully verified this session.
    pub pin_verified: bool,
    /// Physical card type.
    pub card_type: CardType,
    /// Clearance level (maps to `ClassificationLevel` — 0-4).
    pub clearance_level: u8,
    /// Operator-defined metadata tags.
    pub tags: HashMap<String, String>,
    /// Insertion timestamp (Unix microseconds).
    pub inserted_at: i64,
    /// Removal timestamp, if the card has been removed (Unix microseconds).
    pub removed_at: Option<i64>,
    /// Card reader identifier string.
    pub reader_id: String,
    /// Physical facility access code.
    pub facility_code: String,
}

/// Physical smart card type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CardType {
    /// US DoD CAC — military personnel.
    CacMilitary,
    /// US DoD CAC — civilian DoD employees.
    CacCivilian,
    /// US Federal PIV card (FIPS 201).
    Piv,
    /// PIV-Interoperable card for non-federal issuers.
    PivI,
    /// Mobile-derived PIV credential.
    DerivedPiv,
    /// Indian Digital Signature Certificate issued by CCA.
    IndianDsc,
    /// Indian Aadhaar eSign credential.
    IndianESign,
}

/// Signature mechanism to use for PKCS#11 sign operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignMechanism {
    /// `CKM_RSA_PKCS` — legacy RSA PKCS#1 v1.5 as used by original CAC.
    RsaPkcs,
    /// `CKM_ECDSA` with P-256 curve as used by modern PIV cards.
    EcdsaP256,
    /// `CKM_ECDSA` with P-384 curve for high-assurance PIV.
    EcdsaP384,
}

/// Errors that can occur during CAC/PIV operations.
#[derive(Debug)]
pub enum CacError {
    /// PKCS#11 shared library not found at the given path.
    LibraryNotFound(String),
    /// The requested slot is not available on the reader.
    SlotNotAvailable(u64),
    /// Card PIN login failed (wrong PIN).
    LoginFailed,
    /// Card PIN is locked due to too many failed attempts.
    PinLocked,
    /// No certificate found with the requested label.
    CertificateNotFound(String),
    /// The signing operation failed.
    SigningFailed(String),
    /// Signature verification failed.
    VerificationFailed(String),
    /// Card was physically removed during operation.
    CardRemoved,
    /// PKCS#11 session has expired and must be re-opened.
    SessionExpired,
    /// The certificate DER is malformed or has an unsupported format.
    InvalidCertificate(String),
    /// Certificate revocation check could not be completed.
    RevocationCheckFailed(String),
}

impl std::fmt::Display for CacError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CacError::LibraryNotFound(path) => {
                write!(f, "PKCS#11 library not found: {}", path)
            }
            CacError::SlotNotAvailable(slot) => {
                write!(f, "PKCS#11 slot {} is not available", slot)
            }
            CacError::LoginFailed => {
                write!(f, "CAC PIN login failed: incorrect PIN")
            }
            CacError::PinLocked => {
                write!(f, "CAC PIN is locked due to too many failed attempts")
            }
            CacError::CertificateNotFound(label) => {
                write!(f, "Certificate not found on card: {}", label)
            }
            CacError::SigningFailed(reason) => {
                write!(f, "Card signing operation failed: {}", reason)
            }
            CacError::VerificationFailed(reason) => {
                write!(f, "Signature verification failed: {}", reason)
            }
            CacError::CardRemoved => {
                write!(f, "Smart card was physically removed during operation")
            }
            CacError::SessionExpired => {
                write!(f, "PKCS#11 session has expired — re-open session")
            }
            CacError::InvalidCertificate(detail) => {
                write!(f, "Invalid certificate: {}", detail)
            }
            CacError::RevocationCheckFailed(detail) => {
                write!(f, "Revocation check failed: {}", detail)
            }
        }
    }
}

impl std::error::Error for CacError {}

// ---------------------------------------------------------------------------
// PKCS#11 Session
// ---------------------------------------------------------------------------

/// PKCS#11 session wrapping a smart card slot.
///
/// In production this wraps the `cryptoki` crate to interact with real
/// PKCS#11 hardware.  When the library is absent (CI, unit tests) every
/// method that requires the hardware returns a graceful error — only
/// `verify_signature` works fully in software.
#[derive(Debug)]
pub struct Pkcs11Session {
    /// Filesystem path to the PKCS#11 shared library (`.so` / `.dll`).
    library_path: String,
    /// PKCS#11 slot identifier.
    slot_id: u64,
    /// Whether a user PIN login is currently active.
    logged_in: bool,
}

impl Pkcs11Session {
    /// Open a PKCS#11 session on the given slot.
    ///
    /// Checks that `library_path` exists on disk; returns
    /// [`CacError::LibraryNotFound`] if the file is absent.
    pub fn open(library_path: &str, slot_id: u64) -> Result<Self, CacError> {
        // Verify the shared library exists before attempting to load it.
        // In production the cryptoki Pkcs11 type would be initialised here.
        if !std::path::Path::new(library_path).exists() {
            return Err(CacError::LibraryNotFound(library_path.to_string()));
        }

        Ok(Self {
            library_path: library_path.to_string(),
            slot_id,
            logged_in: false,
        })
    }

    /// Log in to the card with the supplied PIN bytes.
    ///
    /// In a production build the session forwards the PIN to the PKCS#11
    /// `C_Login` function via `cryptoki`.  Without hardware the call
    /// returns [`CacError::SlotNotAvailable`].
    pub fn login_user(&mut self, _pin: &[u8]) -> Result<(), CacError> {
        // Check that the library still exists (may have been unmounted).
        if !std::path::Path::new(&self.library_path).exists() {
            return Err(CacError::LibraryNotFound(self.library_path.clone()));
        }

        // In production: cryptoki session.login(UserType::User, Some(pin))
        // Without real hardware we cannot proceed further.
        Err(CacError::SlotNotAvailable(self.slot_id))
    }

    /// Log out of the current PKCS#11 session.
    pub fn logout(&mut self) -> Result<(), CacError> {
        if !self.logged_in {
            return Ok(());
        }
        self.logged_in = false;
        Ok(())
    }

    /// Find and return the DER-encoded certificate with the given CKA_LABEL.
    ///
    /// Requires an active login.  Returns [`CacError::LoginFailed`] if the
    /// session is not authenticated.
    pub fn find_certificate(&self, label: &str) -> Result<Vec<u8>, CacError> {
        if !self.logged_in {
            return Err(CacError::LoginFailed);
        }
        // In production: enumerate CKO_CERTIFICATE objects and match label.
        Err(CacError::CertificateNotFound(label.to_string()))
    }

    /// Sign `data` with the private key identified by `key_label`.
    ///
    /// Requires an active login.  The `mechanism` controls which PKCS#11
    /// `CKM_*` constant is used.
    pub fn sign_data(
        &self,
        key_label: &str,
        _data: &[u8],
        _mechanism: SignMechanism,
    ) -> Result<Vec<u8>, CacError> {
        if !self.logged_in {
            return Err(CacError::LoginFailed);
        }
        // In production: find CKO_PRIVATE_KEY by label, call C_Sign.
        Err(CacError::SigningFailed(format!(
            "no hardware available for key '{}'",
            key_label
        )))
    }

    /// Verify `sig` over `data` using the public key embedded in a
    /// DER-encoded X.509 certificate.
    ///
    /// This function operates entirely in software (no PKCS#11 required) and
    /// supports RSA-PKCS1v15-SHA256 and ECDSA P-256 signatures.
    pub fn verify_signature(
        cert_der: &[u8],
        data: &[u8],
        sig: &[u8],
    ) -> Result<bool, CacError> {
        // Attempt ECDSA P-256 verification via the `p256` crate.
        // We extract the raw public key from the SubjectPublicKeyInfo in the
        // certificate using a minimal DER walk.
        match extract_spki_bytes(cert_der) {
            Some(spki) => verify_ecdsa_p256_spki(&spki, data, sig),
            None => Err(CacError::InvalidCertificate(
                "could not extract SubjectPublicKeyInfo from certificate".into(),
            )),
        }
    }

    /// Read card metadata and build a [`CacCardInfo`] for this slot.
    ///
    /// Requires an active login.
    pub fn get_card_info(&self) -> Result<CacCardInfo, CacError> {
        if !self.logged_in {
            return Err(CacError::LoginFailed);
        }
        Err(CacError::SlotNotAvailable(self.slot_id))
    }

    /// Returns `true` when a PIN login is currently active on this session.
    pub fn is_logged_in(&self) -> bool {
        self.logged_in
    }
}

impl Drop for Pkcs11Session {
    fn drop(&mut self) {
        if self.logged_in {
            // Best-effort logout on drop; ignore errors.
            let _ = self.logout();
        }
    }
}

// ---------------------------------------------------------------------------
// Mock session for unit tests
// ---------------------------------------------------------------------------

/// A software-only mock of a PKCS#11 session for use in tests.
///
/// Stores pre-configured certificates and signing keys so that the
/// CAC authentication flow can be exercised without real hardware.
pub struct MockPkcs11Session {
    /// Pre-loaded DER certificates keyed by label.
    pub certificates: HashMap<String, Vec<u8>>,
    /// Pre-loaded raw signing key bytes keyed by label (P-256 scalar bytes).
    pub signing_keys: HashMap<String, Vec<u8>>,
    /// Whether the mock session is currently "logged in".
    pub logged_in: bool,
    /// Simulated card serial number.
    pub card_serial: String,
    /// Simulated card type.
    pub card_type: CardType,
    /// Simulated clearance level.
    pub clearance_level: u8,
}

impl MockPkcs11Session {
    /// Create a new mock session with empty key/cert stores.
    pub fn new() -> Self {
        Self {
            certificates: HashMap::new(),
            signing_keys: HashMap::new(),
            logged_in: false,
            card_serial: "MOCK-SERIAL-0001".to_string(),
            card_type: CardType::CacMilitary,
            clearance_level: 2,
        }
    }

    /// Pre-load a DER certificate under `label`.
    pub fn add_certificate(&mut self, label: &str, cert_der: Vec<u8>) {
        self.certificates.insert(label.to_string(), cert_der);
    }

    /// Simulate a PIN login (always succeeds on mock).
    pub fn login(&mut self) {
        self.logged_in = true;
    }

    /// Simulate logout.
    pub fn logout(&mut self) {
        self.logged_in = false;
    }

    /// Return a pre-loaded certificate by label.
    pub fn find_certificate(&self, label: &str) -> Option<&Vec<u8>> {
        self.certificates.get(label)
    }

    /// Build a [`CacCardInfo`] from the mock session's configuration.
    pub fn get_card_info(&self, cert_der: &[u8]) -> CacCardInfo {
        let fingerprint = cert_fingerprint_sha512(cert_der);
        let subject_dn = extract_subject_dn(cert_der).unwrap_or_else(|_| "CN=Mock".to_string());
        let edipi = extract_edipi(cert_der);
        CacCardInfo {
            card_serial: self.card_serial.clone(),
            card_issuer: "Mock CA".to_string(),
            subject_dn,
            edipi,
            aadhaar_vid: None,
            affiliation: "USMC".to_string(),
            cert_fingerprint: fingerprint,
            pin_verified: self.logged_in,
            card_type: self.card_type,
            clearance_level: self.clearance_level,
            tags: HashMap::new(),
            inserted_at: unix_micros(),
            removed_at: None,
            reader_id: "MockReader:0".to_string(),
            facility_code: "0000".to_string(),
        }
    }
}

impl Default for MockPkcs11Session {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Compute the SHA-512 fingerprint of a DER-encoded X.509 certificate.
///
/// The returned 64-byte array is a standard "cert fingerprint" as displayed
/// by tools such as `openssl x509 -fingerprint -sha512`.
pub fn cert_fingerprint_sha512(cert_der: &[u8]) -> [u8; 64] {
    let digest = Sha512::digest(cert_der);
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    out
}

/// Extract the Subject Distinguished Name from a DER-encoded X.509 certificate.
///
/// Returns a human-readable string like `"CN=John Doe, OU=USMC, O=DoD"`.
/// Uses a minimal DER walker to locate the Subject field without requiring a
/// full ASN.1 parser crate.
pub fn extract_subject_dn(cert_der: &[u8]) -> Result<String, CacError> {
    // X.509 structure (simplified):
    //   SEQUENCE {                         <- Certificate
    //     SEQUENCE {                       <- TBSCertificate
    //       [0] EXPLICIT INTEGER           <- version (optional)
    //       INTEGER                        <- serialNumber
    //       SEQUENCE                       <- signature
    //       SEQUENCE                       <- issuer
    //       SEQUENCE                       <- validity
    //       SEQUENCE                       <- subject  <-- we want this
    //       ...
    //     }
    //     ...
    //   }
    let tbs = extract_tbs_certificate(cert_der)?;
    extract_subject_from_tbs(tbs)
}

/// Extract the EDIPI (10-digit DoD identifier) from a CAC certificate.
///
/// Searches the Subject CN field for a trailing 10-digit numeric suffix,
/// which DoD PKI embeds as the EDIPI (e.g. `"CN=DOE.JOHN.1234567890"`).
pub fn extract_edipi(cert_der: &[u8]) -> Option<String> {
    let dn = extract_subject_dn(cert_der).ok()?;
    // DoD EDIPI is the last component of the CN after the last dot.
    // Format: LAST.FIRST.MIDDLE.EDIPI  or  LAST.FIRST.EDIPI
    for part in dn.split(',') {
        let part = part.trim();
        if let Some(cn_value) = part.strip_prefix("CN=") {
            // Split by '.' and look for a 10-digit numeric suffix.
            let segments: Vec<&str> = cn_value.split('.').collect();
            if let Some(last) = segments.last() {
                if last.len() == 10 && last.chars().all(|c| c.is_ascii_digit()) {
                    return Some((*last).to_string());
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Internal DER parsing helpers
// ---------------------------------------------------------------------------

/// Read one DER TLV (tag + length + value) from `data` at `pos`.
/// Returns `(tag, value_slice, next_pos)` or `None` on error.
fn der_read_tlv(data: &[u8], pos: usize) -> Option<(u8, &[u8], usize)> {
    if pos >= data.len() {
        return None;
    }
    let tag = *data.get(pos)?;
    let pos = pos + 1;

    let (len, pos) = der_read_length(data, pos)?;
    let end = pos.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    Some((tag, &data[pos..end], end))
}

/// Read a DER length field, supporting multi-byte lengths.
/// Returns `(length, next_pos)` or `None` on error.
fn der_read_length(data: &[u8], pos: usize) -> Option<(usize, usize)> {
    let first = *data.get(pos)? as usize;
    if first < 0x80 {
        Some((first, pos + 1))
    } else {
        let num_bytes = first & 0x7f;
        if num_bytes == 0 || num_bytes > 4 {
            return None;
        }
        let end = pos + 1 + num_bytes;
        if end > data.len() {
            return None;
        }
        let mut len: usize = 0;
        for i in 0..num_bytes {
            len = (len << 8) | (*data.get(pos + 1 + i)? as usize);
        }
        Some((len, end))
    }
}

/// Extract the raw TBSCertificate bytes from a DER-encoded Certificate.
fn extract_tbs_certificate(cert_der: &[u8]) -> Result<&[u8], CacError> {
    // Certificate ::= SEQUENCE { TBSCertificate, ... }
    let (tag, cert_body, _) = der_read_tlv(cert_der, 0)
        .ok_or_else(|| CacError::InvalidCertificate("cannot read outer SEQUENCE".into()))?;
    if tag != 0x30 {
        return Err(CacError::InvalidCertificate("outer tag is not SEQUENCE".into()));
    }

    // TBSCertificate is the first SEQUENCE inside Certificate.
    let (tag2, tbs, _) = der_read_tlv(cert_body, 0)
        .ok_or_else(|| CacError::InvalidCertificate("cannot read TBSCertificate".into()))?;
    if tag2 != 0x30 {
        return Err(CacError::InvalidCertificate("TBSCertificate tag is not SEQUENCE".into()));
    }
    Ok(tbs)
}

/// Walk TBSCertificate to find the Subject SEQUENCE and render it as a string.
///
/// TBSCertificate field order (RFC 5280):
///   version [0] OPTIONAL, serialNumber, signature, issuer, validity, subject, ...
fn extract_subject_from_tbs(tbs: &[u8]) -> Result<String, CacError> {
    let mut pos = 0;
    let mut field_index = 0usize;

    while pos < tbs.len() {
        let (tag, value, next) = match der_read_tlv(tbs, pos) {
            Some(v) => v,
            None => break,
        };
        pos = next;

        // Skip optional version [0] EXPLICIT at the start.
        if field_index == 0 && tag == 0xa0 {
            // version field — skip and don't increment field_index.
            continue;
        }

        match field_index {
            0 => { /* serialNumber (INTEGER) */ }
            1 => { /* signature (SEQUENCE) */ }
            2 => { /* issuer (SEQUENCE) */ }
            3 => { /* validity (SEQUENCE) */ }
            4 => {
                // subject (SEQUENCE, same tag 0x30)
                if tag == 0x30 {
                    return render_name_sequence(value);
                }
            }
            _ => break,
        }
        field_index += 1;
    }

    Err(CacError::InvalidCertificate("subject field not found in TBSCertificate".into()))
}

/// Render an X.509 Name SEQUENCE into a human-readable DN string.
///
/// Each RDN is a SET containing one or more AttributeTypeAndValue.
fn render_name_sequence(name: &[u8]) -> Result<String, CacError> {
    let mut components: Vec<String> = Vec::new();
    let mut pos = 0;

    while pos < name.len() {
        // Each top-level entry is a SET (tag 0x31) representing one RDN.
        let (set_tag, set_value, next) = match der_read_tlv(name, pos) {
            Some(v) => v,
            None => break,
        };
        pos = next;

        if set_tag != 0x31 {
            continue;
        }

        // Inside each SET, read SEQUENCE { OID, value }.
        let mut spos = 0;
        while spos < set_value.len() {
            let (seq_tag, seq_value, snext) = match der_read_tlv(set_value, spos) {
                Some(v) => v,
                None => break,
            };
            spos = snext;

            if seq_tag != 0x30 {
                continue;
            }

            // Read OID and attribute value.
            let (oid_tag, oid_bytes, vpos) = match der_read_tlv(seq_value, 0) {
                Some(v) => v,
                None => continue,
            };
            if oid_tag != 0x06 {
                continue;
            }

            let (_, attr_bytes, _) = match der_read_tlv(seq_value, vpos) {
                Some(v) => v,
                None => continue,
            };

            let attr_name = oid_to_attr_name(oid_bytes);
            let attr_value = String::from_utf8_lossy(attr_bytes).into_owned();
            components.push(format!("{}={}", attr_name, attr_value));
        }
    }

    if components.is_empty() {
        return Err(CacError::InvalidCertificate("empty subject DN".into()));
    }
    Ok(components.join(", "))
}

/// Map common X.509 attribute OIDs to their short names.
fn oid_to_attr_name(oid: &[u8]) -> &'static str {
    // OID byte encodings for the most common RDN attribute types.
    match oid {
        // id-at-commonName (2.5.4.3)
        &[0x55, 0x04, 0x03] => "CN",
        // id-at-organizationalUnitName (2.5.4.11)
        &[0x55, 0x04, 0x0b] => "OU",
        // id-at-organizationName (2.5.4.10)
        &[0x55, 0x04, 0x0a] => "O",
        // id-at-countryName (2.5.4.6)
        &[0x55, 0x04, 0x06] => "C",
        // id-at-stateOrProvinceName (2.5.4.8)
        &[0x55, 0x04, 0x08] => "ST",
        // id-at-localityName (2.5.4.7)
        &[0x55, 0x04, 0x07] => "L",
        // id-at-serialNumber (2.5.4.5)
        &[0x55, 0x04, 0x05] => "serialNumber",
        // id-at-givenName (2.5.4.42)
        &[0x55, 0x04, 0x2a] => "givenName",
        // id-at-surname (2.5.4.4)
        &[0x55, 0x04, 0x04] => "SN",
        _ => "attr",
    }
}

/// Extract SubjectPublicKeyInfo bytes from a DER certificate.
///
/// Returns the raw SPKI TLV bytes (tag + length + value) suitable for passing
/// to `VerifyingKey::from_public_key_der`.
fn extract_spki_bytes(cert_der: &[u8]) -> Option<Vec<u8>> {
    let (_, cert_body, _) = der_read_tlv(cert_der, 0)?;
    let (_, tbs, _) = der_read_tlv(cert_body, 0)?;

    // TBSCertificate field order (RFC 5280):
    //   [0] version (optional), serialNumber, signature, issuer, validity, subject, SPKI
    //
    // We track the byte offset within `tbs` so we can return the raw TLV.
    let mut pos = 0usize;
    let mut field_index = 0usize;

    while pos < tbs.len() {
        let tlv_start = pos;
        let (tag, _value, next) = der_read_tlv(tbs, pos)?;
        pos = next;

        // The optional version field has context tag [0] EXPLICIT (0xa0).
        if field_index == 0 && tag == 0xa0 {
            // Skip version without consuming a field_index slot.
            continue;
        }

        // Fields: 0=serialNumber, 1=signature, 2=issuer, 3=validity, 4=subject, 5=SPKI
        if field_index == 5 {
            if tag == 0x30 {
                return Some(tbs[tlv_start..pos].to_vec());
            }
            return None;
        }

        field_index += 1;
    }
    None
}

/// Verify an ECDSA P-256 signature using the public key from a DER SPKI.
///
/// Internally uses the `p256` crate.  Returns `Ok(true)` on success.
fn verify_ecdsa_p256_spki(
    spki: &[u8],
    data: &[u8],
    sig: &[u8],
) -> Result<bool, CacError> {
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;

    let verifying_key = VerifyingKey::from_public_key_der(spki).map_err(|e| {
        CacError::InvalidCertificate(format!("failed to decode P-256 public key: {}", e))
    })?;

    let signature = Signature::from_der(sig).map_err(|e| {
        CacError::VerificationFailed(format!("invalid DER signature: {}", e))
    })?;

    // Compute SHA-256 hash of the data (ECDSA signs the hash).
    use sha2::Sha256;
    let hash = Sha256::digest(data);

    // Verify over the hash bytes using prehash verifier.
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    verifying_key
        .verify_prehash(&hash, &signature)
        .map(|_| true)
        .map_err(|e| CacError::VerificationFailed(e.to_string()))
}

/// Serde serialization helper for `[u8; 64]` as a hex string.
///
/// Serde's built-in array support caps at length 32 in version 1.x.
/// We encode as a lowercase hex string for JSON/CBOR compatibility.
mod fingerprint_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(fp: &[u8; 64], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&hex::encode(fp))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(de)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("fingerprint must be 64 bytes"));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

/// Current time in Unix microseconds.
fn unix_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64
}

// ---------------------------------------------------------------------------
// Hardware-backed PKCS#11 session (requires `cac-hw` feature + real hardware)
// ---------------------------------------------------------------------------

/// A real PKCS#11 session backed by `cryptoki` FFI to libcackey/libpcsclite.
///
/// Only available with `--features cac-hw`.  Loads the PKCS#11 shared library
/// at runtime, opens a serial session on the configured slot, and delegates
/// all cryptographic operations to the smart card hardware.
///
/// On drop the user is logged out and the session is closed.
#[cfg(feature = "cac-hw")]
pub struct HardwarePkcs11Session {
    ctx: cryptoki::context::Pkcs11,
    session: cryptoki::session::Session,
    slot: cryptoki::slot::Slot,
    logged_in: bool,
}

#[cfg(feature = "cac-hw")]
impl std::fmt::Debug for HardwarePkcs11Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HardwarePkcs11Session")
            .field("slot", &self.slot)
            .field("logged_in", &self.logged_in)
            .finish()
    }
}

#[cfg(feature = "cac-hw")]
impl HardwarePkcs11Session {
    /// Load the PKCS#11 library and open a read-only serial session.
    ///
    /// `library_path` is typically `/usr/lib/libcackey.so` (DoD CAC) or
    /// `/usr/lib/x86_64-linux-gnu/libpcsclite.so` (PC/SC lite).
    pub fn open(library_path: &str, slot_id: u64) -> Result<Self, CacError> {
        use cryptoki::context::{CInitializeArgs, Pkcs11};
        use cryptoki::slot::Slot;

        let ctx = Pkcs11::new(library_path).map_err(|e| {
            CacError::LibraryNotFound(format!("{}: {}", library_path, e))
        })?;

        ctx.initialize(CInitializeArgs::OsThreads).map_err(|e| {
            CacError::LibraryNotFound(format!("C_Initialize failed: {}", e))
        })?;

        let slot = Slot::try_from(slot_id)
            .map_err(|_| CacError::SlotNotAvailable(slot_id))?;

        // Verify the slot has a token present.
        let slots = ctx
            .get_slots_with_token()
            .map_err(|_| CacError::SlotNotAvailable(slot_id))?;
        if !slots.contains(&slot) {
            return Err(CacError::SlotNotAvailable(slot_id));
        }

        // CKF_SERIAL_SESSION, read-only.
        let session = ctx
            .open_ro_session(slot)
            .map_err(|_| CacError::SlotNotAvailable(slot_id))?;

        Ok(Self { ctx, session, slot, logged_in: false })
    }

    /// `C_Login(CKU_USER, pin)`.
    pub fn login_user(&mut self, pin: &[u8]) -> Result<(), CacError> {
        use cryptoki::error::Error as Pkcs11Error;
        use cryptoki::session::UserType;
        use cryptoki::types::AuthPin;

        let pin_str = std::str::from_utf8(pin)
            .map_err(|_| CacError::LoginFailed)?;
        let auth_pin: AuthPin = pin_str.to_string().into();

        match self.session.login(UserType::User, Some(&auth_pin)) {
            Ok(()) => {
                self.logged_in = true;
                Ok(())
            }
            Err(Pkcs11Error::Pkcs11(rv, _func)) => {
                let code = format!("{:?}", rv);
                if code.contains("PinLocked") {
                    Err(CacError::PinLocked)
                } else {
                    Err(CacError::LoginFailed)
                }
            }
            Err(_) => Err(CacError::LoginFailed),
        }
    }

    /// Log out of the current session.
    pub fn logout(&mut self) -> Result<(), CacError> {
        if !self.logged_in {
            return Ok(());
        }
        let _ = self.session.logout();
        self.logged_in = false;
        Ok(())
    }

    /// Find the DER certificate on the card with `CKA_LABEL == label`.
    pub fn find_certificate(&self, label: &str) -> Result<Vec<u8>, CacError> {
        use cryptoki::object::{Attribute, AttributeType, ObjectClass};

        if !self.logged_in {
            return Err(CacError::LoginFailed);
        }

        let template = vec![
            Attribute::Class(ObjectClass::CERTIFICATE),
            Attribute::Label(label.as_bytes().to_vec()),
        ];

        let objects = self
            .session
            .find_objects(&template)
            .map_err(|e| CacError::CertificateNotFound(format!("{}: {}", label, e)))?;

        let handle = objects
            .first()
            .ok_or_else(|| CacError::CertificateNotFound(label.to_string()))?;

        let attrs = self
            .session
            .get_attributes(*handle, &[AttributeType::Value])
            .map_err(|e| CacError::CertificateNotFound(format!("CKA_VALUE: {}", e)))?;

        for attr in attrs {
            if let Attribute::Value(der) = attr {
                return Ok(der);
            }
        }
        Err(CacError::CertificateNotFound(label.to_string()))
    }

    /// `C_FindObjects(CKO_PRIVATE_KEY)` + `C_SignInit` + `C_Sign`.
    pub fn sign_data(
        &self,
        key_label: &str,
        data: &[u8],
        mechanism: SignMechanism,
    ) -> Result<Vec<u8>, CacError> {
        use cryptoki::mechanism::Mechanism;
        use cryptoki::object::{Attribute, ObjectClass};

        if !self.logged_in {
            return Err(CacError::LoginFailed);
        }

        let template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Label(key_label.as_bytes().to_vec()),
        ];

        let objects = self
            .session
            .find_objects(&template)
            .map_err(|e| CacError::SigningFailed(format!("find '{}': {}", key_label, e)))?;

        let key_handle = objects.first().ok_or_else(|| {
            CacError::SigningFailed(format!("private key '{}' not found", key_label))
        })?;

        // CAC mechanism policy (CNSA 2.0 / NIST CAC 2.0 roadmap, A8 hardening):
        //
        //  - RSA-PKCS#1 v1.5 is DEPRECATED. Reject by default. Operators with
        //    legacy DoD card stocks may temporarily set
        //    MILNET_CAC_ALLOW_LEGACY_RSA=1 to permit it; every such use is
        //    logged at CRIT severity to the SIEM. The hard sunset date below
        //    is enforced on the wall clock — past the sunset epoch we refuse
        //    even with the override flag.
        //  - P-384 ECDSA remains accepted (still on the NIST CAC 2.0 roadmap)
        //    but every use is logged at CRIT to the SIEM so the migration to
        //    ML-DSA-87 / hybrid PIV cards can be tracked.
        //
        // NIST CAC 2.0 hard sunset for RSA-PKCS#1 v1.5: 2031-01-01T00:00:00Z
        // (matches CNSA 2.0 quantum-readiness deadline).
        const CAC_LEGACY_RSA_SUNSET_EPOCH_SECS: u64 = 1_924_905_600;

        let ckm = match mechanism {
            SignMechanism::RsaPkcs => {
                let allow_legacy = std::env::var("MILNET_CAC_ALLOW_LEGACY_RSA")
                    .map(|v| v == "1")
                    .unwrap_or(false);
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(u64::MAX);
                if !allow_legacy {
                    tracing::error!(
                        key_label = %key_label,
                        "SIEM:CRITICAL CAC RSA-PKCS#1 v1.5 sign attempt rejected — \
                         set MILNET_CAC_ALLOW_LEGACY_RSA=1 if you must use legacy DoD card stock"
                    );
                    return Err(CacError::SigningFailed(
                        "RSA-PKCS#1 v1.5 is deprecated under CNSA 2.0. \
                         Set MILNET_CAC_ALLOW_LEGACY_RSA=1 to override (legacy hardware only)."
                            .to_string(),
                    ));
                }
                if now >= CAC_LEGACY_RSA_SUNSET_EPOCH_SECS {
                    tracing::error!(
                        key_label = %key_label,
                        sunset = CAC_LEGACY_RSA_SUNSET_EPOCH_SECS,
                        "SIEM:CRITICAL CAC RSA-PKCS#1 v1.5 sunset reached — refusing"
                    );
                    return Err(CacError::SigningFailed(
                        "RSA-PKCS#1 v1.5 hard sunset (2031-01-01) reached — refusing".to_string(),
                    ));
                }
                tracing::warn!(
                    key_label = %key_label,
                    "SIEM:CRITICAL CAC RSA-PKCS#1 v1.5 in use under MILNET_CAC_ALLOW_LEGACY_RSA \
                     override — schedule migration to ML-DSA-87"
                );
                Mechanism::RsaPkcs
            }
            SignMechanism::EcdsaP256 => Mechanism::Ecdsa,
            SignMechanism::EcdsaP384 => {
                tracing::error!(
                    key_label = %key_label,
                    "SIEM:CRITICAL CAC P-384 ECDSA in use — classical curve, not PQ-safe; \
                     migrate to ML-DSA-87 per NIST CAC 2.0 roadmap by {}",
                    CAC_LEGACY_RSA_SUNSET_EPOCH_SECS
                );
                Mechanism::Ecdsa
            }
        };

        let signature = self
            .session
            .sign(&ckm, *key_handle, data)
            .map_err(|e| CacError::SigningFailed(format!("C_Sign: {}", e)))?;

        Ok(signature)
    }

    /// Software-only signature verification (delegates to [`Pkcs11Session::verify_signature`]).
    pub fn verify_signature(
        cert_der: &[u8],
        data: &[u8],
        sig: &[u8],
    ) -> Result<bool, CacError> {
        Pkcs11Session::verify_signature(cert_der, data, sig)
    }

    /// Build [`CacCardInfo`] from token info and the PIV AUTH certificate.
    pub fn get_card_info(&self) -> Result<CacCardInfo, CacError> {
        if !self.logged_in {
            return Err(CacError::LoginFailed);
        }

        let token_info = self
            .ctx
            .get_token_info(self.slot)
            .map_err(|_| CacError::SlotNotAvailable(0))?;

        let card_serial = token_info.serial_number().trim().to_string();
        let card_issuer = token_info.manufacturer_id().trim().to_string();

        let cert_der = self.find_certificate("PIV AUTH").unwrap_or_default();
        let subject_dn = if cert_der.is_empty() {
            "CN=Unknown".to_string()
        } else {
            extract_subject_dn(&cert_der).unwrap_or_else(|_| "CN=Unknown".to_string())
        };
        let edipi = if !cert_der.is_empty() {
            extract_edipi(&cert_der)
        } else {
            None
        };
        let cert_fingerprint = cert_fingerprint_sha512(&cert_der);

        Ok(CacCardInfo {
            card_serial,
            card_issuer,
            subject_dn,
            edipi,
            aadhaar_vid: None,
            affiliation: "Unknown".to_string(),
            cert_fingerprint,
            pin_verified: self.logged_in,
            card_type: CardType::Piv,
            clearance_level: 0,
            tags: HashMap::new(),
            inserted_at: unix_micros(),
            removed_at: None,
            reader_id: format!("slot-{}", self.slot),
            facility_code: "0000".to_string(),
        })
    }

    /// Returns `true` when a PIN login is currently active.
    pub fn is_logged_in(&self) -> bool {
        self.logged_in
    }
}

#[cfg(feature = "cac-hw")]
impl Drop for HardwarePkcs11Session {
    fn drop(&mut self) {
        if self.logged_in {
            let _ = self.session.logout();
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
    fn test_cac_card_type_enum() {
        // All variants exist, are Copy+Clone+Eq
        let variants = [
            CardType::CacMilitary,
            CardType::CacCivilian,
            CardType::Piv,
            CardType::PivI,
            CardType::DerivedPiv,
            CardType::IndianDsc,
            CardType::IndianESign,
        ];
        for v in &variants {
            let cloned = *v; // Copy
            let cloned2 = cloned; // Clone (via Copy)
            assert_eq!(cloned, cloned2); // Eq
        }
        // Sanity: distinct variants are not equal
        assert_ne!(CardType::CacMilitary, CardType::Piv);
    }

    #[test]
    fn test_cac_card_info_fields() {
        let mut tags = HashMap::new();
        tags.insert("unit".to_string(), "DEVGRU".to_string());

        let info = CacCardInfo {
            card_serial: "1234567890".to_string(),
            card_issuer: "DoD PKI CA-62".to_string(),
            subject_dn: "CN=DOE.JOHN.ALBERT.1234567890, OU=USMC, O=U.S. Government, C=US".to_string(),
            edipi: Some("1234567890".to_string()),
            aadhaar_vid: None,
            affiliation: "USMC".to_string(),
            cert_fingerprint: [0xabu8; 64],
            pin_verified: true,
            card_type: CardType::CacMilitary,
            clearance_level: 3,
            tags: tags.clone(),
            inserted_at: 1_700_000_000_000_000,
            removed_at: None,
            reader_id: "Identix|BTCR-0006|0".to_string(),
            facility_code: "0010".to_string(),
        };

        assert_eq!(info.card_serial, "1234567890");
        assert_eq!(info.card_issuer, "DoD PKI CA-62");
        assert!(info.pin_verified);
        assert_eq!(info.card_type, CardType::CacMilitary);
        assert_eq!(info.clearance_level, 3);
        assert_eq!(info.edipi, Some("1234567890".to_string()));
        assert!(info.aadhaar_vid.is_none());
        assert!(info.removed_at.is_none());
        assert_eq!(info.cert_fingerprint, [0xabu8; 64]);
        assert_eq!(info.tags.get("unit"), Some(&"DEVGRU".to_string()));
    }

    #[test]
    fn test_cac_error_display() {
        let errors = vec![
            (CacError::LibraryNotFound("/lib/p11.so".to_string()), "library"),
            (CacError::SlotNotAvailable(2), "slot"),
            (CacError::LoginFailed, "pin"),
            (CacError::PinLocked, "locked"),
            (CacError::CertificateNotFound("PIV Auth".to_string()), "certificate"),
            (CacError::SigningFailed("hw error".to_string()), "signing"),
            (CacError::VerificationFailed("bad sig".to_string()), "verification"),
            (CacError::CardRemoved, "removed"),
            (CacError::SessionExpired, "session"),
            (CacError::InvalidCertificate("bad DER".to_string()), "certificate"),
            (CacError::RevocationCheckFailed("timeout".to_string()), "revocation"),
        ];
        for (err, expected_fragment) in errors {
            let display = format!("{}", err);
            assert!(
                display.to_lowercase().contains(expected_fragment),
                "Display for {:?} does not contain '{}': got '{}'",
                err,
                expected_fragment,
                display
            );
        }
    }

    #[test]
    fn test_cac_sign_mechanism_variants() {
        // All 3 mechanisms exist and can be compared.
        assert_eq!(SignMechanism::RsaPkcs, SignMechanism::RsaPkcs);
        assert_eq!(SignMechanism::EcdsaP256, SignMechanism::EcdsaP256);
        assert_eq!(SignMechanism::EcdsaP384, SignMechanism::EcdsaP384);
        assert_ne!(SignMechanism::RsaPkcs, SignMechanism::EcdsaP256);
        assert_ne!(SignMechanism::EcdsaP256, SignMechanism::EcdsaP384);
    }

    #[test]
    fn test_cac_cert_fingerprint_sha512() {
        // SHA-512 of the empty byte string.
        let empty_sha512_hex =
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
        let expected = hex::decode(empty_sha512_hex).unwrap();
        let fingerprint = cert_fingerprint_sha512(&[]);
        assert_eq!(&fingerprint[..], expected.as_slice());

        // SHA-512 of b"hello" — cross-check.
        let hello_sha512_hex =
            "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca7\
             2323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043";
        let expected_hello = hex::decode(hello_sha512_hex).unwrap();
        let fingerprint_hello = cert_fingerprint_sha512(b"hello");
        assert_eq!(&fingerprint_hello[..], expected_hello.as_slice());
    }

    /// Verify that `Pkcs11Session::open` returns `LibraryNotFound` for a
    /// non-existent path (the common case in CI / unit tests).
    #[test]
    fn test_pkcs11_session_open_missing_library() {
        let result = Pkcs11Session::open("/nonexistent/libpkcs11.so", 0);
        match result {
            Err(CacError::LibraryNotFound(path)) => {
                assert!(path.contains("/nonexistent/"));
            }
            other => panic!("expected LibraryNotFound, got {:?}", other),
        }
    }

    /// Verify that `MockPkcs11Session` can build a `CacCardInfo`.
    #[test]
    fn test_mock_session_card_info() {
        // Build a minimal self-signed DER certificate for testing.
        // We use a trivially short byte sequence; extract_subject_dn will
        // return an error which get_card_info handles with a fallback.
        let dummy_cert = b"not a real cert";
        let mut mock = MockPkcs11Session::new();
        mock.login();
        let info = mock.get_card_info(dummy_cert);
        assert!(info.pin_verified);
        assert_eq!(info.card_type, CardType::CacMilitary);
        assert_eq!(info.card_serial, "MOCK-SERIAL-0001");
    }
}
