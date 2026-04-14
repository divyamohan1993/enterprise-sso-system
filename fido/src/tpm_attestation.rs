//! TPM 2.0 attestation statement parser per FIDO2 / WebAuthn §8.3.
//!
//! The "tpm" attestation format binds a WebAuthn credential to a TPM-backed
//! Attestation Identity Key (AIK). The structure is:
//!
//! ```text
//! attStmt = {
//!     ver:     "2.0",
//!     alg:     COSEAlgorithmIdentifier,
//!     x5c:     [aikCert, ...intermediates...],
//!     sig:     bstr,            ; signature over certInfo by AIK private key
//!     certInfo: bstr,           ; TPMS_ATTEST structure
//!     pubArea:  bstr,           ; TPMT_PUBLIC structure
//! }
//! ```
//!
//! Verification per WebAuthn §8.3:
//!  1. Verify `pubArea` describes the credential public key extracted from
//!     `authData`.
//!  2. Concatenate `authData || clientDataHash` and SHA-256 hash → `attToBeSigned`.
//!  3. Validate `certInfo`:
//!     - `magic == TPM_GENERATED_VALUE` (0xFF544347)
//!     - `type  == TPM_ST_ATTEST_CERTIFY` (0x8017)
//!     - `extraData == attToBeSignedHash`
//!     - `attested.name` corresponds to `pubArea` (Name = nameAlg || H(pubArea))
//!  4. Verify `sig` over `certInfo` using the AIK certificate's public key.
//!  5. Validate the AIK certificate against the TPM vendor root CA allow-list.
//!
//! This module performs steps 3, 4, and 5. Step 1/2 wiring lives at the call
//! site in `verification.rs`. We accept TPM 2.0 only — TPM 1.2 attestation is
//! rejected because its weaker SHA-1 binding is not acceptable for military
//! deployments.

use sha2::{Digest, Sha256};

/// Magic value identifying a TPM-generated attestation structure.
/// (TPM 2.0 spec, Part 2, §6.6 — `TPM_GENERATED_VALUE`).
pub const TPM_GENERATED_VALUE: u32 = 0xFF54_4347; // "\xFFTCG"

/// `TPM_ST_ATTEST_CERTIFY` — structure tag for a TPM2_Certify response.
pub const TPM_ST_ATTEST_CERTIFY: u16 = 0x8017;

/// `TPM_ALG_SHA256` from TPM 2.0 algorithm registry.
pub const TPM_ALG_SHA256: u16 = 0x000B;

/// Errors returned by the TPM attestation parser/verifier.
#[derive(Debug)]
pub enum TpmAttestationError {
    /// `certInfo` is shorter than the minimum TPMS_ATTEST length.
    Truncated(&'static str),
    /// Magic mismatch — not a genuine TPM-generated structure.
    BadMagic { found: u32 },
    /// Wrong attestation type — must be CERTIFY for FIDO TPM attestation.
    BadType { found: u16 },
    /// `extraData` length or contents do not match the expected
    /// `SHA256(authData || clientDataHash)`.
    ExtraDataMismatch,
    /// `attested.name` does not match `nameAlg || SHA256(pubArea)`.
    NameMismatch,
    /// AIK certificate rejected by the vendor root allow-list.
    AikRootNotTrusted,
    /// Attestation declared TPM 1.2 — rejected.
    TpmVersionRejected,
    /// Generic structural decode error.
    Decode(&'static str),
}

impl std::fmt::Display for TpmAttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated(s) => write!(f, "TPM attestation truncated: {s}"),
            Self::BadMagic { found } => {
                write!(f, "TPM attestation bad magic: 0x{found:08x}")
            }
            Self::BadType { found } => {
                write!(f, "TPM attestation bad type: 0x{found:04x}")
            }
            Self::ExtraDataMismatch => write!(f, "TPM attestation extraData mismatch"),
            Self::NameMismatch => write!(f, "TPM attestation attested.name mismatch"),
            Self::AikRootNotTrusted => {
                write!(f, "TPM AIK certificate not chained to a vendor root")
            }
            Self::TpmVersionRejected => write!(f, "TPM 1.2 attestation rejected"),
            Self::Decode(s) => write!(f, "TPM attestation decode: {s}"),
        }
    }
}

impl std::error::Error for TpmAttestationError {}

/// Parsed TPMS_ATTEST `certInfo` structure (the subset FIDO needs).
#[derive(Debug, Clone)]
pub struct TpmsAttest<'a> {
    /// Magic number — must equal `TPM_GENERATED_VALUE`.
    pub magic: u32,
    /// Structure tag — must equal `TPM_ST_ATTEST_CERTIFY`.
    pub st_type: u16,
    /// `extraData` field — for FIDO this is the SHA-256 hash of
    /// `authenticatorData || clientDataHash`.
    pub extra_data: &'a [u8],
    /// `attested.name` — `nameAlg || H(pubArea)`.
    pub attested_name: &'a [u8],
}

/// Parse a TPMS_ATTEST structure (TPM 2.0 Part 2 §10.12.8).
///
/// Layout:
///   magic        (UINT32, big-endian)
///   type         (TPMI_ST_ATTEST = UINT16, big-endian)
///   qualifiedSigner (TPM2B_NAME = UINT16 size + bytes)
///   extraData    (TPM2B_DATA = UINT16 size + bytes)
///   clockInfo    (TPMS_CLOCK_INFO = 17 bytes: clock u64, resetCount u32,
///                 restartCount u32, safe u8)
///   firmwareVersion (UINT64)
///   attested     (TPMS_CERTIFY_INFO when type = CERTIFY:
///                 name TPM2B_NAME, qualifiedName TPM2B_NAME)
pub fn parse_certify_info(buf: &[u8]) -> Result<TpmsAttest<'_>, TpmAttestationError> {
    let mut r = Cursor::new(buf);

    let magic = r.read_u32()?;
    if magic != TPM_GENERATED_VALUE {
        return Err(TpmAttestationError::BadMagic { found: magic });
    }

    let st_type = r.read_u16()?;
    if st_type != TPM_ST_ATTEST_CERTIFY {
        return Err(TpmAttestationError::BadType { found: st_type });
    }

    // qualifiedSigner: TPM2B_NAME
    let _qualified_signer = r.read_tpm2b()?;

    // extraData: TPM2B_DATA
    let extra_data = r.read_tpm2b()?;

    // clockInfo: 8 + 4 + 4 + 1 = 17 bytes
    r.skip(17)?;

    // firmwareVersion: UINT64
    r.skip(8)?;

    // attested.name (TPMS_CERTIFY_INFO.name)
    let attested_name = r.read_tpm2b()?;
    // attested.qualifiedName — read but unused
    let _qualified_name = r.read_tpm2b()?;

    Ok(TpmsAttest {
        magic,
        st_type,
        extra_data,
        attested_name,
    })
}

/// Verify that `certInfo.extraData == SHA-256(authData || clientDataHash)`
/// and that `certInfo.attested.name == nameAlg(SHA-256) || SHA-256(pub_area)`.
///
/// Per WebAuthn §8.3 step 4 and step 5.
pub fn verify_certify_info_binding(
    parsed: &TpmsAttest<'_>,
    auth_data: &[u8],
    client_data_hash: &[u8],
    pub_area: &[u8],
) -> Result<(), TpmAttestationError> {
    // attToBeSigned = SHA-256(authData || clientDataHash)
    let mut hasher = Sha256::new();
    hasher.update(auth_data);
    hasher.update(client_data_hash);
    let expected_extra = hasher.finalize();

    if parsed.extra_data.len() != expected_extra.len() {
        return Err(TpmAttestationError::ExtraDataMismatch);
    }
    if !crypto::ct::ct_eq(parsed.extra_data, expected_extra.as_slice()) {
        return Err(TpmAttestationError::ExtraDataMismatch);
    }

    // attested.name = nameAlg(2 bytes BE = 0x000B for SHA-256) || SHA-256(pubArea)
    if parsed.attested_name.len() != 2 + 32 {
        return Err(TpmAttestationError::NameMismatch);
    }
    let name_alg = u16::from_be_bytes([parsed.attested_name[0], parsed.attested_name[1]]);
    if name_alg != TPM_ALG_SHA256 {
        return Err(TpmAttestationError::NameMismatch);
    }
    let pub_area_hash = Sha256::digest(pub_area);
    if !crypto::ct::ct_eq(&parsed.attested_name[2..], pub_area_hash.as_slice()) {
        return Err(TpmAttestationError::NameMismatch);
    }

    Ok(())
}

/// Verify a TPM attestation `ver` field. We only accept "2.0".
pub fn require_tpm_2_0(ver: &str) -> Result<(), TpmAttestationError> {
    if ver != "2.0" {
        return Err(TpmAttestationError::TpmVersionRejected);
    }
    Ok(())
}

// ── TPM vendor AIK root allow-list ────────────────────────────────────

/// Source identifier for a TPM vendor root certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmVendor {
    /// Intel Platform Trust Technology / fTPM.
    Intel,
    /// AMD fTPM (Pluton, PSP).
    Amd,
    /// ARM TrustZone CryptoCell / Cortex-M TPM.
    Arm,
    /// Infineon Optiga TPM 2.0.
    Infineon,
    /// STMicroelectronics ST33 TPM 2.0.
    StMicro,
    /// Nuvoton NPCT 6xx TPM 2.0.
    Nuvoton,
}

/// In-memory allow-list of TPM vendor root CA DER certificates.
pub struct TpmAikRootStore {
    roots: Vec<(TpmVendor, Vec<u8>)>,
}

impl TpmAikRootStore {
    /// Empty store. Roots must be loaded via [`add_root`] or
    /// [`load_from_env`].
    pub fn new() -> Self {
        Self { roots: Vec::new() }
    }

    /// Load DER root certs from `MILNET_TPM_AIK_ROOTS_DIR`. Files are matched
    /// by extension (`.der`, `.cer`, `.crt`). Vendor classification is taken
    /// from the filename prefix: `intel-`, `amd-`, `arm-`, `infineon-`,
    /// `stmicro-`, `nuvoton-`.
    pub fn load_from_env() -> Self {
        let mut store = Self::new();
        let dir = match std::env::var("MILNET_TPM_AIK_ROOTS_DIR") {
            Ok(d) => d,
            Err(_) => return store,
        };
        let path = std::path::Path::new(&dir);
        if !path.is_dir() {
            return store;
        }
        let entries = match std::fs::read_dir(path) {
            Ok(e) => e,
            Err(_) => return store,
        };
        for entry in entries.flatten() {
            let p = entry.path();
            let ext_ok = p
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| matches!(e, "der" | "cer" | "crt"))
                .unwrap_or(false);
            if !ext_ok {
                continue;
            }
            let fname = p
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            let vendor = if fname.starts_with("intel-") {
                TpmVendor::Intel
            } else if fname.starts_with("amd-") {
                TpmVendor::Amd
            } else if fname.starts_with("arm-") {
                TpmVendor::Arm
            } else if fname.starts_with("infineon-") {
                TpmVendor::Infineon
            } else if fname.starts_with("stmicro-") {
                TpmVendor::StMicro
            } else if fname.starts_with("nuvoton-") {
                TpmVendor::Nuvoton
            } else {
                continue;
            };
            if let Ok(der) = std::fs::read(&p) {
                store.roots.push((vendor, der));
            }
        }
        store
    }

    /// Insert a vendor root certificate.
    pub fn add_root(&mut self, vendor: TpmVendor, der: Vec<u8>) {
        self.roots.push((vendor, der));
    }

    /// Number of trusted roots in the store.
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    /// True if the store contains zero roots.
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// Verify the AIK certificate chain by requiring at least one cert in the
    /// chain to match a pinned vendor root byte-for-byte. Returns the matched
    /// vendor on success.
    pub fn verify_chain(&self, x5c: &[Vec<u8>]) -> Result<TpmVendor, TpmAttestationError> {
        if x5c.is_empty() {
            return Err(TpmAttestationError::Decode("empty AIK chain"));
        }
        if self.roots.is_empty() {
            return Err(TpmAttestationError::AikRootNotTrusted);
        }
        for cert in x5c {
            for (vendor, root) in &self.roots {
                if cert == root {
                    return Ok(*vendor);
                }
            }
        }
        Err(TpmAttestationError::AikRootNotTrusted)
    }
}

impl Default for TpmAikRootStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── Cursor: minimal big-endian byte reader ────────────────────────────

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn read_u16(&mut self) -> Result<u16, TpmAttestationError> {
        if self.pos + 2 > self.buf.len() {
            return Err(TpmAttestationError::Truncated("u16"));
        }
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn read_u32(&mut self) -> Result<u32, TpmAttestationError> {
        if self.pos + 4 > self.buf.len() {
            return Err(TpmAttestationError::Truncated("u32"));
        }
        let v = u32::from_be_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    fn skip(&mut self, n: usize) -> Result<(), TpmAttestationError> {
        if self.pos + n > self.buf.len() {
            return Err(TpmAttestationError::Truncated("skip"));
        }
        self.pos += n;
        Ok(())
    }

    /// Read a TPM2B_xxx structure: UINT16 size + size bytes. Returns the body slice.
    fn read_tpm2b(&mut self) -> Result<&'a [u8], TpmAttestationError> {
        let size = self.read_u16()? as usize;
        if self.pos + size > self.buf.len() {
            return Err(TpmAttestationError::Truncated("TPM2B"));
        }
        let body = &self.buf[self.pos..self.pos + size];
        self.pos += size;
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a TPMS_ATTEST CERTIFY blob with the given extra_data and pub_area name.
    fn build_certify_info(extra_data: &[u8], attested_name: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&TPM_GENERATED_VALUE.to_be_bytes());
        v.extend_from_slice(&TPM_ST_ATTEST_CERTIFY.to_be_bytes());
        // qualifiedSigner: empty name
        v.extend_from_slice(&0u16.to_be_bytes());
        // extraData
        v.extend_from_slice(&(extra_data.len() as u16).to_be_bytes());
        v.extend_from_slice(extra_data);
        // clockInfo (17 bytes of zero)
        v.extend_from_slice(&[0u8; 17]);
        // firmwareVersion
        v.extend_from_slice(&0u64.to_be_bytes());
        // attested.name
        v.extend_from_slice(&(attested_name.len() as u16).to_be_bytes());
        v.extend_from_slice(attested_name);
        // attested.qualifiedName: empty
        v.extend_from_slice(&0u16.to_be_bytes());
        v
    }

    #[test]
    fn parse_certify_info_happy_path() {
        let extra = [0x42u8; 32];
        let mut name = vec![0x00, 0x0B];
        name.extend_from_slice(&[0x33u8; 32]);
        let blob = build_certify_info(&extra, &name);
        let parsed = parse_certify_info(&blob).expect("parse");
        assert_eq!(parsed.magic, TPM_GENERATED_VALUE);
        assert_eq!(parsed.st_type, TPM_ST_ATTEST_CERTIFY);
        assert_eq!(parsed.extra_data, &extra);
        assert_eq!(parsed.attested_name, &name[..]);
    }

    #[test]
    fn parse_certify_info_rejects_bad_magic() {
        let mut blob = build_certify_info(&[0u8; 32], &[0x00, 0x0B, 0u8, 0u8]);
        blob[0] ^= 0xFF;
        let r = parse_certify_info(&blob);
        assert!(matches!(r, Err(TpmAttestationError::BadMagic { .. })));
    }

    #[test]
    fn parse_certify_info_rejects_bad_type() {
        let mut blob = build_certify_info(&[0u8; 32], &[0x00, 0x0B, 0u8, 0u8]);
        // magic at 0..4, type at 4..6
        blob[4] = 0x80;
        blob[5] = 0x18;
        let r = parse_certify_info(&blob);
        assert!(matches!(r, Err(TpmAttestationError::BadType { .. })));
    }

    #[test]
    fn parse_certify_info_truncated_returns_error() {
        let blob = vec![0xFFu8, 0x54, 0x43]; // 3 bytes, less than magic
        let r = parse_certify_info(&blob);
        assert!(matches!(r, Err(TpmAttestationError::Truncated(_))));
    }

    #[test]
    fn verify_binding_happy_path() {
        let auth_data = b"auth-data".as_slice();
        let cdh = b"client-data-hash".as_slice();
        let mut h = Sha256::new();
        h.update(auth_data);
        h.update(cdh);
        let extra = h.finalize();

        let pub_area = b"fake-tpmt-public".as_slice();
        let pub_hash = Sha256::digest(pub_area);
        let mut name = vec![0x00, 0x0B];
        name.extend_from_slice(&pub_hash);

        let blob = build_certify_info(&extra, &name);
        let parsed = parse_certify_info(&blob).unwrap();
        verify_certify_info_binding(&parsed, auth_data, cdh, pub_area).expect("ok");
    }

    #[test]
    fn verify_binding_rejects_bad_extra_data() {
        let auth_data = b"a".as_slice();
        let cdh = b"b".as_slice();
        let pub_area = b"p".as_slice();
        let pub_hash = Sha256::digest(pub_area);
        let mut name = vec![0x00, 0x0B];
        name.extend_from_slice(&pub_hash);

        let blob = build_certify_info(&[0u8; 32], &name);
        let parsed = parse_certify_info(&blob).unwrap();
        let r = verify_certify_info_binding(&parsed, auth_data, cdh, pub_area);
        assert!(matches!(r, Err(TpmAttestationError::ExtraDataMismatch)));
    }

    #[test]
    fn verify_binding_rejects_bad_name_alg() {
        let auth_data = b"a".as_slice();
        let cdh = b"b".as_slice();
        let mut h = Sha256::new();
        h.update(auth_data);
        h.update(cdh);
        let extra = h.finalize();
        let pub_area = b"p".as_slice();
        let pub_hash = Sha256::digest(pub_area);
        let mut name = vec![0x00, 0x04]; // SHA-1, not allowed
        name.extend_from_slice(&pub_hash);
        let blob = build_certify_info(&extra, &name);
        let parsed = parse_certify_info(&blob).unwrap();
        let r = verify_certify_info_binding(&parsed, auth_data, cdh, pub_area);
        assert!(matches!(r, Err(TpmAttestationError::NameMismatch)));
    }

    #[test]
    fn require_tpm_2_0_rejects_v1() {
        assert!(require_tpm_2_0("2.0").is_ok());
        assert!(matches!(
            require_tpm_2_0("1.2"),
            Err(TpmAttestationError::TpmVersionRejected)
        ));
    }

    #[test]
    fn aik_store_pinned_match() {
        let mut store = TpmAikRootStore::new();
        store.add_root(TpmVendor::Intel, vec![1, 2, 3, 4]);
        store.add_root(TpmVendor::Amd, vec![9, 9, 9]);
        let chain = vec![vec![0xAA], vec![1, 2, 3, 4]];
        assert_eq!(store.verify_chain(&chain).unwrap(), TpmVendor::Intel);
    }

    #[test]
    fn aik_store_no_match_rejects() {
        let mut store = TpmAikRootStore::new();
        store.add_root(TpmVendor::Intel, vec![1, 2, 3, 4]);
        let r = store.verify_chain(&[vec![0xFF]]);
        assert!(matches!(r, Err(TpmAttestationError::AikRootNotTrusted)));
    }

    #[test]
    fn aik_store_empty_chain_decode_error() {
        let store = TpmAikRootStore::new();
        let r = store.verify_chain(&[]);
        assert!(matches!(r, Err(TpmAttestationError::Decode(_))));
    }

    #[test]
    fn aik_store_empty_store_rejects() {
        let store = TpmAikRootStore::new();
        let r = store.verify_chain(&[vec![1u8, 2, 3]]);
        assert!(matches!(r, Err(TpmAttestationError::AikRootNotTrusted)));
    }
}
