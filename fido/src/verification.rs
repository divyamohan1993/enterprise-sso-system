//! WebAuthn authenticator data parsing and signature verification.
//!
//! Implements complete FIDO2/WebAuthn verification per the W3C WebAuthn spec
//! (Level 2), including:
//! - Authenticator data parsing and validation (section 6.1)
//! - ECDSA P-256 (ES256) signature verification
//! - COSE key parsing (RFC 8152, algorithm -7 / ES256)
//! - Client data JSON validation (type, challenge, origin)
//! - Attestation verification ("none" and "packed" formats)
//!
//! CNSA 2.0 exception: SHA-256 is mandated by the W3C WebAuthn specification
//! and FIDO2 CTAP2 protocol for RP ID hashing and client data hashing.
//! Changing this hash would break all WebAuthn authenticators. CNSA 2.0
//! exception granted for FIDO2/WebAuthn interoperability.

use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};

/// Minimum authenticator data length:
///   32 bytes (RP ID hash) + 1 byte (flags) + 4 bytes (sign count) = 37
const MIN_AUTH_DATA_LEN: usize = 37;

/// Authenticator data flags (section 6.1).
const FLAG_UP: u8 = 0b0000_0001; // bit 0 -- User Present
const FLAG_UV: u8 = 0b0000_0100; // bit 2 -- User Verified
const FLAG_AT: u8 = 0b0100_0000; // bit 6 -- Attested credential data included
const _FLAG_ED: u8 = 0b1000_0000; // bit 7 -- Extension data included

// ── COSE key constants (RFC 8152 / RFC 9053) ──────────────────────────

/// COSE key type for EC2 (Elliptic Curve with x,y coordinates).
const COSE_KTY_EC2: i64 = 2;
/// COSE algorithm identifier for ES256 (ECDSA w/ SHA-256 on P-256).
const COSE_ALG_ES256: i64 = -7;
/// COSE EC2 curve identifier for P-256.
const COSE_CRV_P256: i64 = 1;

// COSE key map labels
const COSE_LABEL_KTY: i64 = 1;
const COSE_LABEL_ALG: i64 = 3;
const COSE_LABEL_CRV: i64 = -1;
const COSE_LABEL_X: i64 = -2;
const COSE_LABEL_Y: i64 = -3;

// ── DoS prevention bounds for CBOR/DER parsing ──────────────────────────
// SECURITY: Untrusted CBOR input can claim arbitrarily large map/array lengths,
// causing O(n) loops that exhaust CPU or memory. These bounds cap iteration to
// sane maximums far above any legitimate WebAuthn/COSE structure.

/// Maximum number of entries allowed in a CBOR map from untrusted input.
const MAX_CBOR_MAP_LEN: u64 = 256;
/// Maximum number of elements allowed in a CBOR array from untrusted input.
const MAX_CBOR_ARRAY_LEN: u64 = 256;
/// Maximum size of a single CBOR byte/text string from untrusted input (1 MB).
const MAX_CBOR_STRING_LEN: u64 = 1_048_576;
/// Maximum DER element length (64 KB — no legitimate X.509 cert exceeds this).
const MAX_DER_LENGTH: usize = 65536;

// ── Parsed structures ──────────────────────────────────────────────────

/// Parsed representation of the authenticator data binary blob.
#[derive(Debug, Clone)]
pub struct ParsedAuthData {
    /// SHA-256 hash of the RP ID that the authenticator used.
    pub rp_id_hash: [u8; 32],
    /// Raw flags byte.
    pub flags: u8,
    /// Signature counter reported by the authenticator.
    pub sign_count: u32,
    /// True if the User Present flag is set.
    pub user_present: bool,
    /// True if the User Verified flag is set.
    pub user_verified: bool,
    /// True if attested credential data is included.
    pub attested_credential_data: bool,
}

/// Parsed client data JSON (CollectedClientData per WebAuthn spec).
#[derive(Debug, Clone)]
pub struct ParsedClientData {
    /// The type field: "webauthn.create" or "webauthn.get".
    pub client_data_type: String,
    /// The base64url-encoded challenge.
    pub challenge: String,
    /// The origin (scheme + host + optional port).
    pub origin: String,
}

/// Data extracted from attestation during registration.
#[derive(Debug, Clone)]
pub struct AttestationData {
    pub credential_id: Vec<u8>,
    pub public_key_cose: Vec<u8>,
    pub sign_count: u32,
}

/// Result of attestation statement verification.
#[derive(Debug, Clone, PartialEq)]
pub enum AttestationType {
    /// No attestation was provided ("none" format).
    None,
    /// Self-attestation: the credential key signed its own attestation.
    SelfAttestation,
    /// Basic attestation with an attestation certificate chain.
    Basic,
}

// ── Authenticator data parsing ─────────────────────────────────────────

/// Parse the raw authenticator data bytes per WebAuthn section 6.1.
///
/// Returns the parsed structure or a descriptive error.
pub fn parse_authenticator_data(auth_data: &[u8]) -> Result<ParsedAuthData, &'static str> {
    if auth_data.len() < MIN_AUTH_DATA_LEN {
        return Err("Authenticator data too short (must be >= 37 bytes)");
    }

    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&auth_data[0..32]);

    let flags = auth_data[32];

    let sign_count = u32::from_be_bytes([
        auth_data[33],
        auth_data[34],
        auth_data[35],
        auth_data[36],
    ]);

    Ok(ParsedAuthData {
        rp_id_hash,
        flags,
        sign_count,
        user_present: flags & FLAG_UP != 0,
        user_verified: flags & FLAG_UV != 0,
        attested_credential_data: flags & FLAG_AT != 0,
    })
}

/// Validate that the RP ID hash in authenticator data matches the expected RP ID.
pub fn validate_rp_id_hash(parsed: &ParsedAuthData, expected_rp_id: &str) -> Result<(), &'static str> {
    let expected_hash = Sha256::digest(expected_rp_id.as_bytes());
    if parsed.rp_id_hash[..] != expected_hash[..] {
        return Err("RP ID hash mismatch");
    }
    Ok(())
}

/// Validate that the User Present (UP) flag is set, as required by WebAuthn.
pub fn validate_user_present(parsed: &ParsedAuthData) -> Result<(), &'static str> {
    if !parsed.user_present {
        return Err("User Present flag not set");
    }
    Ok(())
}

/// Validate that the User Verified (UV) flag is set (when policy requires it).
pub fn validate_user_verified(parsed: &ParsedAuthData) -> Result<(), &'static str> {
    if !parsed.user_verified {
        return Err("User Verified flag not set but required by policy");
    }
    Ok(())
}

// ── COSE key parsing ───────────────────────────────────────────────────

/// A parsed COSE public key for ES256 (ECDSA P-256 with SHA-256).
#[derive(Debug, Clone)]
pub struct CoseKeyEs256 {
    /// The x-coordinate of the EC point (32 bytes).
    pub x: [u8; 32],
    /// The y-coordinate of the EC point (32 bytes).
    pub y: [u8; 32],
}

impl CoseKeyEs256 {
    /// Convert this COSE key to an uncompressed SEC1 public key (65 bytes: 0x04 || x || y).
    pub fn to_sec1_uncompressed(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(65);
        key.push(0x04);
        key.extend_from_slice(&self.x);
        key.extend_from_slice(&self.y);
        key
    }

    /// Construct a p256 VerifyingKey from this COSE key.
    pub fn to_verifying_key(&self) -> Result<VerifyingKey, &'static str> {
        let sec1 = self.to_sec1_uncompressed();
        VerifyingKey::from_sec1_bytes(&sec1)
            .map_err(|_| "Invalid EC point in COSE key")
    }
}

/// Parse a COSE key encoded as a CBOR map for ES256 (algorithm -7).
///
/// Expects a CBOR-encoded map with the following entries:
///   1 (kty) -> 2 (EC2)
///   3 (alg) -> -7 (ES256)
///  -1 (crv) -> 1 (P-256)
///  -2 (x)   -> bstr (32 bytes)
///  -3 (y)   -> bstr (32 bytes)
///
/// This implements a minimal CBOR map parser sufficient for COSE keys,
/// avoiding the need for a full CBOR library dependency.
pub fn parse_cose_key_es256(cose_bytes: &[u8]) -> Result<CoseKeyEs256, &'static str> {
    // Minimal CBOR parser for the COSE key map structure.
    // CBOR maps from authenticators use small integer keys and byte string values.
    let mut reader = CborReader::new(cose_bytes);

    let map_len = reader.read_map_len()
        .ok_or("COSE key: expected CBOR map")?;

    // SECURITY: Bound CBOR map length to prevent DoS from malicious input
    // claiming billions of entries, causing CPU exhaustion in the loop below.
    if map_len > MAX_CBOR_MAP_LEN {
        return Err("COSE key: CBOR map too large — potential DoS");
    }

    let mut kty: Option<i64> = None;
    let mut alg: Option<i64> = None;
    let mut crv: Option<i64> = None;
    let mut x_bytes: Option<Vec<u8>> = None;
    let mut y_bytes: Option<Vec<u8>> = None;

    for _ in 0..map_len {
        let label = reader.read_int()
            .ok_or("COSE key: failed to read map label")?;

        match label {
            COSE_LABEL_KTY => {
                kty = Some(reader.read_int().ok_or("COSE key: failed to read kty value")?);
            }
            COSE_LABEL_ALG => {
                alg = Some(reader.read_int().ok_or("COSE key: failed to read alg value")?);
            }
            COSE_LABEL_CRV => {
                crv = Some(reader.read_int().ok_or("COSE key: failed to read crv value")?);
            }
            COSE_LABEL_X => {
                x_bytes = Some(reader.read_bstr().ok_or("COSE key: failed to read x coordinate")?);
            }
            COSE_LABEL_Y => {
                y_bytes = Some(reader.read_bstr().ok_or("COSE key: failed to read y coordinate")?);
            }
            _ => {
                // Skip unknown labels: read and discard the value
                reader.skip_value().ok_or("COSE key: failed to skip unknown value")?;
            }
        }
    }

    // Validate required fields
    let kty_val = kty.ok_or("COSE key: missing kty (label 1)")?;
    if kty_val != COSE_KTY_EC2 {
        return Err("COSE key: kty must be 2 (EC2)");
    }

    let alg_val = alg.ok_or("COSE key: missing alg (label 3)")?;
    if alg_val != COSE_ALG_ES256 {
        return Err("COSE key: alg must be -7 (ES256)");
    }

    let crv_val = crv.ok_or("COSE key: missing crv (label -1)")?;
    if crv_val != COSE_CRV_P256 {
        return Err("COSE key: crv must be 1 (P-256)");
    }

    let x = x_bytes.ok_or("COSE key: missing x coordinate (label -2)")?;
    if x.len() != 32 {
        return Err("COSE key: x coordinate must be 32 bytes");
    }

    let y = y_bytes.ok_or("COSE key: missing y coordinate (label -3)")?;
    if y.len() != 32 {
        return Err("COSE key: y coordinate must be 32 bytes");
    }

    let mut x_arr = [0u8; 32];
    let mut y_arr = [0u8; 32];
    x_arr.copy_from_slice(&x);
    y_arr.copy_from_slice(&y);

    Ok(CoseKeyEs256 { x: x_arr, y: y_arr })
}

/// Build a CBOR-encoded COSE key map for ES256 from x and y coordinates.
///
/// This is useful for constructing test vectors and for re-encoding keys.
pub fn encode_cose_key_es256(x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);

    // CBOR map with 5 entries: A5
    out.push(0xA5);

    // 1 (kty) -> 2 (EC2)
    out.push(0x01); // unsigned int 1
    out.push(0x02); // unsigned int 2

    // 3 (alg) -> -7 (ES256)  -- -7 is encoded as CBOR negative: 0x26
    out.push(0x03); // unsigned int 3
    out.push(0x26); // negative int -7 (major type 1, value 6)

    // -1 (crv) -> 1 (P-256)  -- -1 is encoded as 0x20
    out.push(0x20); // negative int -1
    out.push(0x01); // unsigned int 1

    // -2 (x) -> bstr(32)  -- -2 is encoded as 0x21
    out.push(0x21); // negative int -2
    out.push(0x58); // bstr, 1-byte length follows
    out.push(0x20); // length 32
    out.extend_from_slice(x);

    // -3 (y) -> bstr(32)  -- -3 is encoded as 0x22
    out.push(0x22); // negative int -3
    out.push(0x58); // bstr, 1-byte length follows
    out.push(0x20); // length 32
    out.extend_from_slice(y);

    out
}

// ── Minimal CBOR reader ────────────────────────────────────────────────

/// A minimal forward-only CBOR reader for parsing COSE keys and attestation objects.
///
/// Supports only the CBOR types actually used in WebAuthn:
/// unsigned integers, negative integers, byte strings, text strings, arrays, and maps.
struct CborReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> CborReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn peek_byte(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    fn read_byte(&mut self) -> Option<u8> {
        let b = self.data.get(self.pos).copied()?;
        self.pos += 1;
        Some(b)
    }

    fn read_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.pos + n > self.data.len() {
            return None;
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Some(slice)
    }

    /// Read a CBOR unsigned integer argument of the given additional info.
    fn read_uint_arg(&mut self, additional: u8) -> Option<u64> {
        match additional {
            0..=23 => Some(additional as u64),
            24 => {
                let b = self.read_byte()?;
                Some(b as u64)
            }
            25 => {
                let bytes = self.read_bytes(2)?;
                Some(u16::from_be_bytes([bytes[0], bytes[1]]) as u64)
            }
            26 => {
                let bytes = self.read_bytes(4)?;
                Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64)
            }
            27 => {
                let bytes = self.read_bytes(8)?;
                Some(u64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5], bytes[6], bytes[7],
                ]))
            }
            _ => None, // indefinite length not supported
        }
    }

    /// Read a CBOR integer (positive or negative).
    fn read_int(&mut self) -> Option<i64> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1F;

        if major == 0 {
            // Unsigned integer
            let val = self.read_uint_arg(additional)?;
            Some(val as i64)
        } else if major == 1 {
            // Negative integer: -1 - val (CBOR encoding)
            let val = self.read_uint_arg(additional)?;
            let neg = -1i64 - (val as i64);
            Some(neg)
        } else {
            None
        }
    }

    /// Read a CBOR byte string, returning its contents.
    fn read_bstr(&mut self) -> Option<Vec<u8>> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1F;
        if major != 2 {
            return None;
        }
        let raw_len = self.read_uint_arg(additional)?;
        // SECURITY: Bound byte string length to prevent memory exhaustion from
        // malicious CBOR claiming multi-GB strings.
        if raw_len > MAX_CBOR_STRING_LEN {
            return None;
        }
        let len = raw_len as usize;
        let bytes = self.read_bytes(len)?;
        Some(bytes.to_vec())
    }

    /// Read a CBOR text string, returning its contents.
    fn read_tstr(&mut self) -> Option<String> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1F;
        if major != 3 {
            return None;
        }
        let raw_len = self.read_uint_arg(additional)?;
        // SECURITY: Bound text string length to prevent memory exhaustion.
        if raw_len > MAX_CBOR_STRING_LEN {
            return None;
        }
        let len = raw_len as usize;
        let bytes = self.read_bytes(len)?;
        String::from_utf8(bytes.to_vec()).ok()
    }

    /// Read the length of a CBOR map. Returns the number of key-value pairs.
    fn read_map_len(&mut self) -> Option<u64> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1F;
        if major != 5 {
            return None;
        }
        self.read_uint_arg(additional)
    }

    /// Read the length of a CBOR array. Returns the number of elements.
    fn read_array_len(&mut self) -> Option<u64> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1F;
        if major != 4 {
            return None;
        }
        self.read_uint_arg(additional)
    }

    /// Skip a single CBOR value of any type (used to skip unknown map entries).
    fn skip_value(&mut self) -> Option<()> {
        let initial = self.peek_byte()?;
        let major = initial >> 5;

        match major {
            0 | 1 => {
                // Integer: consume it
                self.read_int()?;
            }
            2 => {
                // Byte string
                self.read_bstr()?;
            }
            3 => {
                // Text string
                self.read_tstr()?;
            }
            4 => {
                // Array — bound length to prevent DoS
                let len = self.read_array_len()?;
                if len > MAX_CBOR_ARRAY_LEN {
                    return None; // reject oversized arrays
                }
                for _ in 0..len {
                    self.skip_value()?;
                }
            }
            5 => {
                // Map — bound length to prevent DoS
                let len = self.read_map_len()?;
                if len > MAX_CBOR_MAP_LEN {
                    return None; // reject oversized maps
                }
                for _ in 0..len {
                    self.skip_value()?; // key
                    self.skip_value()?; // value
                }
            }
            6 => {
                // Tagged value: read tag number then skip inner value
                let b = self.read_byte()?;
                let additional = b & 0x1F;
                self.read_uint_arg(additional)?;
                self.skip_value()?;
            }
            7 => {
                // Simple value / float
                let b = self.read_byte()?;
                let additional = b & 0x1F;
                match additional {
                    0..=23 => {} // simple value, no extra bytes
                    24 => { self.read_byte()?; }
                    25 => { self.read_bytes(2)?; }
                    26 => { self.read_bytes(4)?; }
                    27 => { self.read_bytes(8)?; }
                    _ => return None,
                }
            }
            _ => return None,
        }
        Some(())
    }

    /// Attempt to read either a text string or integer (for flexible map key parsing).
    /// Returns an enum to differentiate.
    fn read_map_key(&mut self) -> Option<CborMapKey> {
        let initial = self.peek_byte()?;
        let major = initial >> 5;
        match major {
            0 | 1 => Some(CborMapKey::Int(self.read_int()?)),
            3 => Some(CborMapKey::Text(self.read_tstr()?)),
            _ => None,
        }
    }
}

/// A CBOR map key can be either an integer or a text string.
#[derive(Debug, Clone, PartialEq)]
enum CborMapKey {
    Int(i64),
    Text(String),
}

// ── Client data validation ─────────────────────────────────────────────

/// Parse and validate the client data JSON for a WebAuthn authentication ("webauthn.get").
///
/// Checks:
/// 1. `type` field equals `"webauthn.get"`
/// 2. `challenge` field matches the expected challenge (base64url-encoded)
/// 3. `origin` field matches the expected origin
///
/// The `expected_challenge` should be the raw challenge bytes (not encoded).
/// The `expected_origin` should be the full origin string (e.g., "https://sso.milnet.example").
pub fn validate_client_data_authentication(
    client_data_json: &[u8],
    expected_challenge: &[u8],
    expected_origin: &str,
) -> Result<ParsedClientData, &'static str> {
    validate_client_data(client_data_json, "webauthn.get", expected_challenge, expected_origin)
}

/// Parse and validate the client data JSON for a WebAuthn registration ("webauthn.create").
///
/// Checks:
/// 1. `type` field equals `"webauthn.create"`
/// 2. `challenge` field matches the expected challenge (base64url-encoded)
/// 3. `origin` field matches the expected origin
pub fn validate_client_data_registration(
    client_data_json: &[u8],
    expected_challenge: &[u8],
    expected_origin: &str,
) -> Result<ParsedClientData, &'static str> {
    validate_client_data(client_data_json, "webauthn.create", expected_challenge, expected_origin)
}

/// Internal: parse and validate client data JSON.
fn validate_client_data(
    client_data_json: &[u8],
    expected_type: &str,
    expected_challenge: &[u8],
    expected_origin: &str,
) -> Result<ParsedClientData, &'static str> {
    // Parse the JSON
    let json_str = std::str::from_utf8(client_data_json)
        .map_err(|_| "Client data is not valid UTF-8")?;

    let parsed: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|_| "Client data is not valid JSON")?;

    let obj = parsed.as_object()
        .ok_or("Client data JSON is not an object")?;

    // 1. Validate type
    let cd_type = obj.get("type")
        .and_then(|v| v.as_str())
        .ok_or("Client data missing 'type' field")?;

    if cd_type != expected_type {
        return Err("Client data type mismatch");
    }

    // 2. Validate challenge (base64url-encoded in JSON, compared to raw bytes)
    let challenge_b64 = obj.get("challenge")
        .and_then(|v| v.as_str())
        .ok_or("Client data missing 'challenge' field")?;

    // WebAuthn uses base64url encoding without padding for the challenge
    let decoded_challenge = base64_url_decode(challenge_b64)
        .map_err(|_| "Client data challenge is not valid base64url")?;

    if decoded_challenge != expected_challenge {
        return Err("Client data challenge mismatch");
    }

    // 3. Validate origin
    let origin = obj.get("origin")
        .and_then(|v| v.as_str())
        .ok_or("Client data missing 'origin' field")?;

    if origin != expected_origin {
        return Err("Client data origin mismatch");
    }

    Ok(ParsedClientData {
        client_data_type: cd_type.to_string(),
        challenge: challenge_b64.to_string(),
        origin: origin.to_string(),
    })
}

/// Decode a base64url-encoded string (with or without padding).
fn base64_url_decode(input: &str) -> Result<Vec<u8>, &'static str> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .or_else(|_| {
            base64::engine::general_purpose::URL_SAFE.decode(input)
        })
        .map_err(|_| "base64url decode failed")
}

/// Encode bytes as base64url without padding.
pub fn base64_url_encode(input: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input)
}

// ── ECDSA P-256 signature verification ─────────────────────────────────

/// Verify the authenticator's ECDSA P-256 signature over
/// `authenticator_data || SHA-256(clientDataJSON)`.
///
/// The `public_key` is expected in uncompressed SEC1 form (65 bytes: 0x04 || x || y)
/// or compressed SEC1 form (33 bytes: 0x02/0x03 || x).
///
/// The `signature` is expected in DER encoding (as produced by authenticators).
pub fn verify_signature_es256(
    authenticator_data: &[u8],
    client_data_hash: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<(), &'static str> {
    if authenticator_data.len() < MIN_AUTH_DATA_LEN {
        return Err("Authenticator data too short for signature verification");
    }
    if client_data_hash.len() != 32 {
        return Err("Client data hash must be 32 bytes (SHA-256)");
    }
    if signature.is_empty() {
        return Err("Signature is empty");
    }
    if public_key.is_empty() {
        return Err("Public key is empty");
    }

    if public_key.len() == 65 && public_key[0] != 0x04 {
        return Err("Uncompressed public key must start with 0x04");
    }

    let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|_| "Invalid public key encoding")?;

    let sig = Signature::from_der(signature)
        .map_err(|_| "Invalid DER signature encoding")?;

    // The signed message is: authenticator_data || client_data_hash
    let mut msg = authenticator_data.to_vec();
    msg.extend_from_slice(client_data_hash);

    verifying_key.verify(&msg, &sig)
        .map_err(|_| "ES256 signature verification failed")?;

    Ok(())
}

/// Verify an ES256 signature using a COSE-encoded public key.
///
/// This is a convenience wrapper that first parses the COSE key,
/// then verifies the signature.
pub fn verify_signature_es256_cose(
    authenticator_data: &[u8],
    client_data_hash: &[u8],
    signature: &[u8],
    cose_public_key: &[u8],
) -> Result<(), &'static str> {
    let cose_key = parse_cose_key_es256(cose_public_key)?;
    let sec1_key = cose_key.to_sec1_uncompressed();
    verify_signature_es256(authenticator_data, client_data_hash, signature, &sec1_key)
}

// ── Full authentication response verification ──────────────────────────

/// Full authentication response verification pipeline.
///
/// Validates authenticator data structure, RP ID, flags, sign count,
/// and the assertion signature using ECDSA P-256.
///
/// `require_user_verification`: set to `true` when policy demands UV.
///
/// Returns the new sign count on success so the caller can persist it.
pub fn verify_authentication_response(
    auth_result: &crate::types::AuthenticationResult,
    stored_credential: &crate::types::StoredCredential,
    expected_rp_id: &str,
    require_user_verification: bool,
) -> Result<u32, &'static str> {
    // 1. Parse authenticator data
    let parsed = parse_authenticator_data(&auth_result.authenticator_data)?;

    // 2. Validate RP ID hash
    validate_rp_id_hash(&parsed, expected_rp_id)?;

    // 3. Validate UP flag (always required)
    validate_user_present(&parsed)?;

    // 4. Validate UV flag (when required by policy)
    if require_user_verification {
        validate_user_verified(&parsed)?;
    }

    // 5. Validate sign count (detect cloned authenticators)
    //    The new count must be strictly greater than the stored count.
    //    A sign_count of 0 on both sides is a special case: some authenticators
    //    do not implement counters and always report 0. We allow that.
    if stored_credential.sign_count > 0 || parsed.sign_count > 0 {
        if parsed.sign_count <= stored_credential.sign_count {
            return Err("Possible authenticator clone detected");
        }
    }

    // 6. Compute client data hash
    let client_data_hash = Sha256::digest(&auth_result.client_data);

    // 7. Verify signature over (authenticator_data || client_data_hash)
    verify_signature_es256(
        &auth_result.authenticator_data,
        &client_data_hash,
        &auth_result.signature,
        &stored_credential.public_key,
    )?;

    Ok(parsed.sign_count)
}

/// Full authentication response verification with client data validation.
///
/// Like [`verify_authentication_response`] but also validates the client data JSON
/// (type, challenge, origin) before verifying the signature.
pub fn verify_authentication_response_full(
    auth_result: &crate::types::AuthenticationResult,
    stored_credential: &crate::types::StoredCredential,
    expected_rp_id: &str,
    expected_challenge: &[u8],
    expected_origin: &str,
    require_user_verification: bool,
) -> Result<u32, &'static str> {
    // 0. Validate client data JSON
    validate_client_data_authentication(
        &auth_result.client_data,
        expected_challenge,
        expected_origin,
    )?;

    // Delegate to the core verification pipeline
    verify_authentication_response(
        auth_result,
        stored_credential,
        expected_rp_id,
        require_user_verification,
    )
}

// ── Attestation verification ───────────────────────────────────────────

/// Parse attestation data from a registration response.
///
/// Extracts the RP ID hash from the authenticator data embedded in the
/// attestation object, validates it against the expected RP ID, and
/// extracts the credential ID and public key.
pub fn parse_attestation_auth_data(
    auth_data: &[u8],
    expected_rp_id: &str,
) -> Result<AttestationData, &'static str> {
    let parsed = parse_authenticator_data(auth_data)?;

    // Validate RP ID hash
    validate_rp_id_hash(&parsed, expected_rp_id)?;

    // Validate UP flag (must be set during registration)
    validate_user_present(&parsed)?;

    // The AT flag must be set for registration (attested credential data present)
    if !parsed.attested_credential_data {
        return Err("Attested credential data flag not set in registration response");
    }

    // Parse attested credential data (follows the 37-byte fixed header):
    //   16 bytes  -- AAGUID
    //   2 bytes   -- credential ID length (big-endian)
    //   L bytes   -- credential ID
    //   remaining -- COSE public key
    if auth_data.len() < MIN_AUTH_DATA_LEN + 18 {
        return Err("Authenticator data too short for attested credential data");
    }

    let cred_id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    let cred_id_start: usize = 55;
    // SECURITY: Use checked arithmetic to prevent integer overflow on crafted
    // credential ID lengths that could wrap around and bypass bounds checks.
    let cred_id_end = cred_id_start.checked_add(cred_id_len)
        .ok_or("credential ID length overflow")?;

    if auth_data.len() < cred_id_end.checked_add(1).ok_or("credential ID end overflow")? {
        return Err("Authenticator data truncated before public key");
    }

    let credential_id = auth_data[cred_id_start..cred_id_end].to_vec();
    let public_key_cose = auth_data[cred_id_end..].to_vec();

    Ok(AttestationData {
        credential_id,
        public_key_cose,
        sign_count: parsed.sign_count,
    })
}

/// Verify a "none" attestation statement.
///
/// Per WebAuthn spec, "none" attestation means the authenticator does not
/// provide any attestation statement. The `att_stmt` must be an empty CBOR map.
/// The only validation is on the authenticator data itself.
pub fn verify_attestation_none(
    auth_data: &[u8],
    _client_data_hash: &[u8],
    expected_rp_id: &str,
) -> Result<(AttestationData, AttestationType), &'static str> {
    let att_data = parse_attestation_auth_data(auth_data, expected_rp_id)?;
    Ok((att_data, AttestationType::None))
}

/// Verify a "packed" attestation statement (self-attestation variant).
///
/// In self-attestation, the authenticator signs the attestation with the
/// credential private key itself. There is no attestation certificate.
///
/// The `att_stmt` must contain:
///   - `alg`: -7 (ES256)
///   - `sig`: the signature over `authenticatorData || clientDataHash`
///
/// No `x5c` certificate chain is present in self-attestation.
pub fn verify_packed_self_attestation(
    auth_data: &[u8],
    client_data_hash: &[u8],
    alg: i64,
    sig: &[u8],
    expected_rp_id: &str,
) -> Result<(AttestationData, AttestationType), &'static str> {
    if alg != COSE_ALG_ES256 {
        return Err("Packed attestation: only ES256 (alg -7) is supported");
    }

    let att_data = parse_attestation_auth_data(auth_data, expected_rp_id)?;

    // For self-attestation, verify the signature using the credential public key
    // extracted from the authenticator data.
    let cose_key = parse_cose_key_es256(&att_data.public_key_cose)?;
    let sec1_key = cose_key.to_sec1_uncompressed();

    verify_signature_es256(auth_data, client_data_hash, sig, &sec1_key)?;

    Ok((att_data, AttestationType::SelfAttestation))
}

/// Verify a "packed" attestation statement with x5c certificate chain.
///
/// In basic attestation, the authenticator uses an attestation private key
/// (different from the credential key) and provides a certificate chain.
///
/// The `att_stmt` must contain:
///   - `alg`: -7 (ES256)
///   - `sig`: the signature over `authenticatorData || clientDataHash`
///   - `x5c`: an array of DER-encoded X.509 certificates
///
/// Verification steps:
/// 1. Extract the attestation public key from the first certificate (leaf).
/// 2. Verify the signature over `authenticatorData || clientDataHash`.
/// 3. (Optional, out of scope) Verify the certificate chain up to a trust anchor.
///
/// The `leaf_cert_public_key` parameter is the SEC1-encoded public key extracted
/// from the leaf certificate in the x5c chain. Certificate parsing is left to the
/// caller since it requires an X.509 parser.
pub fn verify_packed_basic_attestation(
    auth_data: &[u8],
    client_data_hash: &[u8],
    alg: i64,
    sig: &[u8],
    leaf_cert_public_key: &[u8],
    expected_rp_id: &str,
) -> Result<(AttestationData, AttestationType), &'static str> {
    if alg != COSE_ALG_ES256 {
        return Err("Packed attestation: only ES256 (alg -7) is supported");
    }

    let att_data = parse_attestation_auth_data(auth_data, expected_rp_id)?;

    // Verify the signature using the leaf certificate's public key
    verify_signature_es256(auth_data, client_data_hash, sig, leaf_cert_public_key)?;

    Ok((att_data, AttestationType::Basic))
}

/// Parse a CBOR-encoded attestation object and verify it.
///
/// The attestation object is a CBOR map with the structure:
///   { "fmt": text, "attStmt": map, "authData": bstr }
///
/// Supports "none" and "packed" attestation formats.
pub fn verify_attestation_object(
    attestation_object: &[u8],
    client_data_hash: &[u8],
    expected_rp_id: &str,
) -> Result<(AttestationData, AttestationType), &'static str> {
    let mut reader = CborReader::new(attestation_object);

    let map_len = reader.read_map_len()
        .ok_or("Attestation object: expected CBOR map")?;

    // SECURITY: Bound attestation object map length to prevent DoS.
    if map_len > MAX_CBOR_MAP_LEN {
        return Err("Attestation object: CBOR map too large — potential DoS");
    }

    let mut fmt: Option<String> = None;
    let mut auth_data_bytes: Option<Vec<u8>> = None;
    let mut att_stmt_alg: Option<i64> = None;
    let mut att_stmt_sig: Option<Vec<u8>> = None;
    let mut att_stmt_x5c: Option<Vec<Vec<u8>>> = None;

    for _ in 0..map_len {
        let key = reader.read_map_key()
            .ok_or("Attestation object: failed to read map key")?;

        match key {
            CborMapKey::Text(ref s) if s == "fmt" => {
                fmt = Some(reader.read_tstr()
                    .ok_or("Attestation object: failed to read fmt value")?);
            }
            CborMapKey::Text(ref s) if s == "authData" => {
                auth_data_bytes = Some(reader.read_bstr()
                    .ok_or("Attestation object: failed to read authData")?);
            }
            CborMapKey::Text(ref s) if s == "attStmt" => {
                // Parse the attestation statement map
                let stmt_map_len = reader.read_map_len()
                    .ok_or("Attestation object: attStmt is not a map")?;

                // SECURITY: Bound attStmt map length to prevent DoS.
                if stmt_map_len > MAX_CBOR_MAP_LEN {
                    return Err("attStmt: CBOR map too large — potential DoS");
                }

                for _ in 0..stmt_map_len {
                    let stmt_key = reader.read_map_key()
                        .ok_or("attStmt: failed to read key")?;

                    match stmt_key {
                        CborMapKey::Text(ref sk) if sk == "alg" => {
                            att_stmt_alg = Some(reader.read_int()
                                .ok_or("attStmt: failed to read alg")?);
                        }
                        CborMapKey::Text(ref sk) if sk == "sig" => {
                            att_stmt_sig = Some(reader.read_bstr()
                                .ok_or("attStmt: failed to read sig")?);
                        }
                        CborMapKey::Text(ref sk) if sk == "x5c" => {
                            let arr_len = reader.read_array_len()
                                .ok_or("attStmt: x5c is not an array")?;
                            // SECURITY: Bound x5c certificate array length to prevent DoS.
                            if arr_len > MAX_CBOR_ARRAY_LEN {
                                return Err("attStmt: x5c array too large — potential DoS");
                            }
                            let mut certs = Vec::with_capacity(arr_len as usize);
                            for _ in 0..arr_len {
                                let cert = reader.read_bstr()
                                    .ok_or("attStmt: failed to read x5c certificate")?;
                                certs.push(cert);
                            }
                            att_stmt_x5c = Some(certs);
                        }
                        _ => {
                            reader.skip_value()
                                .ok_or("attStmt: failed to skip unknown value")?;
                        }
                    }
                }
            }
            _ => {
                reader.skip_value()
                    .ok_or("Attestation object: failed to skip unknown value")?;
            }
        }
    }

    let fmt_str = fmt.ok_or("Attestation object: missing 'fmt' field")?;
    let auth_data = auth_data_bytes.ok_or("Attestation object: missing 'authData' field")?;

    match fmt_str.as_str() {
        "none" => {
            verify_attestation_none(&auth_data, client_data_hash, expected_rp_id)
        }
        "packed" => {
            let alg = att_stmt_alg.ok_or("Packed attestation: missing 'alg' in attStmt")?;
            let sig = att_stmt_sig.ok_or("Packed attestation: missing 'sig' in attStmt")?;

            if let Some(x5c) = att_stmt_x5c {
                // Basic attestation with certificate chain.
                // Extract the public key from the leaf certificate.
                if x5c.is_empty() {
                    return Err("Packed attestation: x5c array is empty");
                }
                let leaf_pubkey = extract_ec_public_key_from_der(&x5c[0])?;
                verify_packed_basic_attestation(
                    &auth_data,
                    client_data_hash,
                    alg,
                    &sig,
                    &leaf_pubkey,
                    expected_rp_id,
                )
            } else {
                // Self-attestation (no x5c)
                verify_packed_self_attestation(
                    &auth_data,
                    client_data_hash,
                    alg,
                    &sig,
                    expected_rp_id,
                )
            }
        }
        _ => {
            Err("Unsupported attestation format")
        }
    }
}

// ── X.509 EC public key extraction (minimal DER parser) ────────────────

/// Extract an EC P-256 public key from a DER-encoded X.509 certificate.
///
/// This is a minimal parser that locates the SubjectPublicKeyInfo structure
/// and extracts the uncompressed EC point. It supports the common case of
/// ECDSA P-256 certificates used in WebAuthn attestation.
///
/// Returns the uncompressed SEC1 public key (65 bytes: 0x04 || x || y).
pub fn extract_ec_public_key_from_der(cert_der: &[u8]) -> Result<Vec<u8>, &'static str> {
    // Strategy: scan for the EC P-256 OID (1.2.840.10045.3.1.7) which is
    // 06 08 2A 86 48 CE 3D 03 01 07
    // The uncompressed public key (starting with 0x04) follows shortly after
    // within a BIT STRING.

    let p256_oid: [u8; 10] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    // Find the P-256 OID in the certificate
    let oid_pos = find_subsequence(cert_der, &p256_oid)
        .ok_or("Certificate does not contain P-256 OID")?;

    // After the OID, we expect a BIT STRING containing the public key.
    // Search for 0x03 (BIT STRING tag) followed by length and 0x00 (no unused bits)
    // then 0x04 (uncompressed point).
    let search_start = oid_pos + p256_oid.len();
    let search_region = &cert_der[search_start..];

    // Look for BIT STRING tag (0x03) containing an uncompressed EC point
    for i in 0..search_region.len().saturating_sub(67) {
        if search_region[i] == 0x03 {
            // Read the length
            let (len, header_size) = read_der_length(&search_region[i + 1..])?;
            if len < 66 {
                continue; // Too short for uncompressed P-256 point + unused bits byte
            }
            let content_start = i + 1 + header_size;
            if content_start + 66 > search_region.len() {
                continue;
            }
            // First byte of BIT STRING content is the "unused bits" count (should be 0)
            if search_region[content_start] != 0x00 {
                continue;
            }
            // Next byte should be 0x04 (uncompressed point marker)
            if search_region[content_start + 1] != 0x04 {
                continue;
            }
            // Extract the 65-byte uncompressed public key
            let key_start = content_start + 1;
            let key_end = key_start + 65;
            if key_end > search_region.len() {
                continue;
            }
            return Ok(search_region[key_start..key_end].to_vec());
        }
    }

    Err("Could not extract EC public key from certificate")
}

/// Read a DER length encoding. Returns (length, number_of_bytes_consumed).
///
/// SECURITY: Enforces MAX_DER_LENGTH (64 KB) to prevent DoS from maliciously
/// crafted certificates claiming enormous element sizes.
fn read_der_length(data: &[u8]) -> Result<(usize, usize), &'static str> {
    if data.is_empty() {
        return Err("DER length: unexpected end of data");
    }

    let first = data[0];
    let (len, consumed) = if first < 0x80 {
        // Short form: length is the byte itself
        (first as usize, 1)
    } else if first == 0x81 {
        if data.len() < 2 {
            return Err("DER length: truncated");
        }
        (data[1] as usize, 2)
    } else if first == 0x82 {
        if data.len() < 3 {
            return Err("DER length: truncated");
        }
        let l = ((data[1] as usize) << 8) | (data[2] as usize);
        (l, 3)
    } else {
        // Lengths > 65535 are not expected in WebAuthn certificates
        return Err("DER length: unsupported long form");
    };

    // SECURITY: Reject DER elements larger than 64 KB to prevent memory
    // exhaustion from crafted attestation certificates.
    if len > MAX_DER_LENGTH {
        return Err("DER element too large: potential DoS");
    }

    Ok((len, consumed))
}

/// Find the first occurrence of `needle` in `haystack`.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len())
        .position(|window| window == needle)
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::SignatureEncoding;

    /// Helper: generate a P-256 keypair and sign authenticator_data || client_data_hash
    fn sign_auth_data(auth_data: &[u8], client_data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        use p256::ecdsa::SigningKey;
        use p256::ecdsa::signature::Signer;
        use sha2::{Sha256, Digest};
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();
        let public_key = verifying_key.to_sec1_bytes().to_vec();

        let client_data_hash = Sha256::digest(client_data);
        let mut msg = auth_data.to_vec();
        msg.extend_from_slice(&client_data_hash);

        let sig: p256::ecdsa::Signature = signing_key.sign(&msg);
        (sig.to_der().to_vec(), public_key)
    }

    /// Helper: generate a P-256 keypair, return (signing_key, sec1_pubkey, cose_pubkey)
    fn generate_keypair() -> (p256::ecdsa::SigningKey, Vec<u8>, Vec<u8>) {
        use p256::ecdsa::SigningKey;
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();
        let sec1 = verifying_key.to_sec1_bytes().to_vec();

        // Extract x and y from uncompressed SEC1 (0x04 || x || y)
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&sec1[1..33]);
        y.copy_from_slice(&sec1[33..65]);

        let cose = encode_cose_key_es256(&x, &y);
        (signing_key, sec1, cose)
    }

    /// Helper: build a minimal 37-byte authenticator data blob.
    fn make_auth_data(rp_id: &str, flags: u8, sign_count: u32) -> Vec<u8> {
        let rp_hash = Sha256::digest(rp_id.as_bytes());
        let mut data = Vec::with_capacity(37);
        data.extend_from_slice(&rp_hash);
        data.push(flags);
        data.extend_from_slice(&sign_count.to_be_bytes());
        data
    }

    /// Helper: build auth data with attested credential data appended.
    fn make_auth_data_with_cred(
        rp_id: &str,
        flags: u8,
        sign_count: u32,
        credential_id: &[u8],
        public_key_cose: &[u8],
    ) -> Vec<u8> {
        let mut data = make_auth_data(rp_id, flags, sign_count);
        // AAGUID (16 bytes of zeros)
        data.extend_from_slice(&[0u8; 16]);
        // credential ID length (2 bytes, big-endian)
        let cred_len = credential_id.len() as u16;
        data.extend_from_slice(&cred_len.to_be_bytes());
        // credential ID
        data.extend_from_slice(credential_id);
        // COSE public key
        data.extend_from_slice(public_key_cose);
        data
    }

    /// Helper: build a client data JSON string.
    fn make_client_data_json(cd_type: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
        let challenge_b64 = base64_url_encode(challenge);
        let json = serde_json::json!({
            "type": cd_type,
            "challenge": challenge_b64,
            "origin": origin,
            "crossOrigin": false,
        });
        serde_json::to_vec(&json).unwrap()
    }

    /// Helper: build a CBOR-encoded "none" attestation object.
    fn make_none_attestation_object(auth_data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        // CBOR map with 3 entries
        out.push(0xA3);

        // "fmt" -> "none"
        // text(3) "fmt"
        out.push(0x63);
        out.extend_from_slice(b"fmt");
        // text(4) "none"
        out.push(0x64);
        out.extend_from_slice(b"none");

        // "attStmt" -> {}
        // text(7) "attStmt"
        out.push(0x67);
        out.extend_from_slice(b"attStmt");
        // empty map
        out.push(0xA0);

        // "authData" -> bstr
        // text(8) "authData"
        out.push(0x68);
        out.extend_from_slice(b"authData");
        // bstr with auth_data
        if auth_data.len() < 24 {
            out.push(0x40 | auth_data.len() as u8);
        } else if auth_data.len() < 256 {
            out.push(0x58);
            out.push(auth_data.len() as u8);
        } else {
            out.push(0x59);
            out.push((auth_data.len() >> 8) as u8);
            out.push((auth_data.len() & 0xFF) as u8);
        }
        out.extend_from_slice(auth_data);

        out
    }

    /// Helper: build a CBOR-encoded "packed" self-attestation object.
    fn make_packed_self_attestation_object(auth_data: &[u8], alg: i64, sig: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        // CBOR map with 3 entries
        out.push(0xA3);

        // "fmt" -> "packed"
        out.push(0x63);
        out.extend_from_slice(b"fmt");
        out.push(0x66);
        out.extend_from_slice(b"packed");

        // "attStmt" -> { "alg": alg, "sig": sig }
        out.push(0x67);
        out.extend_from_slice(b"attStmt");
        out.push(0xA2); // map(2)

        // "alg" -> alg
        out.push(0x63);
        out.extend_from_slice(b"alg");
        // Encode the algorithm as CBOR int
        if alg >= 0 {
            if alg < 24 {
                out.push(alg as u8);
            } else {
                out.push(0x18);
                out.push(alg as u8);
            }
        } else {
            // Negative: -1 - val, so val = -1 - alg
            let val = (-1 - alg) as u64;
            if val < 24 {
                out.push(0x20 | val as u8);
            } else {
                out.push(0x38);
                out.push(val as u8);
            }
        }

        // "sig" -> bstr
        out.push(0x63);
        out.extend_from_slice(b"sig");
        if sig.len() < 24 {
            out.push(0x40 | sig.len() as u8);
        } else if sig.len() < 256 {
            out.push(0x58);
            out.push(sig.len() as u8);
        } else {
            out.push(0x59);
            out.push((sig.len() >> 8) as u8);
            out.push((sig.len() & 0xFF) as u8);
        }
        out.extend_from_slice(sig);

        // "authData" -> bstr
        out.push(0x68);
        out.extend_from_slice(b"authData");
        if auth_data.len() < 24 {
            out.push(0x40 | auth_data.len() as u8);
        } else if auth_data.len() < 256 {
            out.push(0x58);
            out.push(auth_data.len() as u8);
        } else {
            out.push(0x59);
            out.push((auth_data.len() >> 8) as u8);
            out.push((auth_data.len() & 0xFF) as u8);
        }
        out.extend_from_slice(auth_data);

        out
    }

    // ── Authenticator data parsing tests ───────────────────────────────

    #[test]
    fn test_parse_authenticator_data_valid() {
        let auth_data = make_auth_data("sso.milnet.example", 0x05, 42);
        let parsed = parse_authenticator_data(&auth_data).unwrap();
        assert!(parsed.user_present);
        assert!(parsed.user_verified);
        assert!(!parsed.attested_credential_data);
        assert_eq!(parsed.sign_count, 42);
    }

    #[test]
    fn test_parse_authenticator_data_too_short() {
        let short = vec![0u8; 36];
        assert_eq!(
            parse_authenticator_data(&short).unwrap_err(),
            "Authenticator data too short (must be >= 37 bytes)"
        );
    }

    #[test]
    fn test_validate_rp_id_hash_ok() {
        let auth_data = make_auth_data("sso.milnet.example", 0x01, 0);
        let parsed = parse_authenticator_data(&auth_data).unwrap();
        assert!(validate_rp_id_hash(&parsed, "sso.milnet.example").is_ok());
    }

    #[test]
    fn test_validate_rp_id_hash_mismatch() {
        let auth_data = make_auth_data("sso.milnet.example", 0x01, 0);
        let parsed = parse_authenticator_data(&auth_data).unwrap();
        assert_eq!(
            validate_rp_id_hash(&parsed, "evil.example.com").unwrap_err(),
            "RP ID hash mismatch"
        );
    }

    #[test]
    fn test_user_present_flag() {
        let data_up_set = make_auth_data("x", 0x01, 0);
        let parsed = parse_authenticator_data(&data_up_set).unwrap();
        assert!(validate_user_present(&parsed).is_ok());

        let data_up_clear = make_auth_data("x", 0x00, 0);
        let parsed = parse_authenticator_data(&data_up_clear).unwrap();
        assert_eq!(
            validate_user_present(&parsed).unwrap_err(),
            "User Present flag not set"
        );
    }

    #[test]
    fn test_user_verified_flag() {
        // UV = bit 2 = 0x04
        let data_uv_set = make_auth_data("x", 0x05, 0); // UP + UV
        let parsed = parse_authenticator_data(&data_uv_set).unwrap();
        assert!(validate_user_verified(&parsed).is_ok());

        let data_uv_clear = make_auth_data("x", 0x01, 0); // UP only
        let parsed = parse_authenticator_data(&data_uv_clear).unwrap();
        assert_eq!(
            validate_user_verified(&parsed).unwrap_err(),
            "User Verified flag not set but required by policy"
        );
    }

    // ── Signature verification tests ───────────────────────────────────

    #[test]
    fn test_verify_signature_structural_checks() {
        let auth_data = make_auth_data("x", 0x05, 1);
        let hash = [0u8; 32];
        let sig = vec![0x30, 0x44]; // minimal DER-like
        let pubkey = vec![0x04; 65]; // uncompressed point prefix

        // Empty signature
        assert_eq!(
            verify_signature_es256(&auth_data, &hash, &[], &pubkey).unwrap_err(),
            "Signature is empty"
        );

        // Empty public key
        assert_eq!(
            verify_signature_es256(&auth_data, &hash, &sig, &[]).unwrap_err(),
            "Public key is empty"
        );

        // Bad client data hash length
        assert_eq!(
            verify_signature_es256(&auth_data, &[0u8; 16], &sig, &pubkey).unwrap_err(),
            "Client data hash must be 32 bytes (SHA-256)"
        );

        // Auth data too short
        assert_eq!(
            verify_signature_es256(&[0u8; 10], &hash, &sig, &pubkey).unwrap_err(),
            "Authenticator data too short for signature verification"
        );
    }

    #[test]
    fn test_verify_signature_es256_real_signature() {
        use p256::ecdsa::SigningKey;
        use p256::ecdsa::signature::Signer;

        let auth_data = make_auth_data("sso.milnet.example", 0x05, 1);
        let client_data_hash = Sha256::digest(b"test-client-data");

        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();
        let public_key = verifying_key.to_sec1_bytes().to_vec();

        let mut msg = auth_data.clone();
        msg.extend_from_slice(&client_data_hash);
        let sig: p256::ecdsa::Signature = signing_key.sign(&msg);
        let sig_der = sig.to_der().to_vec();

        // Valid signature should pass
        assert!(verify_signature_es256(&auth_data, &client_data_hash, &sig_der, &public_key).is_ok());

        // Tampered auth data should fail
        let mut tampered = auth_data.clone();
        tampered[36] ^= 0xFF;
        assert!(verify_signature_es256(&tampered, &client_data_hash, &sig_der, &public_key).is_err());
    }

    // ── COSE key parsing tests ─────────────────────────────────────────

    #[test]
    fn test_cose_key_roundtrip() {
        let (_, sec1, cose) = generate_keypair();

        let parsed = parse_cose_key_es256(&cose).unwrap();
        let reconstructed = parsed.to_sec1_uncompressed();
        assert_eq!(reconstructed, sec1);
    }

    #[test]
    fn test_cose_key_verifying_key() {
        let (_, sec1, cose) = generate_keypair();

        let parsed = parse_cose_key_es256(&cose).unwrap();
        let vk = parsed.to_verifying_key().unwrap();
        let expected_vk = VerifyingKey::from_sec1_bytes(&sec1).unwrap();
        assert_eq!(vk, expected_vk);
    }

    #[test]
    fn test_cose_key_wrong_algorithm() {
        // Build a COSE key with alg = -8 (EdDSA) instead of -7 (ES256)
        let mut out = Vec::new();
        out.push(0xA5);
        out.push(0x01); out.push(0x02); // kty=2
        out.push(0x03); out.push(0x27); // alg=-8 (wrong!)
        out.push(0x20); out.push(0x01); // crv=1
        out.push(0x21); out.push(0x58); out.push(0x20);
        out.extend_from_slice(&[0xAA; 32]); // x
        out.push(0x22); out.push(0x58); out.push(0x20);
        out.extend_from_slice(&[0xBB; 32]); // y

        let err = parse_cose_key_es256(&out).unwrap_err();
        assert_eq!(err, "COSE key: alg must be -7 (ES256)");
    }

    #[test]
    fn test_cose_key_wrong_kty() {
        let mut out = Vec::new();
        out.push(0xA5);
        out.push(0x01); out.push(0x01); // kty=1 (OKP, wrong!)
        out.push(0x03); out.push(0x26); // alg=-7
        out.push(0x20); out.push(0x01); // crv=1
        out.push(0x21); out.push(0x58); out.push(0x20);
        out.extend_from_slice(&[0xAA; 32]);
        out.push(0x22); out.push(0x58); out.push(0x20);
        out.extend_from_slice(&[0xBB; 32]);

        let err = parse_cose_key_es256(&out).unwrap_err();
        assert_eq!(err, "COSE key: kty must be 2 (EC2)");
    }

    #[test]
    fn test_cose_key_verification_e2e() {
        use p256::ecdsa::signature::Signer;

        let (signing_key, _, cose) = generate_keypair();

        let auth_data = make_auth_data("sso.milnet.example", 0x05, 1);
        let client_data_hash = Sha256::digest(b"test-data");

        let mut msg = auth_data.clone();
        msg.extend_from_slice(&client_data_hash);
        let sig: p256::ecdsa::Signature = signing_key.sign(&msg);

        assert!(verify_signature_es256_cose(
            &auth_data,
            &client_data_hash,
            &sig.to_der().as_bytes(),
            &cose,
        ).is_ok());
    }

    // ── Client data validation tests ───────────────────────────────────

    #[test]
    fn test_validate_client_data_authentication_ok() {
        let challenge = b"random-challenge-bytes";
        let origin = "https://sso.milnet.example";
        let cd_json = make_client_data_json("webauthn.get", challenge, origin);

        let result = validate_client_data_authentication(&cd_json, challenge, origin);
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.client_data_type, "webauthn.get");
        assert_eq!(parsed.origin, origin);
    }

    #[test]
    fn test_validate_client_data_registration_ok() {
        let challenge = b"reg-challenge";
        let origin = "https://sso.milnet.example";
        let cd_json = make_client_data_json("webauthn.create", challenge, origin);

        let result = validate_client_data_registration(&cd_json, challenge, origin);
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.client_data_type, "webauthn.create");
    }

    #[test]
    fn test_validate_client_data_wrong_type() {
        let challenge = b"challenge";
        let origin = "https://sso.milnet.example";
        let cd_json = make_client_data_json("webauthn.create", challenge, origin);

        // Expecting "webauthn.get" but got "webauthn.create"
        let err = validate_client_data_authentication(&cd_json, challenge, origin).unwrap_err();
        assert_eq!(err, "Client data type mismatch");
    }

    #[test]
    fn test_validate_client_data_wrong_challenge() {
        let origin = "https://sso.milnet.example";
        let cd_json = make_client_data_json("webauthn.get", b"real-challenge", origin);

        let err = validate_client_data_authentication(&cd_json, b"wrong-challenge", origin)
            .unwrap_err();
        assert_eq!(err, "Client data challenge mismatch");
    }

    #[test]
    fn test_validate_client_data_wrong_origin() {
        let challenge = b"challenge";
        let cd_json = make_client_data_json("webauthn.get", challenge, "https://evil.com");

        let err = validate_client_data_authentication(
            &cd_json,
            challenge,
            "https://sso.milnet.example",
        ).unwrap_err();
        assert_eq!(err, "Client data origin mismatch");
    }

    #[test]
    fn test_validate_client_data_invalid_json() {
        let err = validate_client_data_authentication(
            b"not json",
            b"challenge",
            "https://example.com",
        ).unwrap_err();
        assert_eq!(err, "Client data is not valid JSON");
    }

    // ── Authentication response tests ──────────────────────────────────

    #[test]
    fn test_verify_authentication_response_sign_count() {
        use crate::types::{AuthenticationResult, StoredCredential};
        use uuid::Uuid;

        let rp_id = "sso.milnet.example";
        let user_id = Uuid::new_v4();

        // flags: UP | UV = 0x05, sign_count = 10
        let auth_data = make_auth_data(rp_id, 0x05, 10);
        let client_data = b"test-client-data".to_vec();

        let (signature, public_key) = sign_auth_data(&auth_data, &client_data);

        let auth_result = AuthenticationResult {
            credential_id: vec![1, 2, 3],
            authenticator_data: auth_data,
            client_data,
            signature,
        };

        // Stored credential with sign_count = 5 (< 10, should pass)
        let stored = StoredCredential {
            credential_id: vec![1, 2, 3],
            public_key,
            user_id,
            sign_count: 5,
            authenticator_type: "cross-platform".into(),
        };

        let new_count = verify_authentication_response(&auth_result, &stored, rp_id, true).unwrap();
        assert_eq!(new_count, 10);
    }

    #[test]
    fn test_verify_authentication_response_clone_detected() {
        use crate::types::{AuthenticationResult, StoredCredential};
        use uuid::Uuid;

        let rp_id = "sso.milnet.example";
        let user_id = Uuid::new_v4();

        // sign_count = 5 in authenticator data, but stored is 10
        let auth_data = make_auth_data(rp_id, 0x05, 5);

        let auth_result = AuthenticationResult {
            credential_id: vec![1, 2, 3],
            authenticator_data: auth_data,
            client_data: b"test".to_vec(),
            signature: vec![0x30, 0x44],
        };

        let stored = StoredCredential {
            credential_id: vec![1, 2, 3],
            public_key: vec![0x04; 65],
            user_id,
            sign_count: 10,
            authenticator_type: "platform".into(),
        };

        let err = verify_authentication_response(&auth_result, &stored, rp_id, true).unwrap_err();
        assert_eq!(err, "Possible authenticator clone detected");
    }

    #[test]
    fn test_verify_authentication_response_equal_sign_count_rejected() {
        use crate::types::{AuthenticationResult, StoredCredential};
        use uuid::Uuid;

        let rp_id = "sso.milnet.example";
        let auth_data = make_auth_data(rp_id, 0x05, 5);

        let auth_result = AuthenticationResult {
            credential_id: vec![1, 2, 3],
            authenticator_data: auth_data,
            client_data: b"test".to_vec(),
            signature: vec![0x30, 0x44],
        };

        let stored = StoredCredential {
            credential_id: vec![1, 2, 3],
            public_key: vec![0x04; 65],
            user_id: Uuid::new_v4(),
            sign_count: 5,
            authenticator_type: "platform".into(),
        };

        let err = verify_authentication_response(&auth_result, &stored, rp_id, true).unwrap_err();
        assert_eq!(err, "Possible authenticator clone detected");
    }

    #[test]
    fn test_verify_authentication_response_zero_counters_allowed() {
        use crate::types::{AuthenticationResult, StoredCredential};
        use uuid::Uuid;

        let rp_id = "sso.milnet.example";
        // Both stored and reported sign counts are 0 (authenticator doesn't support counters)
        let auth_data = make_auth_data(rp_id, 0x05, 0);
        let client_data = b"test".to_vec();

        let (signature, public_key) = sign_auth_data(&auth_data, &client_data);

        let auth_result = AuthenticationResult {
            credential_id: vec![1, 2, 3],
            authenticator_data: auth_data,
            client_data,
            signature,
        };

        let stored = StoredCredential {
            credential_id: vec![1, 2, 3],
            public_key,
            user_id: Uuid::new_v4(),
            sign_count: 0,
            authenticator_type: "cross-platform".into(),
        };

        let result = verify_authentication_response(&auth_result, &stored, rp_id, true);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_verify_authentication_response_rp_id_mismatch() {
        use crate::types::{AuthenticationResult, StoredCredential};
        use uuid::Uuid;

        // Auth data is for "evil.com", but we expect "sso.milnet.example"
        let auth_data = make_auth_data("evil.com", 0x05, 1);

        let auth_result = AuthenticationResult {
            credential_id: vec![1, 2, 3],
            authenticator_data: auth_data,
            client_data: b"test".to_vec(),
            signature: vec![0x30, 0x44],
        };

        let stored = StoredCredential {
            credential_id: vec![1, 2, 3],
            public_key: vec![0x04; 65],
            user_id: Uuid::new_v4(),
            sign_count: 0,
            authenticator_type: "cross-platform".into(),
        };

        let err = verify_authentication_response(&auth_result, &stored, "sso.milnet.example", true)
            .unwrap_err();
        assert_eq!(err, "RP ID hash mismatch");
    }

    #[test]
    fn test_verify_authentication_response_uv_not_required() {
        use crate::types::{AuthenticationResult, StoredCredential};
        use uuid::Uuid;

        let rp_id = "sso.milnet.example";
        // flags: UP only (0x01), no UV
        let auth_data = make_auth_data(rp_id, 0x01, 1);
        let client_data = b"test".to_vec();

        let (signature, public_key) = sign_auth_data(&auth_data, &client_data);

        let auth_result = AuthenticationResult {
            credential_id: vec![1, 2, 3],
            authenticator_data: auth_data,
            client_data,
            signature,
        };

        let stored = StoredCredential {
            credential_id: vec![1, 2, 3],
            public_key,
            user_id: Uuid::new_v4(),
            sign_count: 0,
            authenticator_type: "cross-platform".into(),
        };

        // UV not required -- should pass
        let result = verify_authentication_response(&auth_result, &stored, rp_id, false);
        assert!(result.is_ok());

        // UV required -- should fail (fails before signature verification)
        let auth_data2 = make_auth_data(rp_id, 0x01, 2);
        let auth_result2 = AuthenticationResult {
            credential_id: vec![1, 2, 3],
            authenticator_data: auth_data2,
            client_data: b"test".to_vec(),
            signature: vec![0x30, 0x44],
        };
        let err = verify_authentication_response(&auth_result2, &stored, rp_id, true).unwrap_err();
        assert_eq!(err, "User Verified flag not set but required by policy");
    }

    // ── Full authentication with client data validation ────────────────

    #[test]
    fn test_verify_authentication_response_full() {
        use crate::types::{AuthenticationResult, StoredCredential};
        use uuid::Uuid;

        let rp_id = "sso.milnet.example";
        let origin = "https://sso.milnet.example";
        let challenge = b"server-generated-challenge";

        let auth_data = make_auth_data(rp_id, 0x05, 1);
        let client_data_json = make_client_data_json("webauthn.get", challenge, origin);

        let (signature, public_key) = sign_auth_data(&auth_data, &client_data_json);

        let auth_result = AuthenticationResult {
            credential_id: vec![1, 2, 3],
            authenticator_data: auth_data,
            client_data: client_data_json,
            signature,
        };

        let stored = StoredCredential {
            credential_id: vec![1, 2, 3],
            public_key,
            user_id: Uuid::new_v4(),
            sign_count: 0,
            authenticator_type: "cross-platform".into(),
        };

        let result = verify_authentication_response_full(
            &auth_result,
            &stored,
            rp_id,
            challenge,
            origin,
            true,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);
    }

    #[test]
    fn test_verify_authentication_response_full_bad_origin() {
        use crate::types::{AuthenticationResult, StoredCredential};
        use uuid::Uuid;

        let rp_id = "sso.milnet.example";
        let challenge = b"challenge";
        let client_data_json = make_client_data_json("webauthn.get", challenge, "https://evil.com");

        let auth_data = make_auth_data(rp_id, 0x05, 1);
        let (signature, public_key) = sign_auth_data(&auth_data, &client_data_json);

        let auth_result = AuthenticationResult {
            credential_id: vec![1, 2, 3],
            authenticator_data: auth_data,
            client_data: client_data_json,
            signature,
        };

        let stored = StoredCredential {
            credential_id: vec![1, 2, 3],
            public_key,
            user_id: Uuid::new_v4(),
            sign_count: 0,
            authenticator_type: "cross-platform".into(),
        };

        let err = verify_authentication_response_full(
            &auth_result,
            &stored,
            rp_id,
            challenge,
            "https://sso.milnet.example",
            true,
        ).unwrap_err();
        assert_eq!(err, "Client data origin mismatch");
    }

    // ── Attestation parsing tests ──────────────────────────────────────

    #[test]
    fn test_parse_attestation_auth_data_valid() {
        let rp_id = "sso.milnet.example";
        let cred_id = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let cose_key = vec![0x01, 0x02, 0x03]; // dummy COSE key

        // flags: UP | UV | AT = 0x45
        let auth_data = make_auth_data_with_cred(rp_id, 0x45, 0, &cred_id, &cose_key);

        let att = parse_attestation_auth_data(&auth_data, rp_id).unwrap();
        assert_eq!(att.credential_id, cred_id);
        assert_eq!(att.public_key_cose, cose_key);
        assert_eq!(att.sign_count, 0);
    }

    #[test]
    fn test_parse_attestation_auth_data_no_at_flag() {
        let rp_id = "sso.milnet.example";
        // flags: UP | UV = 0x05 (no AT flag)
        let auth_data = make_auth_data(rp_id, 0x05, 0);

        let err = parse_attestation_auth_data(&auth_data, rp_id).unwrap_err();
        assert_eq!(err, "Attested credential data flag not set in registration response");
    }

    #[test]
    fn test_parse_attestation_auth_data_rp_mismatch() {
        let cred_id = vec![0xAA];
        let cose_key = vec![0x01];
        let auth_data = make_auth_data_with_cred("evil.com", 0x45, 0, &cred_id, &cose_key);

        let err = parse_attestation_auth_data(&auth_data, "sso.milnet.example").unwrap_err();
        assert_eq!(err, "RP ID hash mismatch");
    }

    // ── Attestation verification tests ─────────────────────────────────

    #[test]
    fn test_verify_attestation_none() {
        let rp_id = "sso.milnet.example";
        let (_, _, cose) = generate_keypair();
        let cred_id = vec![0x01, 0x02, 0x03, 0x04];

        let auth_data = make_auth_data_with_cred(rp_id, 0x45, 0, &cred_id, &cose);
        let client_data_hash = Sha256::digest(b"client-data");

        let (att_data, att_type) = verify_attestation_none(&auth_data, &client_data_hash, rp_id)
            .unwrap();
        assert_eq!(att_type, AttestationType::None);
        assert_eq!(att_data.credential_id, cred_id);
    }

    #[test]
    fn test_verify_attestation_none_object() {
        let rp_id = "sso.milnet.example";
        let (_, _, cose) = generate_keypair();
        let cred_id = vec![0x01, 0x02, 0x03, 0x04];

        let auth_data = make_auth_data_with_cred(rp_id, 0x45, 0, &cred_id, &cose);
        let client_data_hash = Sha256::digest(b"client-data");
        let att_obj = make_none_attestation_object(&auth_data);

        let (att_data, att_type) = verify_attestation_object(&att_obj, &client_data_hash, rp_id)
            .unwrap();
        assert_eq!(att_type, AttestationType::None);
        assert_eq!(att_data.credential_id, cred_id);
    }

    #[test]
    fn test_verify_packed_self_attestation() {
        use p256::ecdsa::signature::Signer;

        let rp_id = "sso.milnet.example";
        let (signing_key, _, cose) = generate_keypair();
        let cred_id = vec![0xDE, 0xAD, 0xBE, 0xEF];

        let auth_data = make_auth_data_with_cred(rp_id, 0x45, 0, &cred_id, &cose);
        let client_data_hash = Sha256::digest(b"registration-client-data");

        // Sign: authenticatorData || clientDataHash
        let mut msg = auth_data.clone();
        msg.extend_from_slice(&client_data_hash);
        let sig: p256::ecdsa::Signature = signing_key.sign(&msg);
        let sig_der = sig.to_der().to_vec();

        let (att_data, att_type) = verify_packed_self_attestation(
            &auth_data,
            &client_data_hash,
            -7,
            &sig_der,
            rp_id,
        ).unwrap();

        assert_eq!(att_type, AttestationType::SelfAttestation);
        assert_eq!(att_data.credential_id, cred_id);
    }

    #[test]
    fn test_verify_packed_self_attestation_object() {
        use p256::ecdsa::signature::Signer;

        let rp_id = "sso.milnet.example";
        let (signing_key, _, cose) = generate_keypair();
        let cred_id = vec![0xCA, 0xFE];

        let auth_data = make_auth_data_with_cred(rp_id, 0x45, 0, &cred_id, &cose);
        let client_data_hash = Sha256::digest(b"reg-data");

        let mut msg = auth_data.clone();
        msg.extend_from_slice(&client_data_hash);
        let sig: p256::ecdsa::Signature = signing_key.sign(&msg);
        let sig_der = sig.to_der().to_vec();

        let att_obj = make_packed_self_attestation_object(&auth_data, -7, &sig_der);

        let (att_data, att_type) = verify_attestation_object(&att_obj, &client_data_hash, rp_id)
            .unwrap();
        assert_eq!(att_type, AttestationType::SelfAttestation);
        assert_eq!(att_data.credential_id, cred_id);
    }

    #[test]
    fn test_verify_packed_self_attestation_wrong_sig() {
        use p256::ecdsa::signature::Signer;

        let rp_id = "sso.milnet.example";
        let (signing_key, _, cose) = generate_keypair();
        let cred_id = vec![0x01];

        let auth_data = make_auth_data_with_cred(rp_id, 0x45, 0, &cred_id, &cose);
        let client_data_hash = Sha256::digest(b"data");

        // Sign with wrong message
        let wrong_msg = b"totally wrong message";
        let sig: p256::ecdsa::Signature = signing_key.sign(&wrong_msg[..]);
        let sig_der = sig.to_der().to_vec();

        let err = verify_packed_self_attestation(
            &auth_data,
            &client_data_hash,
            -7,
            &sig_der,
            rp_id,
        ).unwrap_err();
        assert_eq!(err, "ES256 signature verification failed");
    }

    #[test]
    fn test_verify_packed_wrong_algorithm() {
        let rp_id = "sso.milnet.example";
        let (_, _, cose) = generate_keypair();
        let cred_id = vec![0x01];

        let auth_data = make_auth_data_with_cred(rp_id, 0x45, 0, &cred_id, &cose);
        let client_data_hash = Sha256::digest(b"data");

        let err = verify_packed_self_attestation(
            &auth_data,
            &client_data_hash,
            -257, // RS256, not supported
            &[0x30, 0x44],
            rp_id,
        ).unwrap_err();
        assert_eq!(err, "Packed attestation: only ES256 (alg -7) is supported");
    }

    // ── Base64url tests ────────────────────────────────────────────────

    #[test]
    fn test_base64url_roundtrip() {
        let data = b"Hello, WebAuthn!";
        let encoded = base64_url_encode(data);
        let decoded = base64_url_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64url_no_padding() {
        // base64url of [0, 1, 2] without padding
        let encoded = base64_url_encode(&[0, 1, 2]);
        assert!(!encoded.contains('='));
        let decoded = base64_url_decode(&encoded).unwrap();
        assert_eq!(decoded, vec![0, 1, 2]);
    }

    // ── Minimal CBOR reader tests ──────────────────────────────────────

    #[test]
    fn test_cbor_reader_integers() {
        // 0x00 = unsigned 0
        let mut r = CborReader::new(&[0x00]);
        assert_eq!(r.read_int(), Some(0));

        // 0x17 = unsigned 23
        let mut r = CborReader::new(&[0x17]);
        assert_eq!(r.read_int(), Some(23));

        // 0x18 0x18 = unsigned 24
        let mut r = CborReader::new(&[0x18, 0x18]);
        assert_eq!(r.read_int(), Some(24));

        // 0x20 = negative -1
        let mut r = CborReader::new(&[0x20]);
        assert_eq!(r.read_int(), Some(-1));

        // 0x26 = negative -7
        let mut r = CborReader::new(&[0x26]);
        assert_eq!(r.read_int(), Some(-7));
    }

    #[test]
    fn test_cbor_reader_bstr() {
        // 0x43 0x01 0x02 0x03 = bstr(3) [1,2,3]
        let mut r = CborReader::new(&[0x43, 0x01, 0x02, 0x03]);
        assert_eq!(r.read_bstr(), Some(vec![1, 2, 3]));
    }

    #[test]
    fn test_cbor_reader_tstr() {
        // 0x63 "fmt" = tstr(3) "fmt"
        let mut r = CborReader::new(&[0x63, b'f', b'm', b't']);
        assert_eq!(r.read_tstr(), Some("fmt".to_string()));
    }
}
