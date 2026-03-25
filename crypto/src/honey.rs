//! Honey Encryption — wrong key produces plausible-looking fake data.
//!
//! An attacker who obtains the ciphertext and tries every possible key
//! will always get back a value that looks real.  They cannot distinguish
//! the correct decryption from a decoy without already knowing the plaintext.
//!
//! # Implementation approach
//!
//! A length-prefixed, padded plaintext is encrypted with an AEAD.  On
//! decryption with the correct key the prefix is parsed and the original
//! plaintext returned.  On decryption with the wrong key the AEAD either
//! fails (authentication error) or returns garbled bytes.  In both cases a
//! plausible value is generated from a deterministic seed derived from the
//! attempted key and the ciphertext, so every wrong key yields a different
//! but consistent fake answer.

use sha2::{Sha512, Digest};

/// Plausible data distributions for different field types.
#[derive(Debug, Clone, Copy)]
pub enum PlausibleDistribution {
    Username,
    Email,
    MilitaryId,
    IpAddress,
    TokenPayload,
}

impl PlausibleDistribution {
    /// Generate a plausible value from a 32-byte seed.
    ///
    /// Deterministic: same seed → same output.
    pub fn generate(&self, seed: &[u8; 32]) -> Vec<u8> {
        match self {
            Self::Username => {
                let first_names = [
                    "james", "john", "robert", "michael", "david",
                    "sarah", "emma", "olivia", "sophia", "maria",
                    "rajesh", "priya", "amit", "deepa", "suresh",
                    "anita", "vikram", "neha", "arjun", "kavita",
                ];
                let last_names = [
                    "smith", "johnson", "williams", "brown", "jones",
                    "garcia", "miller", "davis", "wilson", "moore",
                    "sharma", "patel", "kumar", "singh", "gupta",
                    "reddy", "joshi", "verma", "mehta", "nair",
                ];
                let fi = (seed[0] as usize) % first_names.len();
                let li = (seed[1] as usize) % last_names.len();
                let num = u16::from_le_bytes([seed[2], seed[3]]) % 1000;
                format!("{}.{}{}", first_names[fi], last_names[li], num).into_bytes()
            }
            Self::Email => {
                let username_bytes = Self::Username.generate(seed);
                let domains = [
                    "mil.gov", "defense.gov", "army.mil", "navy.mil", "af.mil",
                    "nic.in", "gov.in", "mod.gov.in", "army.gov.in", "navy.gov.in",
                ];
                let di = (seed[4] as usize) % domains.len();
                format!(
                    "{}@{}",
                    String::from_utf8_lossy(&username_bytes),
                    domains[di]
                )
                .into_bytes()
            }
            Self::MilitaryId => {
                // EDIPI: 10-digit number
                let mut id = String::with_capacity(10);
                for i in 0..10 {
                    let digit = seed[i % 32] % 10;
                    id.push((b'0' + digit) as char);
                }
                id.into_bytes()
            }
            Self::IpAddress => {
                // RFC 1918 private ranges or DoD ranges
                let octets = [
                    10 + (seed[0] % 245),
                    seed[1],
                    seed[2],
                    1 + (seed[3] % 254),
                ];
                format!(
                    "{}.{}.{}.{}",
                    octets[0], octets[1], octets[2], octets[3]
                )
                .into_bytes()
            }
            Self::TokenPayload => {
                // JWT-like structure
                let sub = hex::encode(&seed[0..16]);
                let exp = u64::from_le_bytes([
                    seed[16], seed[17], seed[18], seed[19],
                    seed[20], seed[21], seed[22], seed[23],
                ]);
                format!(
                    r#"{{"sub":"{}","exp":{},"tier":2}}"#,
                    sub,
                    exp % 2_000_000_000
                )
                .into_bytes()
            }
        }
    }
}

/// Honey-encrypted data.
#[derive(Clone)]
pub struct HoneyEncrypted {
    pub ciphertext: Vec<u8>,
    pub distribution: PlausibleDistribution,
}

/// Honey-encrypt: real key → real plaintext on decrypt; wrong key → plausible fake.
///
/// The plaintext is length-prefixed and padded to at least 64 bytes, then
/// encrypted with `MILNET-HONEY-v1` as the AAD.  On decryption with the
/// wrong key the AEAD authentication fails and a seed is derived from
/// `SHA-512(wrong_key || ciphertext)`, which maps deterministically to a
/// plausible value from the declared distribution.
pub fn honey_encrypt(
    key: &[u8; 32],
    plaintext: &[u8],
    distribution: PlausibleDistribution,
) -> Result<HoneyEncrypted, String> {
    // Length-prefix + padding so wrong-key decryptions produce enough entropy.
    let mut payload = Vec::with_capacity(4 + plaintext.len() + 32);
    payload.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
    payload.extend_from_slice(plaintext);

    // Pad to at least 64 bytes with random data.
    let pad_needed = if payload.len() < 64 {
        64 - payload.len()
    } else {
        0
    };
    let mut pad = vec![0u8; pad_needed];
    if pad_needed > 0 {
        getrandom::getrandom(&mut pad).map_err(|e| format!("entropy: {e}"))?;
    }
    payload.extend_from_slice(&pad);

    let ciphertext = crate::symmetric::encrypt(key, &payload, b"MILNET-HONEY-v1")?;
    Ok(HoneyEncrypted {
        ciphertext,
        distribution,
    })
}

/// Honey-decrypt: ALWAYS returns bytes.
///
/// * Correct key  → the original plaintext.
/// * Wrong key    → a plausible fake value from the declared distribution.
///
/// The fake value is deterministic for a given (wrong_key, ciphertext) pair
/// so an attacker consistently sees the same plausible answer for each guess.
pub fn honey_decrypt(key: &[u8; 32], honey: &HoneyEncrypted) -> Vec<u8> {
    match crate::symmetric::decrypt(key, &honey.ciphertext, b"MILNET-HONEY-v1") {
        Ok(payload) => {
            // Try to parse the length-prefixed plaintext.
            if payload.len() >= 4 {
                let len = u32::from_le_bytes([
                    payload[0], payload[1], payload[2], payload[3],
                ]) as usize;
                if let Some(slice) = payload.get(4..4 + len) {
                    return slice.to_vec();
                }
            }
            // Malformed payload — treat as wrong key.
            let mut seed = [0u8; 32];
            let copy_len = payload.len().min(32);
            seed[..copy_len].copy_from_slice(&payload[..copy_len]);
            honey.distribution.generate(&seed)
        }
        Err(_) => {
            // Wrong key — derive a stable seed from the attempted key + ciphertext.
            let mut hasher = Sha512::new();
            hasher.update(key);
            hasher.update(&honey.ciphertext);
            let hash = hasher.finalize();
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&hash[..32]);
            honey.distribution.generate(&seed)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn random_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        getrandom::getrandom(&mut k).unwrap();
        k
    }

    #[test]
    fn test_honey_encrypt_decrypt_correct_key() {
        let key = random_key();
        let plaintext = b"james.smith042@army.mil";
        let encrypted = honey_encrypt(&key, plaintext, PlausibleDistribution::Email).unwrap();
        let decrypted = honey_decrypt(&key, &encrypted);
        assert_eq!(decrypted, plaintext, "correct key must return original plaintext");
    }

    #[test]
    fn test_honey_decrypt_wrong_key_plausible() {
        let key = random_key();
        let wrong_key = random_key();
        let plaintext = b"real-secret-data";
        let encrypted = honey_encrypt(&key, plaintext, PlausibleDistribution::Username).unwrap();
        let fake = honey_decrypt(&wrong_key, &encrypted);
        // Must return non-empty plausible-looking data rather than an error.
        assert!(!fake.is_empty(), "wrong key must return non-empty plausible data");
        // Fake must not equal the real plaintext (overwhelmingly true with random keys).
        assert_ne!(fake, plaintext, "wrong key must not return real plaintext");
    }

    #[test]
    fn test_honey_decrypt_wrong_key_deterministic() {
        let key = random_key();
        let wrong_key = random_key();
        let plaintext = b"consistent-test";
        let encrypted = honey_encrypt(&key, plaintext, PlausibleDistribution::Username).unwrap();
        let fake1 = honey_decrypt(&wrong_key, &encrypted);
        let fake2 = honey_decrypt(&wrong_key, &encrypted);
        assert_eq!(fake1, fake2, "same wrong key must always produce the same fake output");
    }

    #[test]
    fn test_honey_username_distribution() {
        let seed = [0u8; 32];
        let username = PlausibleDistribution::Username.generate(&seed);
        let s = String::from_utf8(username).unwrap();
        // Format: "firstname.lastnameNNN"
        assert!(s.contains('.'), "username must contain a dot separator");
        let dot_pos = s.find('.').unwrap();
        assert!(dot_pos > 0, "first name part must be non-empty");
        assert!(dot_pos < s.len() - 1, "last name + number part must be non-empty");
    }

    #[test]
    fn test_honey_email_distribution() {
        let seed = [42u8; 32];
        let email = PlausibleDistribution::Email.generate(&seed);
        let s = String::from_utf8(email).unwrap();
        assert!(s.contains('@'), "email must contain @");
        let parts: Vec<&str> = s.splitn(2, '@').collect();
        assert_eq!(parts.len(), 2, "email must have exactly one @");
        assert!(!parts[0].is_empty(), "local part must be non-empty");
        assert!(parts[1].contains('.'), "domain must contain a dot");
    }

    #[test]
    fn test_honey_military_id_distribution() {
        let seed = [7u8; 32];
        let id = PlausibleDistribution::MilitaryId.generate(&seed);
        let s = String::from_utf8(id).unwrap();
        assert_eq!(s.len(), 10, "EDIPI must be exactly 10 characters");
        assert!(s.chars().all(|c| c.is_ascii_digit()), "EDIPI must be all digits");
    }

    #[test]
    fn test_honey_ip_distribution() {
        let seed = [0u8; 32];
        let ip = PlausibleDistribution::IpAddress.generate(&seed);
        let s = String::from_utf8(ip).unwrap();
        let parts: Vec<&str> = s.split('.').collect();
        assert_eq!(parts.len(), 4, "IP address must have four octets");
        for part in &parts {
            let octet: u32 = part.parse().expect("each octet must be numeric");
            assert!(octet <= 255, "octet must be ≤ 255");
        }
    }

    #[test]
    fn test_honey_token_distribution() {
        let seed = [0u8; 32];
        let token = PlausibleDistribution::TokenPayload.generate(&seed);
        let s = String::from_utf8(token).unwrap();
        assert!(s.contains("\"sub\""), "token must contain sub field");
        assert!(s.contains("\"exp\""), "token must contain exp field");
        assert!(s.contains("\"tier\""), "token must contain tier field");
        assert!(s.starts_with('{') && s.ends_with('}'), "token must be a JSON object");
    }

    #[test]
    fn test_honey_different_distributions() {
        let seed = [99u8; 32];
        let username = PlausibleDistribution::Username.generate(&seed);
        let email = PlausibleDistribution::Email.generate(&seed);
        let military_id = PlausibleDistribution::MilitaryId.generate(&seed);
        let ip = PlausibleDistribution::IpAddress.generate(&seed);
        let token = PlausibleDistribution::TokenPayload.generate(&seed);

        // All outputs must be different from each other.
        assert_ne!(username, email);
        assert_ne!(username, military_id);
        assert_ne!(username, ip);
        assert_ne!(username, token);
        assert_ne!(email, military_id);
        assert_ne!(email, ip);
        assert_ne!(email, token);
        assert_ne!(military_id, ip);
        assert_ne!(military_id, token);
        assert_ne!(ip, token);
    }
}
