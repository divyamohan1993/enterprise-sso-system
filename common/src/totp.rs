//! TOTP (Time-based One-Time Password) implementation per RFC 6238.
//!
//! Uses HMAC-SHA1 as mandated by interoperability requirements (most authenticator
//! apps only support SHA1). This is a CNSA 2.0 exception for TOTP compatibility.

use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

/// Time step in seconds (RFC 6238 default).
const TIME_STEP: u64 = 30;

/// Number of TOTP digits.
const TOTP_DIGITS: u32 = 6;

/// Generate a 32-byte random secret for TOTP enrollment.
pub fn generate_secret() -> [u8; 32] {
    let mut secret = [0u8; 32];
    getrandom::getrandom(&mut secret).expect("getrandom failed");
    secret
}

/// Generate a 6-digit TOTP code for the given secret and unix timestamp.
///
/// Implements HOTP (RFC 4226) with time-based counter per RFC 6238.
/// Uses dynamic truncation to extract a 6-digit code from the HMAC-SHA1 result.
pub fn generate_totp(secret: &[u8], time: u64) -> String {
    let counter = time / TIME_STEP;
    let counter_bytes = counter.to_be_bytes();

    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC-SHA1 accepts any key length");
    mac.update(&counter_bytes);
    let result = mac.finalize().into_bytes();

    // Dynamic truncation per RFC 4226 Section 5.4
    let offset = (result[19] & 0x0F) as usize;
    let binary = ((result[offset] as u32 & 0x7F) << 24)
        | ((result[offset + 1] as u32) << 16)
        | ((result[offset + 2] as u32) << 8)
        | (result[offset + 3] as u32);

    let otp = binary % 10u32.pow(TOTP_DIGITS);
    format!("{:0width$}", otp, width = TOTP_DIGITS as usize)
}

/// Verify a TOTP code against the given secret and time, checking ± window steps.
///
/// Uses constant-time comparison to prevent timing side-channels on the code value.
pub fn verify_totp(secret: &[u8], code: &str, time: u64, window: u32) -> bool {
    use subtle::ConstantTimeEq;

    let mut result = 0u8;
    for i in 0..=(window * 2) {
        let check_time = if i <= window {
            time.wrapping_sub((window as u64 - i as u64) * TIME_STEP)
        } else {
            time + (i as u64 - window as u64) * TIME_STEP
        };
        let expected = generate_totp(secret, check_time);
        // Accumulate match results in constant time
        result |= code.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8();
    }
    result == 1
}

/// Build an otpauth:// URI for QR code generation.
pub fn secret_to_otpauth_uri(secret: &[u8], issuer: &str, account: &str) -> String {
    let encoded_secret = encode_base32(secret);
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        issuer, account, encoded_secret, issuer
    )
}

/// RFC 4648 Base32 encoding (no padding).
pub fn encode_base32(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::new();
    let mut buffer: u64 = 0;
    let mut bits_left: u32 = 0;

    for &byte in data {
        buffer = (buffer << 8) | byte as u64;
        bits_left += 8;
        while bits_left >= 5 {
            bits_left -= 5;
            let index = ((buffer >> bits_left) & 0x1F) as usize;
            result.push(ALPHABET[index] as char);
        }
    }
    if bits_left > 0 {
        let index = ((buffer << (5 - bits_left)) & 0x1F) as usize;
        result.push(ALPHABET[index] as char);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 Appendix B test vector: SHA1, secret = "12345678901234567890", time = 59.
    /// Expected TOTP: 287082
    #[test]
    fn test_rfc6238_test_vector_time_59() {
        let secret = b"12345678901234567890";
        let code = generate_totp(secret, 59);
        assert_eq!(code, "287082", "RFC 6238 test vector at time=59 failed");
    }

    /// RFC 6238 Appendix B: time = 1111111109
    /// Expected TOTP: 081804
    #[test]
    fn test_rfc6238_test_vector_time_1111111109() {
        let secret = b"12345678901234567890";
        let code = generate_totp(secret, 1111111109);
        assert_eq!(code, "081804");
    }

    /// RFC 6238 Appendix B: time = 1234567890
    /// Expected TOTP: 005924
    #[test]
    fn test_rfc6238_test_vector_time_1234567890() {
        let secret = b"12345678901234567890";
        let code = generate_totp(secret, 1234567890);
        assert_eq!(code, "005924");
    }

    #[test]
    fn test_verify_totp_exact() {
        let secret = b"12345678901234567890";
        assert!(verify_totp(secret, "287082", 59, 0));
    }

    #[test]
    fn test_verify_totp_with_window() {
        let secret = b"12345678901234567890";
        // Code for time=59 (step 1), verify at time=89 (step 2) with window=1
        assert!(verify_totp(secret, "287082", 89, 1));
    }

    #[test]
    fn test_verify_totp_wrong_code() {
        let secret = b"12345678901234567890";
        assert!(!verify_totp(secret, "000000", 59, 1));
    }

    #[test]
    fn test_generate_secret_is_random() {
        let s1 = generate_secret();
        let s2 = generate_secret();
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_encode_base32() {
        // Known test: "Hello!" -> "JBSWY3DPEE"
        // Actually let's use a simpler known vector
        assert_eq!(encode_base32(b""), "");
        assert_eq!(encode_base32(b"f"), "MY");
        assert_eq!(encode_base32(b"fo"), "MZXQ");
        assert_eq!(encode_base32(b"foo"), "MZXW6");
        assert_eq!(encode_base32(b"foob"), "MZXW6YQ");
        assert_eq!(encode_base32(b"fooba"), "MZXW6YTB");
        assert_eq!(encode_base32(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn test_otpauth_uri() {
        let secret = b"12345678901234567890";
        let uri = secret_to_otpauth_uri(secret, "MILNET", "user@example.com");
        assert!(uri.starts_with("otpauth://totp/MILNET:user@example.com?"));
        assert!(uri.contains("algorithm=SHA1"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
    }
}
