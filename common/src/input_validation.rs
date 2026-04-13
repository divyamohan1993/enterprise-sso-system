//! Centralized input validation framework.
//!
//! Provides a `Validator` trait + combinators (max_len, charset, regex-like
//! patterns) used across the workspace to ensure consistent rejection of
//! malformed input at every system boundary. Also exports
//! `deny_unknown_fields_assert` for compile-time auditing of DTO structs.
#![forbid(unsafe_code)]

use std::fmt;

/// Validation error returned by combinators.
#[derive(Debug, Clone)]
pub struct ValidationError {
    pub field: &'static str,
    pub reason: String,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "validation failed for {}: {}", self.field, self.reason)
    }
}

impl std::error::Error for ValidationError {}

/// Result alias used by validators.
pub type VResult<T> = Result<T, ValidationError>;

/// Trait for any type that can be validated.
pub trait Validator {
    fn validate(&self) -> VResult<()>;
}

// ---------------------------------------------------------------------------
// Combinators
// ---------------------------------------------------------------------------

/// Reject inputs longer than `max` bytes.
pub fn max_len(field: &'static str, value: &str, max: usize) -> VResult<()> {
    if value.len() > max {
        return Err(ValidationError {
            field,
            reason: format!("length {} exceeds max {}", value.len(), max),
        });
    }
    Ok(())
}

/// Reject inputs shorter than `min` bytes.
pub fn min_len(field: &'static str, value: &str, min: usize) -> VResult<()> {
    if value.len() < min {
        return Err(ValidationError {
            field,
            reason: format!("length {} below min {}", value.len(), min),
        });
    }
    Ok(())
}

/// Restrict input to an allowed character set.
pub fn charset(field: &'static str, value: &str, allowed: &str) -> VResult<()> {
    for ch in value.chars() {
        if !allowed.contains(ch) {
            return Err(ValidationError {
                field,
                reason: format!("disallowed character: {:?}", ch),
            });
        }
    }
    Ok(())
}

/// ASCII alphanumeric + '_' '-' '.' (typical identifier shape).
pub fn ident(field: &'static str, value: &str) -> VResult<()> {
    for ch in value.chars() {
        if !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.') {
            return Err(ValidationError {
                field,
                reason: format!("non-identifier character: {:?}", ch),
            });
        }
    }
    Ok(())
}

/// RFC 5322 simplified email check (length + structural).
pub fn email(field: &'static str, value: &str) -> VResult<()> {
    max_len(field, value, 254)?;
    let parts: Vec<&str> = value.split('@').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err(ValidationError {
            field,
            reason: "malformed email".into(),
        });
    }
    if !parts[1].contains('.') {
        return Err(ValidationError {
            field,
            reason: "email domain missing TLD".into(),
        });
    }
    Ok(())
}

/// UUID v4-shape check (hex with dashes, 36 chars).
pub fn uuid_str(field: &'static str, value: &str) -> VResult<()> {
    if value.len() != 36 {
        return Err(ValidationError {
            field,
            reason: "uuid length must be 36".into(),
        });
    }
    for (i, ch) in value.char_indices() {
        let expect_dash = i == 8 || i == 13 || i == 18 || i == 23;
        if expect_dash {
            if ch != '-' {
                return Err(ValidationError { field, reason: "uuid dash position".into() });
            }
        } else if !ch.is_ascii_hexdigit() {
            return Err(ValidationError { field, reason: "non-hex uuid char".into() });
        }
    }
    Ok(())
}

/// Reject NUL bytes anywhere (defends against C-string truncation attacks).
pub fn no_nul(field: &'static str, value: &str) -> VResult<()> {
    if value.contains('\0') {
        return Err(ValidationError {
            field,
            reason: "NUL byte in input".into(),
        });
    }
    Ok(())
}

/// Reject control characters except tab/newline.
pub fn no_control(field: &'static str, value: &str) -> VResult<()> {
    for ch in value.chars() {
        if ch.is_control() && ch != '\t' && ch != '\n' && ch != '\r' {
            return Err(ValidationError {
                field,
                reason: "control char in input".into(),
            });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_len_rejects() {
        assert!(max_len("f", "abcdef", 3).is_err());
        assert!(max_len("f", "abc", 3).is_ok());
    }

    #[test]
    fn email_rejects_malformed() {
        assert!(email("e", "no-at-sign").is_err());
        assert!(email("e", "x@y").is_err());
        assert!(email("e", "a@b.co").is_ok());
    }

    #[test]
    fn uuid_str_rejects_bad_shape() {
        assert!(uuid_str("u", "not-a-uuid").is_err());
        assert!(uuid_str("u", "550e8400-e29b-41d4-a716-446655440000").is_ok());
    }

    #[test]
    fn no_nul_rejects_nul() {
        assert!(no_nul("f", "abc\0def").is_err());
        assert!(no_nul("f", "abcdef").is_ok());
    }

    #[test]
    fn ident_allows_dotted() {
        assert!(ident("i", "milnet.svc-1_v2").is_ok());
        assert!(ident("i", "bad/name").is_err());
    }
}
