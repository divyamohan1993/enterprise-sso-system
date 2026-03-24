//! Error response sanitisation for the MILNET SSO system.
//!
//! In production (developer mode OFF), internal error details are replaced with
//! generic messages to prevent information leakage.  In developer mode, full
//! error context including file/line information is preserved for debugging.
#![forbid(unsafe_code)]

use crate::config::developer_mode;

// ---------------------------------------------------------------------------
// Error sanitisation
// ---------------------------------------------------------------------------

/// Strip internal details from an error message when developer mode is off.
///
/// When `developer_mode` is true, the full error string is returned verbatim.
/// When false, the error is mapped to a safe, generic message that reveals
/// nothing about internal state.
pub fn sanitize_error(err: &str, dev_mode: bool) -> String {
    if dev_mode {
        return err.to_string();
    }
    map_to_safe_message(err).to_string()
}

/// Convenience wrapper that reads developer mode from the global config.
pub fn sanitize(err: &str) -> String {
    sanitize_error(err, developer_mode().is_enabled())
}

/// Attach file and line information to an error message.
///
/// Uses `#[track_caller]` so that the returned string includes the
/// caller's source location, not this function's location.
#[track_caller]
pub fn error_with_location(err: &str) -> String {
    let loc = std::panic::Location::caller();
    if developer_mode().is_enabled() {
        format!("{err} [at {file}:{line}]", file = loc.file(), line = loc.line())
    } else {
        // In production, never expose file/line — just return the safe message.
        map_to_safe_message(err).to_string()
    }
}

/// Build a full error context string suitable for logging internally.
///
/// Always includes location regardless of developer mode — this is for the
/// *log*, not the HTTP response.
#[track_caller]
pub fn log_error_with_location(err: &str) -> String {
    let loc = std::panic::Location::caller();
    format!(
        "{err} [at {file}:{line}]",
        file = loc.file(),
        line = loc.line()
    )
}

/// Create a structured error response payload.
///
/// In developer mode returns `{ "error": "<full detail>", "location": "file:line" }`.
/// In production returns `{ "error": "<safe message>" }`.
#[track_caller]
pub fn error_json(err: &str) -> serde_json::Value {
    let dev = developer_mode().is_enabled();
    if dev {
        let loc = std::panic::Location::caller();
        serde_json::json!({
            "error": err,
            "location": format!("{}:{}", loc.file(), loc.line()),
        })
    } else {
        serde_json::json!({
            "error": map_to_safe_message(err),
        })
    }
}

// ---------------------------------------------------------------------------
// Internal error → safe external message mapping
// ---------------------------------------------------------------------------

/// Map an internal error string to a generic, safe external message.
///
/// The patterns are checked with `contains` so partial matches work even if
/// the surrounding text varies.
fn map_to_safe_message(err: &str) -> &'static str {
    let lower = err.to_lowercase();

    // Receipt / ceremony verification
    if lower.contains("receipt verification failed")
        || lower.contains("receipt chain integrity")
        || lower.contains("invalid puzzle solution")
        || lower.contains("nonce mismatch")
        || lower.contains("opaque")
        || lower.contains("credential")
        || lower.contains("password")
        || lower.contains("authentication failed")
        || lower.contains("login failed")
    {
        return "authentication failed";
    }

    // Token expiry
    if lower.contains("token expired")
        || lower.contains("token has expired")
        || lower.contains("session expired")
        || lower.contains("inactivity timeout")
    {
        return "session expired";
    }

    // PKCE / authorization
    if lower.contains("pkce verification failed")
        || lower.contains("pkce")
        || lower.contains("authorization failed")
        || lower.contains("insufficient")
        || lower.contains("forbidden")
        || lower.contains("not authorized")
    {
        return "authorization failed";
    }

    // Crypto / internal errors — never expose details
    if lower.contains("crypto")
        || lower.contains("aes")
        || lower.contains("hmac")
        || lower.contains("signature")
        || lower.contains("encrypt")
        || lower.contains("decrypt")
        || lower.contains("key")
        || lower.contains("entropy")
        || lower.contains("attestation")
        || lower.contains("canary")
        || lower.contains("kem")
        || lower.contains("x-wing")
        || lower.contains("ml-dsa")
        || lower.contains("ml-kem")
        || lower.contains("frost")
        || lower.contains("tss")
        || lower.contains("shard")
    {
        return "internal error";
    }

    // Rate limiting
    if lower.contains("rate limit") || lower.contains("too many") {
        return "too many requests";
    }

    // Catch-all
    "internal error"
}

// ---------------------------------------------------------------------------
// Verbose logging helpers
// ---------------------------------------------------------------------------

/// Log a verbose-level event.  Only emits if developer mode is enabled
/// and log level is Verbose.
///
/// This is a macro-style helper; call it with a tracing-compatible format.
pub fn verbose_log(category: &str, message: &str) {
    if developer_mode().is_verbose() {
        tracing::debug!(category = category, "{}", message);
    }
}

/// Log a verbose-level event with structured fields.
pub fn verbose_log_fields(category: &str, message: &str, fields: &[(&str, &str)]) {
    if developer_mode().is_verbose() {
        let field_str: String = fields
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(", ");
        tracing::debug!(category = category, fields = %field_str, "{}", message);
    }
}

/// Log an incoming request when verbose logging is active.
pub fn log_request(method: &str, path: &str, source_ip: &str) {
    if developer_mode().is_verbose() {
        tracing::info!(
            category = "request",
            method = method,
            path = path,
            source_ip = source_ip,
            "incoming request"
        );
    }
}

/// Log a ceremony step with timing information.
pub fn log_ceremony_step(ceremony_id: &str, step: &str, elapsed_ms: u64) {
    if developer_mode().is_verbose() {
        tracing::info!(
            category = "ceremony",
            ceremony_id = ceremony_id,
            step = step,
            elapsed_ms = elapsed_ms,
            "ceremony step completed"
        );
    }
}

/// Log a token operation (creation or verification).
pub fn log_token_operation(operation: &str, user_id: &str, tier: u8, dev_mode: bool) {
    if developer_mode().is_verbose() {
        if dev_mode {
            tracing::info!(
                category = "token",
                operation = operation,
                user_id = user_id,
                tier = tier,
                "token operation"
            );
        } else {
            tracing::info!(
                category = "token",
                operation = operation,
                user_id = "[REDACTED]",
                tier = tier,
                "token operation"
            );
        }
    }
}

/// Log a crypto operation (algorithm used, key ID — never actual keys).
pub fn log_crypto_operation(operation: &str, algorithm: &str, key_id: &str) {
    if developer_mode().is_verbose() {
        tracing::info!(
            category = "crypto",
            operation = operation,
            algorithm = algorithm,
            key_id = key_id,
            "crypto operation"
        );
    }
}

/// Log risk scoring signal values and final score.
pub fn log_risk_score(user_id: &str, signals: &[(&str, f64)], final_score: f64) {
    if developer_mode().is_verbose() {
        let signal_str: String = signals
            .iter()
            .map(|(k, v)| format!("{}={:.3}", k, v))
            .collect::<Vec<_>>()
            .join(", ");
        tracing::info!(
            category = "risk",
            user_id = user_id,
            signals = %signal_str,
            final_score = final_score,
            "risk score computed"
        );
    }
}

// ---------------------------------------------------------------------------
// Display impl for MilnetError (enhanced for dev mode)
// ---------------------------------------------------------------------------

/// Format a MilnetError for external consumption.
///
/// In developer mode, includes the full error chain.  In production, maps
/// to a generic safe message.
pub fn format_error_for_response(err: &dyn std::fmt::Display) -> String {
    let msg = err.to_string();
    sanitize(&msg)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_masks_receipt_errors() {
        assert_eq!(
            sanitize_error("receipt verification failed: bad HMAC", false),
            "authentication failed"
        );
    }

    #[test]
    fn sanitize_masks_token_expired() {
        assert_eq!(
            sanitize_error("token expired at 1700000000", false),
            "session expired"
        );
    }

    #[test]
    fn sanitize_masks_pkce() {
        assert_eq!(
            sanitize_error("PKCE verification failed", false),
            "authorization failed"
        );
    }

    #[test]
    fn sanitize_masks_crypto() {
        assert_eq!(
            sanitize_error("AES-256-GCM decrypt: authentication tag mismatch", false),
            "internal error"
        );
    }

    #[test]
    fn sanitize_passes_through_in_dev_mode() {
        let detail = "receipt verification failed: HMAC mismatch on step 3";
        assert_eq!(sanitize_error(detail, true), detail);
    }

    #[test]
    fn error_with_location_includes_file_in_dev() {
        // Temporarily enable dev mode for this test
        developer_mode().set_developer_mode(true);
        let msg = error_with_location("test error");
        assert!(msg.contains("test error"));
        assert!(msg.contains("error_response.rs"));
        developer_mode().set_developer_mode(false);
    }

    #[test]
    fn error_with_location_masks_in_prod() {
        developer_mode().set_developer_mode(false);
        let msg = error_with_location("AES-256-GCM decrypt failed");
        assert_eq!(msg, "internal error");
        assert!(!msg.contains("error_response.rs"));
    }

    #[test]
    fn generic_fallback() {
        assert_eq!(
            sanitize_error("some unknown internal failure", false),
            "internal error"
        );
    }
}
