// ALL PII MUST be pseudonymized before logging.
//! Error response handling for the MILNET SSO system.
//!
//! Error verbosity is controlled by `error_level()`:
//! - `Verbose`: full error details including file/line exposed in responses
//! - `Warn`: errors mapped to generic safe messages, no file/line
//!
//! Default is Warn. Verbose may only be enabled by explicitly setting
//! MILNET_ERROR_LEVEL=verbose, which logs a startup WARN. Source paths and
//! file:line never leak to clients in Warn mode.
#![forbid(unsafe_code)]

use crate::config::error_level;

// ---------------------------------------------------------------------------
// Error sanitisation
// ---------------------------------------------------------------------------

/// Strip internal details from an error message when error_level is Warn.
///
/// When `verbose` is true, the full error string is returned verbatim.
/// When false, the error is mapped to a safe, generic message.
pub fn sanitize_error(err: &str, verbose: bool) -> String {
    if verbose {
        return err.to_string();
    }
    map_to_safe_message(err).to_string()
}

/// Convenience wrapper that reads error level from the global config.
pub fn sanitize(err: &str) -> String {
    sanitize_error(err, error_level().is_verbose())
}

/// Attach file and line information to an error message.
///
/// Uses `#[track_caller]` so that the returned string includes the
/// caller's source location, not this function's location.
#[track_caller]
pub fn error_with_location(err: &str) -> String {
    let loc = std::panic::Location::caller();
    if error_level().is_verbose() {
        format!("{err} [at {file}:{line}]", file = loc.file(), line = loc.line())
    } else {
        // Warn mode: never expose file/line — just return the safe message.
        map_to_safe_message(err).to_string()
    }
}

/// Build a full error context string suitable for logging internally.
///
/// Always includes location regardless of error level — this is for the
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
/// In verbose mode returns `{ "error": "<full detail>", "location": "file:line" }`.
/// In warn mode returns `{ "error": "<safe message>" }`.
///
/// All verbose errors are emitted to SIEM so super admins can track
/// issues with exact file:line on the dashboard.
#[track_caller]
pub fn error_json(err: &str) -> serde_json::Value {
    if error_level().is_verbose() {
        let loc = std::panic::Location::caller();
        let location = format!("{}:{}", loc.file(), loc.line());
        // Emit to SIEM panel for super admin visibility
        tracing::error!(
            target: "siem",
            error = err,
            location = %location,
            "SIEM:ERROR verbose error report"
        );
        serde_json::json!({
            "error": err,
            "location": location,
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

/// Log a verbose-level event.  Only emits if error_level is Verbose.
pub fn verbose_log(category: &str, message: &str) {
    if error_level().is_verbose() {
        tracing::debug!(category = category, "{}", message);
    }
}

/// Log a verbose-level event with structured fields.
pub fn verbose_log_fields(category: &str, message: &str, fields: &[(&str, &str)]) {
    if error_level().is_verbose() {
        let field_str: String = fields
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(", ");
        tracing::debug!(category = category, fields = %field_str, "{}", message);
    }
}

/// Log an incoming request when verbose logging is active.
/// Source IP is pseudonymized before logging to prevent PII leakage.
pub fn log_request(method: &str, path: &str, source_ip: &str) {
    if error_level().is_verbose() {
        let pseudo_ip = crate::log_pseudonym::pseudonym_ip(source_ip);
        tracing::info!(
            category = "request",
            method = method,
            path = path,
            source_ip = %pseudo_ip,
            "incoming request"
        );
    }
}

/// Log a ceremony step with timing information.
pub fn log_ceremony_step(ceremony_id: &str, step: &str, elapsed_ms: u64) {
    if error_level().is_verbose() {
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
/// User ID is always pseudonymized before logging at all verbosity levels.
pub fn log_token_operation(operation: &str, user_id: &str, tier: u8, _dev_mode: bool) {
    let pseudo_uid = crate::log_pseudonym::pseudonym_str("user_id", user_id);
    tracing::info!(
        category = "token",
        operation = operation,
        user_id = %pseudo_uid,
        tier = tier,
        "token operation"
    );
}

/// Log a crypto operation (algorithm used, key ID — never actual keys).
pub fn log_crypto_operation(operation: &str, algorithm: &str, key_id: &str) {
    if error_level().is_verbose() {
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
/// User ID is pseudonymized before logging to prevent PII leakage.
pub fn log_risk_score(user_id: &str, signals: &[(&str, f64)], final_score: f64) {
    if error_level().is_verbose() {
        let pseudo_uid = crate::log_pseudonym::pseudonym_str("user_id", user_id);
        let signal_str: String = signals
            .iter()
            .map(|(k, v)| format!("{}={:.3}", k, v))
            .collect::<Vec<_>>()
            .join(", ");
        tracing::info!(
            category = "risk",
            user_id = %pseudo_uid,
            signals = %signal_str,
            final_score = final_score,
            "risk score computed"
        );
    }
}

// ---------------------------------------------------------------------------
// Display impl for MilnetError (enhanced for verbose mode)
// ---------------------------------------------------------------------------

/// Format a MilnetError for external consumption.
///
/// In verbose mode, includes the full error chain.  In warn mode, maps
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
    fn sanitize_passes_through_in_verbose_mode() {
        let detail = "receipt verification failed: HMAC mismatch on step 3";
        assert_eq!(sanitize_error(detail, true), detail);
    }

    #[test]
    fn error_with_location_includes_file_in_verbose() {
        // Remove env vars that force Warn level (may leak from parallel tests)
        let prev_mil = std::env::var("MILNET_MILITARY_DEPLOYMENT").ok();
        let prev_prod = std::env::var("MILNET_PRODUCTION").ok();
        std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
        std::env::remove_var("MILNET_PRODUCTION");

        // Set error_level to Verbose for this test.
        error_level().set_level(crate::config::ErrorLevel::Verbose);
        let msg = error_with_location("validation check failed for input");
        assert!(msg.contains("validation check failed for input"));
        assert!(msg.contains("error_response.rs"));

        // Restore env vars
        if let Some(v) = prev_mil { std::env::set_var("MILNET_MILITARY_DEPLOYMENT", v); }
        if let Some(v) = prev_prod { std::env::set_var("MILNET_PRODUCTION", v); }
    }

    #[test]
    fn error_with_location_masks_in_warn() {
        error_level().set_level(crate::config::ErrorLevel::Warn);
        let msg = error_with_location("AES-256-GCM decrypt failed");
        assert_eq!(msg, "internal error");
        assert!(!msg.contains("error_response.rs"));
        // Restore default
        error_level().set_level(crate::config::ErrorLevel::Verbose);
    }

    #[test]
    fn generic_fallback() {
        assert_eq!(
            sanitize_error("some unknown internal failure", false),
            "internal error"
        );
    }

    #[test]
    fn log_request_pseudonymizes_source_ip() {
        // Verify pseudonym_ip returns a deterministic hex string, not the raw IP.
        let raw_ip = "192.168.1.42";
        let pseudo = crate::log_pseudonym::pseudonym_ip(raw_ip);
        assert_ne!(pseudo, raw_ip, "source_ip must be pseudonymized, not raw");
        assert_eq!(pseudo.len(), 32, "pseudonym should be 32 hex chars");
        // Deterministic: same input yields same output.
        assert_eq!(pseudo, crate::log_pseudonym::pseudonym_ip(raw_ip));
    }

    #[test]
    fn log_risk_score_pseudonymizes_user_id() {
        let raw = "user-abc-123";
        let pseudo = crate::log_pseudonym::pseudonym_str("user_id", raw);
        assert_ne!(pseudo, raw, "user_id must be pseudonymized");
        assert_eq!(pseudo.len(), 32);
    }

    #[test]
    fn log_token_operation_pseudonymizes_user_id() {
        // Confirms the pseudonym_str function used by log_token_operation
        // produces a stable, non-raw identifier at all log levels.
        let raw = "token-user-456";
        let pseudo = crate::log_pseudonym::pseudonym_str("user_id", raw);
        assert_ne!(pseudo, raw);
        assert_eq!(pseudo.len(), 32);
        // Stable across calls.
        assert_eq!(pseudo, crate::log_pseudonym::pseudonym_str("user_id", raw));
    }
}
