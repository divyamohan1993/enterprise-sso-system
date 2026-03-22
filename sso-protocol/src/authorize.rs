use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Authorization code expiry in seconds. Set to 30s for tighter security
/// (OAuth 2.0 recommends a maximum of 10 minutes; 30s limits replay window).
const CODE_EXPIRY_SECS: i64 = 30;

#[derive(Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String, // "code"
    pub scope: String,
    pub state: String,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
}

#[derive(Clone)]
pub struct AuthorizationCode {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub user_id: Uuid,
    pub scope: String,
    pub code_challenge: Option<String>,
    pub nonce: Option<String>,
    pub tier: u8,
    pub expires_at: i64,
    /// Whether this code has already been consumed (redeemed for a token).
    pub consumed: bool,
}

/// Authorization code store.
///
/// **IMPORTANT: Production Deployment**
/// This in-memory store is suitable for single-instance development only.
/// In production, this store MUST be backed by persistent storage (Redis or PostgreSQL)
/// to support horizontal scaling, crash recovery, and cross-instance code consumption
/// tracking. Without persistent storage, authorization codes may be replayed across
/// different instances or lost on restart.
pub struct AuthorizationStore {
    codes: HashMap<String, AuthorizationCode>,
    /// Tracks total number of code consumption attempts (including double-consumption).
    /// Used to detect replay attacks — if consume_count exceeds issued code count,
    /// an attack may be underway.
    consume_count: AtomicU64,
}

impl AuthorizationStore {
    pub fn new() -> Self {
        Self {
            codes: HashMap::new(),
            consume_count: AtomicU64::new(0),
        }
    }

    pub fn create_code(
        &mut self,
        client_id: &str,
        redirect_uri: &str,
        user_id: Uuid,
        scope: &str,
        code_challenge: Option<String>,
        nonce: Option<String>,
    ) -> String {
        self.create_code_with_tier(client_id, redirect_uri, user_id, scope, code_challenge, nonce, 2)
    }

    pub fn create_code_with_tier(
        &mut self,
        client_id: &str,
        redirect_uri: &str,
        user_id: Uuid,
        scope: &str,
        code_challenge: Option<String>,
        nonce: Option<String>,
        tier: u8,
    ) -> String {
        let code = Uuid::new_v4().to_string();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        self.codes.insert(
            code.clone(),
            AuthorizationCode {
                code: code.clone(),
                client_id: client_id.to_string(),
                redirect_uri: redirect_uri.to_string(),
                user_id,
                scope: scope.to_string(),
                code_challenge,
                nonce,
                tier,
                consumed: false,
                expires_at: now + CODE_EXPIRY_SECS, // 30 second expiry for tighter security
            },
        );
        code
    }

    pub fn consume_code(&mut self, code: &str) -> Option<AuthorizationCode> {
        self.consume_count.fetch_add(1, Ordering::SeqCst);

        let auth_code = self.codes.get_mut(code)?;

        // Reject already-consumed codes (replay detection)
        if auth_code.consumed {
            // Remove the code entirely on double-consumption attempt (per RFC 6749 sec 4.1.2:
            // "If an authorization code is used more than once, the authorization server MUST
            // deny the request and SHOULD revoke all tokens previously issued based on that code.")
            self.codes.remove(code);
            return None;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        if now > auth_code.expires_at {
            self.codes.remove(code);
            return None;
        }

        // Mark as consumed, then remove and return
        auth_code.consumed = true;
        self.codes.remove(code)
    }

    /// Check whether a code has already been consumed (redeemed).
    pub fn is_code_consumed(&self, code: &str) -> bool {
        self.codes
            .get(code)
            .map(|c| c.consumed)
            // If the code is not in the store, treat it as consumed/invalid
            .unwrap_or(true)
    }

    /// Remove all expired codes older than 2x the expiry time.
    /// Should be called periodically (e.g., every 30 seconds) to prevent unbounded growth.
    pub fn cleanup_expired(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let cutoff = now - (CODE_EXPIRY_SECS * 2);
        self.codes.retain(|_, auth_code| auth_code.expires_at > cutoff);
    }
}

impl Default for AuthorizationStore {
    fn default() -> Self {
        Self::new()
    }
}
