use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

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
}

pub struct AuthorizationStore {
    codes: HashMap<String, AuthorizationCode>,
}

impl AuthorizationStore {
    pub fn new() -> Self {
        Self {
            codes: HashMap::new(),
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
                expires_at: now + 60, // 60 second expiry per OAuth 2.0 BCP
            },
        );
        code
    }

    pub fn consume_code(&mut self, code: &str) -> Option<AuthorizationCode> {
        let auth_code = self.codes.remove(code)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        if now > auth_code.expires_at {
            return None;
        }
        Some(auth_code)
    }
}

impl Default for AuthorizationStore {
    fn default() -> Self {
        Self::new()
    }
}
