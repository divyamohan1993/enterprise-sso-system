use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize)]
pub struct OAuthClient {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uris: Vec<String>,
    pub name: String,
    pub allowed_scopes: Vec<String>,
}

pub struct ClientRegistry {
    clients: std::collections::HashMap<String, OAuthClient>,
}

impl ClientRegistry {
    pub fn new() -> Self {
        Self {
            clients: std::collections::HashMap::new(),
        }
    }

    pub fn register(&mut self, name: &str, redirect_uris: Vec<String>) -> OAuthClient {
        let client = OAuthClient {
            client_id: Uuid::new_v4().to_string(),
            client_secret: hex::encode(crypto::entropy::generate_nonce()),
            redirect_uris,
            name: name.to_string(),
            allowed_scopes: vec!["openid".into(), "profile".into()],
        };
        self.clients.insert(client.client_id.clone(), client.clone());
        client
    }

    /// Register a client with a specific client_id and secret (for pre-seeding)
    pub fn register_with_id(
        &mut self,
        client_id: &str,
        client_secret: &str,
        name: &str,
        redirect_uris: Vec<String>,
    ) -> OAuthClient {
        let client = OAuthClient {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            redirect_uris,
            name: name.to_string(),
            allowed_scopes: vec!["openid".into(), "profile".into(), "email".into()],
        };
        self.clients.insert(client.client_id.clone(), client.clone());
        client
    }

    pub fn validate(&self, client_id: &str, client_secret: &str) -> Option<&OAuthClient> {
        self.clients
            .get(client_id)
            .filter(|c| c.client_secret == client_secret)
    }

    pub fn get(&self, client_id: &str) -> Option<&OAuthClient> {
        self.clients.get(client_id)
    }
}

impl Default for ClientRegistry {
    fn default() -> Self {
        Self::new()
    }
}
