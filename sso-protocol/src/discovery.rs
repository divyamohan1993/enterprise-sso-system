use serde::Serialize;

#[derive(Serialize)]
pub struct OpenIdConfiguration {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub response_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
}

impl OpenIdConfiguration {
    pub fn new(issuer: &str) -> Self {
        Self {
            issuer: issuer.to_string(),
            authorization_endpoint: format!("{issuer}/oauth/authorize"),
            token_endpoint: format!("{issuer}/oauth/token"),
            userinfo_endpoint: format!("{issuer}/oauth/userinfo"),
            jwks_uri: format!("{issuer}/oauth/jwks"),
            response_types_supported: vec!["code".into()],
            subject_types_supported: vec!["public".into()],
            id_token_signing_alg_values_supported: vec!["RS256".into()],
            scopes_supported: vec!["openid".into(), "profile".into(), "email".into()],
            token_endpoint_auth_methods_supported: vec!["client_secret_post".into()],
            code_challenge_methods_supported: vec!["S256".into()],
        }
    }
}
