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
    /// Build the OpenID Connect discovery document.
    ///
    /// The `issuer` **must** use the `https://` scheme. If a bare `http://`
    /// issuer is supplied it is automatically promoted to `https://` so that
    /// every URL in the resulting document is TLS-only.
    pub fn new(issuer: &str) -> Self {
        // Enforce HTTPS: promote http:// to https:// to guarantee all
        // discovery URLs are TLS-protected.
        let issuer = if issuer.starts_with("http://") {
            issuer.replacen("http://", "https://", 1)
        } else {
            issuer.to_string()
        };

        Self {
            authorization_endpoint: format!("{issuer}/oauth/authorize"),
            token_endpoint: format!("{issuer}/oauth/token"),
            userinfo_endpoint: format!("{issuer}/oauth/userinfo"),
            jwks_uri: format!("{issuer}/oauth/jwks"),
            issuer,
            response_types_supported: vec!["code".into()],
            subject_types_supported: vec!["public".into()],
            id_token_signing_alg_values_supported: vec!["ML-DSA-87".into()],
            scopes_supported: vec!["openid".into(), "profile".into(), "email".into()],
            token_endpoint_auth_methods_supported: vec!["client_secret_post".into()],
            code_challenge_methods_supported: vec!["S256".into()],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_urls_are_https() {
        let config = OpenIdConfiguration::new("https://sso.example.com");
        assert!(config.issuer.starts_with("https://"));
        assert!(config.authorization_endpoint.starts_with("https://"));
        assert!(config.token_endpoint.starts_with("https://"));
        assert!(config.userinfo_endpoint.starts_with("https://"));
        assert!(config.jwks_uri.starts_with("https://"));
    }

    #[test]
    fn discovery_promotes_http_to_https() {
        let config = OpenIdConfiguration::new("http://insecure.example.com");
        assert_eq!(config.issuer, "https://insecure.example.com");
        assert!(config.authorization_endpoint.starts_with("https://"));
        assert!(config.token_endpoint.starts_with("https://"));
    }

    #[test]
    fn discovery_only_s256_challenge_method() {
        let config = OpenIdConfiguration::new("https://sso.example.com");
        assert_eq!(config.code_challenge_methods_supported, vec!["S256"]);
        assert!(!config.code_challenge_methods_supported.contains(&"plain".to_string()));
    }
}
