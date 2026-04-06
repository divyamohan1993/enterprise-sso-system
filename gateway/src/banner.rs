//! DoD Standard Notice and Consent Banner endpoint.
//!
//! DISA STIG V-222396 requires displaying a warning banner before any
//! authentication interaction. This module provides the banner text and
//! a standalone endpoint that returns it.

pub use crate::puzzle::DOD_BANNER;

/// Banner response for the `/banner` endpoint.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BannerResponse {
    pub banner: String,
    pub stig_id: &'static str,
}

impl BannerResponse {
    pub fn new() -> Self {
        Self {
            banner: DOD_BANNER.to_string(),
            stig_id: "V-222396",
        }
    }
}

/// OIDC discovery document metadata extension for DoD banner.
/// Include in the `.well-known/openid-configuration` response.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OidcBannerMetadata {
    pub dod_notice_and_consent_banner: String,
    pub dod_banner_stig_id: &'static str,
    pub banner_endpoint: String,
}

impl OidcBannerMetadata {
    pub fn new(issuer_url: &str) -> Self {
        Self {
            dod_notice_and_consent_banner: DOD_BANNER.to_string(),
            dod_banner_stig_id: "V-222396",
            banner_endpoint: format!("{}/banner", issuer_url.trim_end_matches('/')),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_response_contains_dod_text() {
        let resp = BannerResponse::new();
        assert!(resp.banner.contains("U.S. Government"));
        assert!(resp.banner.contains("USG-authorized use only"));
        assert!(resp.banner.contains("routine monitoring"));
        assert!(resp.banner.contains("attorneys, psychotherapists, or clergy"));
        assert_eq!(resp.stig_id, "V-222396");
    }

    #[test]
    fn puzzle_challenge_includes_banner() {
        let challenge = crate::puzzle::generate_challenge(4);
        assert!(challenge.dod_banner.is_some());
        let banner = challenge.dod_banner.unwrap();
        assert!(banner.contains("U.S. Government"));
        assert!(banner.contains("USG-authorized use only"));
    }

    #[test]
    fn oidc_metadata_includes_banner() {
        let meta = OidcBannerMetadata::new("https://sso.mil.gov");
        assert!(meta.dod_notice_and_consent_banner.contains("U.S. Government"));
        assert_eq!(meta.dod_banner_stig_id, "V-222396");
        assert_eq!(meta.banner_endpoint, "https://sso.mil.gov/banner");
    }

    #[test]
    fn banner_constant_is_complete() {
        // Verify all required STIG sections are present.
        assert!(DOD_BANNER.contains("provided for USG-authorized use only"));
        assert!(DOD_BANNER.contains("penetration testing"));
        assert!(DOD_BANNER.contains("COMSEC monitoring"));
        assert!(DOD_BANNER.contains("inspect and seize data"));
        assert!(DOD_BANNER.contains("not private"));
        assert!(DOD_BANNER.contains("authentication and access controls"));
        assert!(DOD_BANNER.contains("private and confidential"));
        assert!(DOD_BANNER.contains("User Agreement"));
    }
}
