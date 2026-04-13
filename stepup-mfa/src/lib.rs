//! Step-up MFA enforcement (J6).
//!
//! A pure decision engine: given a request URL/method and the timestamp of
//! the user's last MFA assertion, decide whether the operation is allowed
//! or whether a fresh MFA proof is required. Wireable into any HTTP layer.
#![forbid(unsafe_code)]

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Sensitivity {
    Low,
    Medium,
    High,
    Critical,
}

impl Sensitivity {
    pub fn freshness_secs(self) -> i64 {
        match self {
            Sensitivity::Low => i64::MAX,
            Sensitivity::Medium => 30 * 60,
            Sensitivity::High => 5 * 60,
            Sensitivity::Critical => 60,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub method: String,
    pub path_regex: Regex,
    pub sensitivity: Sensitivity,
}

#[derive(Debug, Default, Clone)]
pub struct SensitivityMap {
    pub rules: Vec<Rule>,
    pub default: Option<Sensitivity>,
}

impl SensitivityMap {
    pub fn classify(&self, method: &str, path: &str) -> Sensitivity {
        for r in &self.rules {
            if r.method.eq_ignore_ascii_case(method) && r.path_regex.is_match(path) {
                return r.sensitivity;
            }
        }
        self.default.unwrap_or(Sensitivity::Low)
    }

    pub fn add(&mut self, method: &str, path_pattern: &str, s: Sensitivity) -> Result<(), regex::Error> {
        self.rules.push(Rule {
            method: method.into(),
            path_regex: Regex::new(path_pattern)?,
            sensitivity: s,
        });
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    RequireFreshMfa { max_age_secs: i64 },
}

pub fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

pub fn decide(map: &SensitivityMap, method: &str, path: &str, last_mfa_at: Option<i64>) -> Decision {
    let s = map.classify(method, path);
    let max_age = s.freshness_secs();
    if max_age == i64::MAX {
        return Decision::Allow;
    }
    match last_mfa_at {
        Some(t) if now_secs() - t <= max_age => Decision::Allow,
        _ => Decision::RequireFreshMfa { max_age_secs: max_age },
    }
}
