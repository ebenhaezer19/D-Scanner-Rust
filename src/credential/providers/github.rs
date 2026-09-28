// src/credential/providers/github.rs
use once_cell::sync::Lazy;
use regex::Regex;
use crate::credential::CredentialProvider;
use crate::types::Confidence;

static RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:ghp|ghs|gho|ghu|ghr)_[A-Za-z0-9]{36}").unwrap()
});

pub struct GitHubProvider;

impl CredentialProvider for GitHubProvider {
    fn name(&self) -> &'static str { "github" }

    fn extract<'a>(&self, text: &'a str) -> Vec<&'a str> {
        RE.find_iter(text).map(|m| m.as_str()).collect()
    }

    fn confidence(&self, candidate: &str) -> Confidence {
        if candidate.len() > 20 {
            Confidence::High
        } else {
            Confidence::Medium
        }
    }
}
