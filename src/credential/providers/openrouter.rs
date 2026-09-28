// src/credential/providers/openrouter.rs
use once_cell::sync::Lazy;
use regex::Regex;
use crate::credential::CredentialProvider;
use crate::types::Confidence;

static RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"sk-or-v1-[A-Za-z0-9]{64}").unwrap()
});

pub struct OpenRouterProvider;

impl CredentialProvider for OpenRouterProvider {
    fn name(&self) -> &'static str { "openrouter" }

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
