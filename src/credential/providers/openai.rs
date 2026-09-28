// src/credential/providers/openai.rs
use once_cell::sync::Lazy;
use regex::Regex;
use crate::credential::CredentialProvider;
use crate::types::Confidence;

static RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{40,}").unwrap()
});

pub struct OpenAIProvider;

impl CredentialProvider for OpenAIProvider {
    fn name(&self) -> &'static str { "openai" }

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
