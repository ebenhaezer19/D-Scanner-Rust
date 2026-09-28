// src/credential/providers/perplexity.rs
use once_cell::sync::Lazy;
use regex::Regex;
use crate::credential::CredentialProvider;
use crate::types::Confidence;

static RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"pplx-[A-Za-z0-9]{48}").unwrap()
});

pub struct PerplexityProvider;

impl CredentialProvider for PerplexityProvider {
    fn name(&self) -> &'static str { "perplexity" }

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
