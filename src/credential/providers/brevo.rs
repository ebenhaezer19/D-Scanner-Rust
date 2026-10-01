// src/credential/providers/brevo.rs
use once_cell::sync::Lazy;
use regex::Regex;
use crate::credential::CredentialProvider;
use crate::types::Confidence;

static RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"xkeysib-[A-Za-z0-9]{64}-[A-Za-z0-9]{12}").unwrap()
});

pub struct BrevoProvider;

impl CredentialProvider for BrevoProvider {
    fn name(&self) -> &'static str { "brevo" }

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
