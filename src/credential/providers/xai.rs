// src/credential/providers/xai.rs
use once_cell::sync::Lazy;
use regex::Regex;
use crate::credential::CredentialProvider;
use crate::types::Confidence;

static RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"xai-[A-Za-z0-9]{80}").unwrap()
});

pub struct XaiProvider;

impl CredentialProvider for XaiProvider {
    fn name(&self) -> &'static str { "xai" }

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
