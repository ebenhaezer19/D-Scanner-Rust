// src/credential/providers/huggingface.rs
use once_cell::sync::Lazy;
use regex::Regex;
use crate::credential::CredentialProvider;
use crate::types::Confidence;

static RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"hf_[A-Za-z0-9]{34}").unwrap()
});

pub struct HuggingFaceProvider;

impl CredentialProvider for HuggingFaceProvider {
    fn name(&self) -> &'static str { "huggingface" }

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
