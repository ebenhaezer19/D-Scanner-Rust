// src/credential/providers/stripe.rs
use once_cell::sync::Lazy;
use regex::Regex;
use crate::credential::CredentialProvider;
use crate::types::Confidence;

static RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{24,}").unwrap()
});

pub struct StripeProvider;

impl CredentialProvider for StripeProvider {
    fn name(&self) -> &'static str { "stripe" }

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
