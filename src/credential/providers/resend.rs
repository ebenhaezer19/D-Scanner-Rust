// src/credential/providers/resend.rs
use once_cell::sync::Lazy;
use regex::Regex;
use crate::credential::CredentialProvider;
use crate::types::Confidence;

static RE: Lazy<Regex> = Lazy::new(|| {
    // Real Resend keys: re_ + 32 alphanumeric chars (no underscores in key body)
    // Pattern excludes CSS/HTML class names which contain underscores
    Regex::new(r"(?i)re_[A-Za-z0-9]{24,}").unwrap()
});

pub struct ResendProvider;

impl CredentialProvider for ResendProvider {
    fn name(&self) -> &'static str { "resend" }

    fn extract<'a>(&self, text: &'a str) -> Vec<&'a str> {
        RE.find_iter(text).map(|m| m.as_str()).collect()
    }

    fn confidence(&self, candidate: &str) -> Confidence {
        // Real Resend keys are exactly re_ + 32 chars, no underscores in body
        let body = &candidate[3..]; // skip "re_"
        let has_underscore = body.contains('_');
        let good_length = candidate.len() >= 27 && candidate.len() <= 40;
        if good_length && !has_underscore {
            Confidence::High
        } else {
            Confidence::Low // likely false positive
        }
    }
}
