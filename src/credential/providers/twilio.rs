// src/credential/providers/twilio.rs
use once_cell::sync::Lazy;
use regex::Regex;
use crate::credential::CredentialProvider;
use crate::types::Confidence;

// Twilio Account SID and Auth Token
static RE_SID: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"AC[a-f0-9]{32}").unwrap()
});

static RE_TOKEN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"SK[a-f0-9]{32}").unwrap()
});

pub struct TwilioProvider;

impl CredentialProvider for TwilioProvider {
    fn name(&self) -> &'static str { "twilio" }

    fn extract<'a>(&self, text: &'a str) -> Vec<&'a str> {
        let mut results: Vec<&str> = RE_SID.find_iter(text).map(|m| m.as_str()).collect();
        results.extend(RE_TOKEN.find_iter(text).map(|m| m.as_str()));
        results
    }

    fn confidence(&self, candidate: &str) -> Confidence {
        if candidate.len() == 34 {
            Confidence::High
        } else {
            Confidence::Medium
        }
    }
}
