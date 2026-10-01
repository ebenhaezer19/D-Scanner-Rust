// src/credential/providers/sendgrid.rs
use once_cell::sync::Lazy;
use regex::Regex;
use crate::credential::CredentialProvider;
use crate::types::Confidence;

static RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}").unwrap()
});

pub struct SendGridProvider;

impl CredentialProvider for SendGridProvider {
    fn name(&self) -> &'static str { "sendgrid" }

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
