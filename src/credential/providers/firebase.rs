// src/credential/providers/firebase.rs
use once_cell::sync::Lazy;
use regex::Regex;
use crate::credential::CredentialProvider;
use crate::types::Confidence;

// Firebase API key pattern - commonly exposed in JS
static RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"AIza[0-9A-Za-z\-_]{35}").unwrap()
});

pub struct FirebaseProvider;

impl CredentialProvider for FirebaseProvider {
    fn name(&self) -> &'static str { "firebase" }

    fn extract<'a>(&self, text: &'a str) -> Vec<&'a str> {
        RE.find_iter(text).map(|m| m.as_str()).collect()
    }

    fn confidence(&self, candidate: &str) -> Confidence {
        if candidate.len() == 39 {
            Confidence::High
        } else {
            Confidence::Medium
        }
    }
}
