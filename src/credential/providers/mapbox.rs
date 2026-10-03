// src/credential/providers/mapbox.rs
use once_cell::sync::Lazy;
use regex::Regex;
use crate::credential::CredentialProvider;
use crate::types::Confidence;

// Mapbox public/secret token - commonly exposed in JS
static RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"pk\.[a-zA-Z0-9]{60,}").unwrap()
});

static RE_SECRET: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"sk\.[a-zA-Z0-9]{60,}").unwrap()
});

pub struct MapboxProvider;

impl CredentialProvider for MapboxProvider {
    fn name(&self) -> &'static str { "mapbox" }

    fn extract<'a>(&self, text: &'a str) -> Vec<&'a str> {
        let mut results: Vec<&str> = RE.find_iter(text).map(|m| m.as_str()).collect();
        results.extend(RE_SECRET.find_iter(text).map(|m| m.as_str()));
        results
    }

    fn confidence(&self, candidate: &str) -> Confidence {
        if candidate.starts_with("sk.") {
            Confidence::High // Secret token
        } else if candidate.len() > 80 {
            Confidence::High
        } else {
            Confidence::Medium
        }
    }
}
