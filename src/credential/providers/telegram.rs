// src/credential/providers/telegram.rs
use once_cell::sync::Lazy;
use regex::Regex;
use crate::credential::CredentialProvider;
use crate::types::Confidence;

// Telegram Bot Token: 123456789:ABCdefGHIjklMNOpqrsTUVwxyz
static RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[0-9]{8,10}:[A-Za-z0-9_-]{35}").unwrap()
});

pub struct TelegramProvider;

impl CredentialProvider for TelegramProvider {
    fn name(&self) -> &'static str { "telegram" }

    fn extract<'a>(&self, text: &'a str) -> Vec<&'a str> {
        RE.find_iter(text).map(|m| m.as_str()).collect()
    }

    fn confidence(&self, candidate: &str) -> Confidence {
        // Telegram tokens are very specific format
        if candidate.len() >= 45 && candidate.contains(':') {
            Confidence::High
        } else {
            Confidence::Medium
        }
    }
}
