// src/credential/providers/discord.rs
use once_cell::sync::Lazy;
use regex::Regex;
use crate::credential::CredentialProvider;
use crate::types::Confidence;

// Discord bot token pattern
static RE_TOKEN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}").unwrap()
});

// Discord webhook URL
static RE_WEBHOOK: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+").unwrap()
});

pub struct DiscordProvider;

impl CredentialProvider for DiscordProvider {
    fn name(&self) -> &'static str { "discord" }

    fn extract<'a>(&self, text: &'a str) -> Vec<&'a str> {
        let mut results: Vec<&str> = RE_TOKEN.find_iter(text).map(|m| m.as_str()).collect();
        results.extend(RE_WEBHOOK.find_iter(text).map(|m| m.as_str()));
        results
    }

    fn confidence(&self, candidate: &str) -> Confidence {
        if candidate.contains("discord") {
            Confidence::High
        } else if candidate.len() > 50 {
            Confidence::High
        } else {
            Confidence::Medium
        }
    }
}
