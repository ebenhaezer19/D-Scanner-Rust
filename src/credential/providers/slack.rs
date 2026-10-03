// src/credential/providers/slack.rs
use once_cell::sync::Lazy;
use regex::Regex;
use crate::credential::CredentialProvider;
use crate::types::Confidence;

// Slack tokens: xoxb- (bot), xoxp- (user), xoxa- (app), xoxs- (session)
static RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"xox[bpas]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}").unwrap()
});

// Slack webhook URLs
static RE_WEBHOOK: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+").unwrap()
});

pub struct SlackProvider;

impl CredentialProvider for SlackProvider {
    fn name(&self) -> &'static str { "slack" }

    fn extract<'a>(&self, text: &'a str) -> Vec<&'a str> {
        let mut results: Vec<&str> = RE.find_iter(text).map(|m| m.as_str()).collect();
        results.extend(RE_WEBHOOK.find_iter(text).map(|m| m.as_str()));
        results
    }

    fn confidence(&self, candidate: &str) -> Confidence {
        if candidate.starts_with("xoxb-") || candidate.starts_with("xoxp-") {
            Confidence::High
        } else if candidate.contains("hooks.slack.com") {
            Confidence::High
        } else {
            Confidence::Medium
        }
    }
}
