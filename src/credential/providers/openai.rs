// src/credential/providers/openai.rs
use once_cell::sync::Lazy;
use regex::Regex;
use crate::credential::CredentialProvider;
use crate::types::Confidence;

// OpenAI key formats:
//   sk-<legacy>           : sk- + 48 alphanumeric chars (continuous, no internal hyphens)
//   sk-proj-<key>         : sk-proj- + 48+ chars
//   sk-svcacct-<key>      : sk-svcacct- + 48+ chars
//   sk-or-v1-<key>        : OpenRouter (also caught by openrouter provider)
static RE: Lazy<Regex> = Lazy::new(|| {
    // (?<![A-Za-z]) — negative lookbehind: ensure sk- is NOT preceded by a letter.
    // Prevents matching "Sosialantropologisk-institutt-..." (Norwegian word ending in -sk)
    // Real OpenAI keys always start at a word boundary / after non-alpha char.
    Regex::new(r"(?<![A-Za-z])sk-(?:proj-|svcacct-|or-v1-)?[A-Za-z0-9_\-]{20,}").unwrap()
});


pub struct OpenAIProvider;

impl CredentialProvider for OpenAIProvider {
    fn name(&self) -> &'static str { "openai" }

    fn extract<'a>(&self, text: &'a str) -> Vec<&'a str> {
        RE.find_iter(text).map(|m| m.as_str()).collect()
    }

    fn confidence(&self, candidate: &str) -> Confidence {
        // Strip known prefix to get the key body
        let body = if let Some(s) = candidate.strip_prefix("sk-proj-") { s }
            else if let Some(s) = candidate.strip_prefix("sk-svcacct-") { s }
            else if let Some(s) = candidate.strip_prefix("sk-or-v1-") { s }
            else { &candidate[3..] }; // strip "sk-"

        // Too short
        if body.len() < 20 {
            return Confidence::Low;
        }

        // Split body by hyphens and analyze segments
        // Real key with no hyphens in body: single segment, high entropy
        // Slug/article title: many readable word segments
        let segments: Vec<&str> = body.split('-').collect();

        // A "word-like" segment is purely alphabetic (case-insensitive) and >= 2 chars.
        // Real key bodies don't have many pure-alpha word segments.
        // Article slugs (sk-walk-in-cancel-fee) have many.
        let word_like: usize = segments.iter().filter(|s| {
            s.len() >= 2 && s.chars().all(|c| c.is_ascii_alphabetic())
        }).count();

        // More than 2 readable word segments = almost certainly a slug or internal ID
        // e.g. sk-institutt-Universitetet-i-Oslo-343887709134352
        if word_like >= 3 {
            return Confidence::Low;
        }

        // Check entropy: real keys have mix of upper, lower, and digits
        let has_digit  = body.chars().any(|c| c.is_ascii_digit());
        let has_upper  = body.chars().any(|c| c.is_ascii_uppercase());
        let has_lower  = body.chars().any(|c| c.is_ascii_lowercase());
        let long_enough = body.len() >= 32;

        if long_enough && has_digit && has_upper && has_lower {
            Confidence::High
        } else if long_enough && (has_digit || has_upper) && has_lower {
            // Long random-looking string (e.g. all lowercase 48-char random)
            // Likely real but no digit mix
            Confidence::Medium
        } else if word_like <= 1 && body.len() >= 48 {
            // Single long segment, no readable words — likely real
            Confidence::Medium
        } else {
            Confidence::Low
        }
    }
}
