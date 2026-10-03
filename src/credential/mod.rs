// src/credential/mod.rs
// Credential extraction engine — per-provider model with regex + validator.
//
// Architecture:
//   - CredentialProvider trait defines regex patterns + validation logic
//   - ProviderRegistry holds all registered providers
//   - scan_text() runs all providers against a text blob
//   - Each provider is in its own file under providers/

use once_cell::sync::Lazy;
use chrono::Utc;

use crate::types::{Confidence, Hit, HitSource};

pub mod providers;

/// Trait that every credential provider must implement.
pub trait CredentialProvider: Send + Sync {
    /// Provider name (e.g. "openai", "stripe")
    fn name(&self) -> &'static str;

    /// Extract raw candidate strings from text.
    fn extract<'a>(&self, text: &'a str) -> Vec<&'a str>;

    /// Confidence level for a candidate (without API call).
    fn confidence(&self, candidate: &str) -> Confidence;
}

/// Global provider registry — all providers registered here.
static REGISTRY: Lazy<Vec<Box<dyn CredentialProvider>>> = Lazy::new(|| {
    vec![
        Box::new(providers::openai::OpenAIProvider),
        Box::new(providers::stripe::StripeProvider),
        Box::new(providers::aws::AwsProvider),
        Box::new(providers::github::GitHubProvider),
        Box::new(providers::sendgrid::SendGridProvider),
        Box::new(providers::resend::ResendProvider),
        Box::new(providers::anthropic::AnthropicProvider),
        Box::new(providers::brevo::BrevoProvider),
        Box::new(providers::mailgun::MailgunProvider),
        Box::new(providers::huggingface::HuggingFaceProvider),
        Box::new(providers::groq::GroqProvider),
        Box::new(providers::xai::XaiProvider),
        Box::new(providers::openrouter::OpenRouterProvider),
        Box::new(providers::replicate::ReplicateProvider),
        Box::new(providers::cerebras::CerebrasProvider),
        Box::new(providers::perplexity::PerplexityProvider),
        Box::new(providers::gitlab::GitLabProvider),
        Box::new(providers::livewire::LivewireProvider),  // Livewire v3 pre-qualifier for M2
        Box::new(providers::langflow::LangflowProvider),  // Langflow pre-qualifier for M2 (CVE-2025-3248)
        Box::new(providers::wordpress::WordPressProvider), // WordPress pre-qualifier for M2 wp2shell
    ]
});

/// Scan a text blob with all providers. Returns hits at or above min_confidence.
/// min_confidence: "low" | "medium" | "high"  (default "medium")
pub fn scan_text(text: &str, target_url: &str, source: HitSource, min_confidence: &str) -> Vec<Hit> {
    let mut hits = Vec::new();

    for provider in REGISTRY.iter() {
        let candidates = provider.extract(text);
        for candidate in candidates {
            // Deduplicate within this call
            if hits.iter().any(|h: &Hit| h.value == candidate) {
                continue;
            }

            let confidence = provider.confidence(candidate);

            // Apply confidence filter
            let passes = match min_confidence {
                "high" => matches!(confidence, Confidence::High),
                "low"  => true,
                _      => !matches!(confidence, Confidence::Low), // default: medium+
            };
            if !passes {
                continue;
            }

            hits.push(Hit {
                target: target_url.to_string(),
                provider: provider.name().to_string(),
                value: candidate.to_string(),
                confidence,
                source: source.clone(),
                found_at: Utc::now(),
            });
        }
    }

    hits
}
