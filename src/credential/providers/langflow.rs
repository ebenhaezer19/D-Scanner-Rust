// src/credential/providers/langflow.rs
// Langflow presence detector — M1 provider.
// Detects Langflow instances in HTML/JS response body.
// Emits Hit with provider="langflow", value="detected" when confirmed.
// This pre-qualifies targets for M2 langflow2shell exploit (CVE-2025-3248).
//
// Detection signals:
//   Strong (any 1 = confirmed):
//     - "/api/v1/flows"           → Langflow flows API endpoint
//     - "/api/v1/validate/code"   → Vulnerable code validation endpoint
//     - "langflow"                → Explicit Langflow branding (case-insensitive)
//     - "/api/v1/login"           → Langflow login endpoint
//     - "langflow-frontend"       → Langflow React app identifier
//
//   Weak (need 2+):
//     - "/api/v1/store"           → Langflow store endpoint
//     - "/api/v1/monitor"         → Langflow monitor endpoint
//     - "reactflow"               → React Flow library (used by Langflow)

use crate::credential::CredentialProvider;
use crate::types::Confidence;

pub struct LangflowProvider;

impl CredentialProvider for LangflowProvider {
    fn name(&self) -> &'static str { "langflow" }

    fn extract<'a>(&self, text: &'a str) -> Vec<&'a str> {
        let text_lower = text.to_lowercase();

        // Strong signals — any ONE is sufficient (very specific to Langflow)
        let strong_matches = [
            "/api/v1/flows",
            "/api/v1/validate/code",
            "/api/v1/login",
            "langflow-frontend",
            "langflow-backend",
        ].iter().filter(|&&s| text.contains(s)).count();

        // Case-insensitive check for "langflow" brand
        let has_langflow_brand = text_lower.contains("langflow");

        // Weak signals — need at least 2 of these
        let weak_matches = [
            "/api/v1/store",
            "/api/v1/monitor",
            "/api/v1/build",
            "reactflow",
            "__reactflow",
            "react-flow",
        ].iter().filter(|&&s| text_lower.contains(s)).count();

        // Confirmed Langflow: 1+ strong OR brand present OR 2+ weak
        if strong_matches >= 1 || has_langflow_brand || weak_matches >= 2 {
            vec!["detected"]
        } else {
            vec![]
        }
    }

    fn confidence(&self, _candidate: &str) -> Confidence {
        // Always High — we only emit when detection is confirmed.
        // M2 langflow2shell accepts provider=langflow regardless of value.
        Confidence::High
    }
}
