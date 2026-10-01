// src/credential/providers/livewire.rs
// Livewire v3 presence detector — M1 provider.
// Detects Livewire v3 in HTML response body.
// Emits Hit with provider="livewire", value="v3" when confirmed.
// This pre-qualifies targets for M2 livewire2shell exploit.
//
// Detection signals (any one is sufficient for Medium, 2+ for High):
//   - "wire:id="              → Livewire component attribute in DOM
//   - "livewire/livewire.js"  → Livewire JS asset URL
//   - "/livewire/update"      → Livewire update endpoint reference
//   - "Livewire.start("       → Livewire JS bootstrap call
//   - "@livewire("            → Blade directive in error/debug output
//   - "wire:snapshot="        → Livewire v3 snapshot attribute

use crate::credential::CredentialProvider;
use crate::types::Confidence;

pub struct LivewireProvider;

impl CredentialProvider for LivewireProvider {
    fn name(&self) -> &'static str { "livewire" }

    fn extract<'a>(&self, text: &'a str) -> Vec<&'a str> {
        // Strong signals — any ONE is sufficient (very specific to Livewire v3)
        let strong = [
            "wire:id=",          // Livewire component attribute in DOM
            "wire:snapshot=",    // Livewire v3 snapshot
            "wire:effects=",     // Livewire v3 effects
            "Livewire.start(",   // Livewire JS bootstrap
            "window.livewire_token", // Livewire CSRF token
        ];

        // Weak signals — need at least 2 of these
        let weak = [
            "livewire/livewire.js",
            "/livewire/update",
            "@livewire(",
            "window.livewire",
            "livewire.min.js",
        ];

        let strong_count = strong.iter().filter(|&&s| text.contains(s)).count();
        let weak_count   = weak.iter().filter(|&&s| text.contains(s)).count();

        // Confirmed Livewire v3: 1+ strong signal OR 2+ weak signals
        if strong_count >= 1 || weak_count >= 2 {
            vec!["v3"]
        } else {
            vec![]
        }
    }

    fn confidence(&self, _candidate: &str) -> Confidence {
        // Confidence is determined by signal count in extract() context,
        // but since we already filter count>0, return High.
        // M2 livewire2shell accepts provider=livewire regardless of value.
        Confidence::High
    }
}
