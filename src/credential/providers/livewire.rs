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
        // Count detection signals
        let signals = [
            "wire:id=",
            "livewire/livewire.js",
            "/livewire/update",
            "Livewire.start(",
            "@livewire(",
            "wire:snapshot=",
            "wire:effects=",
            "window.livewire",
        ];
        let count = signals.iter().filter(|&&s| text.contains(s)).count();

        if count > 0 {
            // Return a synthetic marker so M2 knows this is a Livewire target
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
