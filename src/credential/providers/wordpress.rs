// src/credential/providers/wordpress.rs
// WordPress detection provider for M1 → M2 pipeline.
// Detects WordPress installations for wp2shell exploit engine.

use crate::credential::CredentialProvider;
use crate::types::Confidence;

pub struct WordPressProvider;

impl CredentialProvider for WordPressProvider {
    fn name(&self) -> &'static str {
        "wordpress"
    }

    fn extract<'a>(&self, text: &'a str) -> Vec<&'a str> {
        let text_lower = text.to_lowercase();

        // Strong indicators (definitive WordPress)
        let strong_indicators = [
            "/wp-content/",
            "/wp-includes/",
            "/wp-admin/",
            "/wp-login.php",
            "/wp-json/",
            "/xmlrpc.php",
            "wp-emoji-release.min.js",
            "generator\" content=\"wordpress",
        ];

        // Weak indicators (might be WordPress)
        let weak_indicators = [
            "wordpress",
            "/themes/",
            "/plugins/",
            "powered by wordpress",
        ];

        let strong_count = strong_indicators
            .iter()
            .filter(|&&s| text_lower.contains(s))
            .count();

        let weak_count = weak_indicators
            .iter()
            .filter(|&&s| text_lower.contains(s))
            .count();

        // Detection logic:
        // - 1+ strong indicator = definite WordPress
        // - 2+ weak indicators = likely WordPress
        if strong_count >= 1 || weak_count >= 2 {
            vec!["detected"]
        } else {
            vec![]
        }
    }

    fn confidence(&self, _candidate: &str) -> Confidence {
        Confidence::High
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wp_content() {
        let provider = WordPressProvider;
        let html = r#"<link href="/wp-content/themes/flavor/style.css">"#;
        assert!(!provider.extract(html).is_empty());
    }

    #[test]
    fn test_wp_includes() {
        let provider = WordPressProvider;
        let html = r#"<script src="/wp-includes/js/jquery.min.js"></script>"#;
        assert!(!provider.extract(html).is_empty());
    }

    #[test]
    fn test_generator_meta() {
        let provider = WordPressProvider;
        let html = r#"<meta name="generator" content="WordPress 6.4.2">"#;
        assert!(!provider.extract(html).is_empty());
    }

    #[test]
    fn test_no_wordpress() {
        let provider = WordPressProvider;
        let html = r#"<html><body>Hello World</body></html>"#;
        assert!(provider.extract(html).is_empty());
    }
}
