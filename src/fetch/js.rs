// src/fetch/js.rs
// Smart JS URL extractor with tier scoring.
// Prioritizes build artifacts (webpack/vite) over generic scripts.
// Skips CDN domains, node_modules, and low-signal scripts.

use scraper::{Html, Selector};
use url::Url;

/// Tier scores — lower = higher priority.
const TIER_HIGH: u8 = 1;   // main.*.js, /static/, /dist/
const TIER_MED: u8 = 2;    // /assets/, /bundle/
const TIER_LOW: u8 = 3;    // everything else in-origin
const TIER_SKIP: u8 = 255; // CDN, node_modules, external

/// Scored JS URL candidate.
struct Candidate {
    url: String,
    tier: u8,
}

/// Extract and rank JS URLs from an HTML page.
/// Returns top `max_count` URLs sorted by tier.
pub fn extract_js_urls(html: &str, base_url: &str, max_count: usize) -> Vec<String> {
    if max_count == 0 {
        return vec![];
    }

    let base = match Url::parse(base_url) {
        Ok(u) => u,
        Err(_) => return vec![],
    };
    let base_host = base.host_str().unwrap_or("").to_string();

    let document = Html::parse_document(html);
    let selector = Selector::parse("script[src]").unwrap();

    let mut candidates: Vec<Candidate> = document
        .select(&selector)
        .filter_map(|el| el.value().attr("src"))
        .filter_map(|src| {
            // Resolve relative URL
            let resolved = base.join(src).ok()?;
            let url_str = resolved.to_string();
            let tier = score_js_url(&resolved, &base_host);
            if tier == TIER_SKIP {
                return None;
            }
            Some(Candidate { url: url_str, tier })
        })
        .collect();

    // Sort by tier (lower = better)
    candidates.sort_by_key(|c| c.tier);
    candidates.dedup_by(|a, b| a.url == b.url);

    candidates
        .into_iter()
        .take(max_count)
        .map(|c| c.url)
        .collect()
}

/// Score a JS URL by path heuristics.
fn score_js_url(url: &Url, base_host: &str) -> u8 {
    let host = url.host_str().unwrap_or("");
    let path = url.path().to_lowercase();

    // Skip external domains (CDN, analytics, etc.)
    if host != base_host {
        return TIER_SKIP;
    }

    // Skip node_modules and vendor
    if path.contains("node_modules") || path.contains("/vendor/") {
        return TIER_SKIP;
    }

    // Skip minified polyfills and runtime chunks (low signal)
    if path.contains("polyfill") || path.contains("runtime~") {
        return TIER_LOW;
    }

    // Tier 1: webpack/vite build artifacts (highest credential density)
    if path.contains("/static/js/")
        || path.contains("/dist/")
        || path.contains("/build/")
        || path.contains("main.")
        || path.contains("app.")
        || path.contains("bundle.")
    {
        return TIER_HIGH;
    }

    // Tier 2: assets folder (vite style)
    if path.contains("/assets/") || path.contains("/chunks/") {
        return TIER_MED;
    }

    TIER_LOW
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_js_basic() {
        let html = r#"
            <html><body>
            <script src="/static/js/main.abc123.js"></script>
            <script src="https://cdn.example.com/jquery.min.js"></script>
            <script src="/assets/index-BKdXb29p.js"></script>
            <script src="/utils.js"></script>
            </body></html>
        "#;

        let urls = extract_js_urls(html, "https://example.com", 3);
        // Should include in-origin scripts, skip CDN
        assert!(!urls.is_empty());
        assert!(urls.iter().all(|u| u.contains("example.com")));
        assert!(!urls.iter().any(|u| u.contains("cdn.example.com")));
        // main.js should be first (tier 1)
        assert!(urls[0].contains("main."));
    }
}
