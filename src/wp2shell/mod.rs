// src/wp2shell/mod.rs
// WordPress wp2shell vulnerability scanner — Rust port of ZephrFish/wp2shell-scanner
// Detects CVE-2026-63030 (REST batch route-confusion RCE) and CVE-2026-60137 (SQLi).
// Non-destructive scan mode only: version fingerprint + batch route probe.

use anyhow::Result;
use reqwest::{Client, redirect};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

const UA: &str = "wp2shell-rce/1.0";

// ─── Result types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct WpScanResult {
    pub host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub batch_route: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cve: Option<String>,
    pub verdict: String,
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub threads: usize,
    pub timeout_secs: u64,
    pub json_output: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self { threads: 50, timeout_secs: 15, json_output: false }
    }
}

// ─── Version logic (mirrors Python _vkey / affected) ─────────────────────────

/// (major, minor, patch, stage, sub) — stage: 0=alpha 1=beta 2=rc 3=stable
fn version_key(ver: &str) -> (u32, u32, u32, u32, u32) {
    let (head, tail) = ver.split_once('-').unwrap_or((ver, ""));
    let nums: Vec<u32> = head.split('.').filter_map(|s| s.parse().ok()).take(3).collect();
    let major = nums.first().copied().unwrap_or(0);
    let minor = nums.get(1).copied().unwrap_or(0);
    let patch = nums.get(2).copied().unwrap_or(0);

    let tl = tail.to_ascii_lowercase();
    let (stage, sub) = if tl.is_empty() {
        (3, 0)
    } else if let Some(rest) = tl.strip_prefix("alpha") {
        (0, rest.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().unwrap_or(0))
    } else if let Some(rest) = tl.strip_prefix("beta") {
        (1, rest.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().unwrap_or(0))
    } else if let Some(rest) = tl.strip_prefix("rc") {
        (2, rest.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().unwrap_or(0))
    } else {
        (3, 0)
    };

    (major, minor, patch, stage, sub)
}

fn affected(ver: &str) -> Option<(&'static str, &'static str)> {
    let k = version_key(ver);
    // CVE-2026-63030: batch route confusion -> RCE chain
    if (k >= (6, 9, 0, 0, 0) && k < (6, 9, 5, 3, 0))
        || (k >= (7, 0, 0, 0, 0) && k < (7, 0, 2, 3, 0))
        || (k >= (7, 1, 0, 0, 0) && k < (7, 1, 0, 1, 2))
    {
        return Some(("RCE", "CVE-2026-63030 (+ CVE-2026-60137)"));
    }
    // CVE-2026-60137: SQLi only, no RCE chain on 6.8 line
    if k >= (6, 8, 0, 0, 0) && k < (6, 8, 6, 3, 0) {
        return Some(("SQLi", "CVE-2026-60137"));
    }
    None
}

// ─── HTTP helpers ──────────────────────────────────────────────────────────────

fn extract_wp_version(html: &str) -> Option<String> {
    let needle = r#"name="generator" content="WordPress "#;
    let start = html.find(needle)?;
    let after = &html[start + needle.len()..];
    let end = after.find('"')?;
    let v = after[..end].trim();
    if v.is_empty() { None } else { Some(v.to_string()) }
}

async fn scan_host(client: &Client, host: &str) -> WpScanResult {
    let base = if host.contains("://") {
        host.trim_end_matches('/').to_string()
    } else {
        format!("https://{}", host.trim_end_matches('/'))
    };

    // 1. Fetch homepage — detect WordPress version
    let version = match client.get(&base).send().await {
        Ok(resp) => resp.text().await.ok().and_then(|b| extract_wp_version(&b)),
        Err(_) => {
            // Retry over http
            let http_base = base.replacen("https://", "http://", 1);
            match client.get(&http_base).send().await {
                Ok(resp) => resp.text().await.ok().and_then(|b| extract_wp_version(&b)),
                Err(_) => {
                    return WpScanResult {
                        host: host.to_string(),
                        version: None,
                        batch_route: false,
                        severity: None,
                        cve: None,
                        verdict: "unreachable".to_string(),
                    };
                }
            }
        }
    };

    // 2. Probe the REST batch route
    let batch_url = format!("{}/?rest_route=/batch/v1", base);
    let batch_route = match client
        .post(&batch_url)
        .header("Content-Type", "application/json")
        .body("{}")
        .send()
        .await
    {
        Ok(resp) => {
            let text = resp.text().await.unwrap_or_default();
            text.contains("rest_missing_callback_param") || text.contains("rest_invalid_param")
        }
        Err(_) => false,
    };

    // 3. Correlate version + route with known-affected ranges
    let (severity, cve, verdict) = match version.as_deref() {
        Some(v) => match affected(v) {
            Some((sev, c)) if batch_route => (
                Some(sev.to_string()),
                Some(c.to_string()),
                format!("VULNERABLE ({sev}, {c})"),
            ),
            Some((sev, c)) => (
                Some(sev.to_string()),
                Some(c.to_string()),
                format!("version-affected ({sev}, {c}), route unconfirmed"),
            ),
            None => (None, None, "not affected".to_string()),
        },
        None => (None, None, "wordpress not detected".to_string()),
    };

    WpScanResult { host: host.to_string(), version, batch_route, severity, cve, verdict }
}

// ─── Public scan entry-point ───────────────────────────────────────────────────

pub async fn run_scan(hosts: Vec<String>, cfg: ScanConfig) -> Result<Vec<WpScanResult>> {
    let client = Arc::new(
        Client::builder()
            .user_agent(UA)
            .timeout(Duration::from_secs(cfg.timeout_secs))
            .danger_accept_invalid_certs(true)
            .redirect(redirect::Policy::limited(5))
            .build()?,
    );
    let sem = Arc::new(Semaphore::new(cfg.threads));

    eprintln!("[*] wp2shell: scanning {} host(s) ...", hosts.len());

    let handles: Vec<_> = hosts
        .into_iter()
        .map(|host| {
            let client = client.clone();
            let sem = sem.clone();
            tokio::spawn(async move {
                let _permit = sem.acquire().await.expect("semaphore closed");
                scan_host(&client, &host).await
            })
        })
        .collect();

    let mut results = Vec::with_capacity(handles.len());
    for h in handles {
        results.push(h.await?);
    }
    Ok(results)
}

pub fn print_results(results: &[WpScanResult], json: bool) {
    if json {
        println!("{}", serde_json::to_string_pretty(results).unwrap_or_default());
    } else {
        for r in results {
            let ver_tag = r.version.as_deref().map(|v| format!("  [{}]", v)).unwrap_or_default();
            println!("{:<45} {}{}", r.host, r.verdict, ver_tag);
        }
    }
}

// ─── CLI dispatch ──────────────────────────────────────────────────────────────

pub async fn run_from_args(
    hosts: Vec<String>,
    file: Option<PathBuf>,
    json: bool,
    threads: usize,
    timeout: u64,
) -> anyhow::Result<()> {
    let mut targets = hosts;
    if let Some(path) = file {
        let content = std::fs::read_to_string(&path)?;
        targets.extend(
            content.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_string),
        );
    }
    if targets.is_empty() {
        anyhow::bail!("[-] provide one or more hosts, or -f hosts.txt");
    }

    let cfg = ScanConfig { threads, timeout_secs: timeout, json_output: json };
    let t0 = Instant::now();
    let results = run_scan(targets, cfg).await?;
    let elapsed = t0.elapsed();

    print_results(&results, json);

    let vuln = results.iter().filter(|r| r.verdict.starts_with("VULNERABLE")).count();
    eprintln!(
        "[*] done: {} scanned, {} VULNERABLE — {:.2}s",
        results.len(),
        vuln,
        elapsed.as_secs_f64()
    );
    Ok(())
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_key_stable() {
        assert_eq!(version_key("7.0.1"), (7, 0, 1, 3, 0));
    }

    #[test]
    fn version_key_beta() {
        assert_eq!(version_key("7.1.0-beta2"), (7, 1, 0, 1, 2));
    }

    #[test]
    fn version_key_rc() {
        assert_eq!(version_key("6.9.3-rc1"), (6, 9, 3, 2, 1));
    }

    #[test]
    fn affected_rce() {
        let r = affected("7.0.1");
        assert_eq!(r, Some(("RCE", "CVE-2026-63030 (+ CVE-2026-60137)")));
    }

    #[test]
    fn affected_sqli_only() {
        let r = affected("6.8.3");
        assert_eq!(r, Some(("SQLi", "CVE-2026-60137")));
    }

    #[test]
    fn not_affected() {
        assert_eq!(affected("6.7.0"), None);
        assert_eq!(affected("7.2.0"), None);
    }

    #[test]
    fn fixed_version_not_affected() {
        // 7.1.0-beta2 is the fix; beta1 is still vulnerable
        assert!(affected("7.1.0-beta1").is_some());
        assert_eq!(affected("7.1.0-beta2"), None);
    }

    #[test]
    fn extract_version_from_html() {
        let html = r#"<meta name="generator" content="WordPress 7.0.1" />"#;
        assert_eq!(extract_wp_version(html), Some("7.0.1".to_string()));
    }

    #[test]
    fn extract_version_missing() {
        let html = "<html><head><title>Not WordPress</title></head></html>";
        assert_eq!(extract_wp_version(html), None);
    }
}
