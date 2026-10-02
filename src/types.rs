// src/types.rs
// Core domain types shared across all pipeline stages.

use serde::{Deserialize, Serialize};
use std::fmt;
use chrono::{DateTime, Utc};

/// A target URL to be scanned. Created from a raw domain string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub url: String,
    pub host: String,
    pub scheme: String,
    pub port: Option<u16>,
    /// Pre-resolved IP from massdns (--skip-dns mode).
    /// When set, DNS worker is bypassed — IP used directly for TCP connect.
    pub resolved_ip: Option<String>,
}

impl Target {
    /// Parse a raw string (domain or full URL) into a Target.
    /// Adds https:// prefix if no scheme is present.
    pub fn from_str(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        if raw.is_empty() || raw.starts_with('#') {
            return None;
        }

        // Add scheme if missing
        let with_scheme = if raw.contains("://") {
            raw.to_string()
        } else {
            format!("https://{}", raw)
        };

        let url = url::Url::parse(&with_scheme).ok()?;
        let host = url.host_str()?.to_string();
        let scheme = url.scheme().to_string();
        let port = url.port();

        Some(Self { url: with_scheme, host, scheme, port, resolved_ip: None })
    }

    /// Parse massdns -o S output line:
    ///   "example.com. A 1.2.3.4"  → Target with resolved_ip=Some("1.2.3.4")
    ///   "example.com A 1.2.3.4"   → same (with or without trailing dot)
    ///   "1.2.3.4"                  → bare IP target
    ///   "example.com"             → plain domain (no IP — falls back to from_str)
    ///
    /// Returns Vec<Target> because we emit BOTH http:// and https:// variants
    /// when an IP is known, maximizing hit coverage (some sites HTTPS-only).
    pub fn from_massdns_line(line: &str) -> Vec<Self> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return vec![];
        }

        let parts: Vec<&str> = line.split_whitespace().collect();

        match parts.len() {
            // Format: "domain. A ip" or "domain A ip" (massdns -o S)
            n if n >= 3 => {
                let rtype = parts[1].to_uppercase();
                if rtype != "A" && rtype != "AAAA" {
                    return vec![]; // skip CNAME, NS, MX etc.
                }
                let domain = parts[0].trim_end_matches('.');
                let ip = parts[n - 1];
                // Emit both http and https to maximise coverage
                let mut targets = Vec::new();
                for scheme in ["http", "https"] {
                    if let Some(mut t) = Self::from_str(&format!("{}://{}", scheme, domain)) {
                        t.resolved_ip = Some(ip.to_string());
                        targets.push(t);
                    }
                }
                targets
            }
            // Single token: bare IP or bare domain
            1 => {
                let is_ip = parts[0].parse::<std::net::IpAddr>().is_ok();
                let mut targets = Vec::new();
                for scheme in ["http", "https"] {
                    if let Some(mut t) = Self::from_str(&format!("{}://{}", scheme, parts[0])) {
                        if is_ip {
                            t.resolved_ip = Some(parts[0].to_string());
                        }
                        targets.push(t);
                    }
                }
                targets
            }
            // Format: "domain ip" (2 tokens)
            2 => {
                let domain = parts[0].trim_end_matches('.');
                let ip = parts[1];
                if ip.parse::<std::net::IpAddr>().is_ok() {
                    let mut targets = Vec::new();
                    for scheme in ["http", "https"] {
                        if let Some(mut t) = Self::from_str(&format!("{}://{}", scheme, domain)) {
                            t.resolved_ip = Some(ip.to_string());
                            targets.push(t);
                        }
                    }
                    targets
                } else {
                    Self::from_str(domain).into_iter().collect()
                }
            }
            _ => vec![],
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.url)
    }
}

/// A credential hit found in a page or JS file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hit {
    pub target: String,
    pub provider: String,         // e.g. "openai", "stripe", "aws"
    pub value: String,            // the raw credential value
    pub confidence: Confidence,
    pub source: HitSource,
    pub found_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Confidence {
    High,    // matches known format exactly
    Medium,  // pattern match but not validated
    Low,     // weak signal
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Confidence::High => write!(f, "high"),
            Confidence::Medium => write!(f, "medium"),
            Confidence::Low => write!(f, "low"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HitSource {
    Html,
    JsFile(String),   // URL of the JS file
    EnvFile,
    ConfigFile,
    GitObject,
}

impl fmt::Display for HitSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HitSource::Html => write!(f, "html"),
            HitSource::JsFile(url) => write!(f, "js:{}", url),
            HitSource::EnvFile => write!(f, ".env"),
            HitSource::ConfigFile => write!(f, "config"),
            HitSource::GitObject => write!(f, "git"),
        }
    }
}

/// DNS resolution outcome.
#[derive(Debug, Clone)]
pub enum DnsResult {
    Resolved(Vec<std::net::IpAddr>),
    NxDomain,
    Timeout,
    Error(String),
}

/// Final outcome for a scanned target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub target: String,
    pub status: ScanStatus,
    pub hits: Vec<Hit>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanStatus {
    Ok,
    DnsNxDomain,
    DnsTimeout,
    ConnectTimeout,
    ConnectRefused,
    TlsError,
    HttpError(u16),
    Skipped,
    Error(String),
}

/// Scan-wide progress counters (atomic, shared across threads).
#[derive(Debug, Default)]
pub struct ScanStats {
    pub total: std::sync::atomic::AtomicU64,
    pub done: std::sync::atomic::AtomicU64,
    pub hits: std::sync::atomic::AtomicU64,
    pub dns_ok: std::sync::atomic::AtomicU64,
    pub dns_nxdomain: std::sync::atomic::AtomicU64,
    pub dns_timeout: std::sync::atomic::AtomicU64,
    pub connect_timeout: std::sync::atomic::AtomicU64,
    pub http_ok: std::sync::atomic::AtomicU64,
    pub http_error: std::sync::atomic::AtomicU64,
}
