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
    pub fn from_massdns_line(line: &str) -> Option<Self> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();

        match parts.len() {
            // Format: "domain. A ip" or "domain A ip"
            n if n >= 3 => {
                let rtype = parts[1].to_uppercase();
                if rtype != "A" && rtype != "AAAA" {
                    return None; // skip CNAME, NS, MX etc.
                }
                let domain = parts[0].trim_end_matches('.');
                let ip = parts[n - 1];
                // Build HTTP target using domain as Host, IP for connect
                let url = format!("http://{}", domain);
                let mut t = Self::from_str(&url)?;
                t.resolved_ip = Some(ip.to_string());
                Some(t)
            }
            // Single token: bare IP or bare domain
            1 => {
                // Check if it looks like an IP
                let is_ip = parts[0].parse::<std::net::IpAddr>().is_ok();
                let mut t = Self::from_str(parts[0])?;
                if is_ip {
                    t.resolved_ip = Some(parts[0].to_string());
                }
                Some(t)
            }
            // Format: "domain ip" (2 tokens, space-separated)
            2 => {
                let domain = parts[0].trim_end_matches('.');
                let ip = parts[1];
                if ip.parse::<std::net::IpAddr>().is_ok() {
                    let mut t = Self::from_str(domain)?;
                    t.resolved_ip = Some(ip.to_string());
                    Some(t)
                } else {
                    Self::from_str(domain)
                }
            }
            _ => None,
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
