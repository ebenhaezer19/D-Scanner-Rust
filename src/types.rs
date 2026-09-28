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

        Some(Self { url: with_scheme, host, scheme, port })
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
