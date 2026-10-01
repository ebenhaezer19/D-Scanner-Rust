// src/config.rs
// Scanner configuration — loaded from CLI args + optional JSON file.

use clap::Parser;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// D-Scanner Rust Engine — CLI arguments
#[derive(Parser, Debug)]
#[command(name = "dreks", version, about = "High-performance web scanner")]
pub struct Cli {
    // ── M1: credential scan ─────────────────────────────────────────────────

    /// Domain/URL list file (one per line). Use '-' for stdin.
    #[arg(short, long, default_value = "domains.txt")]
    pub input: String,

    /// Max concurrent HTTP connections
    #[arg(short, long, default_value_t = 2000)]
    pub concurrency: usize,

    /// DNS resolvers (comma-separated IPs)
    #[arg(long, default_value = "8.8.8.8,1.1.1.1,9.9.9.9,8.8.4.4")]
    pub dns_servers: String,

    /// HTTP connect timeout (seconds)
    #[arg(long, default_value_t = 10)]
    pub timeout: u64,

    /// Max body size to download (bytes)
    #[arg(long, default_value_t = 1_048_576)] // 1MB
    pub max_body: usize,

    /// Max JS files to fetch per domain
    #[arg(long, default_value_t = 3)]
    pub max_js: usize,

    /// Output hits to this file (JSONL). Stdout if not set.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    pub log_level: String,

    /// Disable raw UDP DNS (fall back to system resolver)
    #[arg(long, default_value_t = false)]
    pub no_raw_dns: bool,

    /// Minimum confidence level to output (low, medium, high)
    #[arg(long, default_value = "medium")]
    pub min_confidence: String,

    // ── M2: exploit engines ─────────────────────────────────────────────────

    /// Operation mode: scan (M1 only), exploit (M2 only), full (M1+M2).
    #[arg(long, default_value = "scan")]
    pub mode: String,

    /// M1 hits JSONL to read in exploit/full mode.
    #[arg(long)]
    pub hits_input: Option<String>,

    /// Exploit results output file (JSONL). Stdout if not set.
    #[arg(long)]
    pub exploit_output: Option<String>,

    /// Max concurrent exploit attempts (exploit engines are slow).
    #[arg(long, default_value_t = 10)]
    pub exploit_concurrency: usize,
}

/// Runtime config derived from CLI + any JSON overrides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    // M1
    pub input: String,
    pub concurrency: usize,
    pub dns_servers: Vec<String>,
    pub connect_timeout_secs: u64,
    pub max_body_bytes: usize,
    pub max_js_per_domain: usize,
    pub output_path: Option<PathBuf>,
    pub raw_dns: bool,
    pub min_confidence: String,
    // M2
    pub mode: String,
    pub hits_input: Option<String>,
    pub exploit_output: Option<String>,
    pub exploit_concurrency: usize,
}

impl Config {
    pub fn from_cli(cli: &Cli) -> Self {
        let dns_servers = cli
            .dns_servers
            .split(',')
            .map(|s| {
                let s = s.trim();
                if s.contains(':') { s.to_string() } else { format!("{}:53", s) }
            })
            .collect();

        Self {
            input: cli.input.clone(),
            concurrency: cli.concurrency,
            dns_servers,
            connect_timeout_secs: cli.timeout,
            max_body_bytes: cli.max_body,
            max_js_per_domain: cli.max_js,
            output_path: cli.output.clone(),
            raw_dns: !cli.no_raw_dns,
            min_confidence: cli.min_confidence.to_lowercase(),
            // M2
            mode: cli.mode.to_lowercase(),
            hits_input: cli.hits_input.clone(),
            exploit_output: cli.exploit_output.clone(),
            exploit_concurrency: cli.exploit_concurrency,
        }
    }
}
