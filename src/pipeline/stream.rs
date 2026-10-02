// src/pipeline/stream.rs
// Streaming domain input — reads domains line by line without loading to RAM.
// Supports: file path, stdin ('-'), or direct URL list.
// With --skip-dns: parses massdns -o S output (domain A ip) for pre-resolved targets.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{debug, info};

use crate::config::Config;
use crate::types::{ScanStats, Target};

/// Stream domains from file/stdin into `tx` channel.
/// Never loads the entire file into RAM — reads one line at a time.
pub async fn stream_domains(
    config: &Config,
    tx: async_channel::Sender<Target>,
    stats: &Arc<ScanStats>,
) -> anyhow::Result<()> {
    let input = &config.input;
    info!(
        "streaming domains from: {input} (skip_dns={})",
        config.skip_dns
    );

    if input == "-" {
        let stdin = tokio::io::stdin();
        stream_reader(BufReader::new(stdin), tx, stats, config.skip_dns).await
    } else {
        let file = tokio::fs::File::open(input).await.map_err(|e| {
            anyhow::anyhow!("cannot open input file '{}': {e}", input)
        })?;
        stream_reader(BufReader::new(file), tx, stats, config.skip_dns).await
    }
}

/// Generic line-by-line reader that sends parsed Targets to the pipeline channel.
/// When `skip_dns=true`, uses massdns output parser (from_massdns_line).
/// When `skip_dns=false`, uses standard domain parser (from_str).
async fn stream_reader<R: tokio::io::AsyncRead + Unpin>(
    reader: BufReader<R>,
    tx: async_channel::Sender<Target>,
    stats: &Arc<ScanStats>,
    skip_dns: bool,
) -> anyhow::Result<()> {
    let mut lines = reader.lines();
    let mut sent = 0u64;
    let mut skipped = 0u64;

    while let Some(line) = lines.next_line().await? {
        // Strip BOM (UTF-8 with BOM from Windows tools) and whitespace
        let line = line.trim_start_matches('\u{FEFF}').trim().to_string();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            skipped += 1;
            continue;
        }

        // Parse into Target(s) — massdns returns Vec (http+https), normal returns Option
        if skip_dns {
            let targets = Target::from_massdns_line(&line);
            if targets.is_empty() {
                skipped += 1;
            }
            for t in targets {
                stats.total.fetch_add(1, Ordering::Relaxed);
                debug!("queued: {} (ip={:?})", t.url, t.resolved_ip);
                if tx.send(t).await.is_err() {
                    break;
                }
                sent += 1;
            }
        } else {
            match Target::from_str(&line) {
                Some(t) => {
                    stats.total.fetch_add(1, Ordering::Relaxed);
                    debug!("queued: {} (ip={:?})", t.url, t.resolved_ip);
                    if tx.send(t).await.is_err() {
                        break;
                    }
                    sent += 1;
                }
                None => { skipped += 1; }
            }
        }
    }

    info!("stream done: {sent} queued, {skipped} skipped");
    Ok(())
}
