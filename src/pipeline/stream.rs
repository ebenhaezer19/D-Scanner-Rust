// src/pipeline/stream.rs
// Streaming domain input — reads domains line by line without loading to RAM.
// Supports: file path, stdin ('-'), or direct URL list.

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
    // Determine input source
    let input = &config.input;
    info!("streaming domains from: {input}");

    if input == "-" {
        // Read from stdin
        let stdin = tokio::io::stdin();
        stream_reader(BufReader::new(stdin), tx, stats).await
    } else {
        // Read from file
        let file = tokio::fs::File::open(input).await.map_err(|e| {
            anyhow::anyhow!("cannot open input file '{}': {e}", input)
        })?;
        stream_reader(BufReader::new(file), tx, stats).await
    }
}

/// Generic line-by-line reader that sends parsed Targets to the pipeline channel.
async fn stream_reader<R: tokio::io::AsyncRead + Unpin>(
    reader: BufReader<R>,
    tx: async_channel::Sender<Target>,
    stats: &Arc<ScanStats>,
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

        // Parse into Target
        match Target::from_str(&line) {
            Some(target) => {
                stats.total.fetch_add(1, Ordering::Relaxed);
                debug!("queued: {}", target.url);

                // Send to pipeline — blocks if channel is full (backpressure)
                if tx.send(target).await.is_err() {
                    // Channel closed — pipeline shutting down
                    break;
                }
                sent += 1;
            }
            None => {
                skipped += 1;
            }
        }
    }

    info!("stream done: {sent} queued, {skipped} skipped");
    Ok(())
    // tx drops here → DNS workers will see channel closed and exit
}

// ─── Config field for input (add to Config struct) ───────────────────────────
// We reference config.input above — make sure Config has this field.
// Already defined in config.rs as pub input: String.
