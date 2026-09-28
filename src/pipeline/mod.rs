// src/pipeline/mod.rs
// Async pipeline: domain stream → DNS → probe → fetch → credential scan.
//
// Architecture:
//   [StreamReader] --tx_target--> [DnsStage] --tx_live--> [FetchStage] --tx_hit--> [Sink]
//
// Each stage runs as a pool of tokio tasks. Channels are bounded for backpressure.
// If FetchStage is slow, DnsStage blocks, which blocks StreamReader — natural throttle.

use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::{info, warn};

use crate::config::Config;
use crate::types::{Hit, ScanStats, Target};

pub mod stream;

/// Entry point: run the full scan pipeline.
/// Returns total hits found.
pub async fn run(
    config: Arc<Config>,
    stats: Arc<ScanStats>,
    hit_tx: tokio::sync::mpsc::Sender<Hit>,
) -> anyhow::Result<u64> {

    // Channel: raw targets from stream → DNS stage
    let (target_tx, target_rx) = async_channel::bounded::<Target>(10_000);

    // Channel: DNS-resolved (live) targets → fetch stage
    let (live_tx, live_rx) = async_channel::bounded::<Target>(5_000);

    // Semaphore: limits concurrent HTTP connections (FD budget)
    let sem = Arc::new(Semaphore::new(config.concurrency));

    // Spawn domain stream reader
    let cfg_stream = config.clone();
    let stats_stream = stats.clone();
    let _stream_task = tokio::spawn(async move {
        if let Err(e) = stream::stream_domains(&cfg_stream, target_tx, &stats_stream).await {
            warn!("stream error: {e}");
        }
    });

    // Spawn DNS workers (56 cores → 512 DNS workers reasonable)
    let dns_workers = (config.concurrency / 4).max(64).min(512);
    info!("starting {dns_workers} DNS workers");
    for _ in 0..dns_workers {
        let rx = target_rx.clone();
        let tx = live_tx.clone();
        let cfg = config.clone();
        let st = stats.clone();
        tokio::spawn(async move {
            crate::dns::dns_worker(rx, tx, &cfg, &st).await;
        });
    }
    drop(target_rx);
    drop(live_tx);

    // Spawn fetch workers
    let fetch_workers = config.concurrency;
    info!("starting {fetch_workers} fetch workers");
    for _ in 0..fetch_workers {
        let rx = live_rx.clone();
        let hit_tx = hit_tx.clone();
        let cfg = config.clone();
        let st = stats.clone();
        let sem = sem.clone();
        tokio::spawn(async move {
            crate::fetch::fetch_worker(rx, hit_tx, &cfg, &st, sem).await;
        });
    }
    drop(live_rx);

    // Wait for all workers to finish (channels close when senders drop)
    // stream_task finishes → target_tx drops → dns_workers exit → live_tx drops → fetch_workers exit

    // Give workers time to drain
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    let total = stats.hits.load(std::sync::atomic::Ordering::Relaxed);
    Ok(total)
}
