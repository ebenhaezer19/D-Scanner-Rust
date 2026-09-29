// src/pipeline/mod.rs
// Async pipeline: domain stream -> DNS -> fetch -> credential scan.
//
// Architecture:
//   [StreamReader] --target_tx--> [DnsWorkers] --live_tx--> [FetchWorkers] --hit_tx--> [Sink]
//
// Shutdown sequence:
//   StreamReader finishes -> target_tx dropped -> DNS workers see closed channel -> exit
//   DNS workers exit -> live_tx dropped (all senders gone) -> fetch workers see closed channel -> exit
//   Fetch workers exit -> hit_tx dropped -> hit_rx in main returns None -> writer task exits

use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{info, warn};

use crate::config::Config;
use crate::types::{Hit, ScanStats, Target};

pub mod stream;

/// Entry point: run the full scan pipeline.
/// Blocks until all domains are processed and all workers have exited.
pub async fn run(
    config: Arc<Config>,
    stats: Arc<ScanStats>,
    hit_tx: tokio::sync::mpsc::Sender<Hit>,
) -> anyhow::Result<u64> {

    // Channel: raw targets from stream -> DNS workers
    let (target_tx, target_rx) = async_channel::bounded::<Target>(10_000);

    // Channel: DNS-resolved (live) targets -> fetch workers
    let (live_tx, live_rx) = async_channel::bounded::<Target>(5_000);

    // Semaphore: cap concurrent HTTP connections (FD budget)
    let sem = Arc::new(Semaphore::new(config.concurrency));

    let mut tasks: JoinSet<()> = JoinSet::new();

    // --- Stream reader ---
    {
        let cfg = config.clone();
        let st = stats.clone();
        let tx = target_tx.clone();
        tasks.spawn(async move {
            if let Err(e) = stream::stream_domains(&cfg, tx, &st).await {
                warn!("stream error: {e}");
            }
            // tx (target_tx clone) drops here -> one fewer sender on the channel
        });
    }
    drop(target_tx); // drop the original so DNS workers see channel close when stream task exits

    // --- DNS workers ---
    let dns_workers = (config.concurrency / 4).max(64).min(512);
    info!("starting {dns_workers} DNS workers");
    for _ in 0..dns_workers {
        let rx = target_rx.clone();
        let tx = live_tx.clone();
        let cfg = config.clone();
        let st = stats.clone();
        tasks.spawn(async move {
            crate::dns::dns_worker(rx, tx, &cfg, &st).await;
            // tx (live_tx clone) drops here when this worker exits
        });
    }
    drop(target_rx); // no more receivers needed outside workers
    drop(live_tx);   // drop original; channel closes when all DNS worker clones drop

    // --- Fetch workers ---
    let fetch_workers = config.concurrency;
    info!("starting {fetch_workers} fetch workers");
    for _ in 0..fetch_workers {
        let rx = live_rx.clone();
        let htx = hit_tx.clone();
        let cfg = config.clone();
        let st = stats.clone();
        let sem = sem.clone();
        tasks.spawn(async move {
            crate::fetch::fetch_worker(rx, htx, &cfg, &st, sem).await;
        });
    }
    drop(live_rx);
    drop(hit_tx); // drop pipeline's copy; main's copy still alive for the writer task

    // Wait for all tasks to complete — proper shutdown, no sleep hacks
    while tasks.join_next().await.is_some() {}

    let total = stats.hits.load(std::sync::atomic::Ordering::Relaxed);
    Ok(total)
}
