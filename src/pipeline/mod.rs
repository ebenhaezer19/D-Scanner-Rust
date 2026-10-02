// src/pipeline/mod.rs
// Async pipeline: domain stream -> DNS -> fetch -> credential scan.
//
// Architecture (normal mode):
//   [StreamReader] --target_tx--> [DnsWorkers] --live_tx--> [FetchWorkers] --hit_tx--> [Sink]
//
// Architecture (--skip-dns / massdns pre-resolved mode):
//   [StreamReader] ──────────────────────────> [FetchWorkers] --hit_tx--> [Sink]
//   DNS workers are skipped entirely — resolved_ip already in Target.

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

    let sem = Arc::new(Semaphore::new(config.concurrency));
    let mut tasks: JoinSet<()> = JoinSet::new();

    if config.skip_dns {
        // ── SKIP-DNS MODE (massdns pre-resolved) ──────────────────────────
        // Stream sends pre-resolved targets directly to fetch workers.
        // Eliminates hickory DNS workers and UDP socket contention entirely.

        let (live_tx, live_rx) = async_channel::bounded::<Target>(10_000);

        {
            let cfg = config.clone();
            let st = stats.clone();
            let tx = live_tx.clone();
            tasks.spawn(async move {
                if let Err(e) = stream::stream_domains(&cfg, tx, &st).await {
                    warn!("stream error: {e}");
                }
            });
        }
        drop(live_tx);

        let fetch_workers = config.concurrency;
        info!("skip_dns=true: starting {fetch_workers} fetch workers (DNS bypassed)");
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

    } else {
        // ── NORMAL MODE (hickory DNS resolver) ────────────────────────────

        let (target_tx, target_rx) = async_channel::bounded::<Target>(10_000);
        let (live_tx, live_rx) = async_channel::bounded::<Target>(5_000);

        {
            let cfg = config.clone();
            let st = stats.clone();
            let tx = target_tx.clone();
            tasks.spawn(async move {
                if let Err(e) = stream::stream_domains(&cfg, tx, &st).await {
                    warn!("stream error: {e}");
                }
            });
        }
        drop(target_tx);

        // DNS workers — capped at 256 to prevent UDP socket contention
        let dns_workers = (config.concurrency / 8).max(64).min(256);
        info!("starting {dns_workers} DNS workers");
        for _ in 0..dns_workers {
            let rx = target_rx.clone();
            let tx = live_tx.clone();
            let cfg = config.clone();
            let st = stats.clone();
            tasks.spawn(async move {
                crate::dns::dns_worker(rx, tx, &cfg, &st).await;
            });
        }
        drop(target_rx);
        drop(live_tx);

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
    }

    drop(hit_tx);

    while tasks.join_next().await.is_some() {}

    let total = stats.hits.load(std::sync::atomic::Ordering::Relaxed);
    Ok(total)
}
