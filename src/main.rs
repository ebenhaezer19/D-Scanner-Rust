// src/main.rs
// D-Scanner Rust Engine — entry point.
//
// M1 scope: pipeline foundation + DNS + HTTP fetch + credential scanning.
// M2 scope: exploit engines (livewire2shell, laravel2shell, langflow2shell, etc.)
//
// Use --mode scan    (default) for M1 only.
// Use --mode exploit for M2 only (reads --hits-input).
// Use --mode full    for M1 then M2 in one run.

mod config;
mod credential;
mod dns;
mod exploit;
mod fetch;
mod pipeline;
mod types;

use clap::Parser;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tracing::info;
use tracing_subscriber::EnvFilter;

use config::{Cli, Config};
use types::ScanStats;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Setup structured logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(&cli.log_level)),
        )
        .with_target(false)
        .compact()
        .init();

    let config = Arc::new(Config::from_cli(&cli));
    let stats = Arc::new(ScanStats::default());

    info!(
        concurrency = config.concurrency,
        dns_servers = config.dns_servers.len(),
        input = %cli.input,
        "dreks-core starting"
    );

    // Hit sink — receives hits from fetch workers and writes to stdout/file
    let (hit_tx, mut hit_rx) = tokio::sync::mpsc::channel::<types::Hit>(10_000);

    // Spawn hit writer
    let output_path = config.output_path.clone();
    let writer_task = tokio::spawn(async move {
        // Open output file if specified, otherwise write to stdout
        let mut file_writer: Option<tokio::io::BufWriter<tokio::fs::File>> = None;
        if let Some(ref path) = output_path {
            match tokio::fs::File::create(path).await {
                Ok(f) => file_writer = Some(tokio::io::BufWriter::new(f)),
                Err(e) => tracing::error!("cannot open output file {:?}: {e}", path),
            }
        }

        use tokio::io::AsyncWriteExt;
        while let Some(hit) = hit_rx.recv().await {
            let mut line = serde_json::to_string(&hit).unwrap_or_default();
            line.push('\n');
            if let Some(ref mut fw) = file_writer {
                let _ = fw.write_all(line.as_bytes()).await;
            } else {
                print!("{}", line);
            }
        }
        // Flush file if open
        if let Some(ref mut fw) = file_writer {
            let _ = fw.flush().await;
        }
    });

    // Progress reporter (every 10s)
    let stats_prog = stats.clone();
    let _progress_task = tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            let done = stats_prog.done.load(Ordering::Relaxed);
            let total = stats_prog.total.load(Ordering::Relaxed);
            let hits = stats_prog.hits.load(Ordering::Relaxed);
            let dns_nx = stats_prog.dns_nxdomain.load(Ordering::Relaxed);
            let conn_to = stats_prog.connect_timeout.load(Ordering::Relaxed);
            info!(
                "[progress] {done}/{total} done · hits={hits} · nxdomain={dns_nx} · conn_timeout={conn_to}"
            );
        }
    });

    // ── M1: credential scan (scan + full modes only) ──────────────────────────
    if config.mode == "scan" || config.mode == "full" {
        pipeline::run(config.clone(), stats.clone(), hit_tx).await?;
        writer_task.await?;

        let total = stats.total.load(Ordering::Relaxed);
        let hits  = stats.hits.load(Ordering::Relaxed);
        let dns_ok = stats.dns_ok.load(Ordering::Relaxed);
        let dns_nx = stats.dns_nxdomain.load(Ordering::Relaxed);
        info!(total, hits, dns_ok, dns_nxdomain = dns_nx, "[done] scan complete");
    } else {
        // exploit-only: drop writer immediately (no M1 hits to write)
        drop(hit_tx);
        writer_task.await?;
    }

    // ── M2: exploit mode ─────────────────────────────────────────────────────
    if config.mode == "exploit" || config.mode == "full" {
        // Determine hits input: --hits-input or --output from M1
        let hits_path = config.hits_input.clone()
            .or_else(|| config.output_path.as_ref().map(|p| p.to_string_lossy().to_string()));

        match hits_path {
            None => {
                tracing::error!("--mode exploit requires --hits-input <file.jsonl>");
            }
            Some(hits_file) => {
                info!("[exploit] loading engines");
                let engines = exploit::all_engines();
                info!("[exploit] {} engines registered", engines.len());

                let dispatch_cfg = exploit::dispatcher::DispatchConfig {
                    hits_input: hits_file,
                    exploit_output: config.exploit_output.clone(),
                    concurrency: config.exploit_concurrency,
                };

                if let Err(e) = exploit::dispatcher::run(dispatch_cfg, engines).await {
                    tracing::error!("[exploit] dispatcher error: {e}");
                }
            }
        }
    }

    Ok(())
}
