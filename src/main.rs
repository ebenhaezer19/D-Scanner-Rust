// src/main.rs
// D-Scanner Rust Engine — entry point.
//
// M1 scope: pipeline foundation + DNS + HTTP fetch + credential scanning.
// Exploit engines (livewire2shell, etc.) will be added in M2.

mod config;
mod credential;
mod dns;
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

    // Run pipeline — pass hit_tx into pipeline, drop it here after run returns
    // so the writer task can detect channel closed and exit
    pipeline::run(config.clone(), stats.clone(), hit_tx).await?;
    // hit_tx is now fully dropped (pipeline drops its copy, main drops here)

    // Wait for writer to drain all buffered hits
    writer_task.await?;

    // Final summary
    let total = stats.total.load(Ordering::Relaxed);
    let hits = stats.hits.load(Ordering::Relaxed);
    let dns_ok = stats.dns_ok.load(Ordering::Relaxed);
    let dns_nx = stats.dns_nxdomain.load(Ordering::Relaxed);

    info!(
        total,
        hits,
        dns_ok,
        dns_nxdomain = dns_nx,
        "[done] scan complete"
    );

    Ok(())
}
