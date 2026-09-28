// src/fetch/mod.rs
// HTTP fetcher — one reqwest::Client per worker, with cookie jar.
//
// Key design decisions (learned from Go debugging sessions):
//   1. Never share a Client between targets — cookie jar would leak between sessions
//   2. Use independent timeout (not tied to any job context)
//   3. Limit body size to avoid OOM on huge responses
//   4. Decompress gzip/brotli (many sites compress responses)
//   5. Follow redirects but cap at 5
//   6. Extract JS URLs for tier-scored secondary fetch

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT, ACCEPT, ACCEPT_LANGUAGE};
use tokio::sync::Semaphore;
use tracing::debug;

use crate::config::Config;
use crate::credential;
use crate::types::{Hit, ScanStats, Target};

pub mod js;

/// Build a fresh reqwest Client per target — isolated cookie jar.
/// This is the key fix from the Go livewire2shell debugging:
///   Go was sharing clients → cookies leaked between targets.
fn new_client(config: &Config) -> anyhow::Result<reqwest::Client> {
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
    ));
    headers.insert(ACCEPT, HeaderValue::from_static(
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    ));
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.5"));

    let client = reqwest::Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(config.connect_timeout_secs))
        .connect_timeout(Duration::from_secs(config.connect_timeout_secs))
        .cookie_store(true)              // per-client cookie jar
        .redirect(reqwest::redirect::Policy::limited(5))
        .danger_accept_invalid_certs(true)   // many targets have self-signed certs
        .gzip(true)
        .brotli(true)
        .tcp_nodelay(true)
        .pool_idle_timeout(Duration::from_secs(5))
        .pool_max_idle_per_host(1)
        .build()?;

    Ok(client)
}

/// Fetch target HTML, scan for credentials, then fetch top JS files.
pub async fn fetch_target(
    target: &Target,
    config: &Config,
) -> anyhow::Result<Vec<Hit>> {
    let client = new_client(config)?;
    let mut hits = Vec::new();

    // ── Fetch main HTML page ──────────────────────────────────────────────────
    let resp = client
        .get(&target.url)
        .send()
        .await?;

    let status = resp.status();
    debug!("{} → HTTP {}", target.url, status);

    // Read body with size limit
    let body_bytes = read_limited(resp, config.max_body_bytes).await?;
    let html = String::from_utf8_lossy(&body_bytes);

    // Scan HTML for credentials
    let html_hits = credential::scan_text(&html, &target.url, crate::types::HitSource::Html);
    hits.extend(html_hits);

    // ── JS fetching (tier-scored) ─────────────────────────────────────────────
    let js_urls = js::extract_js_urls(&html, &target.url, config.max_js_per_domain);
    for js_url in js_urls {
        match client.get(&js_url).send().await {
            Ok(js_resp) => {
                let js_bytes = read_limited(js_resp, config.max_body_bytes).await?;
                let js_text = String::from_utf8_lossy(&js_bytes);
                let source = crate::types::HitSource::JsFile(js_url.clone());
                let js_hits = credential::scan_text(&js_text, &target.url, source);
                hits.extend(js_hits);
            }
            Err(e) => {
                debug!("js fetch error {js_url}: {e}");
            }
        }
    }

    Ok(hits)
}

/// Read response body up to `limit` bytes. Returns error if request fails.
async fn read_limited(
    resp: reqwest::Response,
    limit: usize,
) -> anyhow::Result<bytes::Bytes> {
    use futures::StreamExt;

    let mut buf = bytes::BytesMut::new();
    let mut stream = resp.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if buf.len() + chunk.len() > limit {
            // Truncate — don't error, just stop reading
            break;
        }
        buf.extend_from_slice(&chunk);
    }

    Ok(buf.freeze())
}

// ─── Fetch worker (runs as tokio task) ───────────────────────────────────────

/// Receive live targets from DNS stage, fetch + scan, emit hits.
pub async fn fetch_worker(
    rx: async_channel::Receiver<Target>,
    hit_tx: tokio::sync::mpsc::Sender<Hit>,
    config: &Config,
    stats: &Arc<ScanStats>,
    sem: Arc<Semaphore>,
) {
    while let Ok(target) = rx.recv().await {
        // Acquire FD slot before opening TCP connection
        let _permit = sem.acquire().await.unwrap();

        match fetch_target(&target, config).await {
            Ok(hits) => {
                stats.http_ok.fetch_add(1, Ordering::Relaxed);
                stats.done.fetch_add(1, Ordering::Relaxed);

                for hit in hits {
                    stats.hits.fetch_add(1, Ordering::Relaxed);
                    if hit_tx.send(hit).await.is_err() {
                        return; // sink closed
                    }
                }
            }
            Err(e) => {
                debug!("fetch error {}: {e}", target.url);
                stats.http_error.fetch_add(1, Ordering::Relaxed);
                stats.done.fetch_add(1, Ordering::Relaxed);
            }
        }
        // _permit drops here → FD slot released
    }
}
