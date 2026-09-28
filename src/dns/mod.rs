// src/dns/mod.rs
// Raw async DNS resolver using hickory-resolver (pure Rust, no OS resolver).
//
// Why hickory instead of OS resolver:
//   - No getaddrinfo() syscall blocking — OS resolver uses thread-per-lookup
//   - Configurable servers (use 8.8.8.8 directly, not /etc/resolv.conf)
//   - Built-in async, no blocking_spawn needed
//   - Proper NXDOMAIN detection vs timeout discrimination
//
// On the VPS (56 core, Debian 12, unlimited BW):
//   - We run 512 concurrent DNS lookups
//   - Cache hits (DashMap) avoid re-querying the same host
//   - NXDOMAIN cached permanently, timeouts cached 30s only

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use dashmap::DashMap;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts, NameServerConfig, Protocol};
use hickory_resolver::error::ResolveErrorKind;
use tracing::debug;

use crate::config::Config;
use crate::types::{DnsResult, ScanStats, Target};

/// DNS cache entry
#[derive(Clone)]
enum CacheEntry {
    Ok(Vec<IpAddr>),
    NxDomain,
    // Transient failures are not cached
}

/// Shared DNS resolver + cache, cloned cheaply via Arc.
#[derive(Clone)]
pub struct DnsResolver {
    resolver: Arc<TokioAsyncResolver>,
    cache: Arc<DashMap<String, CacheEntry>>,
}

impl DnsResolver {
    /// Build a resolver from config DNS server list.
    pub fn new(config: &Config) -> anyhow::Result<Self> {
        let mut rc = ResolverConfig::new();
        for server in &config.dns_servers {
            let addr: std::net::SocketAddr = server.parse().map_err(|e| {
                anyhow::anyhow!("invalid DNS server '{}': {e}", server)
            })?;
            rc.add_name_server(NameServerConfig {
                socket_addr: addr,
                protocol: Protocol::Udp,
                tls_dns_name: None,
                trust_negative_responses: true,
                bind_addr: None,
            });
        }

        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(2);  // 2s per DNS query
        opts.attempts = 2;                        // retry once on timeout
        opts.cache_size = 65536;                  // internal hickory cache

        let resolver = TokioAsyncResolver::tokio(rc, opts);
        Ok(Self {
            resolver: Arc::new(resolver),
            cache: Arc::new(DashMap::with_capacity(262_144)),
        })
    }

    /// Resolve host → IPs. Uses cache, never blocks.
    pub async fn resolve(&self, host: &str) -> DnsResult {
        // Raw IP — skip lookup
        if let Ok(ip) = host.parse::<IpAddr>() {
            return DnsResult::Resolved(vec![ip]);
        }

        // Cache hit
        if let Some(entry) = self.cache.get(host) {
            return match entry.value() {
                CacheEntry::Ok(ips) => DnsResult::Resolved(ips.clone()),
                CacheEntry::NxDomain => DnsResult::NxDomain,
            };
        }

        // Live lookup
        match self.resolver.lookup_ip(host).await {
            Ok(lookup) => {
                let ips: Vec<IpAddr> = lookup.iter().collect();
                if ips.is_empty() {
                    self.cache.insert(host.to_string(), CacheEntry::NxDomain);
                    return DnsResult::NxDomain;
                }
                debug!("dns ok: {} → {} addr(s)", host, ips.len());
                self.cache.insert(host.to_string(), CacheEntry::Ok(ips.clone()));
                DnsResult::Resolved(ips)
            }
            Err(e) => match e.kind() {
                ResolveErrorKind::NoRecordsFound { .. } => {
                    // Permanent NXDOMAIN — cache forever
                    self.cache.insert(host.to_string(), CacheEntry::NxDomain);
                    DnsResult::NxDomain
                }
                _ => {
                    // Transient (timeout, SERVFAIL) — don't cache
                    debug!("dns timeout/err: {} — {}", host, e);
                    DnsResult::Timeout
                }
            },
        }
    }
}

// ─── DNS worker (runs as tokio task) ─────────────────────────────────────────

/// Receive Targets from channel, resolve DNS, forward live hosts to next stage.
pub async fn dns_worker(
    rx: async_channel::Receiver<Target>,
    tx: async_channel::Sender<Target>,
    config: &Config,
    stats: &Arc<ScanStats>,
) {
    // Each worker has its own resolver (but shares the same DNS servers config)
    // In production: share one DnsResolver across workers via Arc
    let resolver = match DnsResolver::new(config) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("dns resolver init failed: {e}");
            return;
        }
    };

    while let Ok(target) = rx.recv().await {
        let result = resolver.resolve(&target.host).await;

        match result {
            DnsResult::Resolved(_) => {
                stats.dns_ok.fetch_add(1, Ordering::Relaxed);
                let _ = tx.send(target).await;
            }
            DnsResult::NxDomain => {
                stats.dns_nxdomain.fetch_add(1, Ordering::Relaxed);
                stats.done.fetch_add(1, Ordering::Relaxed);
            }
            DnsResult::Timeout | DnsResult::Error(_) => {
                stats.dns_timeout.fetch_add(1, Ordering::Relaxed);
                // Re-queue for retry? For now: skip
                stats.done.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}
