# VPS Deployment and Testing Guide

Repo: https://github.com/ebenhaezer19/D-Scanner-Rust  
Target VPS: Debian 12, 56 cores, 64 GB RAM, unlimited bandwidth, Europe

---

## Setup

```bash
# Install Rust (one time only)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Clone repo
git clone https://github.com/ebenhaezer19/D-Scanner-Rust.git
cd D-Scanner-Rust

# Build release binary (much faster than debug)
cargo build --release

# Binary location
./target/release/dreks
```

---

## Recommended Run Command for Production

```bash
./target/release/dreks \
  --input domains.txt \
  --concurrency 2000 \
  --timeout 5 \
  --max-js 3 \
  --dns-servers 8.8.8.8,1.1.1.1,9.9.9.9,8.8.4.4 \
  --min-confidence high \
  --output hits.jsonl \
  --log-level info
```

| Flag | Value | Reason |
|------|-------|--------|
| `--concurrency` | 2000 | Matches VPS NIC capacity (56 cores, unlimited BW) |
| `--timeout` | 5 | Drop dead hosts fast, keep throughput high |
| `--max-js` | 3 | Fetch top 3 JS bundles per domain |
| `--min-confidence` | high | Zero false positives in output |
| `--log-level` | info | Progress every 10 seconds |

---

## Key Metrics to Watch

### Throughput

Target rate based on Go scanner metrics: **126 URLs/s**  
Expected from Rust release binary on this VPS: **200-400 URLs/s**

Check actual rate by dividing URLs processed by elapsed time from the final log line:

```
[done] scan complete total=X hits=Y dns_ok=Z dns_nxdomain=W
```

If rate is below 100 URLs/s, see the optimization section below.

### Memory Usage

Monitor RAM during scan:

```bash
# In another terminal while scan runs
watch -n 2 'ps aux | grep dreks | grep -v grep | awk "{print \$6/1024 \" MB\"}"'
```

Expected: below 500 MB even for 1M+ domain input files.  
If RAM exceeds 1 GB, report it as a bug.

### DNS Resolution Rate

From the final log line:
- `dns_ok` = domains that resolved and were fetched
- `dns_nxdomain` = domains that do not exist (skipped, correct behavior)

Healthy ratio for a random domain list: roughly 60-70% dns_ok, 30-40% nxdomain.

### Hit Quality

Output is in JSONL format. Each line is one credential hit:

```json
{"target":"https://example.com","provider":"openai","value":"sk-...","confidence":"High","source":"Html","found_at":"..."}
```

Fields:
- `provider`: which API service the key belongs to
- `confidence`: High (very likely real) | Medium (possible) | Low (filtered out by default)
- `source`: Html (found in page HTML) or JsFile (found in a JS bundle)

---

## Optimization Checklist

If throughput is below target, check these in order:

### 1. Confirm you are using the release binary

```bash
# Wrong (debug, 3-5x slower)
./target/debug/dreks

# Correct
./target/release/dreks

# Verify
file ./target/release/dreks
# Should show: ELF 64-bit LSB pie executable, not stripped
```

### 2. Increase open file descriptor limit

The scanner uses one TCP socket per concurrent connection. Default Linux limit is 1024.

```bash
# Check current limit
ulimit -n

# Set higher for this session
ulimit -n 65535

# Set permanently (add to /etc/security/limits.conf)
echo "* soft nofile 65535" >> /etc/security/limits.conf
echo "* hard nofile 65535" >> /etc/security/limits.conf
```

### 3. Tune TCP settings for high concurrency

```bash
# Add to /etc/sysctl.conf
net.ipv4.tcp_tw_reuse = 1
net.core.somaxconn = 65535
net.ipv4.ip_local_port_range = 1024 65535

# Apply
sysctl -p
```

### 4. Check DNS resolution speed

```bash
# Test DNS latency to your resolvers from VPS
time dig @8.8.8.8 google.com
time dig @1.1.1.1 google.com
```

If latency is above 50ms, consider adding a local DNS resolver (unbound or systemd-resolved) and pointing to `127.0.0.1`:

```bash
./target/release/dreks --dns-servers 127.0.0.1,8.8.8.8,1.1.1.1 ...
```

### 5. Run with higher concurrency

Test with increasing concurrency until throughput stops improving:

```bash
# Start at 1000, increase if CPU and network allow
./target/release/dreks --input domains.txt --concurrency 1000 ...
./target/release/dreks --input domains.txt --concurrency 2000 ...
./target/release/dreks --input domains.txt --concurrency 4000 ...
```

Watch CPU usage with `htop`. If CPU is below 50% but throughput is flat, the bottleneck is network RTT, not the scanner.

### 6. Split the domain list across multiple instances

For very large lists (millions of domains), split and run multiple instances:

```bash
# Split into 4 parts
split -n l/4 domains.txt part_

# Run 4 instances in parallel
./target/release/dreks --input part_aa --output hits_1.jsonl &
./target/release/dreks --input part_ab --output hits_2.jsonl &
./target/release/dreks --input part_ac --output hits_3.jsonl &
./target/release/dreks --input part_ad --output hits_4.jsonl &
wait

# Merge results
cat hits_*.jsonl > all_hits.jsonl
```

---

## Log Output Reference

```
INFO dreks-core starting concurrency=2000 dns_servers=4 input=domains.txt
INFO streaming domains from: domains.txt
INFO starting 512 DNS workers
INFO starting 2000 fetch workers
INFO stream done: 126145427 queued, 0 skipped
INFO [progress] 50000/126145427 done · hits=12 · nxdomain=18000 · conn_timeout=5000
...
INFO [done] scan complete total=126145427 hits=1351 dns_ok=... dns_nxdomain=...
```

The progress line prints every 10 seconds. Use it to estimate remaining time.

---

## Known Warnings (Can Be Ignored)

The following warnings appear at high concurrency and are not errors:

```
WARN ignoring response from 8.8.4.4:53 because it does not match name_server: 1.1.1.1:53
WARN expected message id: 33215 got: 14482, dropped
WARN foster parenting not implemented
```

These are from the DNS resolver handling concurrent UDP responses. They do not affect correctness — dropped responses are retried automatically.

---

## Reporting Issues

If you see unexpected behavior, collect this information:

```
OS: Debian 12
Rust version: rustc --version
Binary: release or debug
Command: exact command run
Concurrency: value used
Domain list size: number of lines
Expected behavior: what should happen
Actual behavior: what happened
Last 20 log lines: paste here
```

---

## Actual Test Results (Baseline Reference)

The following results were measured during development on a Windows machine
using the debug binary. Use these numbers as a lower-bound baseline.
The release binary on a Linux VPS is expected to be 3-5x faster.

### Environment

```
Machine:   Windows 11, developer laptop
Binary:    debug (cargo build without --release)
Data:      Production domain list from Go scanner project
```

### TC-05 — Synthetic Throughput (1,000 NXDOMAIN)

```
Input:       1,000 random domains (all NXDOMAIN, no HTTP fetch)
Concurrency: 500
Timeout:     5s
Result:      2.4 seconds
Rate:        416 URL/s  (pure DNS + pipeline, no HTTP)
```

### TC-08 — Memory Under Load (100,000 domains)

```
Input:       100,000 random NXDOMAIN domains
Concurrency: 1,000
Timeout:     3s
Peak RAM:    233 MB
```

Input is streamed line-by-line. RAM does not grow with input file size.
A 10M-domain list uses roughly the same 233 MB.

### Real Scan — 9,980 Production URLs

```
Input:       9,980 real URLs from the production domain list
             (same list previously fed into the Go scanner — scanned here by Rust)
             (HTTP + HTTPS, IPs + hostnames, mixed ports)
Concurrency: 300
Timeout:     8s
Max-JS:      2
Binary:      Rust debug
OS:          Windows
Time:        111 seconds
Rate:        ~90 URL/s
```

Hit results with --min-confidence high:

```
Provider    Hits   Details
--------    ----   -------
stripe        14   All pk_live_ or sk_live_ format (confirmed real)
openai         8   2 distinct keys across 4 domains
openrouter     2   sk-or-v1- key from fouland.com
TOTAL         24   False positives: 0
```

### Confidence Level Comparison (same 9,980 URLs)

| --min-confidence | Total hits | OpenAI hits | Est. false positives |
|-----------------|------------|-------------|----------------------|
| high            | 24         | 8           | 0                    |
| medium (default)| 216        | 183         | ~160                 |

Use `--min-confidence high` for unattended production runs.
Use `--min-confidence medium` for manual review sessions.

### Expected on VPS Release Binary

```
Rate:             200-400 URL/s        (vs 90 URL/s debug on Windows)
RAM (126M input): < 500 MB             (streaming, not loaded into memory)
Run time 126M:    87-175 hours
Hits per 10K:     ~2-5 real credentials
```

The Go scanner found 1,351 hits across 126M domains.
The Rust engine adds JS bundle scanning and more providers,
so the total hit count is expected to be higher.
