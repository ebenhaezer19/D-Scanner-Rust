# D-Scanner Rust

High-performance web credential scanner with exploit engines. Rust rewrite of D-Scanner.

## Architecture

```
Domain list (file or stdin)
        |
        v
  Stream Reader       -- reads one line at a time, no RAM load
        |
        v
  DNS Workers (512)   -- raw UDP via hickory-resolver, DashMap cache
        |
        v
  Fetch Workers       -- per-target HTTP client, isolated cookie jar
        |
        v
  Credential Scanner  -- 17 providers, regex per provider (M1)
        |
        v
  Exploit Engines     -- livewire2shell, wp2shell, etc. (M2)
        |
        v
  Output (JSONL)      -- M1 hits + RCE confirmed results
```

## Requirements

- Rust 1.70 or later
- Linux (Debian 12 recommended for production)
- VPS with good network (1Gbps+ recommended)

## Build

```bash
cargo build --release
```

Binary: `./target/release/dreks`

## Quick Start

```bash
# Basic scan (M1 only)
./target/release/dreks --input domains.txt --output hits.jsonl

# Full pipeline (M1 + M2 exploits)
./target/release/dreks --input domains.txt --mode full \
  --output m1_hits.jsonl --exploit-output rce_hits.jsonl
```

---

## VPS Performance Guide

### Throughput Formula

```
throughput = concurrency / avg_slot_time
```

| Parameter | Description |
|-----------|-------------|
| `concurrency` | `--exploit-concurrency` (parallel exploit attempts) |
| `avg_slot_time` | `--exploit-timeout × 2` (total cap per batch) |

### Recommended Configurations

#### High Speed (126+ t/s)
```bash
./target/release/dreks --input targets.txt --mode full \
  --output m1_hits.jsonl --exploit-output rce_hits.jsonl \
  --exploit-timeout 4 --exploit-concurrency 800
```
- **Throughput:** 130+ t/s
- **Trade-off:** May miss slow targets

#### Balanced (100+ t/s)
```bash
./target/release/dreks --input targets.txt --mode full \
  --output m1_hits.jsonl --exploit-output rce_hits.jsonl \
  --exploit-timeout 5 --exploit-concurrency 700
```
- **Throughput:** 100-110 t/s
- **Trade-off:** Good balance speed/coverage

#### Thorough (slower but complete)
```bash
./target/release/dreks --input targets.txt --mode full \
  --output m1_hits.jsonl --exploit-output rce_hits.jsonl \
  --exploit-timeout 8 --exploit-concurrency 1000
```
- **Throughput:** 60-80 t/s
- **Trade-off:** Catches slow targets

### VPS Requirements

| Targets | RAM | CPU | Bandwidth |
|---------|-----|-----|-----------|
| 10K | 2GB | 2 cores | 100Mbps |
| 100K | 4GB | 4 cores | 500Mbps |
| 1M+ | 8GB | 8 cores | 1Gbps |

### Example: 3K Targets

```bash
# Typical result on good VPS:
# 3082 targets / 23s = 134 t/s
# M1 hits: 3185, RCE confirmed: 18-22

time ./target/release/dreks --input targets.txt --mode full \
  --output m1_hits.jsonl --exploit-output rce_hits.jsonl \
  --exploit-timeout 4
```

---

## CLI Options

### M1: Credential Scan

| Flag | Default | Description |
|------|---------|-------------|
| `--input` | `domains.txt` | Domain/URL list file. Use `-` for stdin |
| `--concurrency` | `2000` | Max concurrent HTTP connections |
| `--dns-servers` | `8.8.8.8,1.1.1.1,...` | DNS resolvers, comma-separated |
| `--timeout` | `10` | HTTP connect timeout (seconds) |
| `--max-body` | `1048576` | Max body size to download (bytes) |
| `--max-js` | `3` | Max JS files to fetch per domain |
| `--output` | stdout | Output file for M1 JSONL hits |
| `--log-level` | `info` | Log level: trace, debug, info, warn, error |
| `--no-raw-dns` | false | Use system resolver instead of raw UDP |
| `--skip-dns` | false | Input is pre-resolved (massdns format) |

### M2: Exploit Engines

| Flag | Default | Description |
|------|---------|-------------|
| `--mode` | `scan` | Mode: `scan` (M1), `exploit` (M2), `full` (M1+M2) |
| `--exploit-output` | stdout | Output file for RCE JSONL results |
| `--exploit-concurrency` | `700` | Parallel exploit attempts |
| `--exploit-timeout` | `5` | Per-request timeout (seconds). Total cap = timeout × 2 |
| `--skip-dead-check` | false | Skip dead target pre-filter |

---

## Exploit Engines

### livewire2shell
- **Target:** Laravel Livewire v3 apps
- **CVE:** CVE-2024-47823 (Arbitrary file read/RCE)
- **Detection:** `/livewire/livewire.js`, `wire:` attributes

### wp2shell
- **Target:** WordPress sites
- **Features:**
  - Config backup detection (wp-config.php.bak, .env, etc.)
  - VCS exposure (.git/config, .git/HEAD)
  - Vulnerable plugin detection (8 known CVEs)
  - User enumeration via REST API
  - **CVE-2024-25600:** Bricks Builder RCE (≤1.9.6)

### langflow2shell
- **Target:** Langflow AI workflow apps
- **CVE:** CVE-2025-3248 (Unauth code execution)

### laravel2shell
- **Target:** Laravel apps with debug mode
- **Detection:** Debug page, env exposure

---

## Output Format

### M1 Hits (credentials)
```json
{"target":"https://example.com","provider":"openai","value":"sk-proj-...","confidence":"high","source":"Html","found_at":"2026-10-03T14:00:00Z"}
```

### M2 Hits (RCE)
```json
{"target":"https://example.com","engine":"livewire2shell","rce_cmd":"id","rce_output":"uid=33(www-data)...","confirmed_at":"2026-10-03T14:00:00Z"}
```

---

## Credential Providers (M1)

17 providers implemented:
- **AI:** OpenAI, Anthropic, Groq, xAI, OpenRouter, Replicate, Cerebras, Perplexity, HuggingFace
- **Payment:** Stripe
- **Cloud:** AWS
- **Code:** GitHub, GitLab
- **Email:** SendGrid, Resend, Brevo, Mailgun

---

## Tips

### Maximize Throughput
```bash
# Use lower timeout for fast scans
--exploit-timeout 4

# Increase concurrency on powerful VPS
--exploit-concurrency 1000

# Skip DNS for pre-resolved lists
--skip-dns
```

### Analyze Results
```bash
# Count RCE by engine
grep -oP '"engine":"[^"]+' rce_hits.jsonl | sort | uniq -c

# Extract credentials
jq -r '.value' m1_hits.jsonl | sort -u

# Find specific CVE
grep 'CVE-2024-25600' rce_hits.jsonl
```

### Large Scale Scanning
```bash
# Use massdns for DNS pre-resolution
massdns -r resolvers.txt -o S domains.txt > resolved.txt

# Then scan with skip-dns
./target/release/dreks --input resolved.txt --mode full \
  --skip-dns --output m1.jsonl --exploit-output rce.jsonl
```

---

## Milestone Status

| Milestone | Description | Status |
|-----------|-------------|--------|
| **M1** | Rust core: pipeline, DNS, HTTP, credential engine (17 providers) | ✅ Done |
| **M2** | Exploit engines: livewire2shell, laravel2shell, langflow2shell, wp2shell | 🔄 In Progress |
| M3 | Additional engines: react2shell, lib scanner, advanced recon | Pending |
| M4 | Controller bridge, WebSocket, Telegram relay | Pending |
| M5 | Docker deploy, benchmark suite, client documentation | Pending |

### M2 Progress
- [x] livewire2shell - CVE-2024-47823 (Livewire v3 RCE)
- [x] laravel2shell - Debug mode exploit
- [x] langflow2shell - CVE-2025-3248 (Langflow RCE)
- [x] wp2shell - WordPress recon + CVE-2024-25600 (Bricks RCE)
- [x] Credential verification module (OpenAI, Anthropic, Stripe, GitHub, etc.)
- [x] Additional WordPress CVEs (30+ plugins tracked)

### WordPress CVEs Tracked
| CVE | Plugin | Type |
|-----|--------|------|
| CVE-2024-27956 | WP Automatic | SQLi to RCE |
| CVE-2024-25600 | Bricks Builder | Unauth RCE |
| CVE-2023-6553 | Backup Migration | Unauth RCE |
| CVE-2024-0757 | Articulate Content | File upload RCE |
| CVE-2025-34085 | Simple File List | File upload RCE |
| CVE-2024-7627 | Bit File Manager | Race condition RCE |
| CVE-2025-3515 | CF7 Multi Upload | File upload RCE |
| CVE-2025-32118 | CMP Coming Soon | RCE |
| CVE-2024-28000 | LiteSpeed Cache | Privilege escalation |
| CVE-2024-10924 | Really Simple SSL | Auth bypass |

### Credential Verification
```bash
# Credentials found by M1 can be verified
# Supported: OpenAI, Anthropic, Groq, Stripe, GitHub, GitLab, SendGrid, HuggingFace
```

---

## License

Private. All rights reserved.
