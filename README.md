# D-Scanner Rust

High-performance web credential scanner. Rust rewrite of D-Scanner.

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
  Credential Scanner  -- 17 providers, regex per provider
        |
        v
  Output (JSONL)      -- one JSON line per hit, stdout or file
```

## Requirements

- Rust 1.70 or later
- Linux (Debian 12 recommended for production)
- On Windows: MSYS2 with MinGW-w64 toolchain

## Build

```bash
cargo build --release
```

Binary: `./target/release/dreks`

## Usage

```bash
# Basic scan from file
./target/release/dreks --input domains.txt

# With options
./target/release/dreks \
  --input domains.txt \
  --concurrency 2000 \
  --timeout 10 \
  --max-js 3 \
  --output hits.jsonl \
  --log-level info

# Read from stdin
cat domains.txt | ./target/release/dreks --input -
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--input` | `domains.txt` | Domain/URL list file. Use `-` for stdin |
| `--concurrency` | `2000` | Max concurrent HTTP connections |
| `--dns-servers` | `8.8.8.8,1.1.1.1,9.9.9.9,8.8.4.4` | DNS resolvers, comma-separated |
| `--timeout` | `10` | HTTP connect timeout in seconds |
| `--max-body` | `1048576` | Max body size to download in bytes |
| `--max-js` | `3` | Max JS files to fetch per domain |
| `--output` | stdout | Output file path for JSONL hits |
| `--log-level` | `info` | Log level: trace, debug, info, warn, error |
| `--no-raw-dns` | false | Disable raw UDP DNS, use system resolver |

## Output Format

Each credential hit is printed as one JSON line:

```json
{"target":"https://example.com","provider":"openai","value":"sk-proj-...","confidence":"high","source":"Html","found_at":"2026-09-28T15:00:00Z"}
```

## Credential Providers

17 providers are currently implemented:

- OpenAI, Anthropic, Groq, xAI, OpenRouter, Replicate, Cerebras, Perplexity, HuggingFace
- Stripe
- AWS
- GitHub, GitLab
- SendGrid, Resend, Brevo, Mailgun

## Milestone Status

| Milestone | Description | Status |
|-----------|-------------|--------|
| M1 | Rust core: pipeline, DNS, HTTP, credential engine | Done |
| M2 | Exploit engines: livewire2shell, laravel2shell, langflow2shell | Pending |
| M3 | Exploit engines: wp2shell, react2shell, lib, recon | Pending |
| M4 | Controller bridge, WebSocket, Telegram relay | Pending |
| M5 | Docker deploy, benchmark, client documentation | Pending |

## Testing

See [TESTING.md](TESTING.md) for the full test plan with 8 test cases.

## License

Private. All rights reserved.
