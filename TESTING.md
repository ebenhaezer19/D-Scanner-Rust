# D-Scanner Rust - Testing Guide (M1)

Repo: https://github.com/ebenhaezer19/D-Scanner-Rust  
Branch: main  
Status: M1 Complete - core pipeline, DNS, HTTP fetch, credential engine

---

## Setup (Linux / Debian - same as production VPS)

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Clone repo
git clone https://github.com/ebenhaezer19/D-Scanner-Rust.git
cd D-Scanner-Rust

# Build release binary
cargo build --release

# Binary location
./target/release/dreks
```

Note: No MSYS2 or MinGW needed on Linux. Just `cargo build` directly.

---

## Test Cases

### TC-01: Binary and Help Output

```bash
./target/release/dreks --help
```

Expected output:

```
High-performance web scanner

Usage: dreks [OPTIONS]

Options:
  -i, --input <INPUT>              [default: domains.txt]
  -c, --concurrency <CONCURRENCY>  [default: 2000]
      --dns-servers <DNS_SERVERS>  [default: 8.8.8.8,1.1.1.1,9.9.9.9,8.8.4.4]
      --timeout <TIMEOUT>          [default: 10]
      --max-body <MAX_BODY>        [default: 1048576]
      --max-js <MAX_JS>            [default: 3]
  -o, --output <OUTPUT>
      --log-level <LOG_LEVEL>      [default: info]
      --no-raw-dns
  -h, --help
  -V, --version
```

---

### TC-02: Streaming Input and Memory Usage

```bash
echo -e "example.com\ngoogle.com\nhttpbin.org\ngithub.com\nstackoverflow.com" > test5.txt

./target/release/dreks --input test5.txt --concurrency 5 --timeout 5 --log-level debug
```

Expected:
- Log shows: `streaming domains from: test5.txt`
- Log shows: `5 queued, 0 skipped`
- DNS queries visible in debug log for each domain
- RAM usage below 50 MB (check with `htop` or `ps aux`)

---

### TC-03: Raw DNS Resolver

```bash
echo -e "google.com\nthis-domain-xyz999-does-not-exist.com" > test_dns.txt

./target/release/dreks --input test_dns.txt --concurrency 2 --timeout 3 --log-level debug
```

Expected:
- `google.com` resolves, proceeds to HTTP fetch
- `this-domain-*.com` hits NXDOMAIN, gets skipped without fetching
- Log shows DNS queries going to `8.8.8.8` and `1.1.1.1` via UDP

---

### TC-04: Credential Detection

```bash
mkdir -p /tmp/testsite

cat > /tmp/testsite/index.html << 'EOF'
<html><body>
<script>
const OPENAI_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGH";
const STRIPE_KEY = "sk_live_abcdefghijklmnopqrstuvwxyz123456";
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
</script>
</body></html>
EOF

python3 -m http.server 8080 --directory /tmp/testsite &
sleep 1

echo "http://localhost:8080" > test_cred.txt
./target/release/dreks --input test_cred.txt --concurrency 1 --timeout 5 --log-level info

kill %1
```

Expected output (one JSON line per hit, printed to stdout):

```
{"target":"http://localhost:8080","provider":"openai","value":"sk-proj-...","confidence":"high","source":"Html","found_at":"..."}
{"target":"http://localhost:8080","provider":"stripe","value":"sk_live_...","confidence":"high","source":"Html","found_at":"..."}
{"target":"http://localhost:8080","provider":"aws","value":"AKIAIOSFODNN7EXAMPLE","confidence":"high","source":"Html","found_at":"..."}
```

This is the most important test case. If credential detection does not work, M1 is not complete.

---

### TC-05: Concurrency and Throughput

```bash
python3 -c "
import random, string
domains = ['google.com', 'github.com', 'cloudflare.com', 'amazon.com']
for i in range(996):
    r = ''.join(random.choices(string.ascii_lowercase, k=10))
    domains.append(f'{r}.com')
random.shuffle(domains)
print('\n'.join(domains))
" > test1000.txt

time ./target/release/dreks --input test1000.txt --concurrency 500 --timeout 5 --log-level info
```

Expected:
- Completes in under 30 seconds for 1000 domains
- Progress log printed every 10 seconds
- Rate above 50 URLs per second

---

### TC-06: Stdin Input

```bash
cat test5.txt | ./target/release/dreks --input - --concurrency 5 --timeout 5
```

Expected: Same behavior as TC-02, reading from stdin instead of file.

---

### TC-07: Output to File

```bash
./target/release/dreks --input test5.txt --concurrency 5 --timeout 5 --output /tmp/hits.jsonl
cat /tmp/hits.jsonl
```

Expected: File `/tmp/hits.jsonl` is created. Each line is a valid JSON object. File may be empty if no credentials are found on the test domains.

---

### TC-08: Large Input Memory Test

```bash
python3 -c "
for i in range(100000):
    print(f'host{i}.nonexistent-test-domain-xyz.com')
" > test100k.txt

/usr/bin/time -v ./target/release/dreks --input test100k.txt --concurrency 1000 --timeout 3 --log-level warn
```

Expected:
- `Maximum resident set size` in `/usr/bin/time` output is below 500 MB
- No OOM kill
- All 100K domains are processed via streaming without loading all into RAM

---

## Bug Report Format

If you find an issue, report it using this format:

```
TC: [test case number]
OS: [e.g. Debian 12]
Rust version: [output of: rustc --version]
Command: [exact command run]
Expected: [what should happen]
Actual: [what actually happened]
Log: [paste relevant log lines]
```

---

## Known Non-Issues

The following warnings appear during build and can be ignored:

- `warning: field 0 is never read` - DnsResult fields will be used in M2
- `warning: struct ScanResult is never constructed` - used in M2
- `warning: enum ScanStatus is never used` - used in M2

---

## Contact

Repo: https://github.com/ebenhaezer19/D-Scanner-Rust  
Submit issues via GitHub Issues with the bug report format above.
