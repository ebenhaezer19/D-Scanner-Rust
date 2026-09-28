# D-Scanner Rust — Testing Guide (M1)
**Repo**: https://github.com/ebenhaezer19/D-Scanner-Rust  
**Branch**: `main`  
**Status**: M1 Complete — core pipeline, DNS, HTTP, credential engine

---

## Setup (Linux/Debian — sama dengan VPS owner)

```bash
# 1. Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# 2. Clone repo
git clone https://github.com/ebenhaezer19/D-Scanner-Rust.git
cd D-Scanner-Rust

# 3. Build
cargo build --release

# Binary ada di:
./target/release/dreks
```

> ⚠️ Tidak perlu MSYS2/MinGW di Linux — langsung `cargo build` tanpa setup tambahan.

---

## Test Cases yang Perlu Diverifikasi

### ✅ TC-01: Binary Berjalan + Help

```bash
./target/release/dreks --help
```

**Expected**:
```
High-performance web scanner

Usage: dreks [OPTIONS]

Options:
  -i, --input <INPUT>              [default: domains.txt]
  -c, --concurrency <CONCURRENCY>  [default: 2000]
      --dns-servers <DNS_SERVERS>  [default: 8.8.8.8,1.1.1.1,9.9.9.9,8.8.4.4]
  ...
```

---

### ✅ TC-02: Streaming Domain Input (Memory Test)

```bash
# Buat domain list kecil
echo -e "example.com\ngoogle.com\nhttpbin.org\ngithub.com\nstackoverflow.com" > test5.txt

# Run dengan log level debug
./target/release/dreks --input test5.txt --concurrency 5 --timeout 5 --log-level debug
```

**Expected**:
- Log: `streaming domains from: test5.txt`
- Log: `5 queued, 0 skipped`
- DNS queries terlihat di log untuk setiap domain
- **RAM usage harus < 50MB** — cek dengan `htop` atau `ps aux`

---

### ✅ TC-03: Raw DNS Resolver

```bash
# Test dengan domain yang pasti ada dan pasti NXDOMAIN
echo -e "google.com\nthis-domain-definitely-does-not-exist-xyz123.com" > test_dns.txt

./target/release/dreks --input test_dns.txt --concurrency 2 --timeout 3 --log-level debug
```

**Expected**:
- `google.com` → DNS resolved, lanjut ke fetch
- `this-domain-*.com` → DNS NXDOMAIN, di-skip (tidak di-fetch)
- Log menunjukkan DNS queries ke `8.8.8.8`/`1.1.1.1` via UDP

---

### ✅ TC-04: Credential Detection

```bash
# Buat file HTML dengan fake credential
cat > /tmp/test_cred.html << 'EOF'
<html><body>
<script>
const API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGH";
const STRIPE_KEY = "sk_live_abcdefghijklmnopqrstuvwxyz123456";
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
</script>
</body></html>
EOF

# Test credential scanner langsung (akan dipakai saat fetch HTML)
# Untuk sekarang: scan localhost jika ada web server
python3 -m http.server 8080 --directory /tmp &
echo "localhost:8080/test_cred.html" > test_cred.txt
./target/release/dreks --input test_cred.txt --concurrency 1 --timeout 5 --log-level info
kill %1
```

**Expected output** (JSONL per hit):
```json
{"target":"http://localhost:8080","provider":"openai","value":"sk-proj-...","confidence":"high","source":"Html","found_at":"..."}
{"target":"http://localhost:8080","provider":"stripe","value":"sk_live_...","confidence":"high","source":"Html","found_at":"..."}
{"target":"http://localhost:8080","provider":"aws","value":"AKIAIOSFODNN7EXAMPLE","confidence":"high","source":"Html","found_at":"..."}
```

---

### ✅ TC-05: Concurrency + Throughput Test

```bash
# Generate 1000 domain list
python3 -c "
import random, string
domains = ['google.com', 'github.com', 'cloudflare.com', 'amazon.com']
# Mix dengan random invalid domains
for i in range(996):
    r = ''.join(random.choices(string.ascii_lowercase, k=10))
    domains.append(f'{r}.com')
random.shuffle(domains)
print('\n'.join(domains))
" > test1000.txt

# Run dengan concurrency tinggi
time ./target/release/dreks --input test1000.txt --concurrency 500 --timeout 5 --log-level info
```

**Expected**:
- Selesai dalam < 30 detik untuk 1000 domain
- Progress log setiap 10 detik
- Rate harus > 50 URL/s

---

### ✅ TC-06: Stdin Input

```bash
cat test5.txt | ./target/release/dreks --input - --concurrency 5 --timeout 5
```

**Expected**: Sama dengan TC-02, baca dari stdin

---

### ✅ TC-07: Output ke File JSONL

```bash
./target/release/dreks --input test5.txt --concurrency 5 --timeout 5 --output /tmp/hits.jsonl
cat /tmp/hits.jsonl
```

**Expected**: File berisi hit dalam format JSONL (atau kosong jika tidak ada credential di target)

---

### ✅ TC-08: Memory Usage Besar (Streaming Test)

```bash
# Generate 100K domain list
python3 -c "
for i in range(100000):
    print(f'host{i}.example-test-nonexistent.com')
" > test100k.txt

# Monitor RAM selama scan
/usr/bin/time -v ./target/release/dreks --input test100k.txt --concurrency 1000 --timeout 3 --log-level warn
```

**Expected**:
- `Maximum resident set size` < 500MB (vs Go yang bisa 2-4GB untuk load 100K domains)
- Tidak ada OOM kill

---

## Bug Report Template

Jika ada issue, report dengan format berikut:

```
TC: [nomor test case]
OS: [Debian 12 / Ubuntu 22.04 / dll]
Rust version: [output rustc --version]
Command: [exact command yang dijalankan]
Expected: [apa yang diharapkan]
Actual: [apa yang terjadi]
Log output: [paste log relevan]
```

---

## Known Issues / Tidak Perlu Di-report

- `warning: field 0 is never read` — normal, struct akan dipakai di M2
- `warning: struct ScanResult is never constructed` — normal, dipakai di M2
- Exit code 1 dari PowerShell redirect (`2>&1`) — ini PowerShell behavior, bukan error Rust

---

## Kontak

Repo: https://github.com/ebenhaezer19/D-Scanner-Rust  
Issues: Buka GitHub Issue dengan template di atas
