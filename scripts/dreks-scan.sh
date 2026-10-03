#!/bin/bash
# dreks-scan.sh - One-click D-Scanner
# Handles IP/domain mix automatically, smart massdns decision
#
# Usage:
#   ./scripts/dreks-scan.sh targets.txt
#   ./scripts/dreks-scan.sh targets.txt output.jsonl
#   CONCURRENCY=3000 ./scripts/dreks-scan.sh targets.txt
#
# Environment variables:
#   CONCURRENCY       - HTTP concurrency (default: 2000)
#   EXPLOIT_TIMEOUT   - Per-request timeout in seconds (default: 5)
#   EXPLOIT_CONC      - Exploit concurrency (default: 700)
#   LOG_LEVEL         - Log level: info, warn, debug (default: info)
#   FORCE_MASSDNS     - Force massdns mode (default: false)
#   MASSDNS_THRESHOLD - Min targets for auto-massdns (default: 50000)
#   RESOLVERS         - Path to resolvers file (default: /tmp/resolvers_raw.txt)

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Config with defaults
INPUT="${1:-targets.txt}"
OUTPUT="${2:-rce_hits.jsonl}"
CONCURRENCY="${CONCURRENCY:-2000}"
EXPLOIT_TIMEOUT="${EXPLOIT_TIMEOUT:-5}"
EXPLOIT_CONC="${EXPLOIT_CONC:-700}"
LOG_LEVEL="${LOG_LEVEL:-info}"
MASSDNS_THRESHOLD="${MASSDNS_THRESHOLD:-50000}"
RESOLVERS="${RESOLVERS:-/tmp/resolvers_raw.txt}"

# Find dreks binary
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DREKS="$SCRIPT_DIR/../target/release/dreks"

if [ ! -f "$DREKS" ]; then
    DREKS="./target/release/dreks"
fi

if [ ! -x "$DREKS" ]; then
    echo -e "${RED}[!] dreks binary not found. Run: cargo build --release${NC}"
    exit 1
fi

if [ ! -f "$INPUT" ]; then
    echo -e "${RED}[!] Input file not found: $INPUT${NC}"
    exit 1
fi

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         D-Scanner Smart Mode (One-Click)                  ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Analyze input
TOTAL_LINES=$(wc -l < "$INPUT")
IP_COUNT=$(grep -cE '^https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$INPUT" 2>/dev/null || echo 0)
DOMAIN_COUNT=$((TOTAL_LINES - IP_COUNT))

echo -e "${GREEN}[*]${NC} Input file: $INPUT"
echo -e "${GREEN}[*]${NC} Total targets: $TOTAL_LINES"
echo -e "${GREEN}[*]${NC} ├── Domains: $DOMAIN_COUNT"
echo -e "${GREEN}[*]${NC} └── Direct IPs: $IP_COUNT"
echo -e "${GREEN}[*]${NC} Output: $OUTPUT"
echo ""

# Decision logic for massdns
# Based on testing: Direct mode finds MORE RCE than massdns mode
# Massdns skips IP addresses and can miss domains due to DNS issues
# Only use massdns for VERY large lists (>50k) AND when explicitly enabled
USE_MASSDNS=false
MASSDNS_AVAILABLE=false

if command -v massdns &> /dev/null && [ -f "$RESOLVERS" ]; then
    MASSDNS_AVAILABLE=true
fi

# Use massdns only if:
# 1. FORCE_MASSDNS=true is set, OR
# 2. More than 50k targets AND <10% are IPs (very conservative)
if [ "${FORCE_MASSDNS:-false}" = "true" ]; then
    USE_MASSDNS=true
elif [ "$MASSDNS_AVAILABLE" = true ] && \
     [ "$TOTAL_LINES" -ge 50000 ] && \
     [ "$IP_COUNT" -lt $((TOTAL_LINES / 10)) ]; then
    USE_MASSDNS=true
fi

START_TIME=$(date +%s)

if [ "$USE_MASSDNS" = true ]; then
    echo -e "${YELLOW}[*]${NC} Mode: Hybrid (massdns + direct IPs)"
    echo ""

    # Create temp directory
    TMPDIR=$(mktemp -d)
    trap "rm -rf $TMPDIR" EXIT

    # Separate IPs and domains
    grep -E '^https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$INPUT" > "$TMPDIR/ips.txt" 2>/dev/null || touch "$TMPDIR/ips.txt"
    grep -vE '^https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$INPUT" > "$TMPDIR/domains.txt" 2>/dev/null || touch "$TMPDIR/domains.txt"

    # Extract unique domains for resolution
    cat "$TMPDIR/domains.txt" | sed -E 's|https?://||' | cut -d'/' -f1 | cut -d':' -f1 | sort -u > "$TMPDIR/to_resolve.txt"
    UNIQUE_DOMAINS=$(wc -l < "$TMPDIR/to_resolve.txt")

    echo -e "${GREEN}[*]${NC} Resolving $UNIQUE_DOMAINS unique domains with massdns..."
    massdns -r "$RESOLVERS" -t A -o S --flush --quiet "$TMPDIR/to_resolve.txt" 2>/dev/null | grep " A " > "$TMPDIR/resolved.txt"
    RESOLVED_COUNT=$(wc -l < "$TMPDIR/resolved.txt")
    echo -e "${GREEN}[*]${NC} Resolved: $RESOLVED_COUNT"

    # Combine: resolved domains + direct IPs
    cat "$TMPDIR/resolved.txt" > "$TMPDIR/combined.txt"

    # Add IP targets (convert to massdns-like format for --skip-dns)
    # Format: "IP A IP" so dreks treats it as pre-resolved
    while IFS= read -r line; do
        # Extract IP from URL like http://1.2.3.4:8080
        ip=$(echo "$line" | sed -E 's|https?://([0-9.]+).*|\1|')
        echo "$ip A $ip" >> "$TMPDIR/combined.txt"
    done < "$TMPDIR/ips.txt"

    COMBINED_COUNT=$(wc -l < "$TMPDIR/combined.txt")
    echo -e "${GREEN}[*]${NC} Combined targets: $COMBINED_COUNT (resolved + IPs)"
    echo ""

    echo -e "${GREEN}[*]${NC} Starting scan with --skip-dns..."
    "$DREKS" \
        --mode full \
        --input "$TMPDIR/combined.txt" \
        --skip-dns \
        --exploit-output "$OUTPUT" \
        --concurrency "$CONCURRENCY" \
        --exploit-concurrency "$EXPLOIT_CONC" \
        --exploit-timeout "$EXPLOIT_TIMEOUT" \
        --log-level "$LOG_LEVEL"
else
    if [ "$MASSDNS_AVAILABLE" = false ]; then
        echo -e "${YELLOW}[*]${NC} Mode: Direct (massdns not available)"
    else
        echo -e "${YELLOW}[*]${NC} Mode: Direct (targets < $MASSDNS_THRESHOLD or >20% IPs)"
    fi
    echo ""

    echo -e "${GREEN}[*]${NC} Starting scan..."
    "$DREKS" \
        --mode full \
        --input "$INPUT" \
        --exploit-output "$OUTPUT" \
        --concurrency "$CONCURRENCY" \
        --exploit-concurrency "$EXPLOIT_CONC" \
        --exploit-timeout "$EXPLOIT_TIMEOUT" \
        --log-level "$LOG_LEVEL"
fi

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                      SCAN COMPLETE                        ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

if [ -f "$OUTPUT" ]; then
    RCE_COUNT=$(wc -l < "$OUTPUT")
    echo -e "${GREEN}[✓]${NC} RCE Confirmed: ${GREEN}$RCE_COUNT${NC}"
    echo -e "${GREEN}[✓]${NC} Output: $OUTPUT"

    if [ "$RCE_COUNT" -gt 0 ]; then
        echo ""
        echo -e "${GREEN}[*]${NC} Unique targets with shell access:"
        grep -oP '"target":"[^"]+' "$OUTPUT" | cut -d'"' -f4 | sort -u | head -10

        UNIQUE_TARGETS=$(grep -oP '"target":"[^"]+' "$OUTPUT" | cut -d'"' -f4 | sort -u | wc -l)
        if [ "$UNIQUE_TARGETS" -gt 10 ]; then
            echo "    ... and $((UNIQUE_TARGETS - 10)) more"
        fi
    fi
else
    echo -e "${YELLOW}[*]${NC} No RCE confirmed"
fi

echo ""
echo -e "${GREEN}[*]${NC} Duration: ${DURATION}s"
echo -e "${GREEN}[*]${NC} Throughput: ~$((TOTAL_LINES / (DURATION + 1))) targets/sec"
