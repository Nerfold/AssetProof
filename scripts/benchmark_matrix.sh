#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'EOF'
Usage:
  ./poa benchmark-matrix [cpu|cuda|network]

Runs the complete NIZK benchmark matrix from mock-data preparation through
proof generation and verification:
  n = 2^10, 2^11, 2^12, 2^13 = 1024, 2048, 4096, 8192
  m = 2^8,  2^9,  2^10 = 256, 512, 1024
  measured samples per result row = 5; warmup = 1

Examples:
  ./poa benchmark-matrix
  ./poa benchmark-matrix cuda
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi
if [[ $# -gt 1 ]]; then
  usage >&2
  exit 2
fi

PROVER="${1:-${SP1_PROVER:-cpu}}"
PROOF_MODE="${POA_SP1_PROOF_MODE:-compressed}"
case "$PROVER" in
  cpu|cuda|network) ;;
  *) echo "prover must be cpu, cuda, or network; got: $PROVER" >&2; exit 2 ;;
esac
case "$PROOF_MODE" in
  compressed|groth16|plonk) ;;
  *) echo "POA_SP1_PROOF_MODE must be compressed, groth16, or plonk." >&2; exit 2 ;;
esac

MASTER_N=8192
N_SIZES="1024,2048,4096,8192"
M_SIZES="256,512,1024"
SAMPLES_COUNT=5
WARMUP_COUNT=1
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
FIXTURE_DIR="${FIXTURE_DIR:-data/mock/bench/matrix-powers-of-two}"
SRS_DIR="${SRS_DIR:-params/srs/matrix-n8192-m1024}"
OUTPUT_DIR="${OUTPUT_DIR:-artifacts/benchmarks/nizk-matrix-${RUN_ID}}"
PREP_OUTPUT="$OUTPUT_DIR/preparation"
LOG_FILE="$OUTPUT_DIR/run.log"

mkdir -p "$OUTPUT_DIR"
: > "$LOG_FILE"

fail_with_log() {
  local step="$1"
  echo >&2
  echo "$step failed. Last log lines:" >&2
  tail -n 30 "$LOG_FILE" >&2 || true
  echo "Full log: $LOG_FILE" >&2
  exit 1
}

echo "NIZK benchmark matrix"
echo "  n: 1024, 2048, 4096, 8192"
echo "  m: 256, 512, 1024"
echo "  prover=$PROVER, mode=$PROOF_MODE, samples=5, warmup=1"

echo "[1/2] Preparing or validating all mock fixtures and the shared SRS..."
if ! env \
  MASTER_N="$MASTER_N" N_SIZES="$N_SIZES" M_SIZES="$M_SIZES" \
  FIXTURE_DIR="$FIXTURE_DIR" SRS_DIR="$SRS_DIR" OUTPUT_DIR="$PREP_OUTPUT" \
  "${ROOT_DIR}/scripts/initialize_benchmark_data.sh" >>"$LOG_FILE" 2>&1; then
  fail_with_log "Matrix input preparation"
fi

echo "[2/2] Preparing SP1 and running the complete benchmark matrix..."
if ! env \
  MASTER_N="$MASTER_N" N_SIZES="$N_SIZES" M_SIZES="$M_SIZES" \
  FIXTURE_DIR="$FIXTURE_DIR" SRS_DIR="$SRS_DIR" OUTPUT_DIR="$OUTPUT_DIR" \
  SP1_PROVER="$PROVER" POA_SP1_PROOF_MODE="$PROOF_MODE" \
  BENCHMARK_OPERATIONS="initialization,update,insert" \
  SAMPLES="$SAMPLES_COUNT" WARMUP="$WARMUP_COUNT" POA_SP1_PROFILE=0 \
  "${ROOT_DIR}/scripts/benchmark_protocol.sh" >>"$LOG_FILE" 2>&1; then
  fail_with_log "Matrix benchmark"
fi

SUMMARY="$OUTPUT_DIR/summary.csv"
if [[ ! -s "$SUMMARY" ]]; then
  fail_with_log "Matrix summary generation"
fi

echo
"$ROOT_DIR/scripts/print_benchmark_summary.sh" "$SUMMARY" "$SAMPLES_COUNT"
echo
echo "Coverage: init=4 rows, update=12 rows, insert=4 rows; each row uses 5 measured samples."
echo "Details: $OUTPUT_DIR/summary.md"
echo "Raw samples: $OUTPUT_DIR/raw.csv"
echo "Full log: $LOG_FILE"
