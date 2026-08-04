#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'EOF'
Usage:
  ./poa benchmark <n> <m> [cpu|cuda|network] [samples]

Examples:
  ./poa benchmark 1000 100
  ./poa benchmark 1000 100 cuda
  ./poa benchmark 1000 100 cuda 5

Defaults: cpu prover, compressed proof mode, 3 measured samples, 1 warmup.
The command prepares/reuses mock data and SRS, then benchmarks init, update,
and insert. Set POA_SP1_PROOF_MODE=groth16 or plonk only when needed.

  n = number of initialized reserve addresses
  m = number of addresses touched by update
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi
if [[ $# -lt 2 || $# -gt 4 ]]; then
  usage >&2
  exit 2
fi

N="$1"
M="$2"
PROVER="${3:-${SP1_PROVER:-cpu}}"
SAMPLES_COUNT="${4:-${SAMPLES:-3}}"
WARMUP_COUNT="${WARMUP:-1}"
PROOF_MODE="${POA_SP1_PROOF_MODE:-compressed}"

for value in "$N" "$M" "$SAMPLES_COUNT" "$WARMUP_COUNT"; do
  if [[ ! "$value" =~ ^[0-9]+$ ]]; then
    echo "n, m, samples, and warmup must be non-negative integers; got: $value" >&2
    exit 2
  fi
done
if (( N == 0 || M == 0 || SAMPLES_COUNT == 0 )); then
  echo "n, m, and samples must be greater than zero." >&2
  exit 2
fi
if (( M > N )); then
  echo "This persisted transition fixture currently requires m <= n (n=$N, m=$M)." >&2
  exit 2
fi
case "$PROVER" in
  cpu|cuda|network) ;;
  *) echo "prover must be cpu, cuda, or network; got: $PROVER" >&2; exit 2 ;;
esac
case "$PROOF_MODE" in
  compressed|groth16|plonk) ;;
  *) echo "POA_SP1_PROOF_MODE must be compressed, groth16, or plonk." >&2; exit 2 ;;
esac

RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
FIXTURE_DIR="${FIXTURE_DIR:-data/mock/bench/simple-n${N}-m${M}}"
SRS_DIR="${SRS_DIR:-params/srs/simple-n${N}-m${M}}"
OUTPUT_DIR="${OUTPUT_DIR:-artifacts/benchmarks/nizk-n${N}-m${M}-${RUN_ID}}"
LOG_FILE="$OUTPUT_DIR/run.log"
PREP_OUTPUT="$OUTPUT_DIR/preparation"
MASTER_DIR="$FIXTURE_DIR/master_n_${N}/ethereum-keccak-fixed32-merkle-prefix-v3-ecdsa"
SRS_FILE="$SRS_DIR/bench-max-degree-$((N + 1))-g2-degree-${M}.bin"

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

fixtures_ready() {
  [[ -s "$FIXTURE_DIR/preparation-manifest.txt" ]] \
    && grep -Fxq "master.max_n=$N" "$FIXTURE_DIR/preparation-manifest.txt" \
    && [[ -s "$MASTER_DIR/accounts.bin" ]] \
    && [[ -s "$MASTER_DIR/init-merkle-proofs-n-${N}.bin" ]] \
    && [[ -s "$MASTER_DIR/insert-merkle-proof.bin" ]] \
    && [[ -s "$MASTER_DIR/mock-initialized-state-n-${N}.txt" ]] \
    && [[ -s "$MASTER_DIR/deltas-n-${N}-m-${M}.csv" ]] \
    && [[ -s "$SRS_FILE" ]]
}

echo "NIZK benchmark: n=$N, m=$M, prover=$PROVER, mode=$PROOF_MODE, samples=$SAMPLES_COUNT"

if [[ "${FORCE_PREPARE:-0}" == "1" ]] || ! fixtures_ready; then
  echo "[1/2] Preparing mock data and SRS..."
  if ! env \
    MASTER_N="$N" N_SIZES="$N" M_SIZES="$M" \
    FIXTURE_DIR="$FIXTURE_DIR" SRS_DIR="$SRS_DIR" OUTPUT_DIR="$PREP_OUTPUT" \
    "${ROOT_DIR}/scripts/initialize_benchmark_data.sh" >>"$LOG_FILE" 2>&1; then
    fail_with_log "Input preparation"
  fi
else
  echo "[1/2] Reusing prepared mock data and SRS."
fi

echo "[2/2] Preparing SP1 and running init, update, and insert..."
if ! env \
  MASTER_N="$N" N_SIZES="$N" M_SIZES="$M" \
  FIXTURE_DIR="$FIXTURE_DIR" SRS_DIR="$SRS_DIR" OUTPUT_DIR="$OUTPUT_DIR" \
  SP1_PROVER="$PROVER" POA_SP1_PROOF_MODE="$PROOF_MODE" \
  BENCHMARK_OPERATIONS="initialization,update,insert" \
  SAMPLES="$SAMPLES_COUNT" WARMUP="$WARMUP_COUNT" POA_SP1_PROFILE=0 \
  "${ROOT_DIR}/scripts/benchmark_protocol.sh" >>"$LOG_FILE" 2>&1; then
  fail_with_log "Benchmark"
fi

SUMMARY="$OUTPUT_DIR/summary.csv"
if [[ ! -s "$SUMMARY" ]]; then
  fail_with_log "Summary generation"
fi

echo
"$ROOT_DIR/scripts/print_benchmark_summary.sh" "$SUMMARY" "$SAMPLES_COUNT"

echo
echo "Details: $OUTPUT_DIR/summary.md"
echo "Full log: $LOG_FILE"
