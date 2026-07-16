#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

N_SIZES="${N_SIZES:-10000,100000,1000000}"
M_SIZES="${M_SIZES:-100,1000}"
SAMPLES="${SAMPLES:-3}"
WARMUP="${WARMUP:-1}"
POA_SP1_PROOF_MODE="${POA_SP1_PROOF_MODE:-groth16}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
OUTPUT_DIR="${OUTPUT_DIR:-artifacts/benchmarks/protocol-$RUN_ID}"
SRS_DIR="${SRS_DIR:-params/srs/bench}"
FIXTURE_DIR="${FIXTURE_DIR:-data/mock/bench/generated}"

export POA_SP1_PROOF_MODE

echo "Dynamic PoA benchmark"
echo "  n:          $N_SIZES"
echo "  m:          $M_SIZES"
echo "  samples:    $SAMPLES"
echo "  warmup:     $WARMUP"
echo "  SP1 mode:   $POA_SP1_PROOF_MODE"
echo "  output:     $OUTPUT_DIR"

if [[ ! -f "$FIXTURE_DIR/preparation-manifest.txt" ]]; then
  echo >&2
  echo "Missing prepared benchmark fixtures: $FIXTURE_DIR/preparation-manifest.txt" >&2
  echo "Run scripts/initialize_benchmark_data.sh first." >&2
  exit 1
fi

echo
echo "Preparing SP1 verification-key setup outside benchmark timers..."
./poa sp1-setup

echo
echo "Building release benchmark binary outside benchmark timers..."
cargo build --release -p poa-bench

echo
exec ./target/release/poa-bench \
  --mode benchmark \
  --require-existing true \
  --output "$OUTPUT_DIR" \
  --srs-dir "$SRS_DIR" \
  --fixture-dir "$FIXTURE_DIR" \
  --n "$N_SIZES" \
  --m "$M_SIZES" \
  --samples "$SAMPLES" \
  --warmup "$WARMUP"
