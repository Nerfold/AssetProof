#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

N_SIZES="${N_SIZES:-10000,100000,1000000}"
M_SIZES="${M_SIZES:-100,1000}"
MASTER_N="${MASTER_N:-1000000}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
OUTPUT_DIR="${OUTPUT_DIR:-artifacts/benchmarks/preparation-$RUN_ID}"
SRS_DIR="${SRS_DIR:-params/srs/bench}"
FIXTURE_DIR="${FIXTURE_DIR:-data/mock/bench/generated}"
SRS_THREADS="${SRS_THREADS:-$(sysctl -n hw.logicalcpu 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)}"

export RAYON_NUM_THREADS="$SRS_THREADS"

echo "Dynamic PoA benchmark fixture initialization"
echo "  n:          $N_SIZES"
echo "  m:          $M_SIZES"
echo "  master n:   $MASTER_N"
echo "  fixtures:   $FIXTURE_DIR"
echo "  SRS:        $SRS_DIR"
echo "  SRS threads: $SRS_THREADS"
echo "  manifest:   $OUTPUT_DIR/preparation-manifest.txt"
echo
echo "This stage can require substantial RAM, disk space, and time for n=1000000."
echo "It builds one master_n+1 account store and one shared fixed-height binary Merkle tree."
echo "Each n reuses that tree/root and stores its own prefix Merkle paths."
echo "It does not run SP1 proving."
echo "One shared SRS is generated: full G1 through master_n+1,"
echo "and only the G2 prefix required through max(m). Existing matching SRS is reused."

echo
echo "Building release fixture generator..."
cargo build --release -p poa-bench

echo
./target/release/poa-bench \
  --mode prepare \
  --require-existing false \
  --output "$OUTPUT_DIR" \
  --srs-dir "$SRS_DIR" \
  --fixture-dir "$FIXTURE_DIR" \
  --master-n "$MASTER_N" \
  --n "$N_SIZES" \
  --m "$M_SIZES" \
  --samples 1 \
  --warmup 0

echo
echo "Fixtures are ready under $FIXTURE_DIR."
echo "Run scripts/benchmark_protocol.sh to benchmark only the persisted inputs."
