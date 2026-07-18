#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

N_SIZES="${N_SIZES:-10000,100000,1000000}"
M_SIZES="${M_SIZES:-100,1000}"
MASTER_N="${MASTER_N:-1000000}"
SAMPLES="${SAMPLES:-3}"
WARMUP="${WARMUP:-1}"
POA_SP1_PROOF_MODE="${POA_SP1_PROOF_MODE:-groth16}"
BENCHMARK_OPERATIONS="${BENCHMARK_OPERATIONS:-initialization,insert,update}"
# SP1's defaults target large proving machines (2^24-cycle shards and very
# large trace buffers). Keep protocol benchmarks bounded on workstation-class
# machines while allowing every value to be overridden explicitly.
SHARD_SIZE="${SHARD_SIZE:-1048576}"
MINIMAL_TRACE_CHUNK_THRESHOLD="${MINIMAL_TRACE_CHUNK_THRESHOLD:-1048576}"
TRACE_CHUNK_SLOTS="${TRACE_CHUNK_SLOTS:-2}"
GAS_TRACE_CHUNK_THRESHOLD="${GAS_TRACE_CHUNK_THRESHOLD:-8388608}"
GAS_TRACE_CHUNK_SLOTS="${GAS_TRACE_CHUNK_SLOTS:-2}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
OUTPUT_DIR="${OUTPUT_DIR:-artifacts/benchmarks/protocol-$RUN_ID}"
SRS_DIR="${SRS_DIR:-params/srs/bench}"
FIXTURE_DIR="${FIXTURE_DIR:-data/mock/bench/generated}"

export POA_SP1_PROOF_MODE
export SHARD_SIZE MINIMAL_TRACE_CHUNK_THRESHOLD TRACE_CHUNK_SLOTS
export GAS_TRACE_CHUNK_THRESHOLD GAS_TRACE_CHUNK_SLOTS

echo "Dynamic PoA benchmark"
echo "  n:          $N_SIZES"
echo "  m:          $M_SIZES"
echo "  master n:   $MASTER_N"
echo "  samples:    $SAMPLES"
echo "  warmup:     $WARMUP"
echo "  SP1 mode:   $POA_SP1_PROOF_MODE"
echo "  operations: $BENCHMARK_OPERATIONS"
echo "  SP1 shard:  $SHARD_SIZE cycles"
echo "  trace:      chunk=$MINIMAL_TRACE_CHUNK_THRESHOLD slots=$TRACE_CHUNK_SLOTS"
echo "  gas trace:  chunk=$GAS_TRACE_CHUNK_THRESHOLD slots=$GAS_TRACE_CHUNK_SLOTS"
echo "  output:     $OUTPUT_DIR"

if [[ ! -f "$FIXTURE_DIR/preparation-manifest.txt" ]]; then
  echo >&2
  echo "Missing prepared benchmark fixtures: $FIXTURE_DIR/preparation-manifest.txt" >&2
  echo "Run scripts/initialize_benchmark_data.sh first." >&2
  exit 1
fi
if ! grep -Fxq "fixture_version=ethereum-binary-merkle-v1-ecdsa" "$FIXTURE_DIR/preparation-manifest.txt" \
  || ! grep -Fxq "master.max_n=$MASTER_N" "$FIXTURE_DIR/preparation-manifest.txt"; then
  echo >&2
  echo "Prepared fixtures do not match binary-Merkle ECDSA fixture / MASTER_N=$MASTER_N." >&2
  echo "Run scripts/initialize_benchmark_data.sh again." >&2
  exit 1
fi

case ",$BENCHMARK_OPERATIONS," in
  *,all,*|*,initialization,*|*,init,*|*,insert,*)
    echo
    echo "Preparing protocol SP1 setup (init Merkle + init ownership + KZG insert) outside benchmark timers..."
    ./poa sp1-setup
    ;;
  *)
    echo
    echo "Skipping SP1 setup: selected operations do not use an SP1 guest."
    ;;
esac

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
  --master-n "$MASTER_N" \
  --n "$N_SIZES" \
  --m "$M_SIZES" \
  --operations "$BENCHMARK_OPERATIONS" \
  --samples "$SAMPLES" \
  --warmup "$WARMUP"
