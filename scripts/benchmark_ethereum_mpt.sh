#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/check-sp1-cuda-runtime.sh"
cd "$ROOT_DIR"

PROVER="${1:-${SP1_PROVER:-cpu}}"
SAMPLES_COUNT="${2:-${SAMPLES:-3}}"
COUNTS="${3:-${MPT_COUNTS:-1}}"
WARMUP_COUNT="${WARMUP:-1}"
PROOF_MODE="${POA_SP1_PROOF_MODE:-compressed}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
OUTPUT_DIR="${OUTPUT_DIR:-artifacts/benchmarks/ethereum-mpt-sp1-${RUN_ID}}"
PROVE="${MPT_PROVE:-1}"

case "$PROVER" in
  cpu|cuda|network) ;;
  *) echo "prover must be cpu, cuda, or network; got: $PROVER" >&2; exit 2 ;;
esac

if [[ "$PROVER" == "cuda" ]]; then
  CUDA_WORKER="${POA_SP1_CUDA_WORKER:-$ROOT_DIR/tools/sp1-cuda-worker/target/release/sp1-cuda-worker}"
  check_sp1_cuda_runtime
  if [[ ! -x "$CUDA_WORKER" ]]; then
    echo "Missing SP1 CUDA worker: $CUDA_WORKER" >&2
    echo "Run ./poa sp1-cuda-build first." >&2
    exit 1
  fi
fi

if [[ "$PROVER" == "network" && -z "${NETWORK_PRIVATE_KEY:-}" ]]; then
  echo "NETWORK_PRIVATE_KEY is required for network proving." >&2
  exit 1
fi

echo "Building the isolated Ethereum MPT benchmark outside timers..."
cargo build --release -p ethereum-mpt-bench

echo
exec env \
  SP1_PROVER="$PROVER" \
  POA_SP1_PROOF_MODE="$PROOF_MODE" \
  POA_SP1_PROFILE="${POA_SP1_PROFILE:-0}" \
  ./target/release/ethereum-mpt-bench \
  --counts "$COUNTS" \
  --samples "$SAMPLES_COUNT" \
  --warmup "$WARMUP_COUNT" \
  --prove "$PROVE" \
  --output "$OUTPUT_DIR"
