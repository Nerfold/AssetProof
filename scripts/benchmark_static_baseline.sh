#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/sp1-version.env"
source "$ROOT_DIR/scripts/sp1-docker-env.sh"
source "$ROOT_DIR/scripts/check-sp1-cuda-runtime.sh"
cd "$ROOT_DIR"

MASTER_N="${MASTER_N:-1000000}"
N_SIZES="${N_SIZES:-10000,100000,1000000}"
SAMPLES="${SAMPLES:-3}"
WARMUP="${WARMUP:-1}"
FIXTURE_DIR="${FIXTURE_DIR:-data/mock/bench/generated}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
OUTPUT_DIR="${OUTPUT_DIR:-artifacts/benchmarks/static-baseline-$RUN_ID}"
POA_SP1_PROOF_MODE="${POA_SP1_PROOF_MODE:-compressed}"
POA_SP1_PROFILE="${POA_SP1_PROFILE:-0}"
SP1_PROVER="${SP1_PROVER:-cpu}"
SHARD_SIZE="${SHARD_SIZE:-1048576}"
MINIMAL_TRACE_CHUNK_THRESHOLD="${MINIMAL_TRACE_CHUNK_THRESHOLD:-1048576}"
TRACE_CHUNK_SLOTS="${TRACE_CHUNK_SLOTS:-2}"
GAS_TRACE_CHUNK_THRESHOLD="${GAS_TRACE_CHUNK_THRESHOLD:-8388608}"
GAS_TRACE_CHUNK_SLOTS="${GAS_TRACE_CHUNK_SLOTS:-2}"
SP1_GNARK_IMAGE="${SP1_GNARK_IMAGE:-ghcr.io/succinctlabs/sp1-gnark:$SP1_CIRCUIT_VERSION}"

export POA_SP1_PROOF_MODE POA_SP1_PROFILE SP1_PROVER SP1_GNARK_IMAGE
export SHARD_SIZE MINIMAL_TRACE_CHUNK_THRESHOLD TRACE_CHUNK_SLOTS
export GAS_TRACE_CHUNK_THRESHOLD GAS_TRACE_CHUNK_SLOTS

echo "Traditional static PoA SP1 baseline"
echo "  n:          $N_SIZES"
echo "  master n:   $MASTER_N"
echo "  samples:    $SAMPLES"
echo "  warmup:     $WARMUP"
echo "  SP1 mode:   $POA_SP1_PROOF_MODE"
echo "  SP1 prover: $SP1_PROVER"
echo "  fixtures:   $FIXTURE_DIR"
echo "  output:     $OUTPUT_DIR"
echo "  KZG/SRS:    disabled"

if [[ ! -f "$FIXTURE_DIR/preparation-manifest.txt" ]]; then
  echo "Missing Ethereum mock fixture manifest: $FIXTURE_DIR/preparation-manifest.txt" >&2
  echo "Run scripts/initialize_benchmark_data.sh first." >&2
  exit 1
fi

case "$SP1_PROVER" in
  cpu|local) ;;
  cuda|gpu)
    CUDA_WORKER="${POA_SP1_CUDA_WORKER:-$ROOT_DIR/tools/sp1-cuda-worker/target/release/sp1-cuda-worker}"
    if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
      echo "SP1 CUDA requires Linux x86_64." >&2
      exit 1
    fi
    if ! command -v nvidia-smi >/dev/null 2>&1 || ! nvidia-smi -L >/dev/null 2>&1; then
      echo "NVIDIA GPU/driver is unavailable inside this container." >&2
      exit 1
    fi
    check_sp1_cuda_runtime || exit 1
    if [[ ! -x "$CUDA_WORKER" ]]; then
      echo "SP1 CUDA worker is missing: $CUDA_WORKER" >&2
      echo "Run ./poa sp1-cuda-build first." >&2
      exit 1
    fi
    CUDA_WORKER_VERSION="$("$CUDA_WORKER" protocol-version 2>/dev/null || true)"
    if [[ "$CUDA_WORKER_VERSION" != "poa-sp1-cuda-worker-v4-server-wait" ]]; then
      echo "SP1 CUDA worker is stale or incompatible: ${CUDA_WORKER_VERSION:-unknown}" >&2
      echo "Run ./poa sp1-cuda-build again." >&2
      exit 1
    fi
    ;;
  network)
    NETWORK_WORKER="${POA_SP1_NETWORK_WORKER:-$ROOT_DIR/tools/sp1-network-worker/target/release/sp1-network-worker}"
    if [[ -z "${NETWORK_PRIVATE_KEY:-}" || ! -x "$NETWORK_WORKER" ]]; then
      echo "SP1 Network requires NETWORK_PRIVATE_KEY and a built network worker." >&2
      echo "Run ./poa sp1-network-build first." >&2
      exit 1
    fi
    ;;
  *)
    echo "SP1_PROVER must be cpu, cuda, or network; got $SP1_PROVER." >&2
    exit 1
    ;;
esac

case "$POA_SP1_PROOF_MODE" in
  compressed) ;;
  groth16|plonk)
    if [[ "$SP1_PROVER" != "network" ]]; then
      if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
        echo "Docker must be installed and running for local $POA_SP1_PROOF_MODE wrapping." >&2
        exit 1
      fi
      image_arch="$(docker image inspect --format '{{.Architecture}}' "$SP1_GNARK_IMAGE" 2>/dev/null || true)"
      if [[ -z "$image_arch" ]]; then
        echo "Preparing SP1 gnark image outside benchmark timers..."
        docker pull "$SP1_GNARK_IMAGE"
      fi
    fi
    ;;
  *)
    echo "POA_SP1_PROOF_MODE must be compressed, groth16, or plonk." >&2
    exit 1
    ;;
esac

echo
echo "Building release static baseline binary outside benchmark timers..."
cargo build --release -p static-bench

echo
exec ./target/release/static-bench \
  --fixture-dir "$FIXTURE_DIR" \
  --output "$OUTPUT_DIR" \
  --master-n "$MASTER_N" \
  --n "$N_SIZES" \
  --samples "$SAMPLES" \
  --warmup "$WARMUP"
