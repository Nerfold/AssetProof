#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/sp1-version.env"
source "$ROOT_DIR/scripts/sp1-docker-env.sh"
cd "$ROOT_DIR"

N_SIZES="${N_SIZES:-10000,100000,1000000}"
M_SIZES="${M_SIZES:-100,1000}"
MASTER_N="${MASTER_N:-1000000}"
SAMPLES="${SAMPLES:-3}"
WARMUP="${WARMUP:-1}"
POA_SP1_PROOF_MODE="${POA_SP1_PROOF_MODE:-groth16}"
POA_SP1_PROFILE="${POA_SP1_PROFILE:-0}"
SP1_PROVER="${SP1_PROVER:-cpu}"
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
SP1_GNARK_IMAGE="${SP1_GNARK_IMAGE:-ghcr.io/succinctlabs/sp1-gnark:$SP1_CIRCUIT_VERSION}"

export POA_SP1_PROOF_MODE
export POA_SP1_PROFILE
export SP1_PROVER
export SP1_GNARK_IMAGE
export SHARD_SIZE MINIMAL_TRACE_CHUNK_THRESHOLD TRACE_CHUNK_SLOTS
export GAS_TRACE_CHUNK_THRESHOLD GAS_TRACE_CHUNK_SLOTS

echo "Dynamic PoA benchmark"
echo "  n:          $N_SIZES"
echo "  m:          $M_SIZES"
echo "  master n:   $MASTER_N"
echo "  samples:    $SAMPLES"
echo "  warmup:     $WARMUP"
echo "  SP1 mode:   $POA_SP1_PROOF_MODE"
echo "  SP1 prover: $SP1_PROVER"
echo "  SP1 profile: $POA_SP1_PROFILE"
if [[ "$SP1_PROVER" != "network" && ( "$POA_SP1_PROOF_MODE" == "groth16" || "$POA_SP1_PROOF_MODE" == "plonk" ) ]]; then
  echo "  gnark image: $SP1_GNARK_IMAGE"
  echo "  Docker arch: ${DOCKER_DEFAULT_PLATFORM:-native}"
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
    if [[ ! -x "$CUDA_WORKER" ]]; then
      echo "SP1 CUDA worker is missing: $CUDA_WORKER" >&2
      echo "Run ./poa sp1-cuda-build first." >&2
      exit 1
    fi
    ;;
  network)
    NETWORK_WORKER="${POA_SP1_NETWORK_WORKER:-$ROOT_DIR/tools/sp1-network-worker/target/release/sp1-network-worker}"
    if [[ -z "${NETWORK_PRIVATE_KEY:-}" ]]; then
      echo "NETWORK_PRIVATE_KEY is required for SP1 Network proving." >&2
      exit 1
    fi
    if [[ ! -x "$NETWORK_WORKER" ]]; then
      echo "SP1 Network worker is missing: $NETWORK_WORKER" >&2
      echo "Run ./poa sp1-network-build first." >&2
      exit 1
    fi
    ;;
  *)
    echo "SP1_PROVER must be cpu, cuda, or network; got $SP1_PROVER." >&2
    exit 1
    ;;
esac
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
if ! grep -Fxq "fixture_version=ethereum-keccak-merkle-prefix-v2-ecdsa" "$FIXTURE_DIR/preparation-manifest.txt" \
  || ! grep -Fxq "master.max_n=$MASTER_N" "$FIXTURE_DIR/preparation-manifest.txt"; then
  echo >&2
  echo "Prepared fixtures do not match Keccak-Merkle prefix fixture / MASTER_N=$MASTER_N." >&2
  echo "Run scripts/initialize_benchmark_data.sh again." >&2
  exit 1
fi

case "$POA_SP1_PROOF_MODE" in
  groth16|plonk)
    if [[ "$SP1_PROVER" != "network" ]]; then
      if ! command -v docker >/dev/null 2>&1; then
        echo "Docker is required for local SP1 $POA_SP1_PROOF_MODE wrapping. Run ./poa bootstrap." >&2
        exit 1
      fi
      if ! docker info >/dev/null 2>&1; then
        echo "Docker is installed but its daemon is unavailable. Start Docker Desktop, then rerun." >&2
        exit 1
      fi
      image_arch="$(docker image inspect --format '{{.Architecture}}' "$SP1_GNARK_IMAGE" 2>/dev/null || true)"
      expected_arch=""
      case "${DOCKER_DEFAULT_PLATFORM:-}" in
        linux/amd64) expected_arch="amd64" ;;
        linux/arm64|linux/arm64/v8) expected_arch="arm64" ;;
      esac
      if [[ -z "$image_arch" || ( -n "$expected_arch" && "$image_arch" != "$expected_arch" ) ]]; then
        echo
        echo "Preparing SP1 gnark wrapper image before benchmark timers..."
        if [[ -n "${DOCKER_DEFAULT_PLATFORM:-}" ]]; then
          docker pull --platform "$DOCKER_DEFAULT_PLATFORM" "$SP1_GNARK_IMAGE"
        else
          docker pull "$SP1_GNARK_IMAGE"
        fi
      fi
    fi
    ;;
  compressed) ;;
  *)
    echo "POA_SP1_PROOF_MODE must be compressed, groth16, or plonk" >&2
    exit 1
    ;;
esac

SETUP_COMPONENTS=""
case ",$BENCHMARK_OPERATIONS," in
  *,all,*) SETUP_COMPONENTS="all" ;;
  *)
    case ",$BENCHMARK_OPERATIONS," in
      *,initialization,*|*,init,*) SETUP_COMPONENTS="init" ;;
    esac
    case ",$BENCHMARK_OPERATIONS," in
      *,insert,*)
        if [[ -n "$SETUP_COMPONENTS" ]]; then
          SETUP_COMPONENTS="$SETUP_COMPONENTS,insert"
        else
          SETUP_COMPONENTS="insert"
        fi
        ;;
    esac
    ;;
esac

case "$SETUP_COMPONENTS" in
  all|init|insert|init,insert)
    echo
    echo "Preparing protocol SP1 setup components [$SETUP_COMPONENTS] outside benchmark timers..."
    POA_SP1_SETUP_COMPONENTS="$SETUP_COMPONENTS" ./poa sp1-setup
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
