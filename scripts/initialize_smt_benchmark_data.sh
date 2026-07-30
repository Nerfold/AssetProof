#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/sp1-docker-env.sh"
cd "$ROOT_DIR"

MASTER_N="${MASTER_N:-1000000}"
N_SIZES="${N_SIZES:-10000,100000,1000000}"
M_SIZES="${M_SIZES:-100,1000}"
SMT_DEPTH="${SMT_DEPTH:-128}"
FIXTURE_DIR="${FIXTURE_DIR:-data/mock/bench/generated}"
SMT_OUTPUT_DIR="${SMT_OUTPUT_DIR:-data/mock/bench/smt-persisted/master_n_${MASTER_N}/depth_${SMT_DEPTH}}"
POA_SP1_PROOF_MODE="${POA_SP1_PROOF_MODE:-compressed}"
SP1_PROVER="${SP1_PROVER:-cpu}"
SMT_FORCE="${SMT_FORCE:-false}"

export POA_SP1_PROOF_MODE
export SP1_PROVER

echo "Poseidon SMT persisted benchmark initialization"
echo "  source fixtures: $FIXTURE_DIR"
echo "  master n:        $MASTER_N"
echo "  n sizes:         $N_SIZES"
echo "  m sizes:         $M_SIZES"
echo "  SMT depth:       $SMT_DEPTH"
echo "  SP1 mode:        $POA_SP1_PROOF_MODE"
echo "  SP1 prover:      $SP1_PROVER"
echo "  output:          $SMT_OUTPUT_DIR"
echo "  force rebuild:   $SMT_FORCE"
echo
echo "This reuses the Ethereum-format account, ECDSA, Merkle and delta fixtures"
echo "created by scripts/initialize_benchmark_data.sh. Each successful initialization"
echo "is persisted and verified on reuse. SP1 proving is not included in fixture load time."

if [[ ! -f "$FIXTURE_DIR/preparation-manifest.txt" ]]; then
  echo "Missing $FIXTURE_DIR/preparation-manifest.txt" >&2
  echo "Run scripts/initialize_benchmark_data.sh first with matching MASTER_N/N_SIZES/M_SIZES." >&2
  exit 1
fi
if ! grep -Fxq "fixture_version=ethereum-keccak-merkle-prefix-v2-ecdsa" "$FIXTURE_DIR/preparation-manifest.txt" \
  || ! grep -Fxq "master.max_n=$MASTER_N" "$FIXTURE_DIR/preparation-manifest.txt"; then
  echo "Prepared NIZK fixture version or MASTER_N does not match." >&2
  echo "Regenerate it with scripts/initialize_benchmark_data.sh." >&2
  exit 1
fi

case "$POA_SP1_PROOF_MODE" in
  compressed) ;;
  groth16|plonk)
    if [[ "$SP1_PROVER" == "network" ]]; then
      :
    elif ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
      echo "Docker must be installed and running for $POA_SP1_PROOF_MODE." >&2
      exit 1
    fi
    ;;
  *)
    echo "POA_SP1_PROOF_MODE must be compressed, groth16, or plonk" >&2
    exit 1
    ;;
esac

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
    CUDA_WORKER_VERSION="$("$CUDA_WORKER" protocol-version 2>/dev/null || true)"
    if [[ "$CUDA_WORKER_VERSION" != "poa-sp1-cuda-worker-v3-direct" ]]; then
      echo "SP1 CUDA worker is stale or incompatible: ${CUDA_WORKER_VERSION:-unknown}" >&2
      echo "Run ./poa sp1-cuda-build again." >&2
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

echo
echo "Building the persisted SMT fixture tool..."
cargo build --release -p poa-bench --bin poa-smt-fixture

echo
exec ./target/release/poa-smt-fixture \
  --fixture-dir "$FIXTURE_DIR" \
  --output-dir "$SMT_OUTPUT_DIR" \
  --master-n "$MASTER_N" \
  --n "$N_SIZES" \
  --m "$M_SIZES" \
  --depth "$SMT_DEPTH" \
  --force "$SMT_FORCE"
