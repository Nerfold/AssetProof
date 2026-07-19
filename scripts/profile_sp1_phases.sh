#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MASTER_N="${MASTER_N:-16}"
N_SIZES="${N_SIZES:-16}"
M_SIZES="${M_SIZES:-16}"
FIXTURE_DIR="${FIXTURE_DIR:-data/mock/bench/generated}"
SRS_DIR="${SRS_DIR:-params/srs/bench}"
OUTPUT_DIR="${OUTPUT_DIR:-artifacts/benchmarks/sp1-profile-n${N_SIZES//,/-}}"
POA_SP1_PROOF_MODE="${POA_SP1_PROOF_MODE:-compressed}"
RUST_LOG="${RUST_LOG:-sp1_prover=debug,sp1_core_executor=info,sp1_recursion_gnark_ffi=info}"

export MASTER_N N_SIZES M_SIZES FIXTURE_DIR SRS_DIR OUTPUT_DIR
export POA_SP1_PROOF_MODE RUST_LOG
export POA_SP1_PROFILE=1
export BENCHMARK_OPERATIONS=initialization,insert
export SAMPLES=1
export WARMUP=0
# Gas profiling uses a separate trace engine. One slot keeps the diagnostic
# run bounded on workstation-class machines.
export GAS_TRACE_CHUNK_SLOTS="${GAS_TRACE_CHUNK_SLOTS:-1}"

echo "SP1 phase profiler"
echo "  master n:   $MASTER_N"
echo "  n sizes:    $N_SIZES"
echo "  proof mode: $POA_SP1_PROOF_MODE"
echo "  output:     $OUTPUT_DIR"
echo
echo "The profiler executes each guest once for cycles/gas, then runs the real proof."
echo "The execution probe is reported separately and excluded from benchmark prover time."

./scripts/benchmark_protocol.sh
