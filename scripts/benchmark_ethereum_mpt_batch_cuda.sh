#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SAMPLES_COUNT="${SAMPLES:-3}"
WARMUP_COUNT="${WARMUP:-1}"
PROOF_COUNTS="1024,2048,4096,8192"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
OUTPUT_DIR="${OUTPUT_DIR:-artifacts/benchmarks/ethereum-mpt-batch-cuda-${RUN_ID}}"

echo "Ethereum MPT batch benchmark (SP1 CUDA)"
echo "  proof counts: 1024, 2048, 4096, 8192"
echo "  samples: $SAMPLES_COUNT, warmup: $WARMUP_COUNT"
echo "  mode: ${POA_SP1_PROOF_MODE:-compressed}"
echo "  output: $OUTPUT_DIR"
echo

exec env \
  MPT_PROVE=1 \
  WARMUP="$WARMUP_COUNT" \
  OUTPUT_DIR="$OUTPUT_DIR" \
  POA_SP1_PROOF_MODE="${POA_SP1_PROOF_MODE:-compressed}" \
  POA_SP1_CUDA_DEVICE="${POA_SP1_CUDA_DEVICE:-0}" \
  "$ROOT_DIR/scripts/benchmark_ethereum_mpt.sh" \
    cuda "$SAMPLES_COUNT" "$PROOF_COUNTS"
