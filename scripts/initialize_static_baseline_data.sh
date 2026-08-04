#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MASTER_N="${MASTER_N:-1000000}"
N_SIZES="${N_SIZES:-10000,100000,1000000}"
FIXTURE_DIR="${FIXTURE_DIR:-data/mock/bench/static-baseline}"

echo "Static baseline fixture"
echo "  master n: $MASTER_N"
echo "  n sizes:  $N_SIZES"
echo "  output:   $FIXTURE_DIR"
echo "  SRS/KZG/delta/SMT: disabled"

echo
echo "Building static fixture generator..."
cargo build --release -p static-bench --no-default-features --bin static_fixture

echo
exec ./target/release/static_fixture \
  --fixture-dir "$FIXTURE_DIR" \
  --master-n "$MASTER_N" \
  --n "$N_SIZES"
