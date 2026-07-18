#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/sp1-version.env"
cd "$ROOT_DIR"
export PATH="$HOME/.cargo/bin:$HOME/.sp1/bin:$PATH"

MODE="${POA_SP1_PROOF_MODE:-groth16}"
errors=0

ok() { printf '  [ok] %s\n' "$1"; }
bad() { printf '  [missing] %s\n' "$1"; errors=$((errors + 1)); }

printf 'Dynamic PoA environment doctor\n'
printf '  proof mode: %s\n' "$MODE"
printf '  SP1 toolchain pin: %s\n' "$SP1_TOOLCHAIN_VERSION"
printf '  SP1 circuit pin: %s\n\n' "$SP1_CIRCUIT_VERSION"

command -v cargo >/dev/null 2>&1 && ok "Rust/Cargo: $(cargo --version)" \
  || bad "Rust/Cargo (run ./poa bootstrap)"
command -v rustup >/dev/null 2>&1 && rustup toolchain list 2>/dev/null | grep -q '^succinct' \
  && ok "SP1 Rust toolchain: succinct" \
  || bad "SP1 Rust toolchain: succinct (run ./poa bootstrap)"
command -v cargo-prove >/dev/null 2>&1 \
  && ok "cargo-prove: $(cargo prove --version 2>/dev/null || echo installed)" \
  || bad "cargo-prove (run ./poa bootstrap)"

check_artifacts() {
  local kind="$1"
  local dir="$HOME/.sp1/circuits/$kind/$SP1_CIRCUIT_VERSION"
  local complete=0
  case "$kind" in
    groth16)
      [[ -s "$dir/groth16_circuit.bin" && -s "$dir/groth16_pk.bin" && -s "$dir/groth16_vk.bin" ]] && complete=1
      ;;
    plonk)
      [[ -s "$dir/plonk_circuit.bin" && -s "$dir/plonk_pk.bin" \
        && -s "$dir/plonk_vk.bin" ]] && complete=1
      ;;
  esac
  if [[ "$complete" -eq 1 ]]; then
    ok "SP1 $kind circuit artifacts: $dir"
  elif [[ -f "$dir/artifacts.tar.gz" ]]; then
    bad "SP1 $kind artifacts are an interrupted tar-only download: $dir"
  else
    bad "SP1 $kind circuit artifacts: $dir"
  fi
}

case "$MODE" in
  groth16|plonk)
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
      ok "Docker daemon"
    elif command -v docker >/dev/null 2>&1; then
      bad "Docker is installed but the daemon/socket is unavailable; start Docker Desktop or fix docker-group access"
    else
      bad "Docker (required by SP1 $MODE wrapping; compressed mode does not need it)"
    fi
    check_artifacts "$MODE"
    ;;
  compressed)
    ok "Docker/circuit artifacts not required for compressed proofs"
    ;;
  *)
    bad "unknown POA_SP1_PROOF_MODE=$MODE (expected compressed, groth16, or plonk)"
    ;;
esac

for artifact in init.bin init-ownership.bin kzg-insert.bin; do
  [[ -s "params/sp1/$artifact" ]] && ok "protocol setup: params/sp1/$artifact" \
    || bad "protocol setup: params/sp1/$artifact (run ./poa sp1-setup)"
done
[[ -s params/srs/dev.srs.bin ]] && ok "development KZG SRS: params/srs/dev.srs.bin" \
  || bad "development KZG SRS (run ./poa setup)"

printf '\n'
if [[ "$errors" -ne 0 ]]; then
  printf 'Environment is incomplete: %d problem(s). Run ./poa bootstrap.\n' "$errors" >&2
  exit 1
fi
printf 'Environment is ready.\n'
