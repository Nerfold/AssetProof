#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/sp1-version.env"
cd "$ROOT_DIR"
export PATH="$HOME/.cargo/bin:$HOME/.sp1/bin:$PATH"

MODE="${POA_SP1_PROOF_MODE:-groth16}"
SETUP_DEGREE="${POA_SETUP_DEGREE:-256}"
INSTALL_DOCKER="${POA_INSTALL_DOCKER:-1}"

say() { printf '\n==> %s\n' "$1"; }
die() { printf 'bootstrap error: %s\n' "$1" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v tar >/dev/null 2>&1 || die "tar is required"
command -v git >/dev/null 2>&1 || die "git is required"

if ! command -v cargo >/dev/null 2>&1; then
  say "Installing Rust with rustup"
  installer="$(mktemp "${TMPDIR:-/tmp}/poa-rustup.XXXXXX")"
  curl --fail --location --retry 3 https://sh.rustup.rs --output "$installer"
  sh "$installer" -y
  rm -f "$installer"
fi
export PATH="$HOME/.cargo/bin:$HOME/.sp1/bin:$PATH"
command -v rustup >/dev/null 2>&1 || die "rustup is unavailable after Rust installation"

SP1_MARKER="$HOME/.sp1/.poa-toolchain-version"
installed_pin="$(cat "$SP1_MARKER" 2>/dev/null || true)"
if ! command -v cargo-prove >/dev/null 2>&1 \
  || ! rustup toolchain list 2>/dev/null | grep -q '^succinct' \
  || [[ "$installed_pin" != "$SP1_TOOLCHAIN_VERSION" ]]; then
  say "Installing pinned SP1 toolchain $SP1_TOOLCHAIN_VERSION"
  installer="$(mktemp "${TMPDIR:-/tmp}/poa-sp1up.XXXXXX")"
  curl --fail --location --retry 3 https://sp1up.succinct.xyz --output "$installer"
  sh "$installer"
  export PATH="$HOME/.sp1/bin:$PATH"
  sp1up -v "$SP1_TOOLCHAIN_VERSION"
  mkdir -p "$HOME/.sp1"
  printf '%s\n' "$SP1_TOOLCHAIN_VERSION" > "$SP1_MARKER"
else
  say "Reusing pinned SP1 toolchain $SP1_TOOLCHAIN_VERSION"
fi

ensure_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    [[ "$INSTALL_DOCKER" == "1" ]] \
      || die "Docker is missing. Install it, or use POA_SP1_PROOF_MODE=compressed ./poa bootstrap"
    case "$(uname -s)" in
      Darwin)
        command -v brew >/dev/null 2>&1 \
          || die "Homebrew is required for automatic Docker Desktop installation: https://brew.sh"
        say "Installing Docker Desktop"
        brew install --cask docker
        ;;
      Linux)
        say "Installing Docker Engine"
        installer="$(mktemp "${TMPDIR:-/tmp}/poa-docker.XXXXXX")"
        curl --fail --location --retry 3 https://get.docker.com --output "$installer"
        if [[ "$(id -u)" -eq 0 ]]; then
          sh "$installer"
        elif command -v sudo >/dev/null 2>&1; then
          sudo sh "$installer"
          sudo usermod -aG docker "$USER" || true
        else
          rm -f "$installer"
          die "Docker installation needs root or sudo"
        fi
        rm -f "$installer"
        ;;
      *) die "automatic Docker installation is unsupported on $(uname -s)" ;;
    esac
  fi

  if ! docker info >/dev/null 2>&1; then
    case "$(uname -s)" in
      Darwin)
        say "Starting Docker Desktop"
        open -a Docker
        ;;
      Linux)
        if command -v systemctl >/dev/null 2>&1; then
          if [[ "$(id -u)" -eq 0 ]]; then systemctl start docker || true;
          elif command -v sudo >/dev/null 2>&1; then sudo systemctl start docker || true; fi
        fi
        ;;
    esac
  fi
  for _ in $(seq 1 90); do
    docker info >/dev/null 2>&1 && return 0
    sleep 2
  done
  die "Docker is installed but unavailable. Start Docker Desktop; on Linux re-login after joining the docker group. Alternatively use compressed mode."
}

install_circuit_artifacts() {
  local kind="$1"
  local destination="$HOME/.sp1/circuits/$kind/$SP1_CIRCUIT_VERSION"
  local complete=0
  case "$kind" in
    groth16)
      [[ -s "$destination/groth16_circuit.bin" && -s "$destination/groth16_pk.bin" \
        && -s "$destination/groth16_vk.bin" ]] && complete=1
      ;;
    plonk)
      [[ -s "$destination/plonk_circuit.bin" && -s "$destination/plonk_pk.bin" \
        && -s "$destination/plonk_vk.bin" ]] && complete=1
      ;;
    *) die "unsupported SP1 artifact type $kind" ;;
  esac
  [[ "$complete" -eq 1 ]] && { say "Reusing complete SP1 $kind circuit artifacts"; return; }

  say "Downloading SP1 $kind circuit artifacts $SP1_CIRCUIT_VERSION"
  printf '    This official wrapper package is large; allow several GB of free disk space.\n'
  local download_dir="$HOME/.sp1/downloads"
  local archive="$download_dir/$SP1_CIRCUIT_VERSION-$kind.tar.gz"
  local url="$SP1_CIRCUIT_URL_BASE/$SP1_CIRCUIT_VERSION-$kind.tar.gz"
  mkdir -p "$download_dir" "$HOME/.sp1/circuits"
  if ! curl --fail --location --retry 5 --continue-at - --output "$archive" "$url"; then
    rm -f "$archive"
    curl --fail --location --retry 5 --output "$archive" "$url"
  fi
  tar -tzf "$archive" >/dev/null
  local staging
  staging="$(mktemp -d "$HOME/.sp1/circuits/.poa-$kind.XXXXXX")"
  tar -xzf "$archive" -C "$staging"
  case "$kind" in
    groth16)
      [[ -s "$staging/groth16_circuit.bin" && -s "$staging/groth16_pk.bin" \
        && -s "$staging/groth16_vk.bin" ]] || die "downloaded Groth16 archive is incomplete"
      ;;
    plonk)
      [[ -s "$staging/plonk_circuit.bin" && -s "$staging/plonk_pk.bin" \
        && -s "$staging/plonk_vk.bin" ]] || die "downloaded Plonk archive is incomplete"
      ;;
  esac
  rm -rf "$destination"
  mkdir -p "$(dirname "$destination")"
  mv "$staging" "$destination"
}

case "$MODE" in
  groth16|plonk)
    ensure_docker
    install_circuit_artifacts "$MODE"
    ;;
  compressed)
    say "Compressed mode selected; Docker and wrapper circuit artifacts are not required"
    ;;
  *) die "POA_SP1_PROOF_MODE must be compressed, groth16, or plonk" ;;
esac

say "Fetching and building Rust dependencies"
cargo fetch --locked
cargo build --release -p poa-cli

say "Generating development KZG SRS (degree=$SETUP_DEGREE)"
./poa setup "$SETUP_DEGREE"

say "Compiling protocol guests and generating SP1 verification-key setup"
POA_SP1_SETUP_COMPONENTS=all ./poa sp1-setup

say "Final environment check"
POA_SP1_PROOF_MODE="$MODE" ./scripts/doctor.sh

printf '\nBootstrap complete. The benchmark fixture/SRS matrix is generated separately by:\n'
printf '  ./scripts/initialize_benchmark_data.sh\n'
