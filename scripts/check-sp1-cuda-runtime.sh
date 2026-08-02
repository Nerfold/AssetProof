#!/usr/bin/env bash

# `nvidia-smi` proves driver visibility, not that the CUDA runtime loader
# dependencies required by sp1-gpu-server exist inside the container.
check_sp1_cuda_runtime() {
  local gpu_server="${HOME}/.sp1/bin/sp1-gpu-server"
  if [[ ! -x "$gpu_server" ]]; then
    return 0
  fi
  if ! command -v ldd >/dev/null 2>&1; then
    echo "ldd is unavailable; cannot validate SP1 GPU server runtime libraries." >&2
    return 1
  fi

  local missing
  missing="$(ldd "$gpu_server" 2>&1 | awk '/not found/ { print }')"
  if [[ -n "$missing" ]]; then
    echo "SP1 GPU server has missing runtime libraries:" >&2
    echo "$missing" >&2
    echo "Install the CUDA 12 runtime inside this container, or add its lib64 directory to LD_LIBRARY_PATH." >&2
    return 1
  fi
}
