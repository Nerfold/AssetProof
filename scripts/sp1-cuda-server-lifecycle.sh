#!/usr/bin/env bash

# Shared lifecycle helpers for benchmarks that use SP1's local CUDA backend.
# SP1 6.2.4 gives a cold GPU server only a short time to create its Unix
# socket. Prestarting it keeps startup outside benchmark timers and lets the
# SDK connect to an already-ready endpoint.

POA_MANAGED_GPU_SERVER_PID=""
POA_MANAGED_GPU_SERVER_SOCKET=""
POA_MANAGED_GPU_SERVER_LOG=""

poa_prestart_sp1_gpu_server() {
  local output_dir="$1"
  local device="${POA_SP1_CUDA_DEVICE:-0}"
  local gpu_server="${HOME}/.sp1/bin/sp1-gpu-server"
  local socket="/tmp/sp1-cuda-${device}.sock"
  local log_file="${output_dir}/sp1-gpu-server.log"

  if [[ ! -x "$gpu_server" ]]; then
    echo "SP1 GPU server is missing or not executable: $gpu_server" >&2
    return 1
  fi

  mkdir -p "$output_dir"
  if [[ -S "$socket" ]]; then
    if ! command -v pgrep >/dev/null 2>&1 || pgrep -f "$gpu_server" >/dev/null 2>&1; then
      echo "SP1 GPU server socket is already ready: $socket"
      echo "The benchmark will reuse it; this script will not stop an externally managed server."
      return 0
    fi
    echo "Removing stale SP1 GPU server socket: $socket"
  fi

  # A non-socket entry or stale socket cannot be used by SP1. The benchmark
  # owns this CUDA device for the duration of the run.
  rm -f "$socket"
  : > "$log_file"
  echo "Prestarting SP1 GPU server on device $device..."
  CUDA_VISIBLE_DEVICES="$device" "$gpu_server" >>"$log_file" 2>&1 &
  local pid=$!
  local started=$SECONDS
  POA_MANAGED_GPU_SERVER_PID="$pid"
  POA_MANAGED_GPU_SERVER_SOCKET="$socket"
  POA_MANAGED_GPU_SERVER_LOG="$log_file"

  for _ in $(seq 1 600); do
    if [[ -S "$socket" ]]; then
      echo "SP1 GPU server ready in $((SECONDS - started))s (pid=$pid, socket=$socket)"
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      wait "$pid" 2>/dev/null || true
      echo "SP1 GPU server exited before creating $socket. Log:" >&2
      tail -n 50 "$log_file" >&2 || true
      rm -f "$socket"
      POA_MANAGED_GPU_SERVER_PID=""
      POA_MANAGED_GPU_SERVER_SOCKET=""
      return 1
    fi
    sleep 0.1
  done

  echo "SP1 GPU server did not create $socket within 60 seconds. Log:" >&2
  tail -n 50 "$log_file" >&2 || true
  poa_stop_managed_sp1_gpu_server
  return 1
}

poa_stop_managed_sp1_gpu_server() {
  local pid="${POA_MANAGED_GPU_SERVER_PID:-}"
  local socket="${POA_MANAGED_GPU_SERVER_SOCKET:-}"
  if [[ -z "$pid" ]]; then
    return 0
  fi

  echo "Stopping managed SP1 GPU server (pid=$pid)..."
  kill "$pid" 2>/dev/null || true
  for _ in $(seq 1 50); do
    if ! kill -0 "$pid" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  if kill -0 "$pid" 2>/dev/null; then
    kill -KILL "$pid" 2>/dev/null || true
  fi
  wait "$pid" 2>/dev/null || true
  if [[ -n "$socket" ]]; then
    rm -f "$socket"
  fi
  POA_MANAGED_GPU_SERVER_PID=""
  POA_MANAGED_GPU_SERVER_SOCKET=""
}
