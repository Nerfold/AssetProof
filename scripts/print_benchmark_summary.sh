#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: print_benchmark_summary.sh <summary.csv> <sample-count>" >&2
  exit 2
fi

SUMMARY="$1"
SAMPLES_COUNT="$2"
if [[ ! -s "$SUMMARY" ]]; then
  echo "missing benchmark summary: $SUMMARY" >&2
  exit 1
fi

echo "Average result ($SAMPLES_COUNT measured sample(s) per row)"
printf '%-8s %10s %10s %16s %16s %14s\n' "operation" "n" "m" "prove avg" "verify avg" "proof size"
printf '%-8s %10s %10s %16s %16s %14s\n' "--------" "----------" "----------" "----------------" "----------------" "--------------"
for operation in initialization update insert; do
  awk -F, -v wanted="$operation" '
    function time_fmt(ms) {
      if (ms >= 60000) return sprintf("%.2f min", ms / 60000)
      if (ms >= 1000) return sprintf("%.3f s", ms / 1000)
      return sprintf("%.3f ms", ms)
    }
    function bytes_fmt(bytes) {
      if (bytes >= 1048576) return sprintf("%.2f MiB", bytes / 1048576)
      if (bytes >= 1024) return sprintf("%.2f KiB", bytes / 1024)
      return sprintf("%d B", bytes)
    }
    NR == 1 {
      for (i = 1; i <= NF; i++) column[$i] = i
      operation_col = column["operation"]
      n_col = column["n"]
      m_col = column["m"]
      prover_col = column["prover_mean_ms"]
      verifier_col = column["verifier_mean_ms"]
      proof_col = column["proof_payload_bytes"]
      if (!proof_col) proof_col = column["proof_bytes"]
      next
    }
    $operation_col == wanted {
      label = ($operation_col == "initialization" ? "init" : $operation_col)
      m = ($operation_col == "update" ? $m_col : "-")
      printf "%-8s %10d %10s %16s %16s %14s\n", label, $n_col, m, time_fmt($prover_col), time_fmt($verifier_col), bytes_fmt($proof_col)
    }
  ' "$SUMMARY"
done
