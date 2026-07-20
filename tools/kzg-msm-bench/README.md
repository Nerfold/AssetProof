# Standalone KZG/MSM microbenchmark

This diagnostic measures raw BLS12-381 commitment, evaluation and quotient-opening work. It is
not part of the Dynamic PoA protocol benchmark.

```bash
cargo run --release -p kzg-msm-bench -- 10000 100000 1000000
```

Use `scripts/benchmark_protocol.sh` for end-to-end initialization, insert and update results.
