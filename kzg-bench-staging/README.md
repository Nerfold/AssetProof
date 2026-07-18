# KZG prover benchmark

Benchmarks KZG proving over BLS12-381 at polynomial degrees 10,000, 100,000,
and 1,000,000. The reported prover total includes commitment, polynomial
evaluation, and opening-proof generation. One-time SRS setup and deterministic
input generation are excluded.

Run on an otherwise idle machine in release mode:

```bash
cargo run --release
```

Override the degree list by passing integer arguments:

```bash
cargo run --release -- 10000 100000
```

For stable comparisons, keep the same machine, power mode, Rust version, and
`RAYON_NUM_THREADS` setting. The degree-1,000,000 case requires substantial RAM
and may take several minutes, especially during the excluded SRS setup.

