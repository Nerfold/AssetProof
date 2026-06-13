# Dynamic Private PoA Prototype

This workspace implements both routes from `paper.tex`:

- the fixed-set algebraic NIZK route
- the mutable-set `SMT + SNARKs (SP1-style)` route with a local mock-SP1 backend

The implementation now includes:

- BLS12-381 scalar-field reserve-set polynomial `P_S(T) = alpha * prod(T - Enc(a))`
- powers-of-tau SRS generation for experiments
- pairing-based KZG commitments and batched update verification
- Pedersen-style G1 commitments for aggregate balances and vector openings
- Fiat-Shamir transcript binding for update proof objects
- fixed-set initialization, update, and verifier pipeline
- mock address, account-balance, transaction, block-window, and delta generator
- benchmark command that runs multi-window mock-chain updates end to end
- a salted local sparse Merkle tree for hidden reserve addresses
- membership / non-membership update witnesses following the SMT protocol
- separate SMT insertion flow for adding newly tracked reserve addresses
- SP1-style guest/host crate layout so the mock backend can be replaced later

Current limitation:

- The committed-R1CS/Bulletproof layer is represented by a transparent
  witness-carrying proof object plus exact verifier checks for the same
  constraints. This keeps the NIZK relation and KZG/Pedersen plumbing complete
  for experiments while leaving the final zero-knowledge Bulletproof backend as
  the next replaceable module.

## Workspace

- `crates/common`: address encoding, BLS12-381 serialization, file I/O
- `crates/nizk-fixed-set`: polynomial arithmetic, KZG, commitments, prover/verifier
- `crates/mock-chain`: deterministic mock chain and delta-window generator
- `crates/smt`: local salted sparse Merkle tree, proofs, update and insertion
- `crates/sp1-programs/*`: SP1-style guest program layout placeholders
- `crates/sp1-host`: mock-SP1 host that proves/verifies the SMT relations
- `crates/poa-cli`: experiment CLI for both routes

## Quick Start

Generate an experimental SRS:

```bash
cargo run -p poa-cli -- gen-srs 256 examples/mock_srs.bin
```

Generate a mock chain with 64 accounts, 8 hidden reserve addresses, 6 block
windows, and 20 transactions per block:

```bash
cargo run -p poa-cli -- mock-gen examples/mock_chain 64 8 6 20 42
```

Run the complete initialization and multi-window update benchmark:

```bash
cargo run -p poa-cli -- mock-bench examples/mock_srs.bin examples/mock_chain/manifest.txt examples/mock_report.txt
```

Run tests:

```bash
cargo test
```

## Fixed-Set NIZK Route

This is the algebraic fixed-set route implemented in `crates/nizk-fixed-set`.
Each update combines:

- a KZG batch opening for the hidden evaluation vector
- Pedersen-style commitments `C_U`, `C_Y`, `C_D`
- the `bp.rs` committed-R1CS Bulletproof layer plus the external link proof

The current `proof.txt` produced by this route includes
`bp_proof_hex`, `bp_commitments_hex`, and `link_proof_hex`, so the safest way
to reproduce the flow is to generate a fresh state and proof with the current
CLI.

Generate an experimental SRS if you do not already have one:

```bash
cargo run -p poa-cli -- gen-srs 256 examples/mock_srs.bin
```

Initialize the hidden reserve set from `examples/reserves.csv`:

```bash
cargo run -p poa-cli -- init examples/mock_srs.bin examples/reserves.csv init-root examples/readme_state.txt
```

Apply one public delta window from `examples/deltas.csv` and create the next
state plus NIZK proof:

```bash
cargo run -p poa-cli -- update examples/mock_srs.bin examples/readme_state.txt examples/deltas.csv next-root examples/readme_next_state.txt examples/readme_proof.txt
```

Verify the generated proof:

```bash
cargo run -p poa-cli -- verify examples/mock_srs.bin examples/readme_state.txt examples/deltas.csv examples/readme_next_state.txt examples/readme_proof.txt
```

On the current sample data, the update step reports:

```text
updated m=3, aggregate_delta=5, gate_count=12
```

and verification reports:

```text
verification passed for m=3, new_balance_total=435
```

If you already have a large reusable SRS and only want to materialize a
synthetic initial state, you can keep the SRS in a separate location:

```bash
cargo run -p poa-cli -- prepare-synthetic-state examples/srs_100000.bin 10000 root-poly-10k examples/bench_poly_10k/state_0000.txt
```

## SMT Route Quick Start

Initialize a local SMT state:

```bash
cargo run -p poa-cli -- smt-init 32 examples/smt/reserves.csv root-0 examples/smt/state0.txt
```

Apply a public delta window:

```bash
cargo run -p poa-cli -- smt-update examples/smt/state0.txt examples/smt/deltas.csv root-1 examples/smt/state1.txt examples/smt/proof1.txt
```

Verify the SMT update proof:

```bash
cargo run -p poa-cli -- smt-verify examples/smt/state0.txt examples/smt/state1.txt examples/smt/proof1.txt update
```

Insert a newly tracked reserve address:

```bash
cargo run -p poa-cli -- smt-insert examples/smt/state1.txt 0x3333333333333333333333333333333333333333 40 root-2 examples/smt/state2.txt examples/smt/proof2.txt
```

Verify the insertion proof:

```bash
cargo run -p poa-cli -- smt-verify examples/smt/state1.txt examples/smt/state2.txt examples/smt/proof2.txt insert
```

## Manual Flow

For real datasets later, provide:

- `reserves.csv`: hidden reserve sample for local proving
- `deltas.csv`: canonical public delta window from your real synchronizer
- `state_root`: finalized old/new state-root strings

Commands:

```bash
cargo run -p poa-cli -- init <srs.bin> <reserves.csv> <state-root> <state.txt>
cargo run -p poa-cli -- update <srs.bin> <state.txt> <deltas.csv> <new-state-root> <next-state.txt> <proof.txt>
cargo run -p poa-cli -- verify <srs.bin> <state.txt> <deltas.csv> <next-state.txt> <proof.txt>
```

If you are reusing old local artifacts, make sure they were generated by the
current CLI format. Older sample `state.txt` / `proof.txt` files may be missing
fields now required by the Bulletproof-backed verifier.

## CSV Formats

Reserve file:

```text
0x1111111111111111111111111111111111111111,100
0x2222222222222222222222222222222222222222,250
```

Delta file:

```text
0x1111111111111111111111111111111111111111,-10
0x3333333333333333333333333333333333333333,40
```

The delta reader sorts, deduplicates, merges duplicate address deltas, and drops
zero deltas. This matches the canonical mock synchronizer behavior.
