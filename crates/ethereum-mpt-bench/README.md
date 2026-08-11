# Ethereum MPT verification benchmark

This crate isolates one operation: verifying an Ethereum state-trie account
proof inside an SP1 guest. It does not perform ownership verification, KZG,
Pedersen commitments, range proofs, SMT work, or protocol state updates.

The generator builds one Ethereum-style Keccak-addressed hexary
Merkle-Patricia trie containing the largest requested account set, using
canonical extension, branch, leaf, compact-path, child-reference, and RLP
encoding. It exports one membership proof per account, and every proof shares
the same state root. The fixture is synthetic and deterministic; it is not
claimed to be a particular Ethereum block's state.

Run execution/cycle measurements only (fast and independent of CUDA):

```bash
MPT_PROVE=0 ./poa benchmark-mpt cpu 3 1,16,256
```

Run three compressed-proof samples with CUDA:

```bash
./poa sp1-cuda-build
./poa benchmark-mpt cuda 3 1,16,256
```

Run the requested CUDA batch matrix (`2^10`, `2^11`, `2^12`, and `2^13`
distinct account proofs from one 8192-account trie, three measured samples):

```bash
./poa sp1-cuda-build
./poa benchmark-mpt-cuda-matrix
```

Override the sample counts with `SAMPLES` and `WARMUP`. For example:

```bash
SAMPLES=1 WARMUP=0 ./poa benchmark-mpt-cuda-matrix
```

Arguments are `prover`, measured sample count, and comma-separated proof
counts. The same sample/warmup counts are applied separately to reference
execution and real proof generation. `WARMUP`, `OUTPUT_DIR`,
`MPT_COUNTS`, `POA_SP1_PROOF_MODE`, `POA_SP1_PROFILE`, and
`POA_SP1_CUDA_DEVICE` use the same meanings as the protocol benchmarks.

`summary.csv` and `summary.md` report proof-node count, raw MPT proof bytes,
mean reference-executor time, RISC-V cycles, syscalls, prover time, verifier time,
and serialized SP1 proof size. Guest/backend setup and fixture generation are
reported separately and excluded from samples. A separate profiled execution
also writes `input_decode_cycles`, `mpt_verify_cycles`,
`batch_binding_cycles`, and `public_commit_cycles`; it is excluded from all
timing samples. Keccak address hashing, trie-node hashing, and the public batch
statement commitment use SP1's Keccak permutation syscall. RLP parsing and
compact-path matching are zero-allocation in the verifier hot path.

This is the project's `no_std` Rust verifier for Ethereum's canonical byte
format, not Go source code copied from go-ethereum. The largest tree and proof
set are generated once, then the batch is truncated in place for smaller sizes
to avoid duplicate large witnesses. Fixture tests additionally cross-check the
exported paths with Alloy's independent `alloy-trie::proof::verify_proof`.
Use real `eth_getProof` data for a mainnet-distribution measurement.
