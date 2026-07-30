# Local SP1 CUDA worker

The protocol keeps CUDA out of the main Cargo dependency graph. Local GPU proof generation runs
through the isolated workspace at `tools/sp1-cuda-worker/`; the main process retains the trusted
CPU verifier and verifies every returned proof against the locally persisted VK during the
explicit protocol verification phase.

## Requirements

- Linux x86_64;
- an NVIDIA GPU and driver visible through `nvidia-smi`;
- outbound access to GitHub Releases on the first CUDA setup;
- enough host RAM for guest execution and proof orchestration.

SP1 6.2.4's CUDA client automatically downloads the matching
`~/.sp1/bin/sp1-gpu-server` release binary and starts it with the selected GPU. Building this
worker does not require `nvcc`, but the runtime NVIDIA driver must be available inside the
container.

Build once on the GPU machine:

```bash
./poa sp1-cuda-build
```

Select device zero and run a compressed proof:

```bash
export SP1_PROVER=cuda
export POA_SP1_CUDA_DEVICE=0
export POA_SP1_PROOF_MODE=compressed
```

Override the worker only when necessary:

```bash
export POA_SP1_CUDA_WORKER=/absolute/path/to/sp1-cuda-worker
```

`compressed` uses CUDA for SP1 core proving and requires no Docker wrapper. `groth16` and `plonk`
remain supported, but their final wrapper follows the project's existing local Docker/artifact
path. The optional SP1 `groth16-cuda`/Icicle wrapper is not enabled by this integration.

The benchmark starts one persistent worker and communicates through a private Unix-domain socket.
The SP1 GPU server and guest proving keys therefore survive across warmups and measured samples.
Each selected guest ELF is setup once before timing; worker startup and guest setup wall times are
written to `loading.csv` and to the report's preparation table. A measured prover sample contains
the proof request/response wall time, but not reusable CUDA startup or ELF setup.

Proof generation and verification remain separate API phases. A returned proof is not accepted as
a protocol result until the explicit verifier checks it against the locally persisted trusted VK.

## Diagnostics

```bash
nvidia-smi -L
uname -m
SP1_PROVER=cuda POA_SP1_PROOF_MODE=compressed ./poa doctor
```

During a proof, use a second terminal:

```bash
watch -n 1 nvidia-smi
```

Guest execution and some orchestration still run on CPU. GPU utilization therefore does not need
to remain at 100% for the entire prover wall time.
