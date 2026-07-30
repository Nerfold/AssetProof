# SP1 Network worker

The main protocol process keeps Bulletproofs and its pinned native `blst` dependency. SP1's
Network feature pulls a different native `blst`, so Network proving runs in the isolated Cargo
workspace at `tools/sp1-network-worker/`.

Build it once:

```bash
./poa sp1-network-build
```

Set `NETWORK_PRIVATE_KEY` in the environment (never in a repository file or command argument),
then select the backend with `SP1_PROVER=network`. Both protocol initialization and SMT
initialization scripts inherit this setting.

The main process writes a versioned request into a fresh 0700 temporary directory using 0600
files. Each request contains the guest ELF and serialized `SP1Stdin`. The worker always calls
`private_stdin(true)`, writes the returned proof to a 0600 response file, and the main process
deletes the directory after reading it. During the explicit protocol verifier phase, the main
process verifies the proof against the locally persisted trusted VK; this verification is not
charged to the prover benchmark.

The worker skips the Network client's duplicate local simulation by default, since fixtures and
guest execution are already checked by the project workflow. Set
`POA_SP1_NETWORK_SKIP_SIMULATION=false` when diagnosing a failing remote request.

The worker and all of its SP1/slop transitive crates are pinned to 6.2.4 so its bincode proof
format cannot drift away from the main process. Override the executable only when necessary:

```bash
export POA_SP1_NETWORK_WORKER=/absolute/path/to/sp1-network-worker
```

Supported guests include `init-merkle`, `init-ownership`, `kzg-insert`, `smt-init`, `smt-update`,
and `smt-insert`. Network mode does not require the local gnark Docker image, including for
Groth16 and Plonk proof modes.

Initialization ownership remains one protocol statement and one final proof. It is deliberately
not split into project-level per-address proofs: doing that would either make proof size and
verification linear in the number of chunks or require another aggregation protocol. SP1 Network
already shards the guest execution across provers and recursively aggregates those shards while
preserving the existing public values, VK, and constant-size final proof.
