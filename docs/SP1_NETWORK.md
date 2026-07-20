# SP1 Network integration boundary

The protocol currently generates SP1 proofs in-process with the CPU backend. Proof generation is
routed through `crates/sp1-host/src/prover_backend.rs`, while setup and verification continue to
use locally trusted verification keys.

## Why the Network client must be isolated

With the versions pinned by this repository, enabling `sp1-sdk/network` pulls
`alloy-signer-aws -> c-kzg -> blst >= 0.3.14`. The update/range-proof implementation uses
`bulletproofs-bls -> blstrs_plus -> blst = 0.3.12`. Both native libraries export the same Cargo
`links = "blst"` target, so Cargo cannot place them in one executable dependency graph.

Do not solve this by changing the Bulletproof native dependency without a full cryptographic
regression audit. The intended design is an isolated `sp1-network-worker` process with its own
Cargo workspace and lockfile.

## Worker contract

The future worker should:

1. accept a guest identifier (`init-merkle`, `init-ownership`, or `kzg-insert`), proof mode,
   serialized `SP1Stdin`, and the matching ELF/program identifier;
2. construct `ProverClient::builder().network()` using `NETWORK_PRIVATE_KEY` from the environment;
3. submit every request with `private_stdin(true)` because stdin contains reserve addresses,
   balances, ownership witnesses and native state proofs;
4. return a serialized `SP1ProofWithPublicValues` and request metadata;
5. let the main process verify the returned proof against the locally trusted VK before accepting
   it into a protocol proof.

Secrets must never be placed in repository files or command-line arguments. The worker should use
0600 temporary files or an authenticated local socket, erase request payloads after completion,
and persist only the network request ID plus the returned proof.

The three protocol guests are already separated and stable at:

- `crates/sp1-programs/init-merkle/`
- `crates/sp1-programs/init-ownership/`
- `crates/sp1-programs/kzg-insert/`

The `smt-*` guests belong to a separate experimental accumulator and are not required by the KZG
Dynamic PoA protocol.
