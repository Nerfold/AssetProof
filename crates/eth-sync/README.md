# Ethereum synchronizer

This crate converts a finalized Ethereum execution state diff into the canonical
address and signed-balance-delta vectors required by the DPoA update protocol.

The input is an exhaustive block-level state diff produced after execution and
state commitment. A plain `eth_getBlockByHash` response is not sufficient.
Geth `prestateTracer` diff-mode account objects can be used for `stateDiff`, as
long as the producer also includes protocol-level effects such as withdrawals
and fee-recipient balance changes.

```json
{
  "chainId": "0x1",
  "finalized": true,
  "oldStateRoot": "0x1111111111111111111111111111111111111111111111111111111111111111",
  "block": {
    "hash": "0x2222222222222222222222222222222222222222222222222222222222222222",
    "parentHash": "0x3333333333333333333333333333333333333333333333333333333333333333",
    "stateRoot": "0x4444444444444444444444444444444444444444444444444444444444444444",
    "number": "0x10"
  },
  "stateDiff": {
    "pre": {
      "0x1111111111111111111111111111111111111111": { "balance": "0xa" }
    },
    "post": {
      "0x1111111111111111111111111111111111111111": { "balance": "0x7" },
      "0x2222222222222222222222222222222222222222": { "balance": "0x3" }
    }
  }
}
```

Run with the repository defaults:

```sh
cargo run -p poa-cli -- eth-sync data/ethereum/transition.json
```

This writes `artifacts/deltas/ethereum.csv` and
`artifacts/test-runs/ethereum-sync.json`. Explicit output paths remain supported.
The delta CSV can be passed directly to `prove-update`. The JSON output contains
`addresses`, `deltas`, block/root metadata, the same
canonical delta-list commitment used by the NIZK verifier, and a transition
commitment that binds the vectors to the finalized Ethereum transition.
