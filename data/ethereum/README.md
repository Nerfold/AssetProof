# Ethereum input data

Store real-chain inputs here. `transition.example.json` documents the input
accepted by `poa-cli eth-sync`; copy it to `transition.json` and replace every
field with data from the finalized execution transition.

The synchronizer needs an exhaustive post-execution state diff, not only an
`eth_getBlockByHash` response. When using Geth `prestateTracer` diff mode, the
producer must also account for protocol-level balance effects such as withdrawals
and fee-recipient changes.

Do not commit private RPC credentials or sensitive operational snapshots.
