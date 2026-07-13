# Mock input data

This directory contains synthetic inputs only.

- `reserves.csv` and `deltas.csv`: three-row hand-written NIZK smoke fixtures.
- `smt/`: two-row Sparse Merkle Tree smoke fixtures.
- `bench/`: large fixed fixtures (`10,000` reserves and `1,000` deltas).
- `generated/basic/`: the migrated default generated scenario.
- `generated/latest/`: replaced whenever `./poa mock-data` runs.

`basic/` and `latest/` may contain identical data; `basic/` is a preserved
sample, while only `latest/` is the active generator output.

The CSV formats are headerless:
Both formats are headerless:

```text
0x<40-hex-address>,<unsigned-balance>
0x<40-hex-address>,<signed-delta>
```

Generate a deterministic account-transfer scenario with:

```text
./poa mock-data [accounts reserves blocks txs-per-block seed]
```

The defaults are `64 8 6 20 42`. `accounts` controls the whole mock ledger;
`reserves` selects the committed subset and must be in `1..=accounts`; `blocks`
controls the number of update windows; `txs-per-block` controls attempted
transfers per window; and `seed` makes the output reproducible. Transfers that
touch the same address are merged, so a window CSV has at most twice as many
rows as transactions and usually fewer.

Addresses are random 20-byte values, balances start in `[5,000, 50,000)`, and
each transfer moves at most `1,000` units. Roots are BLAKE3 hashes of the mock
account/balance vector; they are not Ethereum MPT roots and the data contains no
Ethereum signatures, receipts, storage, or account proofs.

Generated and benchmark payloads are ignored by Git.
