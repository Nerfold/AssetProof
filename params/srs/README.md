# KZG SRS

`poa-cli setup` creates `dev.srs.bin` here. It contains the ordinary G1/G2
powers needed by KZG. Insert quotient binding uses a salted hash checked inside
SP1, so setup does not generate a second million-element hiding-G1 sequence.

The built-in generator is deterministic development setup and must not be
treated as a production trusted ceremony. Its `.meta` sidecar is marked
`provenance=development`, and production verifiers reject it.

Import an externally generated ceremony SRS with:

```bash
./poa import-srs <source.srs.bin> <ceremony-id> [destination.srs.bin]
```

The importer uses checked subgroup deserialization, rejects identity/nonstandard
tau^0 points, and batch-validates ordinary G1 and G2 power sequences with
pairing equations. Legacy hiding powers are discarded during import. It then
writes an `external-ceremony` metadata sidecar. The ceremony id is operator
provenance; validation cannot by itself prove that toxic waste was destroyed.

Normal prover/verifier commands authenticate the fixed artifact against the
BLAKE3 digest in that sidecar and use checked point deserialization, but do not
repeat the ceremony power-sequence audit. In particular, proof verification
never scans the full SRS.

The binary reader accepts ordinary G1/G2 powers with no suffix and the former
extended encoding containing an additional hiding-G1 sequence. New files write
an explicit zero hiding-power length; legacy extended files remain readable.
Binary SRS files are ignored by Git.
