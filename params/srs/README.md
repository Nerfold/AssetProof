# KZG SRS

`poa-cli setup` creates `dev.srs.bin` here. It contains the G1/G2 powers needed
by KZG plus the hiding G1 powers used by HPolyCom/HZKOpen.

The built-in generator is deterministic development setup and must not be
treated as a production trusted ceremony. Its `.meta` sidecar is marked
`provenance=development`, and production verifiers reject it.

Import an externally generated ceremony SRS with:

```bash
./poa import-srs <source.srs.bin> <ceremony-id> [destination.srs.bin]
```

The importer uses checked subgroup deserialization, rejects identity/nonstandard
tau^0 points, and batch-validates ordinary G1, G2, and HPolyCom hiding power
sequences with pairing equations. It then writes an `external-ceremony` metadata
sidecar. The ceremony id is operator provenance; validation cannot by itself
prove that toxic waste was destroyed.

The source uses this repository's extended binary encoding: ordinary G1 powers,
ordinary G2 powers, then independent hiding-base G1 powers generated with the
same hidden tau. A plain powers-of-tau file without the hiding sequence supports
ordinary KZG but is insufficient for insert/HPolyCom.
Binary SRS files are ignored by Git.
