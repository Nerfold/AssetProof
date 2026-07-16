# Pedersen CRS

Pedersen commitments and Sigma-protocol ZKOpen use independently
domain-separated G1 bases. They are logically a CRS distinct from the KZG SRS.

The implementation uses a transparent CRS: every base is independently derived
with the BLS12-381 G1 `XMD:SHA-256_SSWU_RO` hash-to-curve suite, DST
`DPOA_PEDERSEN_CRS_BLS12381G1_XMD:SHA-256_SSWU_RO_V1`, and message
`label || 0x00 || decimal(index)`. No toxic waste or binary CRS file is needed,
and the previous known-discrete-log `hash_to_scalar * G` derivation is no longer
used. `domains.json` is the public, versioned derivation manifest.
