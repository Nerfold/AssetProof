# Pedersen CRS

Pedersen commitments and Sigma-protocol ZKOpen use independently
domain-separated G1 bases. They are logically a CRS distinct from the KZG SRS.

The current implementation derives those bases deterministically in code, so no
secret or binary CRS file is loaded at runtime. `domains.json` records the public
derivation labels used by this implementation. If base derivation is later
replaced by an audited hash-to-curve suite or ceremony output, its serialized
parameters and provenance should live in this directory.
