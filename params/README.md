# Cryptographic parameters

- `srs/`: KZG structured reference strings.
- `crs/`: transparent hash-to-curve Pedersen CRS derivation manifest.
- `sp1/`: cached SP1 verifying-key setup artifacts.

These categories are deliberately separate: the transparent Pedersen CRS is not
the trusted KZG SRS. Locally generated SRS files are ignored by Git; production
SRS imports carry a provenance sidecar. The SP1 setup files remain versioned for
compatibility with the repository layout.
