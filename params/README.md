# Cryptographic parameters

- `srs/`: KZG structured reference strings.
- `crs/`: Pedersen/HPolyCom base derivation metadata.
- `sp1/`: cached SP1 verifying-key setup artifacts.

These categories are deliberately separate: the Pedersen CRS is not the KZG
SRS. Locally generated SRS files are ignored by Git. The SP1 setup files remain
versioned for compatibility with the previous repository layout.
