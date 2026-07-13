# KZG SRS

`poa-cli setup` creates `dev.srs.bin` here. It contains the G1/G2 powers needed
by KZG plus the hiding G1 powers used by HPolyCom/HZKOpen.

The built-in generator is deterministic development setup and must not be
treated as a production trusted ceremony. Production deployments should place
validated ceremony output here and record its digest and provenance externally.
Binary SRS files are ignored by Git.
