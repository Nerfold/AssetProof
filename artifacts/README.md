# Runtime artifacts

All generated output belongs here:

- `states/`: private prover states and public companion states;
- `proofs/`: initialization, update, SMT and SP1 proofs;
- `deltas/`: canonicalized protocol delta vectors;
- `test-runs/`: synchronizer metadata and test output;
- `reports/` and `benchmarks/`: measurements and reports;
- `legacy/`: output migrated from the previous layout.

Everything except this file is ignored by Git. Treat private prover states as
sensitive; they contain reserve balances and blinding material.
