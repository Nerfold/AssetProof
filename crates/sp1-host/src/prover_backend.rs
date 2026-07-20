use sp1_sdk::blocking::{CpuProver, ProveRequest, Prover as BlockingProver};
use sp1_sdk::{SP1ProofWithPublicValues, SP1ProvingKey, SP1Stdin};

use crate::proof_mode::ConfiguredProofMode;

/// Boundary between protocol orchestration and proof generation.
///
/// The in-process backend intentionally remains CPU-only. SP1 6.2's network
/// feature links a newer native `blst` than the Bulletproof dependency used by
/// the protocol. The network adapter therefore belongs in an isolated worker
/// process with its own Cargo dependency graph.
#[derive(Clone)]
pub(crate) enum ProofGenerator {
    Cpu,
}

impl ProofGenerator {
    pub(crate) fn from_env() -> Result<Self, String> {
        match std::env::var("SP1_PROVER")
            .unwrap_or_else(|_| "cpu".to_string())
            .to_ascii_lowercase()
            .as_str()
        {
            "cpu" | "local" => Ok(Self::Cpu),
            "network" => Err(
                "SP1 Network must run through an isolated network worker; see docs/SP1_NETWORK.md"
                    .to_string(),
            ),
            value => Err(format!("unsupported SP1_PROVER {value}; expected cpu")),
        }
    }

    pub(crate) fn prove(
        &self,
        cpu: &CpuProver,
        pk: &SP1ProvingKey,
        stdin: SP1Stdin,
        mode: ConfiguredProofMode,
        guest: &str,
    ) -> Result<SP1ProofWithPublicValues, String> {
        match self {
            Self::Cpu => run_cpu(cpu, pk, stdin, mode, guest),
        }
    }
}

fn run_cpu(
    prover: &CpuProver,
    pk: &SP1ProvingKey,
    stdin: SP1Stdin,
    mode: ConfiguredProofMode,
    guest: &str,
) -> Result<SP1ProofWithPublicValues, String> {
    let request = prover.prove(pk, stdin);
    let result = match mode {
        ConfiguredProofMode::Groth16 => request.groth16().run(),
        ConfiguredProofMode::Plonk => request.plonk().run(),
        ConfiguredProofMode::Compressed => request.compressed().run(),
    };
    result.map_err(|err| format!("SP1 {guest} CPU prove failed: {err}"))
}
