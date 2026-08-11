use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use sp1_sdk::blocking::{CpuProver, MockProver, Prover as BlockingProver};
use sp1_sdk::{
    Elf, ProvingKey, SP1ProofWithPublicValues, SP1ProvingKey, SP1PublicValues, SP1Stdin,
};

use crate::proof_mode::configured_proof_mode;
use crate::prover_backend::{shared_cpu_prover, ProofGenerator};

/// One independent SP1 program using the same CPU, CUDA, or Network backend
/// selection as the protocol benchmarks.
pub struct StandaloneProgram {
    executor: MockProver,
    proof: Option<(CpuProver, ProofGenerator, SP1ProvingKey)>,
    elf: Elf,
    guest: String,
}

#[derive(Clone, Copy, Debug)]
pub struct StandalonePreparation {
    pub executor_prepare: Duration,
    pub cpu_setup: Duration,
    pub backend_prepare: Duration,
}

#[derive(Debug)]
pub struct StandaloneExecution {
    pub elapsed: Duration,
    pub cycles: u64,
    pub syscalls: u64,
    pub phase_cycles: BTreeMap<String, u64>,
    pub public_values: SP1PublicValues,
}

impl StandaloneProgram {
    /// Performs CPU VK/PK setup and optional CUDA guest upload. Both durations
    /// are intended to stay outside benchmark sample timers.
    pub fn prepare(
        elf: Elf,
        guest: impl Into<String>,
        prepare_proof_backend: bool,
    ) -> Result<(Self, StandalonePreparation), String> {
        let guest = guest.into();
        // Execution only needs SP1's light node. Constructing the complete CPU
        // prover loads the proving machine and is intentionally deferred until
        // real proof generation is requested.
        let executor_started = Instant::now();
        let executor = MockProver::new();
        let executor_prepare = executor_started.elapsed();
        let (proof, cpu_setup, backend_prepare) = if prepare_proof_backend {
            let cpu = shared_cpu_prover();
            let setup_started = Instant::now();
            let pk = cpu
                .setup(elf.clone())
                .map_err(|err| format!("SP1 {guest} CPU setup failed: {err}"))?;
            let cpu_setup = setup_started.elapsed();
            let generator = ProofGenerator::from_env()?;
            let backend_prepare = generator.prepare(&pk, &guest)?;
            (Some((cpu, generator, pk)), cpu_setup, backend_prepare)
        } else {
            (None, Duration::ZERO, Duration::ZERO)
        };
        Ok((
            Self {
                executor,
                proof,
                elf,
                guest,
            },
            StandalonePreparation {
                executor_prepare,
                cpu_setup,
                backend_prepare,
            },
        ))
    }

    /// Executes the guest in the reference executor to expose exact RISC-V
    /// instruction and syscall counts independently of proof generation.
    pub fn execute(&self, stdin: SP1Stdin) -> Result<StandaloneExecution, String> {
        let started = Instant::now();
        let (public_values, report) = self
            .executor
            .execute(self.elf.clone(), stdin)
            .run()
            .map_err(|err| format!("SP1 {} execute failed: {err}", self.guest))?;
        Ok(StandaloneExecution {
            elapsed: started.elapsed(),
            cycles: report.total_instruction_count(),
            syscalls: report.total_syscall_count(),
            phase_cycles: report
                .cycle_tracker
                .iter()
                .map(|(name, cycles)| (name.clone(), *cycles))
                .collect(),
            public_values,
        })
    }

    pub fn prove(&self, stdin: SP1Stdin) -> Result<SP1ProofWithPublicValues, String> {
        let (cpu, generator, pk) = self
            .proof
            .as_ref()
            .ok_or_else(|| format!("SP1 {} proof backend was not prepared", self.guest))?;
        generator.prove(cpu, pk, stdin, configured_proof_mode()?, &self.guest)
    }

    pub fn verify(&self, proof: &SP1ProofWithPublicValues) -> Result<(), String> {
        let (cpu, _, pk) = self
            .proof
            .as_ref()
            .ok_or_else(|| format!("SP1 {} proof backend was not prepared", self.guest))?;
        cpu.verify(proof, pk.verifying_key(), None)
            .map_err(|err| format!("SP1 {} verification failed: {err}", self.guest))
    }
}
