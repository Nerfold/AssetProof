#[cfg(any(
    feature = "protocol-sp1",
    feature = "smt-sp1",
    feature = "static-baseline"
))]
mod profiling;
mod proof_mode;
mod prover_backend;
#[cfg(any(
    feature = "protocol-sp1",
    feature = "smt-sp1",
    feature = "static-baseline"
))]
mod witness;

pub mod standalone;

#[cfg(feature = "protocol-sp1")]
pub mod init;
#[cfg(feature = "smt-sp1")]
pub mod insert;
#[cfg(feature = "protocol-sp1")]
pub mod kzg_insert;
pub mod setup;
#[cfg(feature = "smt-sp1")]
pub mod smt_init;
#[cfg(feature = "static-baseline")]
pub mod static_init;
#[cfg(feature = "smt-sp1")]
pub mod update;
