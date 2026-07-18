#![cfg_attr(target_os = "zkvm", no_std)]

extern crate alloc;

pub mod bls12_381_scalar;
pub mod ethereum_binary_merkle;
pub mod ethereum_eoa;
pub mod ethereum_mpt;
pub mod io;
