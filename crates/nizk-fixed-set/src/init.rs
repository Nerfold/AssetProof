use common::types::{ReserveEntry, StoredState};

use crate::init_proof::initialize_with_proof;
use crate::kzg::Srs;

#[derive(Clone, Debug)]
pub struct InitResult {
    pub state: StoredState,
}

pub fn initialize(
    reserve_entries: &[ReserveEntry],
    state_root: &str,
    srs: &Srs,
) -> Result<InitResult, String> {
    Ok(InitResult {
        state: initialize_with_proof(reserve_entries, state_root, srs)?.state,
    })
}
