use ark_bls12_381::Fr;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReserveEntry {
    pub address: String,
    pub balance: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delta {
    pub address: String,
    pub delta: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealSrsMeta {
    pub max_degree: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredState {
    pub state_root: String,
    pub srs_max_degree: usize,
    pub alpha: Fr,
    pub reserve_addresses: Vec<String>,
    pub reserve_balances: Vec<i128>,
    pub masked_polynomial_coeffs: Vec<Fr>,
    pub accumulator_hex: String,
    pub balance_total: i128,
    pub balance_blind: Fr,
    pub balance_commitment_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredProof {
    pub old_state_root: String,
    pub new_state_root: String,
    pub c_u_hex: String,
    pub c_y_hex: String,
    pub c_d_hex: String,
    pub eval_proof_hex: String,
    pub d_value: i128,
    pub r_u: Fr,
    pub rho_y: Fr,
    pub r_d: Fr,
    pub y_values: Vec<Fr>,
    pub u_values: Vec<u8>,
    pub z_values: Vec<Fr>,
    pub w_values: Vec<Fr>,
    pub gate_count: usize,
    pub transcript_hex: String,
    pub bp_proof_hex: String,
    pub bp_commitments_hex: String,
    pub link_proof_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmtLeafRecord {
    pub address: String,
    pub balance: i128,
    pub salt_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredSmtState {
    pub state_root: String,
    pub smt_root_hex: String,
    pub depth: usize,
    pub balance_total: i128,
    pub balance_blind: Fr,
    pub balance_commitment_hex: String,
    pub leaves: Vec<SmtLeafRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredSmtProof {
    pub scheme: String,
    pub mode: String,
    pub old_state_root: String,
    pub new_state_root: String,
    pub old_smt_root_hex: String,
    pub new_smt_root_hex: String,
    pub aggregate_delta: i128,
    pub balance_blind_delta: Fr,
    pub old_balance_commitment_hex: String,
    pub new_balance_commitment_hex: String,
    pub proof_digest_hex: String,
    pub witness_hex: String,
    pub touched_addresses: Vec<String>,
    pub membership_flags: Vec<u8>,
    pub sp1_proof_hex: String,
    pub sp1_vk_hex: String,
    pub sp1_public_values_hex: String,
}
