use ark_bls12_381::Fr;
use std::collections::HashSet;

use common::crypto::{point_g1_from_hex, scalar_to_hex};
use common::encoding::encode_address;
use common::types::{Delta, StoredInitProof, StoredProof, StoredState};

use crate::bp::verify_logic;
use crate::init_proof::verify_init_proof;
use crate::kzg::{commit_g2, verify_batch, Srs};
use crate::polynomial::product_from_roots;

pub fn verify_init(
    srs: &Srs,
    state: &StoredState,
    proof: &StoredInitProof,
) -> Result<(), String> {
    verify_init_proof(srs, state, proof)
}

pub fn verify_update(
    srs: &Srs,
    old_state: &StoredState,
    deltas: &[Delta],
    new_state: &StoredState,
    proof: &StoredProof,
) -> Result<(), String> {
    if proof.old_state_root != old_state.state_root {
        return Err("proof old_state_root does not match input state".to_string());
    }
    if proof.new_state_root != new_state.state_root {
        return Err("proof new_state_root does not match claimed new state".to_string());
    }
    if old_state.accumulator_hex != new_state.accumulator_hex {
        return Err("fixed-set accumulator changed across update".to_string());
    }

    let old_balance_commitment = point_g1_from_hex(&old_state.balance_commitment_hex)?;
    let new_balance_commitment = point_g1_from_hex(&new_state.balance_commitment_hex)?;
    let c_d = point_g1_from_hex(&proof.c_d_hex)?;
    if new_balance_commitment != old_balance_commitment + c_d {
        return Err("claimed balance commitment does not match homomorphic update".to_string());
    }

    if proof.gate_count != deltas.len() * 4 {
        return Err("gate count does not match 4m relation size".to_string());
    }

    let x_values: Vec<_> = deltas
        .iter()
        .map(|delta| encode_address(&delta.address))
        .collect::<Result<_, _>>()?;
    ensure_distinct(&x_values)?;

    let z_poly = product_from_roots(&x_values);
    let z_commit_g2 = commit_g2(srs, &z_poly)?;
    let accumulator = point_g1_from_hex(&old_state.accumulator_hex)?;
    let c_y = point_g1_from_hex(&proof.c_y_hex)?;
    let eval_proof = point_g1_from_hex(&proof.eval_proof_hex)?;
    if !verify_batch(&accumulator, &c_y, &eval_proof, &z_commit_g2) {
        return Err("KZG batch equation failed".to_string());
    }

    verify_logic(
        srs,
        deltas,
        &x_values,
        &proof.c_u_hex,
        &proof.c_y_hex,
        &proof.c_d_hex,
        &proof.bp_proof_hex,
        &proof.bp_commitments_hex,
        &proof.link_proof_hex,
    )?;

    if old_state.balance_total + proof.d_value != new_state.balance_total {
        return Err("balance_total mismatch".to_string());
    }
    if old_state.balance_blind + proof.r_d != new_state.balance_blind {
        return Err("balance_blind mismatch".to_string());
    }

    Ok(())
}

fn ensure_distinct(points: &[Fr]) -> Result<(), String> {
    let mut seen = HashSet::with_capacity(points.len());
    for point in points {
        if !seen.insert(scalar_to_hex(point).map_err(|err| format!("distinct check encode: {err}"))?) {
            return Err("duplicate encoded query point".to_string());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use common::types::{Delta, ReserveEntry};

    use super::{verify_init, verify_update};
    use crate::init::initialize;
    use crate::init_proof::initialize_with_proof;
    use crate::kzg::Srs;
    use crate::update::apply_update;

    #[test]
    fn accepts_honest_init() {
        let srs = Srs::setup(16, b"test-srs-init");
        let entries = vec![
            ReserveEntry {
                address: "0x1111111111111111111111111111111111111111".to_string(),
                balance: 100,
            },
            ReserveEntry {
                address: "0x2222222222222222222222222222222222222222".to_string(),
                balance: 250,
            },
        ];
        let init = initialize_with_proof(&entries, "root-0", &srs).unwrap();
        verify_init(&srs, &init.state, &init.proof).unwrap();
    }

    #[test]
    fn rejects_tampered_init_digest() {
        let srs = Srs::setup(16, b"test-srs-init-bad");
        let entries = vec![ReserveEntry {
            address: "0x1111111111111111111111111111111111111111".to_string(),
            balance: 100,
        }];
        let mut init = initialize_with_proof(&entries, "root-0", &srs).unwrap();
        init.proof.init_digest_hex.push('0');
        let err = verify_init(&srs, &init.state, &init.proof).expect_err("proof should fail");
        assert!(!err.is_empty());
    }

    #[test]
    fn accepts_honest_update() {
        let srs = Srs::setup(16, b"test-srs");
        let entries = vec![
            ReserveEntry {
                address: "0x1111111111111111111111111111111111111111".to_string(),
                balance: 100,
            },
            ReserveEntry {
                address: "0x2222222222222222222222222222222222222222".to_string(),
                balance: 250,
            },
        ];
        let init = initialize(&entries, "root-0", &srs).unwrap();
        let deltas = vec![
            Delta {
                address: "0x1111111111111111111111111111111111111111".to_string(),
                delta: -10,
            },
            Delta {
                address: "0x3333333333333333333333333333333333333333".to_string(),
                delta: 40,
            },
        ];
        let updated = apply_update(&srs, &init.state, &deltas, "root-1").unwrap();
        verify_update(&srs, &init.state, &deltas, &updated.next_state, &updated.proof).unwrap();
        assert_eq!(updated.next_state.balance_total, 340);
    }

    #[test]
    fn rejects_modified_evaluation() {
        let srs = Srs::setup(8, b"test-srs-small");
        let entries = vec![ReserveEntry {
            address: "0x1111111111111111111111111111111111111111".to_string(),
            balance: 100,
        }];
        let init = initialize(&entries, "root-0", &srs).unwrap();
        let deltas = vec![Delta {
            address: "0x1111111111111111111111111111111111111111".to_string(),
            delta: 7,
        }];
        let mut updated = apply_update(&srs, &init.state, &deltas, "root-1").unwrap();
        updated.proof.c_y_hex.push('0');
        let err = verify_update(&srs, &init.state, &deltas, &updated.next_state, &updated.proof)
            .expect_err("proof should fail");
        assert!(!err.is_empty());
    }
}
