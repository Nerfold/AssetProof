use ark_bls12_381::Fr;
use ark_ff::{Field, One, Zero};

use common::encoding::encode_address;
use common::types::Delta;

use crate::polynomial::{Polynomial, QueryContext};

#[derive(Clone, Debug)]
pub struct UpdateWitness {
    pub x_values: Vec<Fr>,
    pub y_values: Vec<Fr>,
    pub u_values: Vec<Fr>,
    pub z_values: Vec<Fr>,
    pub d_value: i128,
}

pub fn build_update_witness(
    polynomial: &Polynomial,
    deltas: &[Delta],
) -> Result<UpdateWitness, String> {
    let x_values = encode_delta_points(deltas)?;
    let query_ctx = QueryContext::new(&x_values)?;
    let y_values = query_ctx.evaluate(polynomial)?;
    build_update_witness_from_evaluations(x_values, y_values, deltas)
}

pub fn encode_delta_points(deltas: &[Delta]) -> Result<Vec<Fr>, String> {
    deltas
        .iter()
        .map(|delta| encode_address(&delta.address))
        .collect()
}

pub fn build_update_witness_from_evaluations(
    x_values: Vec<Fr>,
    y_values: Vec<Fr>,
    deltas: &[Delta],
) -> Result<UpdateWitness, String> {
    if x_values.len() != deltas.len() || y_values.len() != deltas.len() {
        return Err("update evaluation vector length mismatch".to_string());
    }
    let mut u_values = Vec::with_capacity(deltas.len());
    let mut z_values = Vec::with_capacity(deltas.len());
    let mut d_value = 0i128;

    for (delta, y) in deltas.iter().zip(y_values.iter()) {
        if y.is_zero() {
            u_values.push(Fr::one());
            z_values.push(Fr::zero());
            d_value = d_value
                .checked_add(delta.delta)
                .ok_or_else(|| "aggregate reserve delta overflowed i128".to_string())?;
        } else {
            let z = y
                .inverse()
                .ok_or_else(|| "non-zero y unexpectedly lacked inverse".to_string())?;
            u_values.push(Fr::zero());
            z_values.push(z);
        }
    }

    Ok(UpdateWitness {
        x_values,
        y_values,
        u_values,
        z_values,
        d_value,
    })
}
