use ark_bls12_381::Fr;
use ark_ff::{Field, One, Zero};

use common::encoding::encode_address;
use common::types::Delta;

use crate::polynomial::{fast_multi_evaluate, Polynomial};

#[derive(Clone, Debug)]
pub struct UpdateWitness {
    pub x_values: Vec<Fr>,
    pub y_values: Vec<Fr>,
    pub u_values: Vec<Fr>,
    pub z_values: Vec<Fr>,
    pub w_values: Vec<Fr>,
    pub d_value: i128,
}

pub fn build_update_witness(polynomial: &Polynomial, deltas: &[Delta]) -> Result<UpdateWitness, String> {
    let mut x_values = Vec::with_capacity(deltas.len());
    let mut u_values = Vec::with_capacity(deltas.len());
    let mut z_values = Vec::with_capacity(deltas.len());
    let mut w_values = Vec::with_capacity(deltas.len());
    let mut d_value = 0i128;

    for delta in deltas {
        x_values.push(encode_address(&delta.address)?);
    }

    let y_values = fast_multi_evaluate(polynomial, &x_values)?;

    for (delta, y) in deltas.iter().zip(y_values.iter()) {
        if y.is_zero() {
            u_values.push(Fr::one());
            z_values.push(Fr::zero());
            w_values.push(Fr::zero());
            d_value += delta.delta;
        } else {
            let z = y
                .inverse()
                .ok_or_else(|| "non-zero y unexpectedly lacked inverse".to_string())?;
            u_values.push(Fr::zero());
            z_values.push(z);
            w_values.push(*y * z);
        }
    }

    Ok(UpdateWitness {
        x_values,
        y_values,
        u_values,
        z_values,
        w_values,
        d_value,
    })
}
