use std::{hint::black_box, time::{Duration, Instant}};

use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{PrimeGroup, ScalarMul, VariableBaseMSM};
use ark_ff::{UniformRand, Zero};
use rand::{rngs::StdRng, SeedableRng};

const DEFAULT_DEGREES: &[usize] = &[10_000, 100_000, 1_000_000];

fn main() {
    let degrees = parse_degrees();
    let max_degree = *degrees.iter().max().expect("at least one degree");

    println!("KZG prover benchmark (BLS12-381, arkworks 0.5)");
    println!("degrees: {degrees:?}");
    println!("Rayon threads: {}", rayon::current_num_threads());
    println!("Timing excludes SRS setup and polynomial generation.\n");

    let setup_started = Instant::now();
    let srs = setup_g1_powers(max_degree, Fr::from(7_u64));
    println!("SRS setup: {:.3} s (excluded)\n", setup_started.elapsed().as_secs_f64());

    println!("{:<12} {:>12} {:>12} {:>12} {:>15}",
        "degree", "commit(ms)", "eval(ms)", "open(ms)", "prover total(ms)");

    for (case, degree) in degrees.into_iter().enumerate() {
        let mut rng = StdRng::seed_from_u64(0x4b5a_4700_u64 + case as u64);
        let mut coeffs = (0..=degree).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        if coeffs[degree].is_zero() {
            coeffs[degree] = Fr::from(1_u64);
        }
        let point = Fr::rand(&mut rng);

        // Prover = polynomial commitment + evaluation + KZG opening proof.
        let total_started = Instant::now();

        let started = Instant::now();
        let commitment = msm(&srs[..=degree], &coeffs);
        let commit_time = started.elapsed();

        let started = Instant::now();
        let value = evaluate(&coeffs, point);
        let eval_time = started.elapsed();

        let started = Instant::now();
        let quotient = divide_by_linear(&coeffs, point, value);
        let proof = msm(&srs[..degree], &quotient);
        let open_time = started.elapsed();

        let total_time = total_started.elapsed();
        let _ = black_box((commitment, proof, value));

        println!("{:<12} {:>12.3} {:>12.3} {:>12.3} {:>15.3}", degree,
            ms(commit_time), ms(eval_time), ms(open_time), ms(total_time));
    }
}

fn parse_degrees() -> Vec<usize> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        return DEFAULT_DEGREES.to_vec();
    }
    args.into_iter().map(|arg| {
        let degree = arg.replace('_', "").parse::<usize>()
            .unwrap_or_else(|_| panic!("invalid degree: {arg}"));
        assert!(degree > 0, "degree must be positive");
        degree
    }).collect()
}

fn setup_g1_powers(max_degree: usize, tau: Fr) -> Vec<G1Affine> {
    let mut current = Fr::from(1_u64);
    let mut scalars = Vec::with_capacity(max_degree + 1);
    for _ in 0..=max_degree {
        scalars.push(current);
        current *= tau;
    }
    G1Projective::generator().batch_mul(&scalars)
}

fn msm(bases: &[G1Affine], scalars: &[Fr]) -> G1Projective {
    assert_eq!(bases.len(), scalars.len());
    G1Projective::msm_unchecked(bases, scalars)
}

fn evaluate(coeffs: &[Fr], point: Fr) -> Fr {
    coeffs.iter().rev().fold(Fr::zero(), |acc, coeff| acc * point + coeff)
}

// Synthetic division: (p(X) - p(z)) / (X - z), in ascending coefficient order.
fn divide_by_linear(coeffs: &[Fr], point: Fr, value: Fr) -> Vec<Fr> {
    assert!(coeffs.len() >= 2);
    let degree = coeffs.len() - 1;
    let mut quotient = vec![Fr::zero(); degree];
    quotient[degree - 1] = coeffs[degree];
    for i in (1..degree).rev() {
        quotient[i - 1] = coeffs[i] + point * quotient[i];
    }
    debug_assert_eq!(coeffs[0] + point * quotient[0], value);
    quotient
}

fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_division_reconstructs_polynomial() {
        let coeffs = [Fr::from(3_u64), Fr::from(5_u64), Fr::from(7_u64), Fr::from(11_u64)];
        let point = Fr::from(13_u64);
        let value = evaluate(&coeffs, point);
        let quotient = divide_by_linear(&coeffs, point, value);
        assert_eq!(quotient.len(), coeffs.len() - 1);
        assert_eq!(evaluate(&quotient, Fr::from(17_u64)) * (Fr::from(17_u64) - point) + value,
            evaluate(&coeffs, Fr::from(17_u64)));
    }
}
