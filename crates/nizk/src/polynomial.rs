use ark_bls12_381::Fr;
use ark_ff::{batch_inversion, Field, Zero};
use ark_poly::domain::Radix2EvaluationDomain;
use ark_poly::univariate::{DenseOrSparsePolynomial, DensePolynomial};
use ark_poly::{DenseUVPolynomial, EvaluationDomain, Polynomial as ArkPolynomial};
use rayon::prelude::*;

const FFT_MUL_THRESHOLD: usize = 256;
const FAST_DIVIDEND_THRESHOLD: usize = 4096;
const FAST_DIVISOR_THRESHOLD: usize = 64;
const TREE_PARALLEL_THRESHOLD: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Polynomial {
    pub coeffs: Vec<Fr>,
}

#[derive(Clone)]
pub struct QueryContext {
    points: Vec<Fr>,
    z_poly: Polynomial,
    tree: SubproductTree,
    barycentric_weights: Vec<Fr>,
}

pub struct EvaluationWithQuotient {
    pub values: Vec<Fr>,
    pub remainder: Polynomial,
    pub quotient: Polynomial,
}

impl Polynomial {
    pub fn zero() -> Self {
        Self { coeffs: Vec::new() }
    }

    pub fn constant(value: Fr) -> Self {
        Self::from_dense(DensePolynomial::from_coefficients_vec(vec![value]))
    }

    pub fn from_coeffs(coeffs: Vec<Fr>) -> Self {
        Self::from_dense(DensePolynomial::from_coefficients_vec(coeffs))
    }

    pub fn degree(&self) -> usize {
        self.coeffs.len().saturating_sub(1)
    }

    pub fn evaluate(&self, x: Fr) -> Fr {
        self.coeffs
            .iter()
            .rev()
            .fold(Fr::zero(), |acc, coefficient| acc * x + coefficient)
    }

    pub fn add(&self, other: &Self) -> Self {
        let mut coeffs = vec![Fr::zero(); self.coeffs.len().max(other.coeffs.len())];
        for (slot, value) in coeffs.iter_mut().zip(self.coeffs.iter()) {
            *slot += value;
        }
        for (slot, value) in coeffs.iter_mut().zip(other.coeffs.iter()) {
            *slot += value;
        }
        Self::from_coeffs(coeffs)
    }

    /// Computes `self + scale * other` in one allocation.
    pub fn add_scaled(&self, other: &Self, scale: Fr) -> Self {
        let mut coeffs = self.coeffs.clone();
        coeffs.resize(self.coeffs.len().max(other.coeffs.len()), Fr::zero());
        for (slot, value) in coeffs.iter_mut().zip(other.coeffs.iter()) {
            *slot += *value * scale;
        }
        Self::from_coeffs(coeffs)
    }

    pub fn sub(&self, other: &Self) -> Self {
        let mut coeffs = vec![Fr::zero(); self.coeffs.len().max(other.coeffs.len())];
        for (slot, value) in coeffs.iter_mut().zip(self.coeffs.iter()) {
            *slot += value;
        }
        for (slot, value) in coeffs.iter_mut().zip(other.coeffs.iter()) {
            *slot -= value;
        }
        Self::from_coeffs(coeffs)
    }

    pub fn mul_scalar(&self, scalar: Fr) -> Self {
        Self::from_coeffs(self.coeffs.iter().map(|value| *value * scalar).collect())
    }

    /// Computes `scale * self * (X - root)` without constructing the linear
    /// polynomial or an intermediate product.
    pub fn mul_linear_scaled(&self, root: Fr, scale: Fr) -> Self {
        if self.coeffs.is_empty() || scale.is_zero() {
            return Self::zero();
        }
        let mut coeffs = vec![Fr::zero(); self.coeffs.len() + 1];
        for (index, value) in self.coeffs.iter().enumerate() {
            let scaled = *value * scale;
            coeffs[index] -= scaled * root;
            coeffs[index + 1] += scaled;
        }
        Self::from_coeffs(coeffs)
    }

    /// Synthetic division of `(self - value) / (X - point)`. The caller
    /// normally supplies `value = self(point)`; the remainder check protects
    /// against accidental misuse without allocating the subtracted polynomial.
    pub fn quotient_at(&self, point: Fr, value: Fr) -> Result<Self, String> {
        if self.coeffs.len() <= 1 {
            let remainder = self.coeffs.first().copied().unwrap_or_else(Fr::zero) - value;
            return if remainder.is_zero() {
                Ok(Self::zero())
            } else {
                Err("evaluation does not match polynomial at opening point".to_string())
            };
        }

        let mut quotient = vec![Fr::zero(); self.coeffs.len() - 1];
        let last = quotient.len() - 1;
        quotient[last] = *self.coeffs.last().expect("non-constant polynomial");
        for index in (1..=last).rev() {
            quotient[index - 1] = self.coeffs[index] + point * quotient[index];
        }
        let remainder = self.coeffs[0] - value + point * quotient[0];
        if !remainder.is_zero() {
            return Err("evaluation does not match polynomial at opening point".to_string());
        }
        Ok(Self::from_coeffs(quotient))
    }

    pub fn mul(&self, other: &Self) -> Self {
        Self::from_coeffs(fast_mul_coeffs(&self.coeffs, &other.coeffs))
    }

    pub fn sub_constant_assign(&mut self, value: Fr) {
        if self.coeffs.is_empty() {
            self.coeffs.push(-value);
        } else {
            self.coeffs[0] -= value;
        }
        while self.coeffs.len() > 1 && self.coeffs.last().is_some_and(Zero::is_zero) {
            self.coeffs.pop();
        }
    }

    pub fn div_exact(&self, divisor: &Self) -> Result<Self, String> {
        let dividend = self.as_dense();
        let divisor_dense = divisor.as_dense();
        let (quotient, remainder) = fast_divide_with_q_and_r(&dividend, &divisor_dense)?;
        if !remainder.is_zero() {
            return Err("polynomial division left a non-zero remainder".to_string());
        }
        Ok(Self::from_dense(quotient))
    }

    pub fn as_dense(&self) -> DensePolynomial<Fr> {
        DensePolynomial::from_coefficients_vec(self.coeffs.clone())
    }

    pub fn into_dense(self) -> DensePolynomial<Fr> {
        DensePolynomial::from_coefficients_vec(self.coeffs)
    }

    pub fn from_dense(poly: DensePolynomial<Fr>) -> Self {
        Self {
            coeffs: poly.coeffs,
        }
    }
}

impl QueryContext {
    pub fn new(points: &[Fr]) -> Result<Self, String> {
        if points.is_empty() {
            let unit = Polynomial::constant(Fr::from(1u64));
            return Ok(Self {
                points: Vec::new(),
                z_poly: unit.clone(),
                tree: SubproductTree {
                    poly: unit.as_dense(),
                    kind: TreeKind::Leaf,
                },
                barycentric_weights: Vec::new(),
            });
        }

        let tree = build_subproduct_tree(points);
        let z_poly = Polynomial::from_dense(tree.poly.clone());
        let z_derivative = derivative(&tree.poly);
        let mut barycentric_weights = evaluate_on_tree(&z_derivative, &tree)?;
        if barycentric_weights.iter().any(Zero::is_zero) {
            return Err("duplicate query points".to_string());
        }
        batch_inversion(&mut barycentric_weights);
        Ok(Self {
            points: points.to_vec(),
            z_poly,
            tree,
            barycentric_weights,
        })
    }

    pub fn points(&self) -> &[Fr] {
        &self.points
    }

    pub fn z_poly(&self) -> &Polynomial {
        &self.z_poly
    }

    pub fn evaluate(&self, poly: &Polynomial) -> Result<Vec<Fr>, String> {
        Ok(self.evaluate_with_quotient(poly)?.values)
    }

    pub fn evaluate_with_quotient(
        &self,
        poly: &Polynomial,
    ) -> Result<EvaluationWithQuotient, String> {
        if self.points.is_empty() {
            return Ok(EvaluationWithQuotient {
                values: Vec::new(),
                remainder: Polynomial::zero(),
                quotient: poly.clone(),
            });
        }
        let dense = poly.as_dense();
        self.evaluate_dense_with_quotient(dense)
    }

    pub fn evaluate_with_quotient_owned(
        &self,
        poly: Polynomial,
    ) -> Result<EvaluationWithQuotient, String> {
        if self.points.is_empty() {
            return Ok(EvaluationWithQuotient {
                values: Vec::new(),
                remainder: Polynomial::zero(),
                quotient: poly,
            });
        }
        self.evaluate_dense_with_quotient(poly.into_dense())
    }

    fn evaluate_dense_with_quotient(
        &self,
        dense: DensePolynomial<Fr>,
    ) -> Result<EvaluationWithQuotient, String> {
        let (quotient, remainder) = fast_divide_with_q_and_r(&dense, &self.tree.poly)?;
        let values = evaluate_on_tree(&remainder, &self.tree)?;
        Ok(EvaluationWithQuotient {
            values,
            remainder: Polynomial::from_dense(remainder),
            quotient: Polynomial::from_dense(quotient),
        })
    }

    pub fn interpolate(&self, values: &[Fr]) -> Result<Polynomial, String> {
        if values.len() != self.points.len() {
            return Err("points and values length mismatch".to_string());
        }
        if values.is_empty() {
            return Ok(Polynomial::zero());
        }
        let weighted = values
            .iter()
            .zip(self.barycentric_weights.iter())
            .map(|(value, weight)| *value * *weight)
            .collect::<Vec<_>>();
        Ok(Polynomial::from_dense(interpolate_on_tree(
            &weighted, &self.tree,
        )?))
    }

    pub fn lagrange_at(&self, point: Fr) -> Result<Vec<Fr>, String> {
        if self.points.is_empty() {
            return Ok(Vec::new());
        }
        let z_at_point = self.tree.poly.evaluate(&point);
        let mut inverse_differences = self.points.iter().map(|x| point - *x).collect::<Vec<_>>();
        if inverse_differences.iter().any(Zero::is_zero) {
            return Err("Lagrange evaluation point collides with query point".to_string());
        }
        batch_inversion(&mut inverse_differences);
        Ok(self
            .barycentric_weights
            .iter()
            .zip(inverse_differences.iter())
            .map(|(weight, inverse)| z_at_point * *weight * *inverse)
            .collect())
    }

    pub fn lagrange_basis(&self) -> Result<Vec<Polynomial>, String> {
        build_lagrange_basis_from_z(&self.points, &self.tree.poly)
    }
}

pub fn product_from_roots(roots: &[Fr]) -> Polynomial {
    if roots.is_empty() {
        return Polynomial::constant(Fr::from(1u64));
    }
    product_tree_poly(roots)
}

pub fn interpolate(points: &[Fr], values: &[Fr]) -> Result<Polynomial, String> {
    QueryContext::new(points)?.interpolate(values)
}

pub fn lagrange_basis(points: &[Fr]) -> Result<Vec<Polynomial>, String> {
    QueryContext::new(points)?.lagrange_basis()
}

pub fn fast_multi_evaluate(poly: &Polynomial, points: &[Fr]) -> Result<Vec<Fr>, String> {
    QueryContext::new(points)?.evaluate(poly)
}

fn fast_multi_evaluate_dense(poly: &DensePolynomial<Fr>, points: &[Fr]) -> Result<Vec<Fr>, String> {
    if points.is_empty() {
        return Ok(Vec::new());
    }
    let tree = build_subproduct_tree(points);
    evaluate_on_tree(poly, &tree)
}

fn derivative(poly: &DensePolynomial<Fr>) -> DensePolynomial<Fr> {
    if poly.degree() == 0 {
        return DensePolynomial::from_coefficients_vec(vec![Fr::zero()]);
    }
    let coeffs = poly
        .coeffs
        .iter()
        .enumerate()
        .skip(1)
        .map(|(index, coeff)| *coeff * Fr::from(index as u64))
        .collect();
    DensePolynomial::from_coefficients_vec(coeffs)
}

fn build_lagrange_basis_from_z(
    points: &[Fr],
    z_poly: &DensePolynomial<Fr>,
) -> Result<Vec<Polynomial>, String> {
    if points.is_empty() {
        return Ok(Vec::new());
    }

    let z_derivative = derivative(z_poly);
    let denominators = fast_multi_evaluate_dense(&z_derivative, points)?;
    let mut basis = Vec::with_capacity(points.len());

    for (point, denom) in points.iter().zip(denominators.iter()) {
        if denom.is_zero() {
            return Err("duplicate query points".to_string());
        }
        let divisor = DensePolynomial::from_coefficients_vec(vec![-*point, Fr::from(1u64)]);
        let basis_poly = z_poly / &divisor;
        let scale = denom
            .inverse()
            .ok_or_else(|| "non-invertible lagrange denominator".to_string())?;
        basis.push(Polynomial::from_dense(&basis_poly * scale));
    }

    Ok(basis)
}

#[derive(Clone)]
struct SubproductTree {
    poly: DensePolynomial<Fr>,
    kind: TreeKind,
}

#[derive(Clone)]
enum TreeKind {
    Leaf,
    Node(Box<SubproductTree>, Box<SubproductTree>),
}

fn build_subproduct_tree(points: &[Fr]) -> SubproductTree {
    if points.is_empty() {
        return SubproductTree {
            poly: DensePolynomial::from_coefficients_vec(vec![Fr::from(1u64)]),
            kind: TreeKind::Leaf,
        };
    }
    if points.len() == 1 {
        return SubproductTree {
            poly: DensePolynomial::from_coefficients_vec(vec![-points[0], Fr::from(1u64)]),
            kind: TreeKind::Leaf,
        };
    }

    let mid = points.len() / 2;
    let (left, right) = if points.len() >= TREE_PARALLEL_THRESHOLD {
        rayon::join(
            || build_subproduct_tree(&points[..mid]),
            || build_subproduct_tree(&points[mid..]),
        )
    } else {
        (
            build_subproduct_tree(&points[..mid]),
            build_subproduct_tree(&points[mid..]),
        )
    };
    let poly = fast_mul_dense(&left.poly, &right.poly);
    SubproductTree {
        poly,
        kind: TreeKind::Node(Box::new(left), Box::new(right)),
    }
}

fn evaluate_on_tree(poly: &DensePolynomial<Fr>, tree: &SubproductTree) -> Result<Vec<Fr>, String> {
    match &tree.kind {
        TreeKind::Leaf => {
            let point = -tree.poly.coeffs[0];
            Ok(vec![poly.evaluate(&point)])
        }
        TreeKind::Node(left, right) => {
            let evaluate_left = || -> Result<Vec<Fr>, String> {
                let remainder = fast_remainder(poly, &left.poly)?;
                evaluate_on_tree(&remainder, left)
            };
            let evaluate_right = || -> Result<Vec<Fr>, String> {
                let remainder = fast_remainder(poly, &right.poly)?;
                evaluate_on_tree(&remainder, right)
            };
            let (left_values, right_values) = if tree.poly.degree() >= TREE_PARALLEL_THRESHOLD {
                rayon::join(evaluate_left, evaluate_right)
            } else {
                (evaluate_left(), evaluate_right())
            };
            let mut values = left_values?;
            values.extend(right_values?);
            Ok(values)
        }
    }
}

fn product_tree_poly(roots: &[Fr]) -> Polynomial {
    if roots.len() == 1 {
        return Polynomial::from_coeffs(vec![-roots[0], Fr::from(1u64)]);
    }
    let mid = roots.len() / 2;
    let (left, right) = if roots.len() >= TREE_PARALLEL_THRESHOLD {
        rayon::join(
            || product_tree_poly(&roots[..mid]),
            || product_tree_poly(&roots[mid..]),
        )
    } else {
        (
            product_tree_poly(&roots[..mid]),
            product_tree_poly(&roots[mid..]),
        )
    };
    // Multiply coefficient slices directly. The previous dense conversion
    // cloned both child polynomials at every internal product-tree node.
    left.mul(&right)
}

fn interpolate_on_tree(
    weighted_values: &[Fr],
    tree: &SubproductTree,
) -> Result<DensePolynomial<Fr>, String> {
    match &tree.kind {
        TreeKind::Leaf => {
            if weighted_values.len() != 1 {
                return Err("interpolation leaf shape mismatch".to_string());
            }
            Ok(DensePolynomial::from_coefficients_vec(vec![
                weighted_values[0],
            ]))
        }
        TreeKind::Node(left, right) => {
            let left_len = left.poly.degree();
            if left_len == 0 || left_len >= weighted_values.len() {
                return Err("interpolation tree shape mismatch".to_string());
            }
            let interpolate_left = || interpolate_on_tree(&weighted_values[..left_len], left);
            let interpolate_right = || interpolate_on_tree(&weighted_values[left_len..], right);
            let (left_interp, right_interp) = if weighted_values.len() >= TREE_PARALLEL_THRESHOLD {
                rayon::join(interpolate_left, interpolate_right)
            } else {
                (interpolate_left(), interpolate_right())
            };
            let left_interp = left_interp?;
            let right_interp = right_interp?;
            let left_term = fast_mul_dense(&left_interp, &right.poly);
            let right_term = fast_mul_dense(&right_interp, &left.poly);
            Ok(&left_term + &right_term)
        }
    }
}

fn fast_remainder(
    dividend: &DensePolynomial<Fr>,
    divisor: &DensePolynomial<Fr>,
) -> Result<DensePolynomial<Fr>, String> {
    if dividend.degree() < divisor.degree() {
        return Ok(dividend.clone());
    }
    Ok(fast_divide_with_q_and_r(dividend, divisor)?.1)
}

fn fast_divide_with_q_and_r(
    dividend: &DensePolynomial<Fr>,
    divisor: &DensePolynomial<Fr>,
) -> Result<(DensePolynomial<Fr>, DensePolynomial<Fr>), String> {
    if divisor.is_zero() {
        return Err("polynomial division by zero".to_string());
    }
    if dividend.degree() < divisor.degree() {
        return Ok((DensePolynomial::zero(), dividend.clone()));
    }
    if dividend.coeffs.len() < FAST_DIVIDEND_THRESHOLD
        || divisor.coeffs.len() < FAST_DIVISOR_THRESHOLD
    {
        let dividend_ds = DenseOrSparsePolynomial::from(dividend);
        let divisor_ds = DenseOrSparsePolynomial::from(divisor);
        return dividend_ds
            .divide_with_q_and_r(&divisor_ds)
            .ok_or_else(|| "polynomial division failed".to_string());
    }

    let quotient_len = dividend.coeffs.len() - divisor.coeffs.len() + 1;
    let reversed_dividend = dividend
        .coeffs
        .iter()
        .rev()
        .take(quotient_len)
        .copied()
        .collect::<Vec<_>>();
    let reversed_divisor = divisor.coeffs.iter().rev().copied().collect::<Vec<_>>();
    let inverse = invert_series(&reversed_divisor, quotient_len)?;
    let mut reversed_quotient = fast_mul_coeffs(&reversed_dividend, &inverse);
    reversed_quotient.resize(quotient_len, Fr::zero());
    reversed_quotient.truncate(quotient_len);
    reversed_quotient.reverse();
    trim_coeffs(&mut reversed_quotient);

    let remainder_len = divisor.coeffs.len().saturating_sub(1);
    // Only the low `remainder_len` coefficients of divisor * quotient can
    // affect the remainder. Computing the full product would add another
    // dividend-sized FFT even when the divisor is small.
    let quotient_prefix_len = reversed_quotient.len().min(remainder_len);
    let product = fast_mul_coeffs(
        &divisor.coeffs[..divisor.coeffs.len().min(remainder_len)],
        &reversed_quotient[..quotient_prefix_len],
    );
    let mut remainder = vec![Fr::zero(); remainder_len];
    for (index, slot) in remainder.iter_mut().enumerate() {
        *slot = dividend.coeffs.get(index).copied().unwrap_or_default()
            - product.get(index).copied().unwrap_or_default();
    }
    trim_coeffs(&mut remainder);
    Ok((
        DensePolynomial::from_coefficients_vec(reversed_quotient),
        DensePolynomial::from_coefficients_vec(remainder),
    ))
}

fn invert_series(poly: &[Fr], len: usize) -> Result<Vec<Fr>, String> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let constant_inv = poly
        .first()
        .and_then(Field::inverse)
        .ok_or_else(|| "polynomial reverse has non-invertible constant".to_string())?;
    let mut inverse = vec![constant_inv];
    while inverse.len() < len {
        let target = (inverse.len() * 2).min(len);
        let poly_prefix = &poly[..poly.len().min(target)];
        let mut correction = fast_mul_coeffs(poly_prefix, &inverse);
        correction.resize(target, Fr::zero());
        correction[0] = Fr::from(2u64) - correction[0];
        for value in correction.iter_mut().skip(1) {
            *value = -*value;
        }
        inverse = fast_mul_coeffs(&inverse, &correction);
        inverse.resize(target, Fr::zero());
        inverse.truncate(target);
    }
    Ok(inverse)
}

fn fast_mul_dense(left: &DensePolynomial<Fr>, right: &DensePolynomial<Fr>) -> DensePolynomial<Fr> {
    DensePolynomial::from_coefficients_vec(fast_mul_coeffs(&left.coeffs, &right.coeffs))
}

fn fast_mul_coeffs(left: &[Fr], right: &[Fr]) -> Vec<Fr> {
    if left.is_empty() || right.is_empty() {
        return Vec::new();
    }
    let result_len = left.len() + right.len() - 1;
    if result_len < FFT_MUL_THRESHOLD {
        let mut result = vec![Fr::zero(); result_len];
        for (i, left_value) in left.iter().enumerate() {
            for (j, right_value) in right.iter().enumerate() {
                result[i + j] += *left_value * *right_value;
            }
        }
        trim_coeffs(&mut result);
        return result;
    }

    let domain = Radix2EvaluationDomain::<Fr>::new(result_len)
        .expect("BLS12-381 scalar field supports the requested FFT domain");
    let mut left_evals = left.to_vec();
    let mut right_evals = right.to_vec();
    left_evals.resize(domain.size(), Fr::zero());
    right_evals.resize(domain.size(), Fr::zero());
    rayon::join(
        || domain.fft_in_place(&mut left_evals),
        || domain.fft_in_place(&mut right_evals),
    );
    left_evals
        .par_iter_mut()
        .zip(right_evals.par_iter())
        .for_each(|(left_value, right_value)| {
            *left_value *= *right_value;
        });
    domain.ifft_in_place(&mut left_evals);
    left_evals.truncate(result_len);
    trim_coeffs(&mut left_evals);
    left_evals
}

fn trim_coeffs(coeffs: &mut Vec<Fr>) {
    while coeffs.len() > 1 && coeffs.last().is_some_and(Zero::is_zero) {
        coeffs.pop();
    }
}
