use ark_bls12_381::Fr;
use ark_ff::{Field, Zero};
use ark_poly::univariate::{DenseOrSparsePolynomial, DensePolynomial};
use ark_poly::{DenseUVPolynomial, Polynomial as ArkPolynomial};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Polynomial {
    pub coeffs: Vec<Fr>,
}

#[derive(Clone)]
pub struct QueryContext {
    points: Vec<Fr>,
    z_poly: Polynomial,
    tree: SubproductTree,
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
        self.as_dense().degree()
    }

    pub fn evaluate(&self, x: Fr) -> Fr {
        self.as_dense().evaluate(&x)
    }

    pub fn add(&self, other: &Self) -> Self {
        Self::from_dense(&self.as_dense() + &other.as_dense())
    }

    pub fn sub(&self, other: &Self) -> Self {
        Self::from_dense(&self.as_dense() - &other.as_dense())
    }

    pub fn mul_scalar(&self, scalar: Fr) -> Self {
        Self::from_dense(&self.as_dense() * scalar)
    }

    pub fn mul(&self, other: &Self) -> Self {
        Self::from_dense(&self.as_dense() * &other.as_dense())
    }

    pub fn div_exact(&self, divisor: &Self) -> Result<Self, String> {
        let dividend = self.as_dense();
        let divisor_dense = divisor.as_dense();
        let dividend_ds = DenseOrSparsePolynomial::from(&dividend);
        let divisor_ds = DenseOrSparsePolynomial::from(&divisor_dense);
        let (quotient, remainder) = dividend_ds
            .divide_with_q_and_r(&divisor_ds)
            .ok_or_else(|| "polynomial division failed".to_string())?;
        if !remainder.is_zero() {
            return Err("polynomial division left a non-zero remainder".to_string());
        }
        Ok(Self::from_dense(quotient))
    }

    pub fn as_dense(&self) -> DensePolynomial<Fr> {
        DensePolynomial::from_coefficients_vec(self.coeffs.clone())
    }

    pub fn from_dense(poly: DensePolynomial<Fr>) -> Self {
        Self { coeffs: poly.coeffs }
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
            });
        }

        let tree = build_subproduct_tree(points);
        let z_poly = Polynomial::from_dense(tree.poly.clone());
        Ok(Self {
            points: points.to_vec(),
            z_poly,
            tree,
        })
    }

    pub fn points(&self) -> &[Fr] {
        &self.points
    }

    pub fn z_poly(&self) -> &Polynomial {
        &self.z_poly
    }

    pub fn evaluate(&self, poly: &Polynomial) -> Result<Vec<Fr>, String> {
        evaluate_on_tree(&poly.as_dense(), &self.tree)
    }

    pub fn interpolate(&self, values: &[Fr]) -> Result<Polynomial, String> {
        let basis_polys = self.lagrange_basis()?;
        if values.len() != basis_polys.len() {
            return Err("points and values length mismatch".to_string());
        }
        if values.is_empty() {
            return Ok(Polynomial::zero());
        }

        let max_len = basis_polys.iter().map(|poly| poly.coeffs.len()).max().unwrap_or(0);
        let mut coeffs = vec![Fr::zero(); max_len];
        for (basis, value) in basis_polys.iter().zip(values.iter()) {
            for (index, coeff) in basis.coeffs.iter().enumerate() {
                coeffs[index] += *coeff * *value;
            }
        }
        Ok(Polynomial::from_coeffs(coeffs))
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
    let left = build_subproduct_tree(&points[..mid]);
    let right = build_subproduct_tree(&points[mid..]);
    let poly = &left.poly * &right.poly;
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
            let poly_ds = DenseOrSparsePolynomial::from(poly);
            let left_ds = DenseOrSparsePolynomial::from(&left.poly);
            let right_ds = DenseOrSparsePolynomial::from(&right.poly);

            let (_, left_rem) = poly_ds
                .divide_with_q_and_r(&left_ds)
                .ok_or_else(|| "left remainder computation failed".to_string())?;
            let (_, right_rem) = poly_ds
                .divide_with_q_and_r(&right_ds)
                .ok_or_else(|| "right remainder computation failed".to_string())?;

            let mut values = evaluate_on_tree(&left_rem, left)?;
            values.extend(evaluate_on_tree(&right_rem, right)?);
            Ok(values)
        }
    }
}

fn product_tree_poly(roots: &[Fr]) -> Polynomial {
    if roots.len() == 1 {
        return Polynomial::from_coeffs(vec![-roots[0], Fr::from(1u64)]);
    }
    let mid = roots.len() / 2;
    let left = product_tree_poly(&roots[..mid]);
    let right = product_tree_poly(&roots[mid..]);
    left.mul(&right)
}
