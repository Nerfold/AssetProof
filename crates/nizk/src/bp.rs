use crate::commitment::derive_generator;
use crate::kzg::{commit_g1, Srs};
use crate::polynomial::QueryContext;
use crate::witness::UpdateWitness;
use ark_bls12_381::{Fr, G1Affine as ArkG1Affine, G1Projective as ArkG1};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField, UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bulletproofs_bls::inner_types::{
    group::{Curve, GroupEncoding},
    Field as BpField, G1Projective as BpG1, PrimeField as BpPrimeField, Scalar as BpScalar,
};
use bulletproofs_bls::r1cs::{
    ConstraintSystem, LinearCombination, PhaseOneWitnessCommitmentOpening, Prover, R1CSProof,
    Verifier,
};
use bulletproofs_bls::{BulletproofGens, LinearProof, PedersenGens};
use common::crypto::{hex_decode, hex_encode, point_g1_from_hex, point_g1_to_hex, scalar_to_hex};
use common::types::Delta;
use merlin::Transcript;
use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

#[derive(Clone, Debug)]
pub struct LogicProof {
    pub bp_proof_hex: String,
    pub bp_commitments_hex: String,
    pub link_proof_hex: String,
}

#[derive(Clone, Debug)]
pub struct DirectZeroTestProof {
    pub bp_proof_hex: String,
    pub committed_input_link_ipa_proof: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct InsertRelationProof {
    pub bp_proof_hex: String,
    pub bp_commitments_hex: String,
    pub link_proof_hex: String,
}

#[derive(Clone, Debug)]
enum LinkLayout {
    Full { m: usize },
    ZeroTest { m: usize },
}

#[derive(Clone, Debug)]
struct LinkProof {
    r_bp: Vec<BpG1>,
    r_u_ext: ArkG1,
    r_y_ext: ArkG1,
    r_d_ext: ArkG1,
    s_values: Vec<Fr>,
    s_bp_blinds: Vec<BpScalar>,
    s_r_u: Fr,
    s_rho_y: Fr,
    s_r_d: Fr,
}

#[derive(Clone, Debug)]
struct InsertLinkProof {
    r_bp: Vec<BpG1>,
    r_ext: Vec<ArkG1>,
    s_values: Vec<Fr>,
    s_bp_blinds: Vec<BpScalar>,
    s_ext_blinds: Vec<Fr>,
}

#[derive(Clone, Copy, Debug)]
struct UpdateR1csShape {
    witness_len: usize,
    bp_capacity: usize,
}

static PEDERSEN_GENS: OnceLock<PedersenGens> = OnceLock::new();
static BULLETPROOF_GENS: OnceLock<Mutex<HashMap<usize, Arc<BulletproofGens>>>> = OnceLock::new();
static PROJECTION_IPA_GENS: OnceLock<Mutex<HashMap<usize, Arc<Vec<BpG1>>>>> = OnceLock::new();
static ZERO_TEST_SHAPES: OnceLock<Mutex<HashMap<usize, UpdateR1csShape>>> = OnceLock::new();
static INSERT_SHAPE: OnceLock<UpdateR1csShape> = OnceLock::new();

fn pedersen_gens() -> &'static PedersenGens {
    PEDERSEN_GENS.get_or_init(|| {
        let mut generators = PedersenGens::default();
        generators.B_blinding = ark_g1_to_bp(&derive_generator("balance-h", 0))
            .expect("balance blinding generator conversion must succeed");
        generators
    })
}

fn bulletproof_gens(capacity: usize) -> Arc<BulletproofGens> {
    let cache = BULLETPROOF_GENS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache
        .lock()
        .expect("bulletproof generator cache lock poisoned");
    cache
        .entry(capacity)
        .or_insert_with(|| Arc::new(BulletproofGens::new(capacity, 3)))
        .clone()
}

fn projection_ipa_generators(capacity: usize) -> Result<Arc<Vec<BpG1>>, String> {
    let cache = PROJECTION_IPA_GENS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache
        .lock()
        .expect("projection IPA generator cache lock poisoned");
    if let Some(generators) = cache.get(&capacity) {
        return Ok(Arc::clone(generators));
    }
    let bp_gens = bulletproof_gens(capacity);
    let generators = bp_gens.share(2).G(capacity).copied().collect();
    let generators = Arc::new(generators);
    cache.insert(capacity, Arc::clone(&generators));
    Ok(generators)
}

pub fn commit_membership_vector(values: &[Fr], blind: Fr) -> Result<ArkG1, String> {
    let capacity = values.len().max(1).next_power_of_two();
    let bp_gens = bulletproof_gens(capacity);
    let generators = bp_gens
        .share(2)
        .G(values.len())
        .copied()
        .collect::<Vec<_>>();
    let scalars = values
        .iter()
        .map(fr_to_bp_scalar)
        .collect::<Result<Vec<_>, _>>()?;
    let blind = fr_to_bp_scalar(&blind)?;
    let commitment = BpG1::sum_of_products(
        &generators
            .iter()
            .copied()
            .chain(std::iter::once(pedersen_gens().B_blinding))
            .collect::<Vec<_>>(),
        &scalars
            .iter()
            .copied()
            .chain(std::iter::once(blind))
            .collect::<Vec<_>>(),
    );
    bp_g1_to_ark(&commitment)
}

fn zero_test_shape(m: usize) -> UpdateR1csShape {
    cached_shape(&ZERO_TEST_SHAPES, m, || UpdateR1csShape {
        witness_len: 3 * m,
        bp_capacity: zero_test_relation_capacity(m),
    })
}

fn insert_shape() -> UpdateR1csShape {
    *INSERT_SHAPE.get_or_init(|| UpdateR1csShape {
        witness_len: 9,
        bp_capacity: 16,
    })
}

fn cached_shape(
    cache: &'static OnceLock<Mutex<HashMap<usize, UpdateR1csShape>>>,
    m: usize,
    build: impl FnOnce() -> UpdateR1csShape,
) -> UpdateR1csShape {
    let cache = cache.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache.lock().expect("R1CS shape cache lock poisoned");
    *cache.entry(m).or_insert_with(build)
}

fn update_relation_capacity(m: usize) -> usize {
    (m * 2).max(1).next_power_of_two()
}

fn zero_test_relation_capacity(m: usize) -> usize {
    update_relation_capacity(m)
}

pub fn prove_logic(
    srs: &Srs,
    witness: &UpdateWitness,
    deltas: &[Delta],
    c_u_hex: &str,
    c_y_hex: &str,
    c_d_hex: &str,
    r_u: Fr,
    rho_y: Fr,
    r_d: Fr,
    query_ctx: Option<&QueryContext>,
) -> Result<LogicProof, String> {
    let values = flatten_values(witness);
    let bp_values = values
        .iter()
        .map(fr_to_bp_scalar)
        .collect::<Result<Vec<_>, _>>()?;
    let bp_blinds = derive_bp_blinds(&values)?;

    let pc_gens = pedersen_gens();
    let bp_gens = bulletproof_gens(update_relation_capacity(deltas.len()));
    let mut transcript = Transcript::new(b"dynamic-poa-update-r1cs-v2");
    append_public_to_transcript(&mut transcript, c_u_hex, c_y_hex, c_d_hex, deltas);
    let mut prover = Prover::new(pc_gens, &mut transcript);

    let mut commitments = Vec::with_capacity(values.len());
    let mut vars = Vec::with_capacity(values.len());
    for (value, blind) in bp_values.iter().zip(bp_blinds.iter()) {
        let (commitment, var) = prover.commit(*value, *blind);
        commitments.push(commitment);
        vars.push(var);
    }

    update_relation(&mut prover, &vars, deltas)?;
    let bp_proof = prover
        .prove(bp_gens.as_ref())
        .map_err(|err| format!("bulletproof prove: {err}"))?;
    let link_proof = prove_link(
        srs,
        witness,
        deltas,
        &commitments,
        &values,
        &bp_blinds,
        c_u_hex,
        c_y_hex,
        c_d_hex,
        r_u,
        rho_y,
        r_d,
        query_ctx,
    )?;

    Ok(LogicProof {
        bp_proof_hex: hex_encode(&bp_proof.to_bytes()),
        bp_commitments_hex: encode_bp_points(&commitments),
        link_proof_hex: encode_link_proof(&link_proof)?,
    })
}

pub fn verify_logic(
    srs: &Srs,
    deltas: &[Delta],
    x_values: &[Fr],
    c_u_hex: &str,
    c_y_hex: &str,
    c_d_hex: &str,
    bp_proof_hex: &str,
    bp_commitments_hex: &str,
    link_proof_hex: &str,
) -> Result<(), String> {
    let emit_timing = verify_timing_enabled();
    let logic_total_start = Instant::now();

    let decode_commitments_start = Instant::now();
    let commitments = decode_bp_points(bp_commitments_hex)?;
    let expected_len = deltas.len() * 3 + 1;
    if commitments.len() != expected_len {
        return Err(format!(
            "Bulletproof commitment length mismatch: got {}, expected {}",
            commitments.len(),
            expected_len
        ));
    }
    emit_bp_timing(
        emit_timing,
        "verify_bp_decode_commitments",
        decode_commitments_start,
    );

    let r1cs_build_start = Instant::now();
    let pc_gens = pedersen_gens();
    let bp_gens = bulletproof_gens(update_relation_capacity(deltas.len()));
    let mut transcript = Transcript::new(b"dynamic-poa-update-r1cs-v2");
    append_public_to_transcript(&mut transcript, c_u_hex, c_y_hex, c_d_hex, deltas);
    let mut verifier = Verifier::new(&mut transcript);
    let vars = commitments
        .iter()
        .map(|commitment| verifier.commit(*commitment))
        .collect::<Vec<_>>();
    update_relation(&mut verifier, &vars, deltas)?;
    emit_bp_timing(emit_timing, "verify_bp_r1cs_build", r1cs_build_start);

    let proof_parse_start = Instant::now();
    let bp_bytes = hex_decode(bp_proof_hex)?;
    let bp_proof =
        R1CSProof::from_bytes(&bp_bytes).map_err(|err| format!("bulletproof parse: {err}"))?;
    emit_bp_timing(emit_timing, "verify_bp_proof_parse", proof_parse_start);

    let bp_verify_start = Instant::now();
    verifier
        .verify(&bp_proof, pc_gens, bp_gens.as_ref())
        .map_err(|err| format!("bulletproof verify: {err}"))?;
    emit_bp_timing(emit_timing, "verify_bulletproof_r1cs", bp_verify_start);

    let link_parse_start = Instant::now();
    let link_proof = decode_link_proof(link_proof_hex, expected_len)?;
    emit_bp_timing(emit_timing, "verify_link_proof_parse", link_parse_start);

    let link_start = Instant::now();
    let result = verify_link(
        srs,
        deltas,
        x_values,
        &commitments,
        c_u_hex,
        c_y_hex,
        c_d_hex,
        &link_proof,
    );
    emit_bp_timing(emit_timing, "verify_link_total", link_start);
    emit_bp_timing(
        emit_timing,
        "verify_logic_internal_total",
        logic_total_start,
    );
    result
}

pub fn prove_zero_test_logic(
    srs: &Srs,
    witness: &UpdateWitness,
    deltas: &[Delta],
    c_u_hex: &str,
    c_y_hex: &str,
    r_u: Fr,
    rho_y: Fr,
    query_ctx: Option<&QueryContext>,
) -> Result<LogicProof, String> {
    let shape = zero_test_shape(deltas.len());
    let values = flatten_zero_test_values(witness);
    if values.len() != shape.witness_len {
        return Err("zero-test witness length does not match cached R1CS shape".to_string());
    }
    let bp_values = values
        .iter()
        .map(fr_to_bp_scalar)
        .collect::<Result<Vec<_>, _>>()?;
    let bp_blinds = derive_bp_blinds(&values)?;

    let pc_gens = pedersen_gens();
    let bp_gens = bulletproof_gens(shape.bp_capacity);
    let mut transcript = Transcript::new(b"dynamic-poa-zero-test-r1cs-v2");
    append_zero_test_public_to_transcript(&mut transcript, c_u_hex, c_y_hex, deltas);
    let mut prover = Prover::new(pc_gens, &mut transcript);

    let mut commitments = Vec::with_capacity(values.len());
    let mut vars = Vec::with_capacity(values.len());
    for (value, blind) in bp_values.iter().zip(bp_blinds.iter()) {
        let (commitment, var) = prover.commit(*value, *blind);
        commitments.push(commitment);
        vars.push(var);
    }

    zero_test_relation(&mut prover, &vars, deltas.len())?;
    let bp_proof = prover
        .prove(bp_gens.as_ref())
        .map_err(|err| format!("zero-test bulletproof prove: {err}"))?;
    let link_proof = prove_link_with_layout(
        srs,
        deltas,
        &witness.x_values,
        &commitments,
        &values,
        &bp_blinds,
        c_u_hex,
        c_y_hex,
        "",
        r_u,
        rho_y,
        Fr::zero(),
        query_ctx,
        LinkLayout::ZeroTest { m: deltas.len() },
    )?;

    Ok(LogicProof {
        bp_proof_hex: hex_encode(&bp_proof.to_bytes()),
        bp_commitments_hex: encode_bp_points(&commitments),
        link_proof_hex: encode_link_proof(&link_proof)?,
    })
}

pub fn verify_zero_test_logic(
    srs: &Srs,
    deltas: &[Delta],
    x_values: &[Fr],
    c_u_hex: &str,
    c_y_hex: &str,
    bp_proof_hex: &str,
    bp_commitments_hex: &str,
    link_proof_hex: &str,
) -> Result<(), String> {
    let shape = zero_test_shape(deltas.len());
    let emit_timing = verify_timing_enabled();
    let total_start = Instant::now();
    let decode_commitments_start = Instant::now();
    let commitments = decode_bp_points(bp_commitments_hex)?;
    let expected_len = shape.witness_len;
    if commitments.len() != expected_len {
        return Err(format!(
            "zero-test Bulletproof commitment length mismatch: got {}, expected {}",
            commitments.len(),
            expected_len
        ));
    }
    emit_bp_timing(
        emit_timing,
        "verify_zero_test_bp_decode_commitments",
        decode_commitments_start,
    );

    let r1cs_build_start = Instant::now();
    let pc_gens = pedersen_gens();
    let bp_gens = bulletproof_gens(shape.bp_capacity);
    let mut transcript = Transcript::new(b"dynamic-poa-zero-test-r1cs-v2");
    append_zero_test_public_to_transcript(&mut transcript, c_u_hex, c_y_hex, deltas);
    let mut verifier = Verifier::new(&mut transcript);
    let vars = commitments
        .iter()
        .map(|commitment| verifier.commit(*commitment))
        .collect::<Vec<_>>();
    zero_test_relation(&mut verifier, &vars, deltas.len())?;
    emit_bp_timing(emit_timing, "verify_zero_test_r1cs_build", r1cs_build_start);

    let proof_parse_start = Instant::now();
    let bp_bytes = hex_decode(bp_proof_hex)?;
    let bp_proof = R1CSProof::from_bytes(&bp_bytes)
        .map_err(|err| format!("zero-test bulletproof parse: {err}"))?;
    emit_bp_timing(
        emit_timing,
        "verify_zero_test_bp_proof_parse",
        proof_parse_start,
    );

    let bp_verify_start = Instant::now();
    verifier
        .verify(&bp_proof, pc_gens, bp_gens.as_ref())
        .map_err(|err| format!("zero-test bulletproof verify: {err}"))?;
    emit_bp_timing(emit_timing, "verify_zero_test_bulletproof", bp_verify_start);

    let link_parse_start = Instant::now();
    let link_proof = decode_link_proof(link_proof_hex, expected_len)?;
    emit_bp_timing(emit_timing, "verify_zero_test_link_parse", link_parse_start);

    let link_start = Instant::now();
    let result = verify_link_with_layout(
        srs,
        deltas,
        x_values,
        &commitments,
        c_u_hex,
        c_y_hex,
        "",
        &link_proof,
        LinkLayout::ZeroTest { m: deltas.len() },
    );
    emit_bp_timing(emit_timing, "verify_zero_test_link_total", link_start);
    emit_bp_timing(emit_timing, "verify_zero_test_total", total_start);
    result
}

pub fn prove_direct_zero_test_logic(
    witness: &UpdateWitness,
    deltas: &[Delta],
    old_state_root: &str,
    new_state_root: &str,
    accumulator_hex: &str,
    old_balance_commitment_hex: &str,
    new_balance_commitment_hex: &str,
    c_u_hex: &str,
    d_y_hex: &str,
    c_d_hex: &str,
    r_u: Fr,
    r_y: Fr,
) -> Result<DirectZeroTestProof, String> {
    if witness.u_values.len() != deltas.len()
        || witness.y_values.len() != deltas.len()
        || witness.z_values.len() != deltas.len()
    {
        return Err("optimized zero-test witness length mismatch".to_string());
    }
    let wire_capacity = update_relation_capacity(deltas.len());
    let pc_gens = pedersen_gens();
    let bp_gens = bulletproof_gens(wire_capacity);
    let mut transcript = Transcript::new(b"dynamic-poa-direct-multizkopen-zero-test-v1");
    append_direct_zero_test_public_to_transcript(
        &mut transcript,
        old_state_root,
        new_state_root,
        accumulator_hex,
        old_balance_commitment_hex,
        new_balance_commitment_hex,
        c_u_hex,
        d_y_hex,
        c_d_hex,
        deltas,
    );
    let mut prover = Prover::new(pc_gens, &mut transcript);
    direct_vector_zero_test_relation(&mut prover, Some(witness), deltas.len())?;
    let (bp_proof, phase_one_opening) = prover
        .prove_with_phase_one_opening(bp_gens.as_ref())
        .map_err(|err| format!("direct zero-test Bulletproof prove: {err}"))?;
    let bp_proof_bytes = bp_proof.to_bytes();
    let committed_input_link_ipa_proof = prove_committed_input_link_ipa(
        &bp_proof,
        &phase_one_opening,
        witness,
        wire_capacity,
        deltas,
        c_u_hex,
        d_y_hex,
        r_u,
        r_y,
        &bp_proof_bytes,
    )?;

    Ok(DirectZeroTestProof {
        bp_proof_hex: hex_encode(&bp_proof_bytes),
        committed_input_link_ipa_proof,
    })
}

pub fn verify_direct_zero_test_logic(
    deltas: &[Delta],
    old_state_root: &str,
    new_state_root: &str,
    accumulator_hex: &str,
    old_balance_commitment_hex: &str,
    new_balance_commitment_hex: &str,
    c_u_hex: &str,
    d_y_hex: &str,
    c_d_hex: &str,
    bp_proof_hex: &str,
    committed_input_link_ipa_proof: &[u8],
) -> Result<(), String> {
    let emit_timing = verify_timing_enabled();
    let total_start = Instant::now();
    let wire_capacity = update_relation_capacity(deltas.len());
    let r1cs_start = Instant::now();
    let pc_gens = pedersen_gens();
    let bp_gens = bulletproof_gens(wire_capacity);
    let mut transcript = Transcript::new(b"dynamic-poa-direct-multizkopen-zero-test-v1");
    append_direct_zero_test_public_to_transcript(
        &mut transcript,
        old_state_root,
        new_state_root,
        accumulator_hex,
        old_balance_commitment_hex,
        new_balance_commitment_hex,
        c_u_hex,
        d_y_hex,
        c_d_hex,
        deltas,
    );
    let mut verifier = Verifier::new(&mut transcript);
    direct_vector_zero_test_relation(&mut verifier, None, deltas.len())?;

    let bp_bytes = hex_decode(bp_proof_hex)?;
    let bp_proof = R1CSProof::from_bytes(&bp_bytes)
        .map_err(|err| format!("direct zero-test Bulletproof parse: {err}"))?;
    verifier
        .verify(&bp_proof, pc_gens, bp_gens.as_ref())
        .map_err(|err| format!("direct zero-test Bulletproof verify: {err}"))?;
    emit_bp_timing(emit_timing, "verify_vector_r1cs", r1cs_start);
    let committed_input_link_start = Instant::now();
    verify_committed_input_link_ipa(
        &bp_proof,
        wire_capacity,
        deltas,
        c_u_hex,
        d_y_hex,
        committed_input_link_ipa_proof,
        &bp_bytes,
    )?;
    emit_bp_timing(
        emit_timing,
        "verify_committed_input_link_ipa",
        committed_input_link_start,
    );
    emit_bp_timing(emit_timing, "verify_direct_zero_test_total", total_start);
    Ok(())
}

pub fn prove_projection_ipa(
    u_values: &[Fr],
    deltas: &[Delta],
    c_u_hex: &str,
    c_d_hex: &str,
    r_u: Fr,
    r_d: Fr,
) -> Result<Vec<u8>, String> {
    if u_values.len() != deltas.len() {
        return Err("projection u/delta length mismatch".to_string());
    }
    let capacity = deltas.len().max(1).next_power_of_two();
    let mut a = u_values
        .iter()
        .map(fr_to_bp_scalar)
        .collect::<Result<Vec<_>, _>>()?;
    a.resize(capacity, BpScalar::ZERO);
    let mut b = deltas
        .iter()
        .map(|delta| bp_scalar_from_i128(delta.delta))
        .collect::<Result<Vec<_>, _>>()?;
    b.resize(capacity, BpScalar::ZERO);

    let generators = projection_ipa_generators(capacity)?;
    let f = ark_g1_to_bp(&derive_generator("balance-v", 0))?;
    let blind_base = ark_g1_to_bp(&derive_generator("balance-h", 0))?;
    let c_u = point_g1_from_hex(c_u_hex)?;
    let c_d = point_g1_from_hex(c_d_hex)?;
    let commitment = ark_g1_to_bp(&(c_u + c_d))?;
    let blind = fr_to_bp_scalar(&(r_u + r_d))?;

    let mut transcript = Transcript::new(b"dynamic-poa-projection-ipa-v1");
    append_projection_ipa_public(&mut transcript, c_u_hex, c_d_hex, deltas);
    let proof = LinearProof::create(
        &mut transcript,
        rand::rngs::OsRng,
        &commitment,
        blind,
        a,
        b,
        generators.as_ref().clone(),
        &f,
        &blind_base,
    )
    .map_err(|err| format!("projection IPA prove: {err}"))?;
    Ok(proof.to_bytes())
}

pub fn verify_projection_ipa(
    deltas: &[Delta],
    c_u_hex: &str,
    c_d_hex: &str,
    proof_bytes: &[u8],
) -> Result<(), String> {
    let emit_timing = verify_timing_enabled();
    let total_start = Instant::now();
    let capacity = deltas.len().max(1).next_power_of_two();
    let expected_size = 112 + 96 * capacity.trailing_zeros() as usize;
    if proof_bytes.len() != expected_size {
        return Err(format!(
            "projection IPA length mismatch: got {}, expected {}",
            proof_bytes.len(),
            expected_size
        ));
    }

    let setup_start = Instant::now();
    let generators = projection_ipa_generators(capacity)?;
    let f = ark_g1_to_bp(&derive_generator("balance-v", 0))?;
    let blind_base = ark_g1_to_bp(&derive_generator("balance-h", 0))?;
    let c_u = point_g1_from_hex(c_u_hex)?;
    let c_d = point_g1_from_hex(c_d_hex)?;
    let commitment = ark_g1_to_bp(&(c_u + c_d))?;
    let mut b = deltas
        .iter()
        .map(|delta| bp_scalar_from_i128(delta.delta))
        .collect::<Result<Vec<_>, _>>()?;
    b.resize(capacity, BpScalar::ZERO);
    emit_bp_timing(emit_timing, "verify_projection_ipa_setup", setup_start);

    let parse_start = Instant::now();
    let proof = LinearProof::from_bytes(proof_bytes)
        .map_err(|err| format!("projection IPA parse: {err}"))?;
    emit_bp_timing(emit_timing, "verify_projection_ipa_parse", parse_start);

    let verify_start = Instant::now();
    let mut transcript = Transcript::new(b"dynamic-poa-projection-ipa-v1");
    append_projection_ipa_public(&mut transcript, c_u_hex, c_d_hex, deltas);
    let result = proof
        .verify(
            &mut transcript,
            &commitment,
            generators.as_ref(),
            &f,
            &blind_base,
            b,
        )
        .map_err(|err| format!("projection IPA verify: {err}"));
    emit_bp_timing(emit_timing, "verify_projection_ipa", verify_start);
    emit_bp_timing(emit_timing, "verify_projection_total", total_start);
    result
}

#[allow(clippy::too_many_arguments)]
pub fn prove_insert_relation_logic(
    x: Fr,
    beta: Fr,
    y_x: Fr,
    y: Fr,
    y_prime: Fr,
    q_zeta: Fr,
    z_x: Fr,
    z_beta: Fr,
    inserted_balance: i128,
    zeta: Fr,
    r_x: Fr,
    r_beta: Fr,
    r_y_x: Fr,
    r_y: Fr,
    r_y_prime: Fr,
    r_q: Fr,
    r_ins: Fr,
    c_x_hex: &str,
    c_beta_hex: &str,
    c_y_x_hex: &str,
    c_y_hex: &str,
    c_y_prime_hex: &str,
    c_q_hex: &str,
    old_balance_commitment_hex: &str,
    new_balance_commitment_hex: &str,
) -> Result<InsertRelationProof, String> {
    let shape = insert_shape();
    let values = vec![
        x,
        beta,
        y_x,
        y,
        y_prime,
        q_zeta,
        z_x,
        z_beta,
        common::crypto::scalar_from_i128(inserted_balance),
    ];
    if values.len() != shape.witness_len {
        return Err("insert relation witness length mismatch".to_string());
    }
    let bp_values = values
        .iter()
        .map(fr_to_bp_scalar)
        .collect::<Result<Vec<_>, _>>()?;
    let bp_blinds = derive_bp_blinds(&values)?;
    let pc_gens = pedersen_gens();
    let bp_gens = bulletproof_gens(shape.bp_capacity);
    let mut transcript = Transcript::new(b"dynamic-poa-insert-r1cs");
    append_insert_public_to_transcript(
        &mut transcript,
        zeta,
        c_x_hex,
        c_beta_hex,
        c_y_x_hex,
        c_y_hex,
        c_y_prime_hex,
        c_q_hex,
        old_balance_commitment_hex,
        new_balance_commitment_hex,
    )?;
    let mut prover = Prover::new(pc_gens, &mut transcript);
    let mut commitments = Vec::with_capacity(values.len());
    let mut vars = Vec::with_capacity(values.len());
    for (value, blind) in bp_values.iter().zip(bp_blinds.iter()) {
        let (commitment, var) = prover.commit(*value, *blind);
        commitments.push(commitment);
        vars.push(var);
    }
    insert_relation(&mut prover, &vars, zeta)?;
    let bp_proof = prover
        .prove(bp_gens.as_ref())
        .map_err(|err| format!("insert bulletproof prove: {err}"))?;
    let link_proof = prove_insert_link(
        &commitments,
        &values,
        &bp_blinds,
        c_x_hex,
        c_beta_hex,
        c_y_x_hex,
        c_y_hex,
        c_y_prime_hex,
        c_q_hex,
        old_balance_commitment_hex,
        new_balance_commitment_hex,
        r_x,
        r_beta,
        r_y_x,
        r_y,
        r_y_prime,
        r_q,
        r_ins,
    )?;

    Ok(InsertRelationProof {
        bp_proof_hex: hex_encode(&bp_proof.to_bytes()),
        bp_commitments_hex: encode_bp_points(&commitments),
        link_proof_hex: link_proof,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn verify_insert_relation_logic(
    zeta: Fr,
    c_x_hex: &str,
    c_beta_hex: &str,
    c_y_x_hex: &str,
    c_y_hex: &str,
    c_y_prime_hex: &str,
    c_q_hex: &str,
    old_balance_commitment_hex: &str,
    new_balance_commitment_hex: &str,
    bp_proof_hex: &str,
    bp_commitments_hex: &str,
    link_proof_hex: &str,
) -> Result<(), String> {
    let shape = insert_shape();
    let commitments = decode_bp_points(bp_commitments_hex)?;
    if commitments.len() != shape.witness_len {
        return Err(format!(
            "insert Bulletproof commitment length mismatch: got {}, expected {}",
            commitments.len(),
            shape.witness_len
        ));
    }
    let pc_gens = pedersen_gens();
    let bp_gens = bulletproof_gens(shape.bp_capacity);
    let mut transcript = Transcript::new(b"dynamic-poa-insert-r1cs");
    append_insert_public_to_transcript(
        &mut transcript,
        zeta,
        c_x_hex,
        c_beta_hex,
        c_y_x_hex,
        c_y_hex,
        c_y_prime_hex,
        c_q_hex,
        old_balance_commitment_hex,
        new_balance_commitment_hex,
    )?;
    let mut verifier = Verifier::new(&mut transcript);
    let vars = commitments
        .iter()
        .map(|commitment| verifier.commit(*commitment))
        .collect::<Vec<_>>();
    insert_relation(&mut verifier, &vars, zeta)?;
    let bp_bytes = hex_decode(bp_proof_hex)?;
    let bp_proof = R1CSProof::from_bytes(&bp_bytes)
        .map_err(|err| format!("insert bulletproof parse: {err}"))?;
    verifier
        .verify(&bp_proof, pc_gens, bp_gens.as_ref())
        .map_err(|err| format!("insert bulletproof verify: {err}"))?;
    verify_insert_link(
        &commitments,
        c_x_hex,
        c_beta_hex,
        c_y_x_hex,
        c_y_hex,
        c_y_prime_hex,
        c_q_hex,
        old_balance_commitment_hex,
        new_balance_commitment_hex,
        link_proof_hex,
    )
}

fn update_relation<CS: ConstraintSystem>(
    cs: &mut CS,
    vars: &[bulletproofs_bls::r1cs::Variable],
    deltas: &[Delta],
) -> Result<(), String> {
    let m = deltas.len();
    let u_offset = 0;
    let y_offset = m;
    let z_offset = 2 * m;
    let d_index = 3 * m;

    for j in 0..m {
        let u = vars[u_offset + j];
        let y = vars[y_offset + j];
        let z = vars[z_offset + j];

        let (_, _, uy) = cs.multiply(u.into(), y.into());
        cs.constrain(uy.into());

        let (_, _, yz) = cs.multiply(y.into(), z.into());
        cs.constrain(yz - bp_one() + u);
    }

    let mut delta_lc: LinearCombination = vars[d_index].into();
    for (j, delta) in deltas.iter().enumerate() {
        delta_lc = delta_lc - bp_scalar_from_i128(delta.delta)? * vars[u_offset + j];
    }
    cs.constrain(delta_lc);
    Ok(())
}

fn zero_test_relation<CS: ConstraintSystem>(
    cs: &mut CS,
    vars: &[bulletproofs_bls::r1cs::Variable],
    m: usize,
) -> Result<(), String> {
    let u_offset = 0;
    let y_offset = m;
    let z_offset = 2 * m;

    for j in 0..m {
        let u = vars[u_offset + j];
        let y = vars[y_offset + j];
        let z = vars[z_offset + j];

        let (_, _, uy) = cs.multiply(u.into(), y.into());
        cs.constrain(uy.into());

        let (_, _, yz) = cs.multiply(y.into(), z.into());
        cs.constrain(yz - bp_one() + u);
    }
    Ok(())
}

fn direct_vector_zero_test_relation<CS: ConstraintSystem>(
    cs: &mut CS,
    witness: Option<&UpdateWitness>,
    m: usize,
) -> Result<(), String> {
    if let Some(witness) = witness {
        if witness.u_values.len() != m || witness.y_values.len() != m || witness.z_values.len() != m
        {
            return Err("vector zero-test witness length mismatch".to_string());
        }
    }

    for j in 0..m {
        let gate_uy = match witness {
            Some(w) => Some((
                fr_to_bp_scalar(&w.u_values[j])?,
                fr_to_bp_scalar(&w.y_values[j])?,
            )),
            None => None,
        };
        let gate_yz = match witness {
            Some(w) => Some((
                fr_to_bp_scalar(&w.y_values[j])?,
                fr_to_bp_scalar(&w.z_values[j])?,
            )),
            None => None,
        };
        let (u, y_left, uy) = cs
            .allocate_multiplier(gate_uy)
            .map_err(|err| format!("allocate u*y gate: {err}"))?;
        let (y_right, _z, yz) = cs
            .allocate_multiplier(gate_yz)
            .map_err(|err| format!("allocate y*z gate: {err}"))?;
        cs.constrain(uy.into());
        cs.constrain(y_left - y_right);
        cs.constrain(yz - bp_one() + u);
    }
    Ok(())
}

fn insert_relation<CS: ConstraintSystem>(
    cs: &mut CS,
    vars: &[bulletproofs_bls::r1cs::Variable],
    zeta: Fr,
) -> Result<(), String> {
    if vars.len() != insert_shape().witness_len {
        return Err("insert relation variable length mismatch".to_string());
    }
    let x = vars[0];
    let beta = vars[1];
    let y_x = vars[2];
    let y = vars[3];
    let y_prime = vars[4];
    let q = vars[5];
    let z_x = vars[6];
    let z_beta = vars[7];
    let zeta = fr_to_bp_scalar(&zeta)?;

    let (_, _, beta_y) = cs.multiply(beta.into(), y.into());
    let (_, _, beta_y_zeta) = cs.multiply(beta_y.into(), (zeta * bp_one()).into());
    let (_, _, beta_y_x) = cs.multiply(beta_y.into(), x.into());
    cs.constrain(beta_y_zeta - beta_y_x - y_prime);

    let (_, _, q_zeta) = cs.multiply(q.into(), (zeta * bp_one()).into());
    let (_, _, q_x) = cs.multiply(q.into(), x.into());
    cs.constrain(y - y_x - q_zeta + q_x);

    let (_, _, y_x_inv) = cs.multiply(y_x.into(), z_x.into());
    cs.constrain(y_x_inv - bp_one());

    let (_, _, beta_inv) = cs.multiply(beta.into(), z_beta.into());
    cs.constrain(beta_inv - bp_one());

    Ok(())
}

fn prove_link(
    srs: &Srs,
    witness: &UpdateWitness,
    deltas: &[Delta],
    bp_commitments: &[BpG1],
    values: &[Fr],
    bp_blinds: &[BpScalar],
    c_u_hex: &str,
    c_y_hex: &str,
    c_d_hex: &str,
    r_u: Fr,
    rho_y: Fr,
    r_d: Fr,
    query_ctx: Option<&QueryContext>,
) -> Result<LinkProof, String> {
    prove_link_with_layout(
        srs,
        deltas,
        &witness.x_values,
        bp_commitments,
        values,
        bp_blinds,
        c_u_hex,
        c_y_hex,
        c_d_hex,
        r_u,
        rho_y,
        r_d,
        query_ctx,
        LinkLayout::Full { m: deltas.len() },
    )
}

fn prove_link_with_layout(
    srs: &Srs,
    deltas: &[Delta],
    x_values: &[Fr],
    bp_commitments: &[BpG1],
    values: &[Fr],
    bp_blinds: &[BpScalar],
    c_u_hex: &str,
    c_y_hex: &str,
    c_d_hex: &str,
    r_u: Fr,
    rho_y: Fr,
    r_d: Fr,
    query_ctx: Option<&QueryContext>,
    layout: LinkLayout,
) -> Result<LinkProof, String> {
    let pc_gens = pedersen_gens();
    let mut rng = rand::rngs::OsRng;
    let mut t_values = Vec::with_capacity(values.len());
    let mut t_bp_blinds = Vec::with_capacity(values.len());
    for _ in 0..values.len() {
        t_values.push(Fr::rand(&mut rng));
        t_bp_blinds.push(BpScalar::random(&mut rng));
    }
    let t_r_u = Fr::rand(&mut rng);
    let t_rho_y = Fr::rand(&mut rng);
    let t_r_d = Fr::rand(&mut rng);

    let r_bp = t_values
        .iter()
        .zip(t_bp_blinds.iter())
        .map(|(value, blind)| {
            pc_gens.commit(
                fr_to_bp_scalar(value).expect("hash scalar conversion must work"),
                *blind,
            )
        })
        .collect::<Vec<_>>();

    let r_u_ext = external_u_commit(link_u_values(&t_values, &layout), t_r_u);
    let r_y_ext = match layout {
        LinkLayout::Full { .. } | LinkLayout::ZeroTest { .. } => external_y_commit(
            srs,
            x_values,
            link_y_values(&t_values, &layout),
            t_rho_y,
            query_ctx,
        )?,
    };
    let r_d_ext = match layout {
        LinkLayout::Full { m } => external_d_commit(t_values[3 * m], t_r_d),
        LinkLayout::ZeroTest { .. } => ArkG1::zero(),
    };

    let challenge = link_challenge(
        deltas,
        bp_commitments,
        c_u_hex,
        c_y_hex,
        c_d_hex,
        &r_bp,
        &r_u_ext,
        &r_y_ext,
        &r_d_ext,
    )?;
    let challenge_bp = fr_to_bp_scalar(&challenge)?;

    let mut s_values = Vec::with_capacity(values.len());
    let mut s_bp_blinds = Vec::with_capacity(values.len());
    for ((t_value, value), (t_blind, blind)) in t_values
        .iter()
        .zip(values.iter())
        .zip(t_bp_blinds.iter().zip(bp_blinds.iter()))
    {
        s_values.push(*t_value + challenge * *value);
        s_bp_blinds.push(*t_blind + challenge_bp * *blind);
    }

    Ok(LinkProof {
        r_bp,
        r_u_ext,
        r_y_ext,
        r_d_ext,
        s_values,
        s_bp_blinds,
        s_r_u: t_r_u + challenge * r_u,
        s_rho_y: t_rho_y + challenge * rho_y,
        s_r_d: t_r_d + challenge * r_d,
    })
}

fn verify_link(
    srs: &Srs,
    deltas: &[Delta],
    x_values: &[Fr],
    bp_commitments: &[BpG1],
    c_u_hex: &str,
    c_y_hex: &str,
    c_d_hex: &str,
    proof: &LinkProof,
) -> Result<(), String> {
    verify_link_with_layout(
        srs,
        deltas,
        x_values,
        bp_commitments,
        c_u_hex,
        c_y_hex,
        c_d_hex,
        proof,
        LinkLayout::Full { m: deltas.len() },
    )
}

fn verify_link_with_layout(
    srs: &Srs,
    deltas: &[Delta],
    x_values: &[Fr],
    bp_commitments: &[BpG1],
    c_u_hex: &str,
    c_y_hex: &str,
    c_d_hex: &str,
    proof: &LinkProof,
    layout: LinkLayout,
) -> Result<(), String> {
    let emit_timing = verify_timing_enabled();
    let shape_start = Instant::now();
    let expected_len = match layout {
        LinkLayout::Full { m } => 3 * m + 1,
        LinkLayout::ZeroTest { m } => 3 * m,
    };
    if proof.s_values.len() != expected_len
        || proof.s_bp_blinds.len() != expected_len
        || proof.r_bp.len() != expected_len
    {
        return Err("link proof vector length mismatch".to_string());
    }
    emit_bp_timing(emit_timing, "verify_link_shape_checks", shape_start);

    let challenge_start = Instant::now();
    let challenge = link_challenge(
        deltas,
        bp_commitments,
        c_u_hex,
        c_y_hex,
        c_d_hex,
        &proof.r_bp,
        &proof.r_u_ext,
        &proof.r_y_ext,
        &proof.r_d_ext,
    )?;
    let challenge_bp = fr_to_bp_scalar(&challenge)?;
    emit_bp_timing(emit_timing, "verify_link_challenge", challenge_start);

    let bp_commitment_equations_start = Instant::now();
    verify_bp_commitment_equations_batched(
        bp_commitments,
        &proof.r_bp,
        &proof.s_values,
        &proof.s_bp_blinds,
        challenge,
        challenge_bp,
        b"update-link",
    )?;
    emit_bp_timing(
        emit_timing,
        "verify_link_bp_commitment_batch",
        bp_commitment_equations_start,
    );

    let parse_external_start = Instant::now();
    let c_u = point_g1_from_hex(c_u_hex)?;
    let c_y = if c_y_hex.is_empty() {
        ArkG1::zero()
    } else {
        point_g1_from_hex(c_y_hex)?
    };
    let c_d = if c_d_hex.is_empty() {
        ArkG1::zero()
    } else {
        point_g1_from_hex(c_d_hex)?
    };
    emit_bp_timing(
        emit_timing,
        "verify_link_parse_external_points",
        parse_external_start,
    );

    let c_u_start = Instant::now();
    let lhs_u = external_u_commit(link_u_values(&proof.s_values, &layout), proof.s_r_u);
    let rhs_u = proof.r_u_ext + c_u.mul_bigint(challenge.into_bigint());
    if lhs_u != rhs_u {
        return Err("link proof C_U equation failed".to_string());
    }
    emit_bp_timing(emit_timing, "verify_link_c_u_equation", c_u_start);

    match layout {
        LinkLayout::Full { .. } | LinkLayout::ZeroTest { .. } => {
            let c_y_start = Instant::now();
            let lhs_y = external_y_commit(
                srs,
                x_values,
                link_y_values(&proof.s_values, &layout),
                proof.s_rho_y,
                None,
            )?;
            let rhs_y = proof.r_y_ext + c_y.mul_bigint(challenge.into_bigint());
            if lhs_y != rhs_y {
                return Err("link proof C_Y equation failed".to_string());
            }
            emit_bp_timing(emit_timing, "verify_link_c_y_equation", c_y_start);
        }
    }

    match layout {
        LinkLayout::Full { m } => {
            let c_d_start = Instant::now();
            let lhs_d = external_d_commit(proof.s_values[3 * m], proof.s_r_d);
            let rhs_d = proof.r_d_ext + c_d.mul_bigint(challenge.into_bigint());
            if lhs_d != rhs_d {
                return Err("link proof C_D equation failed".to_string());
            }
            emit_bp_timing(emit_timing, "verify_link_c_d_equation", c_d_start);
        }
        LinkLayout::ZeroTest { .. } => {
            if c_d != ArkG1::zero() || proof.r_d_ext != ArkG1::zero() {
                return Err("zero-test link proof expected empty C_D".to_string());
            }
        }
    }

    Ok(())
}

fn flatten_values(witness: &UpdateWitness) -> Vec<Fr> {
    let mut values = Vec::with_capacity(witness.u_values.len() * 3 + 1);
    values.extend_from_slice(&witness.u_values);
    values.extend_from_slice(&witness.y_values);
    values.extend_from_slice(&witness.z_values);
    values.push(common::crypto::scalar_from_i128(witness.d_value));
    values
}

fn flatten_zero_test_values(witness: &UpdateWitness) -> Vec<Fr> {
    let mut values = Vec::with_capacity(witness.u_values.len() * 3);
    values.extend_from_slice(&witness.u_values);
    values.extend_from_slice(&witness.y_values);
    values.extend_from_slice(&witness.z_values);
    values
}

fn direct_committed_input_generators(wire_capacity: usize, m: usize) -> Result<Vec<BpG1>, String> {
    if 2 * m > wire_capacity {
        return Err("direct committed-input link capacity is too small".to_string());
    }
    let bp_gens = bulletproof_gens(wire_capacity);
    let mut generators = bp_gens
        .share(0)
        .G(wire_capacity)
        .copied()
        .chain(bp_gens.share(0).H(wire_capacity).copied())
        .collect::<Vec<_>>();
    let u_generators = bp_gens.share(2).G(m).copied().collect::<Vec<_>>();
    let y_generators = crate::multizkopen::evaluation_generators(m)
        .iter()
        .map(ark_g1_to_bp)
        .collect::<Result<Vec<_>, _>>()?;
    for j in 0..m {
        // a_L[2j] is u_j and a_R[2j] is the first copy of y_j.
        generators[2 * j] += u_generators[j];
        generators[wire_capacity + 2 * j] += y_generators[j];
    }
    // D_Y uses an independent blinding base. Treat r_Y as an additional
    // committed coordinate in the link IPA instead of folding it into the
    // Bulletproof blinding scalar.
    generators.push(ark_g1_to_bp(
        &crate::multizkopen::evaluation_blinding_generator(),
    )?);
    let padded_len = generators.len().next_power_of_two();
    while generators.len() < padded_len {
        generators.push(ark_g1_to_bp(&derive_generator(
            "update-committed-input-link-padding",
            generators.len(),
        ))?);
    }
    Ok(generators)
}

#[allow(clippy::too_many_arguments)]
fn prove_committed_input_link_ipa(
    bp_proof: &R1CSProof,
    opening: &PhaseOneWitnessCommitmentOpening,
    witness: &UpdateWitness,
    wire_capacity: usize,
    deltas: &[Delta],
    c_u_hex: &str,
    d_y_hex: &str,
    r_u: Fr,
    r_y: Fr,
    bp_proof_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    let n = deltas
        .len()
        .checked_mul(2)
        .ok_or_else(|| "direct link vector length overflow".to_string())?;
    if opening.a_l().len() != n || opening.a_r().len() != n {
        return Err("R1CS phase-one opening length mismatch".to_string());
    }
    for j in 0..deltas.len() {
        if opening.a_l()[2 * j] != fr_to_bp_scalar(&witness.u_values[j])?
            || opening.a_r()[2 * j] != fr_to_bp_scalar(&witness.y_values[j])?
        {
            return Err("Bulletproof wires differ from D_Y/C_U committed inputs".to_string());
        }
    }
    let generators = direct_committed_input_generators(wire_capacity, deltas.len())?;
    let mut opening_values = opening.a_l().to_vec();
    opening_values.resize(wire_capacity, BpScalar::ZERO);
    let mut right = opening.a_r().to_vec();
    right.resize(wire_capacity, BpScalar::ZERO);
    opening_values.extend(right);
    opening_values.push(fr_to_bp_scalar(&r_y)?);
    opening_values.resize(generators.len(), BpScalar::ZERO);

    let c_u = ark_g1_to_bp(&point_g1_from_hex(c_u_hex)?)?;
    let d_y = ark_g1_to_bp(&point_g1_from_hex(d_y_hex)?)?;
    let commitment = bp_proof.phase_one_input_commitment() + c_u + d_y;
    let blind = opening.blinding() + fr_to_bp_scalar(&r_u)?;
    let public_vector = vec![BpScalar::ZERO; generators.len()];
    let mut transcript = Transcript::new(b"dynamic-poa-direct-committed-input-link-v1");
    append_committed_input_link_public(&mut transcript, deltas, c_u_hex, d_y_hex, bp_proof_bytes);
    let proof = LinearProof::create(
        &mut transcript,
        rand::rngs::OsRng,
        &commitment,
        blind,
        opening_values,
        public_vector,
        generators,
        &pedersen_gens().B,
        &pedersen_gens().B_blinding,
    )
    .map_err(|err| format!("committed-input link IPA prove: {err}"))?;
    Ok(proof.to_bytes())
}

fn verify_committed_input_link_ipa(
    bp_proof: &R1CSProof,
    wire_capacity: usize,
    deltas: &[Delta],
    c_u_hex: &str,
    d_y_hex: &str,
    proof_bytes: &[u8],
    bp_proof_bytes: &[u8],
) -> Result<(), String> {
    let generators = direct_committed_input_generators(wire_capacity, deltas.len())?;
    let expected_size = 112 + 96 * generators.len().trailing_zeros() as usize;
    if proof_bytes.len() != expected_size {
        return Err(format!(
            "committed-input link IPA length mismatch: got {}, expected {expected_size}",
            proof_bytes.len()
        ));
    }
    let proof = LinearProof::from_bytes(proof_bytes)
        .map_err(|err| format!("committed-input link IPA parse: {err}"))?;
    let c_u = ark_g1_to_bp(&point_g1_from_hex(c_u_hex)?)?;
    let d_y = ark_g1_to_bp(&point_g1_from_hex(d_y_hex)?)?;
    let commitment = bp_proof.phase_one_input_commitment() + c_u + d_y;
    let public_vector = vec![BpScalar::ZERO; generators.len()];
    let mut transcript = Transcript::new(b"dynamic-poa-direct-committed-input-link-v1");
    append_committed_input_link_public(&mut transcript, deltas, c_u_hex, d_y_hex, bp_proof_bytes);
    proof
        .verify(
            &mut transcript,
            &commitment,
            &generators,
            &pedersen_gens().B,
            &pedersen_gens().B_blinding,
            public_vector,
        )
        .map_err(|err| format!("committed-input link IPA verify: {err}"))
}

fn append_committed_input_link_public(
    transcript: &mut Transcript,
    deltas: &[Delta],
    c_u_hex: &str,
    d_y_hex: &str,
    bp_proof_bytes: &[u8],
) {
    transcript.append_message(b"C_U", c_u_hex.as_bytes());
    transcript.append_message(b"D_Y", d_y_hex.as_bytes());
    transcript.append_message(b"r1cs-proof", bp_proof_bytes);
    for delta in deltas {
        transcript.append_message(b"addr", delta.address.as_bytes());
        transcript.append_message(b"delta", &delta.delta.to_le_bytes());
    }
}

fn external_u_commit(values: &[Fr], blind: Fr) -> ArkG1 {
    commit_membership_vector(values, blind)
        .expect("membership vector commitment conversion must succeed")
}

fn external_d_commit(value: Fr, blind: Fr) -> ArkG1 {
    crate::commitment::derive_generator("balance-v", 0).mul_bigint(value.into_bigint())
        + crate::commitment::derive_generator("balance-h", 0).mul_bigint(blind.into_bigint())
}

fn external_eval_commit(value: Fr, blind: Fr) -> ArkG1 {
    derive_generator("eval-v", 0).mul_bigint(value.into_bigint())
        + derive_generator("eval-h", 0).mul_bigint(blind.into_bigint())
}

fn external_y_commit(
    srs: &Srs,
    x_values: &[Fr],
    values: &[Fr],
    blind: Fr,
    query_ctx: Option<&QueryContext>,
) -> Result<ArkG1, String> {
    let owned_ctx;
    let ctx = match query_ctx {
        Some(ctx) => ctx,
        None => {
            owned_ctx = QueryContext::new(x_values)?;
            &owned_ctx
        }
    };
    let z_poly = ctx.z_poly().clone();
    let i_poly = ctx.interpolate(values)?;
    let j_poly = i_poly.add(&z_poly.mul_scalar(blind));
    commit_g1(srs, &j_poly)
}

fn link_u_values<'a>(values: &'a [Fr], layout: &LinkLayout) -> &'a [Fr] {
    match layout {
        LinkLayout::Full { m } => &values[0..*m],
        LinkLayout::ZeroTest { m } => &values[0..*m],
    }
}

fn link_y_values<'a>(values: &'a [Fr], layout: &LinkLayout) -> &'a [Fr] {
    match layout {
        LinkLayout::Full { m } => &values[*m..2 * *m],
        LinkLayout::ZeroTest { m } => &values[*m..2 * *m],
    }
}

fn append_insert_public_to_transcript(
    transcript: &mut Transcript,
    zeta: Fr,
    c_x: &str,
    c_beta: &str,
    c_y_x: &str,
    c_y: &str,
    c_y_prime: &str,
    c_q: &str,
    old_balance_commitment: &str,
    new_balance_commitment: &str,
) -> Result<(), String> {
    transcript.append_message(b"dom-sep", b"dynamic-poa-insert-relation");
    transcript.append_message(b"zeta", scalar_to_hex(&zeta)?.as_bytes());
    transcript.append_message(b"C_x", c_x.as_bytes());
    transcript.append_message(b"C_beta", c_beta.as_bytes());
    transcript.append_message(b"C_y_x", c_y_x.as_bytes());
    transcript.append_message(b"C_y", c_y.as_bytes());
    transcript.append_message(b"C_y_prime", c_y_prime.as_bytes());
    transcript.append_message(b"C_q", c_q.as_bytes());
    transcript.append_message(b"C_old_balance", old_balance_commitment.as_bytes());
    transcript.append_message(b"C_new_balance", new_balance_commitment.as_bytes());
    Ok(())
}

fn append_zero_test_public_to_transcript(
    transcript: &mut Transcript,
    c_u: &str,
    c_y: &str,
    deltas: &[Delta],
) {
    append_public_to_transcript(transcript, c_u, c_y, "", deltas);
}

fn append_direct_zero_test_public_to_transcript(
    transcript: &mut Transcript,
    old_state_root: &str,
    new_state_root: &str,
    accumulator_hex: &str,
    old_balance_commitment_hex: &str,
    new_balance_commitment_hex: &str,
    c_u: &str,
    d_y: &str,
    c_d: &str,
    deltas: &[Delta],
) {
    transcript.append_message(b"dom-sep", b"dynamic-poa-direct-multizkopen-zero-test-v1");
    transcript.append_u64(b"m", deltas.len() as u64);
    transcript.append_message(b"old-root", old_state_root.as_bytes());
    transcript.append_message(b"new-root", new_state_root.as_bytes());
    transcript.append_message(b"accumulator", accumulator_hex.as_bytes());
    transcript.append_message(b"old-C", old_balance_commitment_hex.as_bytes());
    transcript.append_message(b"new-C", new_balance_commitment_hex.as_bytes());
    transcript.append_message(b"C_U", c_u.as_bytes());
    transcript.append_message(b"D_Y", d_y.as_bytes());
    transcript.append_message(b"C_D", c_d.as_bytes());
    for delta in deltas {
        transcript.append_message(b"addr", delta.address.as_bytes());
        transcript.append_message(b"delta", &delta.delta.to_le_bytes());
    }
}

fn append_projection_ipa_public(
    transcript: &mut Transcript,
    c_u: &str,
    c_d: &str,
    deltas: &[Delta],
) {
    transcript.append_message(b"dom-sep", b"dynamic-poa-projection-ipa-v1");
    transcript.append_u64(b"m", deltas.len() as u64);
    transcript.append_message(b"C_U", c_u.as_bytes());
    transcript.append_message(b"C_D", c_d.as_bytes());
    for delta in deltas {
        transcript.append_message(b"addr", delta.address.as_bytes());
        transcript.append_message(b"delta", &delta.delta.to_le_bytes());
    }
}

fn append_public_to_transcript(
    transcript: &mut Transcript,
    c_u: &str,
    c_y: &str,
    c_d: &str,
    deltas: &[Delta],
) {
    transcript.append_message(b"dom-sep", b"dynamic-poa-update-relation-v2");
    transcript.append_u64(b"m", deltas.len() as u64);
    transcript.append_message(b"C_U", c_u.as_bytes());
    transcript.append_message(b"C_Y", c_y.as_bytes());
    transcript.append_message(b"C_D", c_d.as_bytes());
    for delta in deltas {
        transcript.append_message(b"addr", delta.address.as_bytes());
        transcript.append_message(b"delta", &delta.delta.to_le_bytes());
    }
}

fn link_challenge(
    deltas: &[Delta],
    bp_commitments: &[BpG1],
    c_u_hex: &str,
    c_y_hex: &str,
    c_d_hex: &str,
    r_bp: &[BpG1],
    r_u_ext: &ArkG1,
    r_y_ext: &ArkG1,
    r_d_ext: &ArkG1,
) -> Result<Fr, String> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"dynamic-poa-link-proof-v2");
    hasher.update(c_u_hex.as_bytes());
    hasher.update(c_y_hex.as_bytes());
    hasher.update(c_d_hex.as_bytes());
    for delta in deltas {
        hasher.update(delta.address.as_bytes());
        hasher.update(&delta.delta.to_le_bytes());
    }
    for point in bp_commitments {
        hasher.update(&point.to_affine().to_compressed());
    }
    for point in r_bp {
        hasher.update(&point.to_affine().to_compressed());
    }
    append_ark_g1_bytes(&mut hasher, r_u_ext)?;
    append_ark_g1_bytes(&mut hasher, r_y_ext)?;
    append_ark_g1_bytes(&mut hasher, r_d_ext)?;
    let digest = hasher.finalize();
    Ok(Fr::from_le_bytes_mod_order(digest.as_bytes()))
}

fn verify_bp_commitment_equations_batched(
    bp_commitments: &[BpG1],
    r_bp: &[BpG1],
    s_values: &[Fr],
    s_bp_blinds: &[BpScalar],
    challenge: Fr,
    challenge_bp: BpScalar,
    domain: &[u8],
) -> Result<(), String> {
    let len = bp_commitments.len();
    if len == 0 || r_bp.len() != len || s_values.len() != len || s_bp_blinds.len() != len {
        return Err("batched BP commitment equation length mismatch".to_string());
    }

    let gamma = bp_commitment_batch_challenge(
        domain,
        challenge,
        bp_commitments,
        r_bp,
        s_values,
        s_bp_blinds,
    );
    let mut weight = BpScalar::ONE;
    let mut aggregated_value = BpScalar::ZERO;
    let mut aggregated_blind = BpScalar::ZERO;
    let msm_len = len
        .checked_mul(2)
        .ok_or_else(|| "batched BP commitment length overflow".to_string())?;
    let mut msm_points = Vec::with_capacity(msm_len);
    let mut msm_scalars = Vec::with_capacity(msm_len);

    for index in 0..len {
        aggregated_value += weight * fr_to_bp_scalar(&s_values[index])?;
        aggregated_blind += weight * s_bp_blinds[index];
        msm_points.push(r_bp[index]);
        msm_scalars.push(weight);
        msm_points.push(bp_commitments[index]);
        msm_scalars.push(weight * challenge_bp);
        weight *= gamma;
    }

    let lhs = pedersen_gens().commit(aggregated_value, aggregated_blind);
    let rhs = BpG1::sum_of_products(&msm_points, &msm_scalars);
    if lhs != rhs {
        return Err("batched link proof BP commitment equation failed".to_string());
    }
    Ok(())
}

fn bp_commitment_batch_challenge(
    domain: &[u8],
    challenge: Fr,
    bp_commitments: &[BpG1],
    r_bp: &[BpG1],
    s_values: &[Fr],
    s_bp_blinds: &[BpScalar],
) -> BpScalar {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"dynamic-poa-link-bp-batch-v1");
    hasher.update(domain);
    hasher.update(&(bp_commitments.len() as u64).to_le_bytes());
    hasher.update(&challenge.into_bigint().to_bytes_le());
    for point in bp_commitments {
        hasher.update(&point.to_affine().to_compressed());
    }
    for point in r_bp {
        hasher.update(&point.to_affine().to_compressed());
    }
    for value in s_values {
        hasher.update(&value.into_bigint().to_bytes_le());
    }
    for blind in s_bp_blinds {
        hasher.update(blind.to_repr().as_ref());
    }

    let mut wide = [0u8; 64];
    hasher.finalize_xof().fill(&mut wide);
    let gamma = BpScalar::from_bytes_wide(&wide);
    if gamma == BpScalar::ZERO {
        BpScalar::ONE
    } else {
        gamma
    }
}

fn prove_insert_link(
    bp_commitments: &[BpG1],
    values: &[Fr],
    bp_blinds: &[BpScalar],
    c_x_hex: &str,
    c_beta_hex: &str,
    c_y_x_hex: &str,
    c_y_hex: &str,
    c_y_prime_hex: &str,
    c_q_hex: &str,
    old_balance_commitment_hex: &str,
    new_balance_commitment_hex: &str,
    r_x: Fr,
    r_beta: Fr,
    r_y_x: Fr,
    r_y: Fr,
    r_y_prime: Fr,
    r_q: Fr,
    r_ins: Fr,
) -> Result<String, String> {
    if values.len() != insert_shape().witness_len || bp_commitments.len() != values.len() {
        return Err("insert link witness length mismatch".to_string());
    }
    let mut r_bp = Vec::with_capacity(values.len());
    let mut r_ext = Vec::with_capacity(7);
    let mut a_values = Vec::with_capacity(values.len());
    let mut a_bp_blinds = Vec::with_capacity(values.len());
    let mut a_ext_blinds = Vec::with_capacity(7);
    let pc_gens = pedersen_gens();
    let mut rng = rand::rngs::OsRng;
    for _ in 0..values.len() {
        let a_value = Fr::rand(&mut rng);
        let a_bp_blind = BpScalar::random(&mut rng);
        r_bp.push(pc_gens.commit(fr_to_bp_scalar(&a_value)?, a_bp_blind));
        a_values.push(a_value);
        a_bp_blinds.push(a_bp_blind);
    }
    for _ in 0..7 {
        a_ext_blinds.push(Fr::rand(&mut rng));
    }
    for index in 0..6 {
        r_ext.push(external_eval_commit(a_values[index], a_ext_blinds[index]));
    }
    r_ext.push(external_d_commit(a_values[8], a_ext_blinds[6]));
    let challenge = insert_link_challenge(
        bp_commitments,
        c_x_hex,
        c_beta_hex,
        c_y_x_hex,
        c_y_hex,
        c_y_prime_hex,
        c_q_hex,
        old_balance_commitment_hex,
        new_balance_commitment_hex,
        &r_bp,
        &r_ext,
    )?;
    let challenge_bp = fr_to_bp_scalar(&challenge)?;
    let ext_blinds = [r_x, r_beta, r_y_x, r_y, r_y_prime, r_q, r_ins];
    let mut s_values = Vec::with_capacity(values.len());
    let mut s_bp_blinds = Vec::with_capacity(values.len());
    let mut s_ext_blinds = Vec::with_capacity(7);
    for index in 0..values.len() {
        s_values.push(a_values[index] + challenge * values[index]);
        s_bp_blinds.push(a_bp_blinds[index] + bp_blinds[index] * challenge_bp);
    }
    for index in 0..7 {
        s_ext_blinds.push(a_ext_blinds[index] + challenge * ext_blinds[index]);
    }
    encode_insert_link_proof(&InsertLinkProof {
        r_bp,
        r_ext,
        s_values,
        s_bp_blinds,
        s_ext_blinds,
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_insert_link(
    bp_commitments: &[BpG1],
    c_x_hex: &str,
    c_beta_hex: &str,
    c_y_x_hex: &str,
    c_y_hex: &str,
    c_y_prime_hex: &str,
    c_q_hex: &str,
    old_balance_commitment_hex: &str,
    new_balance_commitment_hex: &str,
    proof_hex: &str,
) -> Result<(), String> {
    let proof = decode_insert_link_proof(proof_hex)?;
    let expected_len = insert_shape().witness_len;
    if bp_commitments.len() != expected_len
        || proof.r_bp.len() != expected_len
        || proof.s_values.len() != expected_len
        || proof.s_bp_blinds.len() != expected_len
        || proof.r_ext.len() != 7
        || proof.s_ext_blinds.len() != 7
    {
        return Err("insert link proof vector length mismatch".to_string());
    }
    let challenge = insert_link_challenge(
        bp_commitments,
        c_x_hex,
        c_beta_hex,
        c_y_x_hex,
        c_y_hex,
        c_y_prime_hex,
        c_q_hex,
        old_balance_commitment_hex,
        new_balance_commitment_hex,
        &proof.r_bp,
        &proof.r_ext,
    )?;
    let challenge_bp = fr_to_bp_scalar(&challenge)?;
    verify_bp_commitment_equations_batched(
        bp_commitments,
        &proof.r_bp,
        &proof.s_values,
        &proof.s_bp_blinds,
        challenge,
        challenge_bp,
        b"insert-link",
    )?;
    let external_commitments = [
        point_g1_from_hex(c_x_hex)?,
        point_g1_from_hex(c_beta_hex)?,
        point_g1_from_hex(c_y_x_hex)?,
        point_g1_from_hex(c_y_hex)?,
        point_g1_from_hex(c_y_prime_hex)?,
        point_g1_from_hex(c_q_hex)?,
        point_g1_from_hex(new_balance_commitment_hex)?
            - point_g1_from_hex(old_balance_commitment_hex)?,
    ];
    for index in 0..6 {
        let lhs = external_eval_commit(proof.s_values[index], proof.s_ext_blinds[index]);
        let rhs =
            proof.r_ext[index] + external_commitments[index].mul_bigint(challenge.into_bigint());
        if lhs != rhs {
            return Err(format!(
                "insert link eval commitment equation failed at index {index}"
            ));
        }
    }
    let lhs = external_d_commit(proof.s_values[8], proof.s_ext_blinds[6]);
    let rhs = proof.r_ext[6] + external_commitments[6].mul_bigint(challenge.into_bigint());
    if lhs != rhs {
        return Err("insert link balance commitment equation failed".to_string());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_link_challenge(
    bp_commitments: &[BpG1],
    c_x_hex: &str,
    c_beta_hex: &str,
    c_y_x_hex: &str,
    c_y_hex: &str,
    c_y_prime_hex: &str,
    c_q_hex: &str,
    old_balance_commitment_hex: &str,
    new_balance_commitment_hex: &str,
    r_bp: &[BpG1],
    r_ext: &[ArkG1],
) -> Result<Fr, String> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"dynamic-poa-insert-link-proof");
    for item in [
        c_x_hex,
        c_beta_hex,
        c_y_x_hex,
        c_y_hex,
        c_y_prime_hex,
        c_q_hex,
        old_balance_commitment_hex,
        new_balance_commitment_hex,
    ] {
        hasher.update(item.as_bytes());
    }
    for point in bp_commitments {
        hasher.update(&point.to_affine().to_compressed());
    }
    for point in r_bp {
        hasher.update(&point.to_affine().to_compressed());
    }
    for point in r_ext {
        append_ark_g1_bytes(&mut hasher, point)?;
    }
    Ok(Fr::from_le_bytes_mod_order(hasher.finalize().as_bytes()))
}

fn append_ark_g1_bytes(hasher: &mut blake3::Hasher, point: &ArkG1) -> Result<(), String> {
    let mut bytes = Vec::new();
    point
        .into_affine()
        .serialize_compressed(&mut bytes)
        .map_err(|err| format!("serialize link point: {err}"))?;
    hasher.update(&bytes);
    Ok(())
}

fn derive_bp_blinds(values: &[Fr]) -> Result<Vec<BpScalar>, String> {
    let mut rng = rand::rngs::OsRng;
    Ok(values.iter().map(|_| BpScalar::random(&mut rng)).collect())
}

pub(crate) fn fr_to_bp_scalar(value: &Fr) -> Result<BpScalar, String> {
    let ark_repr = value.into_bigint().to_bytes_le();
    let mut array = [0u8; 32];
    let len = ark_repr.len().min(32);
    array[..len].copy_from_slice(&ark_repr[..len]);
    let maybe = <BpScalar as bulletproofs_bls::inner_types::PrimeField>::from_repr(array);
    if bool::from(maybe.is_some()) {
        Ok(maybe.unwrap())
    } else {
        Err("invalid scalar conversion".to_string())
    }
}

pub(crate) fn ark_g1_to_bp(point: &ArkG1) -> Result<BpG1, String> {
    ark_g1_affine_to_bp(&point.into_affine())
}

#[cfg(test)]
mod insert_link_security_tests {
    use ark_bls12_381::Fr;
    use ark_ff::{Field, One};
    use common::crypto::point_g1_to_hex;

    use super::{prove_insert_relation_logic, verify_insert_relation_logic};
    use crate::commitment::commit_balance;
    use crate::zkopen::eval_commit;

    #[test]
    fn insert_link_uses_fresh_sigma_randomness() {
        let x = Fr::from(2u64);
        let beta = Fr::from(3u64);
        let y = Fr::from(5u64);
        let zeta = Fr::from(7u64);
        let q = Fr::from(4u64);
        let y_x = y - q * (zeta - x);
        let y_prime = beta * y * (zeta - x);
        let z_x = y_x.inverse().unwrap();
        let z_beta = beta.inverse().unwrap();
        let inserted_balance = 4i128;
        let blinds = (11u64..18).map(Fr::from).collect::<Vec<_>>();
        let commitments = [x, beta, y_x, y, y_prime, q]
            .iter()
            .zip(blinds.iter())
            .map(|(value, blind)| point_g1_to_hex(&eval_commit(*value, *blind)).unwrap())
            .collect::<Vec<_>>();
        let old_balance = commit_balance(10, Fr::from(19u64));
        let new_balance = old_balance + commit_balance(inserted_balance, blinds[6]);
        let old_balance_hex = point_g1_to_hex(&old_balance).unwrap();
        let new_balance_hex = point_g1_to_hex(&new_balance).unwrap();

        let prove = || {
            prove_insert_relation_logic(
                x,
                beta,
                y_x,
                y,
                y_prime,
                q,
                z_x,
                z_beta,
                inserted_balance,
                zeta,
                blinds[0],
                blinds[1],
                blinds[2],
                blinds[3],
                blinds[4],
                blinds[5],
                blinds[6],
                &commitments[0],
                &commitments[1],
                &commitments[2],
                &commitments[3],
                &commitments[4],
                &commitments[5],
                &old_balance_hex,
                &new_balance_hex,
            )
            .unwrap()
        };
        let first = prove();
        let second = prove();
        assert_ne!(first.link_proof_hex, second.link_proof_hex);
        assert_ne!(first.bp_commitments_hex, second.bp_commitments_hex);
        for proof in [&first, &second] {
            verify_insert_relation_logic(
                zeta,
                &commitments[0],
                &commitments[1],
                &commitments[2],
                &commitments[3],
                &commitments[4],
                &commitments[5],
                &old_balance_hex,
                &new_balance_hex,
                &proof.bp_proof_hex,
                &proof.bp_commitments_hex,
                &proof.link_proof_hex,
            )
            .unwrap();
        }
        assert_eq!(y_x * z_x, Fr::one());
    }
}

fn ark_g1_affine_to_bp(point: &ArkG1Affine) -> Result<BpG1, String> {
    let mut bytes = Vec::new();
    point
        .serialize_compressed(&mut bytes)
        .map_err(|err| format!("serialize Arkworks G1 point: {err}"))?;
    if bytes.len() != 48 {
        return Err("invalid compressed Arkworks G1 length".to_string());
    }
    let mut repr = <BpG1 as GroupEncoding>::Repr::default();
    repr.as_mut().copy_from_slice(&bytes);
    let point = BpG1::from_bytes(&repr);
    if bool::from(point.is_some()) {
        Ok(point.unwrap())
    } else {
        Err("Arkworks/Bulletproof G1 conversion failed".to_string())
    }
}

pub(crate) fn bp_g1_to_ark(point: &BpG1) -> Result<ArkG1, String> {
    let bytes = point.to_affine().to_compressed();
    let mut input: &[u8] = bytes.as_ref();
    let point = ArkG1Affine::deserialize_compressed(&mut input)
        .map_err(|err| format!("Bulletproof/Arkworks G1 conversion failed: {err}"))?;
    if !input.is_empty() {
        return Err("trailing bytes in Bulletproof G1 conversion".to_string());
    }
    Ok(point.into())
}

fn bp_scalar_from_i128(value: i128) -> Result<BpScalar, String> {
    fr_to_bp_scalar(&common::crypto::scalar_from_i128(value))
}

fn bp_scalar_from_32(bytes: &[u8; 32]) -> Result<BpScalar, String> {
    let maybe = <BpScalar as bulletproofs_bls::inner_types::PrimeField>::from_repr(*bytes);
    if bool::from(maybe.is_some()) {
        Ok(maybe.unwrap())
    } else {
        Err("invalid BP scalar bytes".to_string())
    }
}

fn bp_one() -> BpScalar {
    BpScalar::ONE
}

fn verify_timing_enabled() -> bool {
    env::var("POA_VERIFY_TIMING").ok().as_deref() == Some("1")
}

fn emit_bp_timing(enabled: bool, stage: &str, start: Instant) {
    if enabled {
        eprintln!("stage={stage} millis={}", start.elapsed().as_millis());
    }
}

fn encode_bp_points(points: &[BpG1]) -> String {
    points
        .iter()
        .map(|point| hex_encode(&point.to_affine().to_compressed()))
        .collect::<Vec<_>>()
        .join(",")
}

fn decode_bp_points(raw: &str) -> Result<Vec<BpG1>, String> {
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    raw.split(',')
        .map(|item| {
            let bytes = hex_decode(item)?;
            if bytes.len() != 48 {
                return Err("invalid BP G1 compressed length".to_string());
            }
            let mut array = [0u8; 48];
            array.copy_from_slice(&bytes);
            {
                let mut repr = <BpG1 as GroupEncoding>::Repr::default();
                repr.as_mut().copy_from_slice(&array);
                let maybe = BpG1::from_bytes(&repr);
                if bool::from(maybe.is_some()) {
                    Ok(maybe.unwrap())
                } else {
                    Err("invalid BP G1 point".to_string())
                }
            }
        })
        .collect()
}

fn encode_link_proof(proof: &LinkProof) -> Result<String, String> {
    let mut parts = Vec::new();
    parts.push(encode_bp_points(&proof.r_bp));
    parts.push(point_g1_to_hex(&proof.r_u_ext)?);
    parts.push(point_g1_to_hex(&proof.r_y_ext)?);
    parts.push(point_g1_to_hex(&proof.r_d_ext)?);
    parts.push(
        proof
            .s_values
            .iter()
            .map(common::crypto::scalar_to_hex)
            .collect::<Result<Vec<_>, _>>()?
            .join(","),
    );
    parts.push(
        proof
            .s_bp_blinds
            .iter()
            .map(|scalar| hex_encode(&scalar.to_le_bytes()))
            .collect::<Vec<_>>()
            .join(","),
    );
    parts.push(common::crypto::scalar_to_hex(&proof.s_r_u)?);
    parts.push(common::crypto::scalar_to_hex(&proof.s_rho_y)?);
    parts.push(common::crypto::scalar_to_hex(&proof.s_r_d)?);
    Ok(parts.join(";"))
}

fn decode_link_proof(raw: &str, expected_len: usize) -> Result<LinkProof, String> {
    let parts = raw.split(';').collect::<Vec<_>>();
    if parts.len() != 9 {
        return Err("invalid link proof part count".to_string());
    }
    let r_bp = decode_bp_points(parts[0])?;
    let s_values = if parts[4].is_empty() {
        Vec::new()
    } else {
        parts[4]
            .split(',')
            .map(common::crypto::scalar_from_hex)
            .collect::<Result<Vec<_>, _>>()?
    };
    let s_bp_blinds = if parts[5].is_empty() {
        Vec::new()
    } else {
        parts[5]
            .split(',')
            .map(|item| {
                let bytes = hex_decode(item)?;
                if bytes.len() != 32 {
                    return Err("invalid BP scalar length".to_string());
                }
                let mut array = [0u8; 32];
                array.copy_from_slice(&bytes);
                bp_scalar_from_32(&array)
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    if r_bp.len() != expected_len
        || s_values.len() != expected_len
        || s_bp_blinds.len() != expected_len
    {
        return Err("invalid link proof vector length".to_string());
    }
    Ok(LinkProof {
        r_bp,
        r_u_ext: point_g1_from_hex(parts[1])?,
        r_y_ext: point_g1_from_hex(parts[2])?,
        r_d_ext: point_g1_from_hex(parts[3])?,
        s_values,
        s_bp_blinds,
        s_r_u: common::crypto::scalar_from_hex(parts[6])?,
        s_rho_y: common::crypto::scalar_from_hex(parts[7])?,
        s_r_d: common::crypto::scalar_from_hex(parts[8])?,
    })
}

fn encode_insert_link_proof(proof: &InsertLinkProof) -> Result<String, String> {
    let mut parts = Vec::new();
    parts.push("insertlink:v1".to_string());
    parts.push(encode_bp_points(&proof.r_bp));
    parts.push(
        proof
            .r_ext
            .iter()
            .map(point_g1_to_hex)
            .collect::<Result<Vec<_>, _>>()?
            .join(","),
    );
    parts.push(
        proof
            .s_values
            .iter()
            .map(scalar_to_hex)
            .collect::<Result<Vec<_>, _>>()?
            .join(","),
    );
    parts.push(
        proof
            .s_bp_blinds
            .iter()
            .map(|blind| hex_encode(blind.to_repr().as_ref()))
            .collect::<Vec<_>>()
            .join(","),
    );
    parts.push(
        proof
            .s_ext_blinds
            .iter()
            .map(scalar_to_hex)
            .collect::<Result<Vec<_>, _>>()?
            .join(","),
    );
    Ok(parts.join(":"))
}

fn decode_insert_link_proof(raw: &str) -> Result<InsertLinkProof, String> {
    let parts = raw.split(':').collect::<Vec<_>>();
    if parts.len() != 7 || parts[0] != "insertlink" || parts[1] != "v1" {
        return Err("invalid insert link proof encoding".to_string());
    }
    Ok(InsertLinkProof {
        r_bp: decode_bp_points(parts[2])?,
        r_ext: decode_ark_g1_points(parts[3])?,
        s_values: decode_fr_csv(parts[4])?,
        s_bp_blinds: decode_bp_scalar_csv(parts[5])?,
        s_ext_blinds: decode_fr_csv(parts[6])?,
    })
}

fn decode_ark_g1_points(raw: &str) -> Result<Vec<ArkG1>, String> {
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    raw.split(',').map(point_g1_from_hex).collect()
}

fn decode_fr_csv(raw: &str) -> Result<Vec<Fr>, String> {
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    raw.split(',')
        .map(common::crypto::scalar_from_hex)
        .collect()
}

fn decode_bp_scalar_csv(raw: &str) -> Result<Vec<BpScalar>, String> {
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    raw.split(',')
        .map(|item| {
            let bytes = hex_decode(item)?;
            if bytes.len() != 32 {
                return Err("invalid BP scalar length".to_string());
            }
            let mut array = [0u8; 32];
            array.copy_from_slice(&bytes);
            bp_scalar_from_32(&array)
        })
        .collect()
}
