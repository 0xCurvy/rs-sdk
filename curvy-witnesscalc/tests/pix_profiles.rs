//! Pure-Rust compatibility gates for the fixed PIX circuit profiles.

use num_bigint::BigUint;
use sha2::{Digest, Sha256};

use curvy_core::babyjubjub::BabyJubPoint;
use curvy_core::eddsa::{ScalarSigningKey, ephemeral_pub_key};
use curvy_core::field::{Bn254Fr, Fr};
use curvy_core::imt::Imt;
use curvy_core::witness::{KnownOwner, Note, NoteSigner, Proof, build_pending_commitment};
use curvy_witnesscalc::pending::to_circuit_input;
use curvy_witnesscalc::pix::{build_pix_aggregation_with_signer, build_pix_multi_owner_withdrawal};
use curvy_witnesscalc::{Circuit, WitnessCalculator};

const TREE_DEPTH: usize = 30;
const TOKEN_ID: u64 = 1;

fn scalar_key(value: u64) -> ScalarSigningKey {
    ScalarSigningKey::from_decimal(&value.to_string()).expect("valid test scalar")
}

fn note_for(owner: BabyJubPoint, amount: u64, nonce: u64) -> Note {
    KnownOwner::new(owner, Bn254Fr::from_fr(Fr::from(10_000 + nonce))).note(
        Fr::from(amount),
        Fr::from(TOKEN_ID),
        ephemeral_pub_key(&BigUint::from(20_000 + nonce)),
        Fr::from(nonce & 0xff),
    )
}

fn proof_for(tree: &Imt, index: usize) -> Proof {
    let proof = tree.create_proof(index);
    Proof {
        leaf_index: proof.index as u64,
        siblings: proof.siblings,
    }
}

fn pix_aggregation_input() -> String {
    let owner = scalar_key(42_424_242);
    let input_notes = vec![
        note_for(*owner.verifying_key(), 10_000, 1),
        note_for(*owner.verifying_key(), 10_000, 2),
    ];
    let tree = Imt::from_leaves(
        TREE_DEPTH,
        &input_notes.iter().map(Note::id).collect::<Vec<_>>(),
    );
    let input_proofs = (0..input_notes.len())
        .map(|index| proof_for(&tree, index))
        .collect::<Vec<_>>();

    let mut output_notes = (0..8)
        .map(|index| {
            let recipient = scalar_key(1_000 + index);
            note_for(*recipient.verifying_key(), 1_000, 100 + index)
        })
        .collect::<Vec<_>>();
    output_notes.push(note_for(*owner.verifying_key(), 11_990, 300));

    let fee_owner = scalar_key(777);
    let fee_note = note_for(*fee_owner.verifying_key(), 10, 301);
    let witness = build_pix_aggregation_with_signer(
        &input_notes,
        &input_proofs,
        &output_notes,
        &fee_note,
        &owner,
        tree.root(),
        Fr::from(0u64),
        Fr::from(10u64),
        fee_owner.verifying_key().as_tuple(),
    )
    .expect("PIX aggregation witness");
    serde_json::to_string(&witness).expect("serialize PIX aggregation witness")
}

fn pix_withdrawal_input() -> String {
    let keys = (0..10)
        .map(|index| scalar_key(50_000 + index))
        .collect::<Vec<_>>();
    let notes = keys
        .iter()
        .enumerate()
        .map(|(index, key)| note_for(*key.verifying_key(), 100 + index as u64, 500 + index as u64))
        .collect::<Vec<_>>();
    let tree = Imt::from_leaves(TREE_DEPTH, &notes.iter().map(Note::id).collect::<Vec<_>>());
    let proofs = (0..notes.len())
        .map(|index| proof_for(&tree, index))
        .collect::<Vec<_>>();
    let signers = keys
        .iter()
        .map(|key| key as &dyn NoteSigner)
        .collect::<Vec<_>>();
    let witness = build_pix_multi_owner_withdrawal(
        &notes,
        &signers,
        &proofs,
        tree.root(),
        Fr::from(0xbeefu64),
        Fr::from(TOKEN_ID),
    )
    .expect("PIX multi-owner withdrawal witness");
    serde_json::to_string(&witness).expect("serialize PIX withdrawal witness")
}

fn pending_input() -> String {
    let tree = Imt::new(TREE_DEPTH);
    let pending_note_ids = (1_u64..=5).map(Fr::from).collect::<Vec<_>>();
    let witness = build_pending_commitment(&tree, TREE_DEPTH, 5, &pending_note_ids);
    to_circuit_input(&witness).expect("pending circuit input").0
}

#[test]
fn real_pix_aggregation_graph_accepts_two_to_nine_witness() {
    let assignment = Circuit::pix_aggregation()
        .load_calculator()
        .expect("load pinned PIX aggregation graph")
        .calculate(&pix_aggregation_input())
        .expect("calculate PIX aggregation witness");
    assert!(assignment.len() > 67);
}

#[test]
fn real_pix_withdrawal_graph_accepts_ten_unrelated_owners() {
    let assignment = Circuit::pix_withdrawal()
        .load_calculator()
        .expect("load pinned PIX withdrawal graph")
        .calculate(&pix_withdrawal_input())
        .expect("calculate PIX withdrawal witness");
    assert!(assignment.len() > 14);
    assert_eq!(assignment[1], Fr::from(1_045u64));
}

/// Every circuit the PIX flow proves, driven all the way to a self-verifying Groth16
/// proof off the CVYWIT assignment. The equivalence tests above show the assignment is
/// right; this shows the deployed proving keys still accept it.
#[test]
#[ignore = "requires the evaluation zkeys via CURVY_ZK_KEYS_DIR"]
fn real_evaluation_zkeys_prove_every_pix_flow_profile() {
    let pending = Circuit::pending()
        .prove(&pending_input())
        .expect("prove and verify pending-notes commitment");
    assert_eq!(pending.public_signals.len(), 1);

    let aggregation = Circuit::pix_aggregation()
        .prove(&pix_aggregation_input())
        .expect("prove and verify PIX aggregation");
    assert_eq!(aggregation.public_signals.len(), 67);

    let withdrawal = Circuit::pix_withdrawal()
        .prove(&pix_withdrawal_input())
        .expect("prove and verify PIX multi-owner withdrawal");
    assert_eq!(withdrawal.public_signals.len(), 14);
}

/// The two evaluators must agree, signal for signal.
///
/// Production now evaluates the Curvy-owned `CVYWIT01` graphs. That is only safe if
/// they reproduce the iden3 `circom-witnesscalc` graphs exactly: the assignment feeds
/// Groth16 directly, so a single differing signal is a proof the deployed verifier
/// rejects - and the two graphs are built by different toolchains from the same
/// circuit, which is precisely the kind of divergence nothing else would catch.
///
/// `circom-witnesscalc` is a dev-dependency only, so it is the *reference* here and
/// never ships.
fn assert_evaluators_agree(circuit: Circuit, input: &str, iden3_graph: &str, iden3_sha256: &str) {
    let reference = iden3_assignment(iden3_graph, iden3_sha256, input);
    let candidate = circuit
        .load_calculator()
        .expect("load pinned CVYWIT01 graph")
        .calculate(input)
        .expect("CVYWIT01 witness");

    assert_eq!(
        candidate.len(),
        reference.len(),
        "assignment length differs between the two evaluators"
    );
    assert_eq!(
        candidate, reference,
        "the two evaluators disagree on at least one signal"
    );
}

/// Evaluate one input against a pinned iden3 graph, the independent reference.
fn iden3_assignment(graph_name: &str, expected_sha256: &str, input: &str) -> Vec<Fr> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../artifacts/graphs")
        .join(graph_name);
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("read iden3 reference graph {}: {e}", path.display()));
    let actual = hex::encode(Sha256::digest(&bytes));
    assert_eq!(
        actual,
        expected_sha256,
        "stale iden3 reference graph at {} - a wrong reference would make this \
         comparison meaningless",
        path.display()
    );
    let wtns = circom_witnesscalc::calc_witness(input, &bytes).expect("iden3 witness");
    curvy_prover::wtns::read_wtns(&wtns).expect("decode iden3 wtns")
}

/// Every bundled graph pin must resolve and authenticate. Cheap, and it catches a
/// stale/misnamed artifact before a run reaches the chain.
#[test]
fn every_bundled_graph_pin_resolves() {
    for circuit in [
        Circuit::withdrawal(),
        Circuit::aggregation(),
        Circuit::pix_aggregation(),
        Circuit::pix_withdrawal(),
        Circuit::pending(),
    ] {
        let key = circuit.key;
        let calculator = circuit
            .load_calculator()
            .unwrap_or_else(|e| panic!("{key}: {e:#}"));
        assert!(calculator.assignment_size() > 1, "{key}: empty assignment");
    }
}

#[test]
fn curvy_witness_reproduces_the_pix_aggregation_assignment() {
    assert_evaluators_agree(
        Circuit::pix_aggregation(),
        &pix_aggregation_input(),
        "pix-aggregation-2-9-30.graph.bin",
        "ca9e05f17773240882cd29b6fba616f798531e2f950ac0185274e027464351e6",
    );
}

#[test]
fn curvy_witness_reproduces_the_pix_withdrawal_assignment() {
    assert_evaluators_agree(
        Circuit::pix_withdrawal(),
        &pix_withdrawal_input(),
        "pix-withdrawal-10-30.graph.bin",
        "1e23f47a4c233453bc5d3a7a550e3b12eddd3b04fa786be772dc06d2cf9ebf24",
    );
}

/// The circuit that blocked the swap: it is the only one using circom's bitwise
/// operators, which the upstream generator left unimplemented.
#[test]
fn curvy_witness_reproduces_the_pending_assignment() {
    assert_evaluators_agree(
        Circuit::pending(),
        &pending_input(),
        "pending-5-30.graph.bin",
        "3cc81fe0a084c0b11bb627c564f20f1f86d5368ffa19d1d558b03c0414b5f69b",
    );
}

/// SAGE, the experimental slot-allocated evaluator, must agree with the shipped one on
/// every artifact we actually deploy, not just on synthetic graphs.
///
/// It stores one field element per *live* node rather than one per node, so the risk
/// it carries is slot recycling: a slot freed one instruction too early yields a wrong
/// assignment, not a crash. Only a full-assignment comparison catches that, and only
/// on real graphs - the recycling pattern depends on the circuit's shape.
#[test]
fn sage_reproduces_every_bundled_profile() {
    // The three profiles this crate has input builders for; they include the largest
    // graph and the only one using bitwise operators. The research harness covers the
    // two legacy profiles as well.
    for (circuit, input) in [
        (Circuit::pix_aggregation(), pix_aggregation_input()),
        (Circuit::pix_withdrawal(), pix_withdrawal_input()),
        (Circuit::pending(), pending_input()),
    ] {
        let key = circuit.key;
        let path = circuit.graph_path();
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{key}: read graph: {e}"));

        let reference = circuit
            .load_calculator()
            .unwrap_or_else(|e| panic!("{key}: {e:#}"))
            .calculate(&input)
            .unwrap_or_else(|e| panic!("{key}: default assignment: {e:#}"));

        let graph = curvy_witness::sage::SageGraph::from_bytes(&bytes, circuit.graph_sha256())
            .unwrap_or_else(|e| panic!("{key}: compile SAGE graph: {e}"));
        let candidate = graph
            .calculate_json(&input)
            .unwrap_or_else(|e| panic!("{key}: SAGE assignment: {e}"));

        assert_eq!(
            candidate, reference,
            "{key}: SAGE disagrees with the default evaluator"
        );
        assert!(
            graph.slot_count() < reference.len(),
            "{key}: {} slots is not a reduction",
            graph.slot_count()
        );
    }
}

/// CVYWIT v2 is a denser wire encoding of the same logical graph. Not published, so
/// this only runs when a v2 artifact is supplied.
#[test]
fn curvy_witness_v2_reproduces_the_pending_assignment() {
    let (Ok(path), Ok(expected_sha)) = (
        std::env::var("CURVY_PENDING_CVYWIT_V2"),
        std::env::var("CURVY_PENDING_CVYWIT_V2_SHA256"),
    ) else {
        eprintln!("skipping: set CURVY_PENDING_CVYWIT_V2 and CURVY_PENDING_CVYWIT_V2_SHA256");
        return;
    };

    let input = pending_input();
    let reference = iden3_assignment(
        "pending-5-30.graph.bin",
        "3cc81fe0a084c0b11bb627c564f20f1f86d5368ffa19d1d558b03c0414b5f69b",
        &input,
    );
    let bytes = std::fs::read(&path).expect("read CVYWIT v2 graph");
    let candidate = curvy_witness::WitnessGraph::from_bytes(&bytes, &expected_sha)
        .expect("parse CVYWIT v2 graph")
        .calculate_json(&input)
        .expect("CVYWIT v2 witness");

    assert_eq!(
        candidate, reference,
        "v2 disagrees with the iden3 reference"
    );
}
