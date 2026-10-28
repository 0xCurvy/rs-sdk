//! Compatibility tests for the bundled circuit profiles.
//!
//! Every profile is a calldata-bound circuit. Its assignment starts `[1, commitment, y, x]`, so
//! evaluating the graph alone checks that the words derived from an input are the words the
//! circuit commits to; proving with the pinned keys (ignored by default) checks the assignment
//! satisfies the circuit, since every proof is verified before it is returned.

use num_bigint::BigUint;
use serde_json::Value;

use curvy_core::babyjubjub::BabyJubPoint;
use curvy_core::calldata::{CalldataBinding, bind_calldata};
use curvy_core::eddsa::{ScalarSigningKey, ephemeral_pub_key};
use curvy_core::field::{Bn254Fr, Fr, fr_to_dec};
use curvy_core::imt::{Imt, IndexedMerkleTree};
use curvy_core::witness::{
    BoundPendingCommitment, KnownOwner, Note, NoteSigner, Proof, build_aggregation_with_signer,
    build_bound_pending_commitment, build_withdrawal_with_signer,
};
use curvy_witnesscalc::pix::{build_pix_aggregation_with_signer, build_pix_multi_owner_withdrawal};
use curvy_witnesscalc::{BOUND_PUBLIC_SIGNALS, Circuit, WitnessCalculator, pending, words};

const TREE_DEPTH: usize = 30;
const GAS_FEE_TREE_DEPTH: usize = 6;
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

/// The proof a zero-amount padding slot carries: the circuits skip its inclusion check.
fn padding_proof() -> Proof {
    Proof {
        leaf_index: 0,
        siblings: vec![Fr::from(0u64); TREE_DEPTH],
    }
}

/// `(siblings, root)` of a gas-fee tree holding `gas_fee` at the test token's leaf.
fn gas_fee_proof(gas_fee: Fr) -> (Vec<String>, String) {
    let mut leaves = vec![Fr::from(0u64); TOKEN_ID as usize + 1];
    leaves[TOKEN_ID as usize] = gas_fee;
    let tree = Imt::from_leaves(GAS_FEE_TREE_DEPTH, &leaves);
    let proof = tree.create_proof(TOKEN_ID as usize);
    (
        proof.siblings.iter().map(fr_to_dec).collect(),
        fr_to_dec(&tree.root()),
    )
}

fn pix_aggregation_input() -> Value {
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
    serde_json::to_value(&witness).expect("serialize PIX aggregation witness")
}

/// Seven owners and three zero-amount padding slots, as the SDK pads a withdrawal.
fn pix_withdrawal_input() -> Value {
    let keys = (0..7)
        .map(|index| scalar_key(50_000 + index))
        .collect::<Vec<_>>();
    let mut notes = keys
        .iter()
        .enumerate()
        .map(|(index, key)| note_for(*key.verifying_key(), 100 + index as u64, 500 + index as u64))
        .collect::<Vec<_>>();
    let tree = Imt::from_leaves(TREE_DEPTH, &notes.iter().map(Note::id).collect::<Vec<_>>());
    let mut proofs = (0..notes.len())
        .map(|index| proof_for(&tree, index))
        .collect::<Vec<_>>();
    let mut signers = keys
        .iter()
        .map(|key| key as &dyn NoteSigner)
        .collect::<Vec<_>>();
    while notes.len() < 10 {
        notes.push(note_for(
            *keys[0].verifying_key(),
            0,
            600 + notes.len() as u64,
        ));
        proofs.push(padding_proof());
        signers.push(&keys[0]);
    }
    let witness = build_pix_multi_owner_withdrawal(
        &notes,
        &signers,
        &proofs,
        tree.root(),
        Fr::from(0xbeefu64),
        Fr::from(TOKEN_ID),
    )
    .expect("PIX multi-owner withdrawal witness");
    serde_json::to_value(&witness).expect("serialize PIX withdrawal witness")
}

/// One real input and one padding input, three outputs (the last a zero pad) and the fee note.
fn aggregation_input() -> Value {
    let owner = scalar_key(31_337);
    let real = note_for(*owner.verifying_key(), 10_000, 700);
    let tree = Imt::from_leaves(TREE_DEPTH, &[real.id()]);
    let input_notes = vec![real, note_for(*owner.verifying_key(), 0, 701)];
    let input_proofs = vec![proof_for(&tree, 0), padding_proof()];

    let recipient = scalar_key(4_242);
    let output_notes = vec![
        note_for(*recipient.verifying_key(), 4_000, 710),
        note_for(*owner.verifying_key(), 5_990, 711),
        note_for(*owner.verifying_key(), 0, 712),
    ];
    let fee_owner = scalar_key(777);
    let fee_note = note_for(*fee_owner.verifying_key(), 10, 713);
    let gas_fee = Fr::from(10u64);
    let witness = build_aggregation_with_signer(
        &input_notes,
        &input_proofs,
        &output_notes,
        &fee_note,
        &owner,
        tree.root(),
        Fr::from(0u64),
        gas_fee,
        fee_owner.verifying_key().as_tuple(),
    )
    .expect("aggregation witness");
    let mut input = serde_json::to_value(&witness).expect("serialize aggregation witness");
    let (siblings, root) = gas_fee_proof(gas_fee);
    input["gasFeeSiblings"] = siblings.into();
    input["commitPendingNotesGasFeeRoot"] = root.into();
    input
}

/// One real input and one padding input, as the SDK withdraws a single note.
fn withdrawal_input() -> Value {
    let owner = scalar_key(8_080);
    let real = note_for(*owner.verifying_key(), 2_500, 800);
    let tree = Imt::from_leaves(TREE_DEPTH, &[real.id()]);
    let witness = build_withdrawal_with_signer(
        &[real, note_for(*owner.verifying_key(), 0, 801)],
        &owner,
        &[proof_for(&tree, 0), padding_proof()],
        tree.root(),
        Fr::from(0xcafeu64),
        Fr::from(TOKEN_ID),
    )
    .expect("withdrawal witness");
    serde_json::to_value(&witness).expect("serialize withdrawal witness")
}

/// Five notes appended to a tree that already holds three.
fn pending_commitment() -> BoundPendingCommitment {
    let committed = (1_u64..=3).map(Fr::from).collect::<Vec<_>>();
    let mut tree = IndexedMerkleTree::from_leaves(TREE_DEPTH, &committed).expect("notes tree");
    let pending_note_ids = (11_u64..=15).map(Fr::from).collect::<Vec<_>>();
    build_bound_pending_commitment(&mut tree, pending::BATCH_SIZE, &pending_note_ids)
        .expect("bound pending commitment")
}

/// `input` with the `x` its words bind to, and that binding.
fn bound_input(circuit: &Circuit, input: &Value) -> (String, CalldataBinding) {
    let words = words::from_input(circuit.layout, input).expect("calldata words");
    let binding = bind_calldata(&words).expect("bind calldata words");
    let mut input = input.clone();
    input["x"] = fr_to_dec(&binding.x).into();
    (input.to_string(), binding)
}

/// Every spend profile with an input, as the bound circuit takes it, and its binding.
fn bound_spend_inputs() -> Vec<(Circuit, String, CalldataBinding)> {
    [
        (Circuit::pix_aggregation(), pix_aggregation_input()),
        (Circuit::pix_withdrawal(), pix_withdrawal_input()),
        (Circuit::aggregation(), aggregation_input()),
        (Circuit::withdrawal(), withdrawal_input()),
    ]
    .into_iter()
    .map(|(circuit, input)| {
        let (json, binding) = bound_input(&circuit, &input);
        (circuit, json, binding)
    })
    .collect()
}

fn assert_bound(circuit: &Circuit, input_json: &str, binding: &CalldataBinding) {
    let key = circuit.key;
    let assignment = circuit
        .load_calculator()
        .unwrap_or_else(|e| panic!("{key}: {e:#}"))
        .calculate(input_json)
        .unwrap_or_else(|e| panic!("{key}: witness: {e:#}"));
    assert_eq!(assignment[0], Fr::from(1u64), "{key}: constant signal");
    assert_eq!(
        assignment[1..=BOUND_PUBLIC_SIGNALS],
        binding.public_signals(),
        "{key}: the circuit's [commitment, y, x] differ from the binding of the derived words"
    );
}

#[test]
fn every_spend_circuit_commits_to_the_derived_words() {
    for (circuit, input, binding) in bound_spend_inputs() {
        assert_bound(&circuit, &input, &binding);
    }
}

#[test]
fn the_pending_circuit_commits_to_rs_cores_words() {
    let commitment = pending_commitment();
    assert_eq!(commitment.note_ids().len(), 5);
    assert_eq!(commitment.current_note_index, 3);
    assert_eq!(commitment.new_note_index, 8);
    assert_bound(
        &Circuit::pending(),
        &commitment.circuit_input_json(),
        &commitment.binding,
    );
}

#[test]
fn words_that_disagree_with_the_circuit_change_its_commitment() {
    let circuit = Circuit::pix_withdrawal();
    let input = pix_withdrawal_input();
    // A padding slot's nullifier where the circuit publishes zero.
    let words = words::withdrawal(&input, false).expect("calldata words");
    let binding = bind_calldata(&words).expect("bind calldata words");
    let mut bound = input.clone();
    bound["x"] = fr_to_dec(&binding.x).into();
    let assignment = circuit
        .load_calculator()
        .expect("load graph")
        .calculate(&bound.to_string())
        .expect("witness");
    assert_ne!(assignment[1], binding.commitment);
}

#[test]
fn pending_prove_refuses_a_binding_that_is_not_of_its_words() {
    let mut commitment = pending_commitment();
    commitment.new_notes_root += Fr::from(1_u64);
    let error = pending::prove(&commitment).expect_err("the words no longer match the binding");
    assert!(
        format!("{error:#}").contains("not the binding of its words"),
        "{error:#}"
    );
}

/// The multi-owner withdrawal publishes 0 for a padding slot's nullifier; deriving the nullifier
/// instead gives words the circuit does not commit to.
#[test]
#[ignore = "requires the proving keys via CURVY_ZK_KEYS_DIR"]
fn prove_bound_refuses_words_the_circuit_does_not_commit_to() {
    let mut circuit = Circuit::pix_withdrawal();
    circuit.layout = words::Layout::Withdrawal {
        zero_padding_nullifiers: false,
    };
    let error = circuit
        .prove_bound(&pix_withdrawal_input())
        .expect_err("the words disagree with the circuit");
    assert!(
        format!("{error:#}").contains("not bound to its words"),
        "{error:#}"
    );
}

#[test]
fn prove_bound_refuses_a_pending_commitment() {
    let error = Circuit::pending()
        .prove_bound(&serde_json::json!({}))
        .expect_err("a pending commitment's words come from the tree");
    assert!(format!("{error:#}").contains("pending::prove"), "{error:#}");
}

/// Every pinned circuit must produce a verifiable proof bound to its words.
#[test]
#[ignore = "requires the proving keys via CURVY_ZK_KEYS_DIR"]
fn real_zkeys_prove_every_bound_profile() {
    let commitment = pending_commitment();
    let pending = pending::prove(&commitment).expect("prove and verify pending-notes commitment");
    assert_eq!(pending.binding, commitment.binding);
    assert_eq!(pending.words.len(), pending::BATCH_SIZE + 4);

    for (circuit, input) in [
        (Circuit::pix_aggregation(), pix_aggregation_input()),
        (Circuit::pix_withdrawal(), pix_withdrawal_input()),
        (Circuit::aggregation(), aggregation_input()),
        (Circuit::withdrawal(), withdrawal_input()),
    ] {
        let key = circuit.key;
        let proof = circuit
            .prove_bound(&input)
            .unwrap_or_else(|e| panic!("{key}: prove and verify: {e:#}"));
        assert_eq!(
            bind_calldata(&proof.words).expect("bind"),
            proof.binding,
            "{key}"
        );
    }
}

/// Every bundled graph must resolve and authenticate.
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

/// The slot-allocated evaluator must match the standard evaluator.
#[test]
fn sage_reproduces_every_bundled_profile() {
    let mut profiles = bound_spend_inputs()
        .into_iter()
        .map(|(circuit, input, _binding)| (circuit, input))
        .collect::<Vec<_>>();
    profiles.push((
        Circuit::pending(),
        pending_commitment().circuit_input_json(),
    ));

    for (circuit, input) in profiles {
        let key = circuit.key;
        let path = circuit
            .graph_path()
            .unwrap_or_else(|e| panic!("{key}: graph path: {e:#}"));
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
