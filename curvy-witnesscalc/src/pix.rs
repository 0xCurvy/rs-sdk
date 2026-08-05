//! Input assembly for the additive PIX circuit profiles.
//!
//! `rs-core` owns every cryptographic primitive used here. This module only
//! supplies the circuit-version-specific, fixed-arity transcript and flattened
//! signal layout from `v3-pix-circuits`.

use num_bigint::BigUint;
use serde::Serialize;

use curvy_core::cipher::encrypt_amount_token;
use curvy_core::eddsa::ScalarSignatureError;
use curvy_core::field::{Fr, fr_from_biguint, fr_to_biguint, fr_to_dec};
use curvy_core::imt::Imt;
use curvy_core::poseidon::poseidon;
use curvy_core::witness::{Note, NoteSigner, Proof};

const PIX_AGGREGATION_DOMAIN_HEX: &[u8] = b"43555256595f5049585f4147475245474154494f4e5f5631";
const PIX_WITHDRAWAL_DOMAIN_HEX: &[u8] = b"43555256595f5049585f5749544844524157414c5f5631";
const GAS_FEE_TREE_DEPTH: usize = 6;

fn pix_domain(encoded: &[u8]) -> Fr {
    let value = BigUint::parse_bytes(encoded, 16).expect("PIX domain is valid hexadecimal");
    fr_from_biguint(&value)
}

fn flat_note(note: &Note) -> Vec<String> {
    vec![
        fr_to_dec(&note.owner_pub.0),
        fr_to_dec(&note.owner_pub.1),
        fr_to_dec(&note.shared_secret),
        fr_to_dec(&note.amount),
        fr_to_dec(&note.token),
    ]
}

fn encrypted_fields(note: &Note) -> [Fr; 5] {
    let encrypted = encrypt_amount_token(
        note.amount,
        note.token,
        &fr_to_biguint(&note.shared_secret),
        (
            &fr_to_biguint(&note.ephemeral_key.0),
            &fr_to_biguint(&note.ephemeral_key.1),
        ),
    );
    [
        encrypted.encrypted_amount,
        encrypted.encrypted_token,
        note.ephemeral_key.0,
        note.ephemeral_key.1,
        note.view_tag,
    ]
}

fn flat_encrypted(note: &Note) -> Vec<String> {
    encrypted_fields(note).iter().map(fr_to_dec).collect()
}

fn flat_proof(proof: &Proof) -> Vec<String> {
    let mut fields = Vec::with_capacity(proof.siblings.len() + 1);
    fields.push(proof.leaf_index.to_string());
    fields.extend(proof.siblings.iter().map(fr_to_dec));
    fields
}

fn flat_signature(signature: curvy_core::eddsa::Signature) -> [String; 3] {
    [
        signature.s.to_string(),
        fr_to_dec(&signature.r8.0),
        fr_to_dec(&signature.r8.1),
    ]
}

fn synthetic_gas_fee_proof(token: &Fr, gas_fee: Fr) -> (Vec<String>, String) {
    let token_index: usize = fr_to_biguint(token)
        .try_into()
        .ok()
        .filter(|index: &usize| *index < (1usize << GAS_FEE_TREE_DEPTH))
        .expect("PIX token id must fit the depth-6 gas-fee tree");
    let mut leaves = vec![Fr::from(0u64); token_index + 1];
    leaves[token_index] = gas_fee;
    let proof = Imt::from_leaves(GAS_FEE_TREE_DEPTH, &leaves).create_proof(token_index);
    (
        proof.siblings.iter().map(fr_to_dec).collect(),
        fr_to_dec(&proof.root),
    )
}

/// Flat input object for `VerifyPixAggregation(2, 9, 30, 6)`.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct PixAggregationWitness {
    #[serde(rename = "inputNotes")]
    pub input_notes: Vec<Vec<String>>,
    #[serde(rename = "inputNoteInclusionProofs")]
    pub input_note_inclusion_proofs: Vec<Vec<String>>,
    #[serde(rename = "outputNotes")]
    pub output_notes: Vec<Vec<String>>,
    #[serde(rename = "publicKey")]
    pub public_key: [String; 2],
    pub signature: [String; 3],
    #[serde(rename = "feeNote")]
    pub fee_note: Vec<String>,
    #[serde(rename = "encryptedNoteData")]
    pub encrypted_note_data: Vec<Vec<String>>,
    #[serde(rename = "notesRoot")]
    pub notes_root: String,
    #[serde(rename = "protocolFeePerThousand")]
    pub protocol_fee_per_thousand: String,
    #[serde(rename = "gasFee")]
    pub gas_fee: String,
    #[serde(rename = "gasFeeSiblings")]
    pub gas_fee_siblings: Vec<String>,
    #[serde(rename = "commitPendingNotesGasFeeRoot")]
    pub commit_pending_notes_gas_fee_root: String,
    #[serde(rename = "feeNotePublicKey")]
    pub fee_note_public_key: [String; 2],
}

/// Build the fixed two-input, nine-regular-output PIX aggregation witness.
#[allow(clippy::too_many_arguments)]
pub fn build_pix_aggregation_with_signer(
    input_notes: &[Note],
    input_proofs: &[Proof],
    output_notes: &[Note],
    fee_note: &Note,
    signer: &impl NoteSigner,
    notes_root: Fr,
    protocol_fee_per_thousand: Fr,
    gas_fee: Fr,
    fee_note_public_key: (Fr, Fr),
) -> Result<PixAggregationWitness, ScalarSignatureError> {
    assert_eq!(
        input_notes.len(),
        2,
        "PIX aggregation requires two input slots"
    );
    assert_eq!(
        input_proofs.len(),
        2,
        "PIX aggregation requires two inclusion proofs"
    );
    assert_eq!(
        output_notes.len(),
        9,
        "PIX aggregation requires nine regular outputs"
    );

    let encrypted_notes = output_notes
        .iter()
        .chain(std::iter::once(fee_note))
        .collect::<Vec<_>>();
    let output_note_hash = poseidon(
        &encrypted_notes
            .iter()
            .map(|note| note.id())
            .collect::<Vec<_>>(),
    );
    let encrypted_note_data_hash = poseidon(
        &encrypted_notes
            .iter()
            .map(|note| poseidon(&encrypted_fields(note)))
            .collect::<Vec<_>>(),
    );
    let signing_hash = poseidon(&[
        pix_domain(PIX_AGGREGATION_DOMAIN_HEX),
        output_note_hash,
        encrypted_note_data_hash,
    ]);
    let signature = signer.sign(signing_hash)?;
    let public_key = signer.public_key();
    let (gas_fee_siblings, commit_pending_notes_gas_fee_root) =
        synthetic_gas_fee_proof(&input_notes[0].token, gas_fee);

    Ok(PixAggregationWitness {
        input_notes: input_notes.iter().map(flat_note).collect(),
        input_note_inclusion_proofs: input_proofs.iter().map(flat_proof).collect(),
        output_notes: output_notes.iter().map(flat_note).collect(),
        public_key: [fr_to_dec(&public_key.0), fr_to_dec(&public_key.1)],
        signature: flat_signature(signature),
        fee_note: flat_note(fee_note),
        encrypted_note_data: encrypted_notes
            .iter()
            .map(|note| flat_encrypted(note))
            .collect(),
        notes_root: fr_to_dec(&notes_root),
        protocol_fee_per_thousand: fr_to_dec(&protocol_fee_per_thousand),
        gas_fee: fr_to_dec(&gas_fee),
        gas_fee_siblings,
        commit_pending_notes_gas_fee_root,
        fee_note_public_key: [
            fr_to_dec(&fee_note_public_key.0),
            fr_to_dec(&fee_note_public_key.1),
        ],
    })
}

/// Flat input object for `VerifyPixMultiOwnerWithdrawal(10, 30)`.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct PixMultiOwnerWithdrawalWitness {
    #[serde(rename = "inputNotes")]
    pub input_notes: Vec<Vec<String>>,
    #[serde(rename = "publicKeys")]
    pub public_keys: Vec<[String; 2]>,
    #[serde(rename = "inputNoteInclusionProofs")]
    pub input_note_inclusion_proofs: Vec<Vec<String>>,
    pub signatures: Vec<[String; 3]>,
    #[serde(rename = "notesRoot")]
    pub notes_root: String,
    #[serde(rename = "destinationAddress")]
    pub destination_address: String,
    #[serde(rename = "tokenId")]
    pub token_id: String,
}

/// Build the fixed ten-slot, independently-owned PIX withdrawal witness.
pub fn build_pix_multi_owner_withdrawal(
    notes: &[Note],
    signers: &[&dyn NoteSigner],
    proofs: &[Proof],
    notes_root: Fr,
    destination_address: Fr,
    token_id: Fr,
) -> Result<PixMultiOwnerWithdrawalWitness, ScalarSignatureError> {
    assert_eq!(notes.len(), 10, "PIX withdrawal requires ten witness slots");
    assert_eq!(
        signers.len(),
        notes.len(),
        "PIX withdrawal requires one signer per slot"
    );
    assert_eq!(
        proofs.len(),
        notes.len(),
        "PIX withdrawal requires one proof per slot"
    );

    let total = notes
        .iter()
        .fold(Fr::from(0u64), |sum, note| sum + note.amount);
    let published_nullifiers = notes
        .iter()
        .map(|note| {
            if note.amount == Fr::from(0u64) {
                Fr::from(0u64)
            } else {
                note.nullifier()
            }
        })
        .collect::<Vec<_>>();
    let mut transcript = Vec::with_capacity(notes.len() + 4);
    transcript.push(pix_domain(PIX_WITHDRAWAL_DOMAIN_HEX));
    transcript.extend_from_slice(&published_nullifiers);
    transcript.push(destination_address);
    transcript.push(total);
    transcript.push(token_id);
    let message = poseidon(&transcript);

    let mut public_keys = Vec::with_capacity(signers.len());
    let mut signatures = Vec::with_capacity(signers.len());
    for (note, signer) in notes.iter().zip(signers) {
        let public_key = signer.public_key();
        assert_eq!(
            public_key, note.owner_pub,
            "PIX withdrawal signer must own its note"
        );
        public_keys.push([fr_to_dec(&public_key.0), fr_to_dec(&public_key.1)]);
        signatures.push(flat_signature(signer.sign(message)?));
    }

    Ok(PixMultiOwnerWithdrawalWitness {
        input_notes: notes.iter().map(flat_note).collect(),
        public_keys,
        input_note_inclusion_proofs: proofs.iter().map(flat_proof).collect(),
        signatures,
        notes_root: fr_to_dec(&notes_root),
        destination_address: fr_to_dec(&destination_address),
        token_id: fr_to_dec(&token_id),
    })
}
