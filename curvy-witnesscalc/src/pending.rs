//! Interim `to_circuit_input()` for the pending-notes-commitment witness.
//!
//! `curvy_core::witness::build_pending_commitment` emits a **superset** of the
//! circuit's input signals (M1 finding): it serializes a `newNotesRoot` the circuit
//! does not declare, and an `inputHash` as the RAW sha256 digest (which can exceed
//! the BN254 modulus). The deployed `VerifyPendingNotesCommitment(5,30)` declares
//! exactly `[currentNoteIndex, inputHash, currentNotesRoot, pendingNoteIds, siblings]`
//! and its `inputHash` public signal is the digest reduced mod p (the contract does
//! the same: `sha256(...) % SNARK_SCALAR_FIELD`).
//!
//! This module localizes the two adjustments (drop `newNotesRoot`, reduce
//! `inputHash`) so the SDK feeds a clean circuit input. It is the documented stopgap
//! until core grows a `to_circuit_input()` view / split struct.

use anyhow::{Context, Result};
use curvy_core::field::{fr_from_dec, fr_to_dec};
use curvy_core::witness::PendingCommitmentWitness;
use serde_json::Value;

/// Turn a `PendingCommitmentWitness` into the circuit-consumable input JSON, and
/// return `(input_json, reduced_input_hash)` — the reduced hash is also the single
/// public signal the on-chain `commitPendingNotes` recomputes.
pub fn to_circuit_input(w: &PendingCommitmentWitness) -> Result<(String, String)> {
    // Field-reduce the raw digest mod p (fr_from_dec reduces; fr_to_dec renders canonical).
    let reduced_input_hash = fr_to_dec(&fr_from_dec(&w.input_hash));

    let mut input = serde_json::to_value(w).context("serialize pending witness")?;
    let map = input
        .as_object_mut()
        .context("pending witness is an object")?;
    map.remove("newNotesRoot"); // not a circuit signal (snarkjs: "Too many values")
    map.insert(
        "inputHash".into(),
        Value::String(reduced_input_hash.clone()),
    );

    Ok((serde_json::to_string(&input)?, reduced_input_hash))
}
