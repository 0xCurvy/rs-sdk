//! Pending-notes commitment input normalization.
//!
//! The circuit omits `newNotesRoot` and expects `inputHash` reduced modulo the
//! BN254 scalar field.

use anyhow::{Context, Result};
use curvy_core::field::{fr_from_dec, fr_to_dec};
use curvy_core::witness::PendingCommitmentWitness;
use serde_json::Value;

/// Build circuit input JSON and return its reduced public hash.
pub fn to_circuit_input(w: &PendingCommitmentWitness) -> Result<(String, String)> {
    // Reduce the digest to a canonical field element.
    let reduced_input_hash = fr_to_dec(&fr_from_dec(&w.input_hash));

    let mut input = serde_json::to_value(w).context("serialize pending witness")?;
    let map = input
        .as_object_mut()
        .context("pending witness is an object")?;
    map.remove("newNotesRoot");
    map.insert(
        "inputHash".into(),
        Value::String(reduced_input_hash.clone()),
    );

    Ok((serde_json::to_string(&input)?, reduced_input_hash))
}
