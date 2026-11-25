//! The calldata-bound pending-notes commitment.
//!
//! rs-core appends the batch to the notes tree from its frontier and binds the words
//! `commitPendingNotes` hashes, `[paddedNoteIds..., currentRoot, newRoot, currentIndex,
//! newIndex]` ([`curvy_core::witness::build_bound_pending_commitment`]). Its circuit input
//! carries the challenge `x`.

use anyhow::{Context, Result, bail};
use curvy_core::calldata::bind_calldata;
use curvy_core::witness::BoundPendingCommitment;

use crate::{ArtifactCache, BoundProof, Circuit};

/// The batch of the pinned circuit, `VerifyPendingNotesCommitmentBound(256, 30)`. A commit posts
/// only its real note ids, up to this many.
pub const BATCH_SIZE: usize = 256;

/// Prove `commitment` with the pinned pending-notes circuit. A commitment whose binding is not the
/// binding of its words is refused before proving. The graph and proving key are loaded for this
/// proof alone.
pub fn prove(commitment: &BoundPendingCommitment) -> Result<BoundProof> {
    prove_using(None, commitment)
}

/// [`prove`] with the graph and proving key held by `cache`, loading them into it on the circuit's
/// first proof.
pub fn prove_cached(
    cache: &ArtifactCache,
    commitment: &BoundPendingCommitment,
) -> Result<BoundProof> {
    prove_using(Some(cache), commitment)
}

fn prove_using(
    cache: Option<&ArtifactCache>,
    commitment: &BoundPendingCommitment,
) -> Result<BoundProof> {
    if commitment.pending_note_ids.len() != BATCH_SIZE {
        bail!(
            "pending-notes commitment has a batch of {}; the pinned circuit takes {BATCH_SIZE}",
            commitment.pending_note_ids.len()
        );
    }
    let words = commitment.words();
    if bind_calldata(&words).context("bind the pending-notes commitment's words")?
        != commitment.binding
    {
        bail!("pending-notes commitment: its binding is not the binding of its words");
    }
    Circuit::pending().prove_bound_input(
        cache,
        &commitment.circuit_input_json(),
        words,
        commitment.binding,
    )
}
