//! The calldata words a bound circuit commits to, derived from its input.
//!
//! Each bound circuit commits to the values its aggregator entry point takes as calldata words.
//! The ones the circuit computes, nullifiers, note ids and the withdrawn amount, are recomputed
//! here from the notes in the input the way the circuit computes them; the rest are copied from the
//! input.
//!
//! A word that disagrees with the circuit's changes the proof's commitment, and
//! [`crate::Circuit::prove_bound`] refuses the proof.

use anyhow::{Context, Result, bail};
use curvy_core::field::{Fr, fr_to_dec, try_fr_from_dec};
use curvy_core::note::{note_id, nullifier, owner_hash};
use serde_json::Value;

/// How a circuit's words are laid out, and so how they are derived from its input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    /// `submitAggregationRequest`: nullifiers, output note ids with the fee note's last, five
    /// encrypted-data fields per output and fee note, notesRoot, protocolFeePerThousand,
    /// commitPendingNotesGasFeeRoot, feeNotePublicKey. Every input slot publishes its nullifier,
    /// padding included.
    Aggregation,
    /// `submitWithdrawalRequest`: withdrawnAmount, nullifiers, notesRoot, destinationAddress,
    /// tokenId. `zero_padding_nullifiers` is whether a zero-amount slot publishes 0 instead of its
    /// nullifier, as the multi-owner withdrawal does.
    Withdrawal { zero_padding_nullifiers: bool },
    /// `commitPendingNotes`: the padded batch, currentRoot, newRoot, currentIndex, newIndex. They
    /// depend on the notes tree; rs-core builds them with the input (see [`crate::pending`]).
    PendingCommitment,
}

/// One canonical decimal field element.
fn field(value: &Value, what: &str) -> Result<Fr> {
    let text = value
        .as_str()
        .with_context(|| format!("{what} is not a decimal string"))?;
    let parsed = try_fr_from_dec(text).map_err(|_| anyhow::anyhow!("{what} is not a decimal"))?;
    // The contract reads the word as written and the circuit reduces it, so they agree only on a
    // canonical value.
    if fr_to_dec(&parsed) != text {
        bail!("{what} is not a canonical field element");
    }
    Ok(parsed)
}

fn array<'a>(input: &'a Value, name: &str) -> Result<&'a Vec<Value>> {
    input
        .get(name)
        .and_then(Value::as_array)
        .with_context(|| format!("circuit input has no array {name}"))
}

fn fields(value: &Value, what: &str) -> Result<Vec<Fr>> {
    value
        .as_array()
        .with_context(|| format!("{what} is not an array"))?
        .iter()
        .enumerate()
        .map(|(index, element)| field(element, &format!("{what}[{index}]")))
        .collect()
}

/// A flat note, `[owner.x, owner.y, sharedSecret, amount, token]`.
struct FlatNote {
    owner: (Fr, Fr),
    shared_secret: Fr,
    amount: Fr,
    token: Fr,
}

impl FlatNote {
    fn parse(value: &Value, what: &str) -> Result<Self> {
        let [owner_x, owner_y, shared_secret, amount, token] = fields(value, what)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("{what} does not have five fields"))?;
        Ok(Self {
            owner: (owner_x, owner_y),
            shared_secret,
            amount,
            token,
        })
    }

    fn id(&self) -> Fr {
        note_id(
            owner_hash(self.owner, self.shared_secret),
            self.amount,
            self.token,
        )
    }

    fn nullifier(&self) -> Fr {
        nullifier(self.shared_secret, self.owner)
    }
}

fn notes(input: &Value, name: &str) -> Result<Vec<FlatNote>> {
    array(input, name)?
        .iter()
        .enumerate()
        .map(|(index, note)| FlatNote::parse(note, &format!("{name}[{index}]")))
        .collect()
}

fn named(input: &Value, name: &str) -> Result<Fr> {
    field(
        input
            .get(name)
            .with_context(|| format!("circuit input has no {name}"))?,
        name,
    )
}

fn named_pair(input: &Value, name: &str) -> Result<[Fr; 2]> {
    fields(
        input
            .get(name)
            .with_context(|| format!("circuit input has no {name}"))?,
        name,
    )?
    .try_into()
    .map_err(|_| anyhow::anyhow!("{name} does not have two fields"))
}

/// The words of an aggregation input, single or PIX.
pub fn aggregation(input: &Value) -> Result<Vec<Fr>> {
    let inputs = notes(input, "inputNotes")?;
    let outputs = notes(input, "outputNotes")?;
    let fee_note = FlatNote::parse(
        input
            .get("feeNote")
            .context("circuit input has no feeNote")?,
        "feeNote",
    )?;
    let encrypted = array(input, "encryptedNoteData")?;
    if encrypted.len() != outputs.len() + 1 {
        bail!(
            "encryptedNoteData has {} entries for {} outputs and the fee note",
            encrypted.len(),
            outputs.len()
        );
    }

    let mut words = Vec::with_capacity(inputs.len() + encrypted.len() * 6 + 5);
    words.extend(inputs.iter().map(FlatNote::nullifier));
    words.extend(outputs.iter().map(FlatNote::id));
    words.push(fee_note.id());
    for (index, entry) in encrypted.iter().enumerate() {
        let entry = fields(entry, &format!("encryptedNoteData[{index}]"))?;
        if entry.len() != 5 {
            bail!("encryptedNoteData[{index}] does not have five fields");
        }
        words.extend(entry);
    }
    words.push(named(input, "notesRoot")?);
    words.push(named(input, "protocolFeePerThousand")?);
    words.push(named(input, "commitPendingNotesGasFeeRoot")?);
    words.extend(named_pair(input, "feeNotePublicKey")?);
    Ok(words)
}

/// The words of a withdrawal input, single or multi-owner.
pub fn withdrawal(input: &Value, zero_padding_nullifiers: bool) -> Result<Vec<Fr>> {
    let inputs = notes(input, "inputNotes")?;
    let zero = Fr::from(0u64);

    let mut words = Vec::with_capacity(inputs.len() + 4);
    words.push(inputs.iter().fold(zero, |total, note| total + note.amount));
    words.extend(inputs.iter().map(|note| {
        if zero_padding_nullifiers && note.amount == zero {
            zero
        } else {
            note.nullifier()
        }
    }));
    words.push(named(input, "notesRoot")?);
    words.push(named(input, "destinationAddress")?);
    words.push(named(input, "tokenId")?);
    Ok(words)
}

/// The words of `input` for a circuit of `layout`.
pub fn from_input(layout: Layout, input: &Value) -> Result<Vec<Fr>> {
    match layout {
        Layout::Aggregation => aggregation(input),
        Layout::Withdrawal {
            zero_padding_nullifiers,
        } => withdrawal(input, zero_padding_nullifiers),
        Layout::PendingCommitment => bail!(
            "a pending-notes commitment's words depend on the notes tree; build them with \
             curvy_core::witness::build_bound_pending_commitment and prove with \
             curvy_witnesscalc::pending::prove"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn note(owner: u64, secret: u64, amount: u64, token: u64) -> Value {
        json!([
            owner.to_string(),
            (owner + 1).to_string(),
            secret.to_string(),
            amount.to_string(),
            token.to_string()
        ])
    }

    #[test]
    fn multi_owner_withdrawal_publishes_zero_for_padding() {
        let input = json!({
            "inputNotes": [note(3, 5, 100, 1), note(7, 9, 0, 1)],
            "notesRoot": "11",
            "destinationAddress": "12",
            "tokenId": "1",
        });
        let padded = withdrawal(&input, true).unwrap();
        let unpadded = withdrawal(&input, false).unwrap();
        assert_eq!(padded[0], Fr::from(100u64));
        assert_eq!(padded[1], unpadded[1]);
        assert_eq!(padded[2], Fr::from(0u64));
        assert_eq!(
            unpadded[2],
            nullifier(Fr::from(9u64), (Fr::from(7u64), Fr::from(8u64)))
        );
        assert_eq!(
            &padded[3..],
            &[Fr::from(11u64), Fr::from(12u64), Fr::from(1u64)]
        );
    }

    #[test]
    fn a_non_canonical_word_is_refused() {
        let input = json!({
            "inputNotes": [note(3, 5, 100, 1)],
            "notesRoot": "011",
            "destinationAddress": "12",
            "tokenId": "1",
        });
        let error = withdrawal(&input, false).unwrap_err();
        assert!(error.to_string().contains("canonical"), "{error}");
    }

    #[test]
    fn aggregation_needs_encrypted_data_for_every_output_and_the_fee_note() {
        let input = json!({
            "inputNotes": [note(3, 5, 100, 1)],
            "outputNotes": [note(13, 15, 60, 1)],
            "feeNote": note(23, 25, 40, 1),
            "encryptedNoteData": [["1", "2", "3", "4", "5"]],
            "notesRoot": "11",
            "protocolFeePerThousand": "0",
            "commitPendingNotesGasFeeRoot": "17",
            "feeNotePublicKey": ["23", "24"],
        });
        let error = aggregation(&input).unwrap_err();
        assert!(error.to_string().contains("fee note"), "{error}");
    }
}
