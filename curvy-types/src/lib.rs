//! Backend-neutral Curvy domain types.

use serde::{Deserialize, Serialize};

/// A field element or `uint256` as a canonical non-negative decimal string.
pub type Dec = String;

/// An EVM address as a `"0x"`-prefixed, 20-byte hex string.
pub type Addr = String;

/// A pre-signed, EIP-2718-encoded raw transaction (what blokli / `eth_sendRawTransaction` take).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawTx(pub Vec<u8>);

impl RawTx {
    /// `0x`-prefixed hex, the shape blokli's `rawTransaction` GraphQL arg wants.
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(2 + self.0.len() * 2);
        s.push_str("0x");
        for b in &self.0 {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

/// Outcome of a submitted transaction (confirmations == 1 on anvil-localhost).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOutcome {
    pub tx_hash: String,
    pub block_number: Option<u64>,
    /// `true` == mined and succeeded.
    pub status: bool,
}

/// A decoded `PendingNotes(noteIds, ephemeralKeys, viewTags, tokens, amounts, isPlaintext)`.
/// `ephemeral_keys` is `[xs, ys]` (the on-chain `uint256[][2]`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingNotesEvent {
    pub note_ids: Vec<Dec>,
    pub ephemeral_keys: [Vec<Dec>; 2],
    pub view_tags: Vec<u64>,
    pub tokens: Vec<Dec>,
    pub amounts: Vec<Dec>,
    pub is_plaintext: Vec<bool>,
    pub block_number: u64,
    pub tx_hash: String,
}

/// One note item normalized out of a [`PendingNotesEvent`].
///
/// Contracts emit pending notes as parallel arrays. This scalar representation is
/// the safer boundary for code that wants to inspect one note without querying an
/// indexer or constructing a transaction-capable client.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingNote {
    pub note_id: Dec,
    pub ephemeral_key: [Dec; 2],
    pub view_tag: u64,
    pub token: Dec,
    pub amount: Dec,
    pub is_plaintext: bool,
}

/// A pending-note event whose parallel arrays do not describe the same number of
/// notes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidPendingNotesEvent {
    pub tx_hash: String,
    pub field: &'static str,
    pub expected: usize,
    pub actual: usize,
}

impl std::fmt::Display for InvalidPendingNotesEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PendingNotes event {} has {} {} values, expected {}",
            self.tx_hash, self.actual, self.field, self.expected
        )
    }
}

impl std::error::Error for InvalidPendingNotesEvent {}

impl PendingNotesEvent {
    /// Converts the event's parallel arrays into scalar note records.
    ///
    /// The conversion fails instead of truncating when any array has a different
    /// length. This is an integrity boundary for data decoded from an indexer.
    pub fn notes(&self) -> Result<Vec<PendingNote>, InvalidPendingNotesEvent> {
        let expected = self.note_ids.len();
        for (field, actual) in [
            ("ephemeral-key x", self.ephemeral_keys[0].len()),
            ("ephemeral-key y", self.ephemeral_keys[1].len()),
            ("view-tag", self.view_tags.len()),
            ("token", self.tokens.len()),
            ("amount", self.amounts.len()),
            ("plaintext flag", self.is_plaintext.len()),
        ] {
            if actual != expected {
                return Err(InvalidPendingNotesEvent {
                    tx_hash: self.tx_hash.clone(),
                    field,
                    expected,
                    actual,
                });
            }
        }

        Ok((0..expected)
            .map(|index| PendingNote {
                note_id: self.note_ids[index].clone(),
                ephemeral_key: [
                    self.ephemeral_keys[0][index].clone(),
                    self.ephemeral_keys[1][index].clone(),
                ],
                view_tag: self.view_tags[index],
                token: self.tokens[index].clone(),
                amount: self.amounts[index].clone(),
                is_plaintext: self.is_plaintext[index],
            })
            .collect())
    }
}

/// A checkpoint-pinned snapshot of the committed notes tree.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotesTreeSnapshot {
    /// Opaque identifier of the checkpoint the leaves were read at.
    pub checkpoint: String,
    /// The notes root the backend recorded at this checkpoint, for cross-checking the
    /// locally rebuilt tree before it is reconciled against the chain.
    pub notes_root: Dec,
    /// Note ids in leaf order: position in this vector *is* the leaf index.
    pub leaves: Vec<Dec>,
}

/// A decoded `CommittedNotes(batchIndex, noteIds)`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommittedNotesEvent {
    pub batch_index: u64,
    pub note_ids: Vec<Dec>,
    pub block_number: u64,
}

/// A decoded `CommittedNullifiers(batchIndex, nullifiers)`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommittedNullifiersEvent {
    pub batch_index: u64,
    pub nullifiers: Vec<Dec>,
    pub block_number: u64,
}

/// Per-token commitment gas fees (`vault.perTokenGasFees(tokenId)`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GasFees {
    pub token_id: Dec,
    pub portal_deployment: Dec,
    pub pending_note_commitment: Dec,
    pub withdrawal: Dec,
}

/// Aggregator and vault fee configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeConfig {
    /// `vault.depositFee()` in basis points (/10000).
    pub deposit_fee_bps: u64,
    /// `vault.withdrawalFee()` in basis points (/10000).
    pub withdrawal_fee_bps: u64,
    /// `aggregator.protocolFeePerThousand()` (parts per thousand).
    pub protocol_fee_per_thousand: Dec,
    /// `aggregator.commitmentFeeRoot()` - the depth-6 per-token gas-fee tree root.
    pub commitment_fee_root: Dec,
    /// `aggregator.feeNotePublicKey(0/1)` - the protocol fee-collector BabyJubJub key.
    pub fee_note_public_key: [Dec; 2],
    /// `vault.perTokenGasFees(tokenId)` for the registered tokens (index by `token_id`).
    pub per_token_gas_fees: Vec<GasFees>,
}

impl FeeConfig {
    /// The gas fee (per-token `pendingNoteCommitment`) charged for `token_id`, the leaf
    /// value the aggregation circuit proves against `commitment_fee_root`. `"0"` if the
    /// token is not in the table.
    pub fn gas_fee_for(&self, token_id: &str) -> Dec {
        self.per_token_gas_fees
            .iter()
            .find(|g| g.token_id == token_id)
            .map(|g| g.pending_note_commitment.clone())
            .unwrap_or_else(|| "0".to_string())
    }
}

/// The on-chain `CurvyTypes.Note` tuple `(ownerHash, token, amount, ephemeralKey[2], viewTag)`
/// passed to `PortalFactory.deployShieldPortal`. All scalars are decimal strings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnchainNote {
    pub owner_hash: Dec,
    pub token: Dec,
    pub amount: Dec,
    pub ephemeral_key: [Dec; 2],
    pub view_tag: u64,
}

/// Groth16 proof in on-chain calldata order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Groth16Proof {
    pub a: [Dec; 2],
    pub b: [[Dec; 2]; 2],
    pub c: [Dec; 2],
}

/// The aggregator's live tree state.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregatorState {
    pub current_notes_root: Dec,
    pub current_note_index: u64,
    pub current_notes_batch_index: u64,
    pub current_nullifiers_batch_index: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_event_normalizes_parallel_arrays() {
        let event = PendingNotesEvent {
            note_ids: vec!["1".into(), "2".into()],
            ephemeral_keys: [vec!["3".into(), "4".into()], vec!["5".into(), "6".into()]],
            view_tags: vec![7, 8],
            tokens: vec!["9".into(), "10".into()],
            amounts: vec!["11".into(), "12".into()],
            is_plaintext: vec![false, true],
            block_number: 13,
            tx_hash: "0xabc".into(),
        };

        assert_eq!(
            event.notes().expect("valid event"),
            vec![
                PendingNote {
                    note_id: "1".into(),
                    ephemeral_key: ["3".into(), "5".into()],
                    view_tag: 7,
                    token: "9".into(),
                    amount: "11".into(),
                    is_plaintext: false,
                },
                PendingNote {
                    note_id: "2".into(),
                    ephemeral_key: ["4".into(), "6".into()],
                    view_tag: 8,
                    token: "10".into(),
                    amount: "12".into(),
                    is_plaintext: true,
                },
            ]
        );
    }

    #[test]
    fn pending_event_rejects_mismatched_parallel_arrays() {
        let event = PendingNotesEvent {
            note_ids: vec!["1".into()],
            ephemeral_keys: [vec!["2".into()], Vec::new()],
            view_tags: vec![3],
            tokens: vec!["4".into()],
            amounts: vec!["5".into()],
            is_plaintext: vec![false],
            tx_hash: "0xdef".into(),
            ..Default::default()
        };

        let error = event.notes().expect_err("invalid event must fail");
        assert_eq!(error.field, "ephemeral-key y");
        assert_eq!(error.expected, 1);
        assert_eq!(error.actual, 0);
        assert!(error.to_string().contains("0xdef"));
    }
}
