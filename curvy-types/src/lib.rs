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
