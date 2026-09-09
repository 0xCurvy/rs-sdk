//! Backend-neutral traits for Curvy chain access.
//!
//! | trait | implementations |
//! |---|---|
//! | [`TxSubmitter`] | Blokli GraphQL or direct RPC |
//! | [`NoteIndexSource`] | Blokli GraphQL or `eth_getLogs` |
//! | [`RootAnchor`] | direct contract read |
//! | [`FeeConfigSource`] | direct contract reads |
//! | [`BalanceReader`] | direct contract reads |
//!
//! Shared types live in `curvy-types`; transport-specific types stay in adapters.

use async_trait::async_trait;
use curvy_types::{
    Addr, AggregatorState, CommittedNotesEvent, CommittedNullifiersEvent, Dec, FeeConfig,
    NotesTreeSnapshot, PendingNotesEvent, RawTx, TxOutcome,
};

/// A backend-neutral chain error.
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    /// The backend transport failed (HTTP/RPC/connection).
    #[error("transport: {0}")]
    Transport(String),
    /// The raw transaction crossed the submission boundary, but the backend could not
    /// say whether it accepted/mined it (for example a sync-relay timeout).
    #[error("submission outcome unknown: {0}")]
    Ambiguous(String),
    /// The submitted transaction was rejected before mining.
    #[error("submission rejected: {0}")]
    Rejected(String),
    /// A submitted transaction mined but reverted.
    #[error("transaction reverted: {tx_hash}")]
    Reverted { tx_hash: String },
    /// The backend returned data that could not be decoded into the expected shape.
    #[error("decode: {0}")]
    Decode(String),
    /// A requested capability/endpoint is unavailable on this backend.
    #[error("unsupported: {0}")]
    Unsupported(String),
}

pub type Result<T> = std::result::Result<T, ChainError>;

/// Submit a pre-signed raw transaction and wait for confirmation.
#[async_trait]
pub trait TxSubmitter: Send + Sync {
    async fn submit(&self, raw: &RawTx) -> Result<TxOutcome>;

    /// A short label for the ledger (e.g. `"blokli"` / `"rpc-direct"`).
    fn backend(&self) -> &'static str;
}

/// Read Curvy's append-only note and nullifier event logs.
#[async_trait]
pub trait NoteIndexSource: Send + Sync {
    async fn pending_notes(&self, from_block: u64, to_block: u64)
    -> Result<Vec<PendingNotesEvent>>;
    async fn committed_notes(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<CommittedNotesEvent>>;
    async fn committed_nullifiers(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<CommittedNullifiersEvent>>;

    /// Latest block, so the sync loop has an upper bound for `eth_getLogs` ranges.
    async fn head_block(&self) -> Result<u64>;

    /// A dense, checkpoint-pinned snapshot of the committed notes tree, when the
    /// backend can serve one.
    ///
    /// `Ok(None)` instructs the caller to fold the event log instead.
    async fn notes_tree_snapshot(&self) -> Result<Option<NotesTreeSnapshot>> {
        Ok(None)
    }
}

/// The aggregator's on-chain notes-tree state.
#[async_trait]
pub trait RootAnchor: Send + Sync {
    async fn state(&self) -> Result<AggregatorState>;
    /// `aggregator.validNotesRoot(root)` - is this a root the aggregator will accept?
    async fn is_valid_notes_root(&self, root: &Dec) -> Result<bool>;
    /// `aggregator.noteStatus(noteId)` as its raw enum ordinal (0 UNKNOWN, 1 PENDING, 2 INCLUDED).
    async fn note_status(&self, note_id: &Dec) -> Result<u8>;
}

/// Read the fee configuration required to build an aggregation.
#[async_trait]
pub trait FeeConfigSource: Send + Sync {
    async fn fees(&self) -> Result<FeeConfig>;
}

/// Resolve deterministic (CREATE2 / EIP-1167) shield-portal addresses. The shield
/// flow pre-funds the portal's predicted address, then `deployShieldPortal` deploys
/// the clone (now holding that ETH) and forwards it to `autoShield`.
#[async_trait]
pub trait PortalDirectory: Send + Sync {
    /// `PortalFactory.getEntryPortalAddress(ownerHash, recovery)`.
    async fn entry_portal_address(&self, owner_hash: &Dec, recovery: &Addr) -> Result<Addr>;
    /// `PortalFactory.portalIsRegistered(portal)`.
    async fn portal_is_registered(&self, portal: &Addr) -> Result<bool>;
}

/// Read balances/nonces/gas-price for tx building and end-of-flow asserts.
#[async_trait]
pub trait BalanceReader: Send + Sync {
    async fn eth_balance(&self, addr: &Addr) -> Result<Dec>;
    /// ERC-20 balance for `owner` at `token`.
    ///
    /// Backends that only expose the chain's configured HOPR token may reject
    /// any other token address.
    async fn erc20_balance(&self, token: &Addr, owner: &Addr) -> Result<Dec> {
        let _ = (token, owner);
        Err(ChainError::Unsupported(
            "ERC-20 balance reads are not supported by this backend".to_string(),
        ))
    }
    /// `IERC20.allowance(owner, spender)`, for deciding whether an approval is still needed.
    ///
    /// Defaults to [`ChainError::Unsupported`] for the same reason as [`Self::erc20_balance`]:
    /// an indexer-backed adapter exposes the chain's own token, not arbitrary contract reads. A
    /// caller that cannot read the allowance should approve unconditionally rather than fail.
    async fn erc20_allowance(&self, token: &Addr, owner: &Addr, spender: &Addr) -> Result<Dec> {
        let _ = (token, owner, spender);
        Err(ChainError::Unsupported(
            "ERC-20 allowance reads are not supported by this backend".to_string(),
        ))
    }
    async fn vault_balance(&self, owner: &Addr, token_id: &Dec) -> Result<Dec>;
    async fn tx_count(&self, addr: &Addr) -> Result<u64>;
    async fn gas_price(&self) -> Result<u128>;
    async fn chain_id(&self) -> Result<u64>;
}
