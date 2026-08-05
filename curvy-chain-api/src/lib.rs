//! The Curvy chain-access seam: five capability traits, split **by capability**
//! because no single backend covers them all today.
//!
//! | trait | PoC backend | why split |
//! |---|---|---|
//! | [`TxSubmitter`]      | blokli GraphQL (primary) / direct RPC (fallback) | blokli relays today; validator may tighten (risk 4) |
//! | [`NoteIndexSource`]  | blokli GraphQL / direct `eth_getLogs` fallback    | keeps the SDK independent of index transport |
//! | [`RootAnchor`]       | **always** a direct chain read                   | the trust anchor is never delegated to an indexer |
//! | [`FeeConfigSource`]  | direct chain reads                               | mirrors the TS `fetchAggregatorFees` |
//! | [`BalanceReader`]    | direct chain reads                               | nonce/gas-price/balances for tx building & asserts |
//!
//! Everything is `#[async_trait]`; the crypto/proving stays synchronous in the SDK
//! (run under `spawn_blocking`). Types crossing the seam live in `curvy-types` — no
//! alloy or reqwest type is ever named here, so `curvy-sdk` (which depends on this
//! crate, not on any adapter) stays backend-agnostic.

use async_trait::async_trait;
use curvy_types::{
    Addr, AggregatorState, CommittedNotesEvent, CommittedNullifiersEvent, Dec, FeeConfig,
    NotesTreeSnapshot, PendingNotesEvent, RawTx, TxOutcome,
};

/// A typed chain error. Adapters map their backend-specific failures (RPC errors,
/// blokli union rejections, decode failures) onto these variants so the SDK sees one
/// error model (plan risk 9).
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    /// The backend transport failed (HTTP/RPC/connection).
    #[error("transport: {0}")]
    Transport(String),
    /// The submitted transaction was rejected before mining (blokli RpcError, validator
    /// rejection, revert-on-estimate, bad-hex, …). Carries the backend's message.
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

/// Submit a pre-signed raw transaction and wait for `confirmations` (1 on
/// anvil-localhost). The caller holds all keys and pays gas; the submitter never
/// signs. blokli's `sendTransactionSync` and direct `eth_sendRawTransaction` both fit.
#[async_trait]
pub trait TxSubmitter: Send + Sync {
    async fn submit(&self, raw: &RawTx) -> Result<TxOutcome>;

    /// A short label for the ledger (e.g. `"blokli"` / `"rpc-direct"`).
    fn backend(&self) -> &'static str;
}

/// Read Curvy's append-only note/nullifier event log. The PIX acceptance path uses
/// Blokli's persisted GraphQL history; direct `eth_getLogs` remains a fallback adapter.
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
    /// `Ok(None)` means "fold the event log instead" — the default, and what a plain
    /// `eth_getLogs` backend must answer, since deriving leaf positions is only
    /// possible from an index that tracks the tree frontier. Preferring the snapshot
    /// removes the caller's dependence on reconstructing leaf order from event
    /// arrival order; both paths still reconcile against the on-chain root, so this
    /// is a robustness improvement rather than a change of trust model.
    async fn notes_tree_snapshot(&self) -> Result<Option<NotesTreeSnapshot>> {
        Ok(None)
    }
}

/// The trust anchor: the aggregator's on-chain notes-tree state. **Always** a direct
/// chain read — never delegated to an indexer (mirrors the TS `rpcRootVerifier` seam).
#[async_trait]
pub trait RootAnchor: Send + Sync {
    async fn state(&self) -> Result<AggregatorState>;
    /// `aggregator.validNotesRoot(root)` — is this a root the aggregator will accept?
    async fn is_valid_notes_root(&self, root: &Dec) -> Result<bool>;
    /// `aggregator.noteStatus(noteId)` as its raw enum ordinal (0 UNKNOWN, 1 PENDING, 2 INCLUDED).
    async fn note_status(&self, note_id: &Dec) -> Result<u8>;
}

/// Read the fee/gas configuration the SDK must match to build a valid aggregation
/// (mirrors the TS `fetchAggregatorFees`).
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
    async fn vault_balance(&self, owner: &Addr, token_id: &Dec) -> Result<Dec>;
    async fn tx_count(&self, addr: &Addr) -> Result<u64>;
    async fn gas_price(&self) -> Result<u128>;
    async fn chain_id(&self) -> Result<u64>;
}
