//! Curvy transaction orchestration and local note-tree synchronization.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};
use curvy_core::cipher::decrypt_amount_token;
use curvy_core::eddsa::ScalarSigningKey;
use curvy_core::field::{Fr, fr_from_biguint, fr_to_biguint, fr_to_dec};
use curvy_core::imt::Imt;
use curvy_core::note::{note_id, owner_hash};
use curvy_core::stealth;
use curvy_core::witness::{
    KnownOwner, NoteSigner, Proof, SeedNoteSigner, build_aggregation, build_pending_commitment,
    build_withdrawal_with_signer,
};
use curvy_types::{FeeConfig, OnchainNote, TxOutcome};
use curvy_witnesscalc::pix::{build_pix_aggregation_with_signer, build_pix_multi_owner_withdrawal};
use num_bigint::BigUint;
use sha3::{Digest, Keccak256};

use curvy_chain_api::{
    BalanceReader, ChainError, FeeConfigSource, NoteIndexSource, PortalDirectory, RootAnchor,
    TxSubmitter,
};

use crate::account::{
    Account, Identity, OwnedNote, parse_fr_decimal, shared_secret_from_spending_pub_key,
};
use crate::send::{fee_note, seal_known_owner, seal_note, shield_net_amount, zero_pad_note};

const TREE_DEPTH: usize = 30;
const BATCH_SIZE: usize = 5;
const LEGACY_MAX_INPUTS: u64 = 2;
const LEGACY_MAX_OUTPUTS: u64 = 3;
const PIX_AGGREGATION_MAX_INPUTS: u64 = 2;
const PIX_AGGREGATION_MAX_OUTPUTS: u64 = 9;
const PIX_WITHDRAWAL_MAX_INPUTS: u64 = 10;

// Fee accessors.

/// The per-token `pendingNoteCommitment` gas fee. Tokens absent from the table are
/// `0` (see [`FeeConfig::gas_fee_for`]); a malformed entry is an error.
fn parse_gas_fee(fees: &FeeConfig, token_dec: &str) -> Result<u128> {
    fees.gas_fee_for(token_dec)
        .parse()
        .with_context(|| format!("parse pendingNoteCommitment gas fee for token {token_dec}"))
}

/// The per-token `withdrawal` gas fee that reimburses the relayer.
fn parse_withdrawal_gas(fees: &FeeConfig, token_dec: &str) -> Result<u128> {
    Ok(fees
        .per_token_gas_fees
        .iter()
        .find(|g| g.token_id == token_dec)
        .map(|g| {
            g.withdrawal
                .parse::<u128>()
                .with_context(|| format!("parse withdrawal gas fee for token {token_dec}"))
        })
        .transpose()?
        .unwrap_or(0))
}

/// `aggregator.protocolFeePerThousand()` as an integer.
fn parse_protocol_fee(fees: &FeeConfig) -> Result<u128> {
    fees.protocol_fee_per_thousand
        .parse()
        .context("parse protocolFeePerThousand")
}

// value ⇄ Fr helpers
fn u128_fr(x: u128) -> Fr {
    fr_from_biguint(&BigUint::from(x))
}
fn fr_u128(x: &Fr) -> Result<u128> {
    fr_to_biguint(x)
        .try_into()
        .context("field element does not fit in u128")
}

/// Which submitter to route a tx through.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Blokli `sendTransactionSync` (the primary protocol path).
    Blokli,
    /// direct `eth_sendRawTransaction` (the fallback / operator path).
    Direct,
}

/// A discovered note (post integrity-gate).
#[derive(Clone, Debug)]
pub struct Discovered {
    pub note_id: Fr,
    pub amount: Fr,
    pub token: Fr,
    pub shared_secret: Fr,
    pub is_plaintext: bool,
}

/// A per-tx ledger entry.
#[derive(Clone, Debug)]
pub struct TxLedger {
    pub label: String,
    pub backend: String,
    pub tx_hash: String,
}

/// A prepared shield deposit. Persist it before funding the portal.
#[derive(Clone, Debug)]
pub struct PreparedDeposit {
    pub note: OwnedNote,
    pub onchain_note: OnchainNote,
    pub portal_address: String,
    pub gross: u128,
    pub recovery: String,
}

impl PreparedDeposit {
    /// Rebuild a prepared deposit from its durable recovery record.
    pub fn from_recovery_parts(
        note: OwnedNote,
        gross: u128,
        recovery: String,
        portal_address: String,
    ) -> Self {
        let onchain_note = OnchainNote {
            owner_hash: fr_to_dec(&note.owner_hash()),
            token: fr_to_dec(&note.token),
            amount: gross.to_string(),
            ephemeral_key: [
                fr_to_dec(&note.ephemeral_key.0),
                fr_to_dec(&note.ephemeral_key.1),
            ],
            view_tag: note.view_tag as u64,
        };
        Self {
            note,
            onchain_note,
            portal_address,
            gross,
            recovery,
        }
    }
}

/// A submission whose final outcome is unknown.
#[derive(Debug)]
pub struct AmbiguousSubmission {
    pub ledger: TxLedger,
    source: ChainError,
}

impl fmt::Display for AmbiguousSubmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} submission outcome is unknown (tx {}): {}",
            self.ledger.label, self.ledger.tx_hash, self.source
        )
    }
}

impl std::error::Error for AmbiguousSubmission {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Recover the locally-known transaction identity from an ambiguous submission.
pub fn ambiguous_submission(error: &anyhow::Error) -> Option<&AmbiguousSubmission> {
    error.downcast_ref::<AmbiguousSubmission>()
}

/// An ambiguous aggregation with the outputs required for reconciliation.
#[derive(Debug)]
pub struct AmbiguousPixAggregation {
    pub result: PixAggregationResult,
    source: anyhow::Error,
}

impl fmt::Display for AmbiguousPixAggregation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "PIX aggregation outcome is unknown: {}",
            self.source
        )
    }
}

impl std::error::Error for AmbiguousPixAggregation {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

pub fn ambiguous_pix_aggregation(error: &anyhow::Error) -> Option<&AmbiguousPixAggregation> {
    error.downcast_ref::<AmbiguousPixAggregation>()
}

/// Aggregation result with every emitted note in on-chain order.
#[derive(Clone, Debug)]
pub struct PixAggregationResult {
    pub allocations: Vec<OwnedNote>,
    pub change: OwnedNote,
    /// The relayer's gas-reimbursement note, when one was requested.
    pub relayer: Option<OwnedNote>,
    pub emitted_notes: Vec<OwnedNote>,
    pub ledger: Vec<TxLedger>,
}

#[derive(Default)]
struct Storage {
    /// Committed note ids in leaf order.
    tree_leaves: Vec<Fr>,
}

/// Chain adapters used by the client.
pub struct CurvyClient {
    pub blokli: Arc<dyn TxSubmitter>,
    pub direct: Arc<dyn TxSubmitter>,
    pub notes: Arc<dyn NoteIndexSource>,
    pub anchor: Arc<dyn RootAnchor>,
    pub fees: Arc<dyn FeeConfigSource>,
    pub balances: Arc<dyn BalanceReader>,
    pub portals: Arc<dyn PortalDirectory>,
    pub aggregator: String,
    pub portal_factory: String,
    pub chain_id: u64,
    storage: Mutex<Storage>,
    /// Per-signer transaction locks.
    nonce_locks: tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl CurvyClient {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        blokli: Arc<dyn TxSubmitter>,
        direct: Arc<dyn TxSubmitter>,
        notes: Arc<dyn NoteIndexSource>,
        anchor: Arc<dyn RootAnchor>,
        fees: Arc<dyn FeeConfigSource>,
        balances: Arc<dyn BalanceReader>,
        portals: Arc<dyn PortalDirectory>,
        aggregator: String,
        portal_factory: String,
        chain_id: u64,
    ) -> Self {
        Self {
            blokli,
            direct,
            notes,
            anchor,
            fees,
            balances,
            portals,
            aggregator,
            portal_factory,
            chain_id,
            storage: Mutex::new(Storage::default()),
            nonce_locks: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    /// The aggregator's live tree state (trust anchor), as an anyhow result.
    pub async fn anchor_state(&self) -> Result<curvy_types::AggregatorState> {
        self.anchor.state().await.map_err(|e| anyhow::anyhow!(e))
    }

    /// Direct `noteStatus` read for durable orchestration/recovery layers.
    pub async fn note_status(&self, note_id: &Fr) -> Result<u8> {
        self.anchor
            .note_status(&fr_to_dec(note_id))
            .await
            .map_err(anyhow::Error::new)
    }

    /// An EOA's native balance in wei (for end-of-flow asserts).
    pub async fn eth_balance(&self, addr: &str) -> Result<u128> {
        let dec = self
            .balances
            .eth_balance(&addr.to_string())
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        dec.parse().context("parse eth balance")
    }

    fn submitter(&self, route: Route) -> &Arc<dyn TxSubmitter> {
        match route {
            Route::Blokli => &self.blokli,
            Route::Direct => &self.direct,
        }
    }

    /// Resolve submission ambiguity from note statuses.
    async fn wait_for_note_statuses(&self, note_ids: &[Fr], accepted: &[u8]) -> bool {
        for _ in 0..20 {
            let mut all_match = true;
            for note_id in note_ids {
                match self.anchor.note_status(&fr_to_dec(note_id)).await {
                    Ok(status) if accepted.contains(&status) => {}
                    _ => {
                        all_match = false;
                        break;
                    }
                }
            }
            if all_match {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        false
    }

    /// Resolve an ambiguous withdrawal response from committed nullifier events.
    async fn wait_for_nullifiers(&self, nullifiers: &[Fr]) -> bool {
        for _ in 0..20 {
            if self.nullifiers_committed(nullifiers).await.unwrap_or(false) {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        false
    }

    /// Whether every supplied nullifier is present in the committed event history.
    pub async fn nullifiers_committed(&self, nullifiers: &[Fr]) -> Result<bool> {
        let wanted = nullifiers.iter().map(fr_to_dec).collect::<Vec<_>>();
        let head = self.notes.head_block().await?;
        let events = self.notes.committed_nullifiers(0, head).await?;
        Ok(wanted.iter().all(|nullifier| {
            events
                .iter()
                .any(|event| event.nullifiers.contains(nullifier))
        }))
    }

    /// Build, sign and submit a call.
    #[allow(clippy::too_many_arguments)]
    async fn submit_call(
        &self,
        signer_priv: &str,
        to: &str,
        calldata: Vec<u8>,
        value: &str,
        gas_limit: u64,
        route: Route,
        label: &str,
    ) -> Result<(TxOutcome, TxLedger)> {
        let signer_addr = curvy_abi::address_of(signer_priv)?;
        let nonce_lock = {
            let mut locks = self.nonce_locks.lock().await;
            Arc::clone(
                locks
                    .entry(signer_addr.clone())
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
            )
        };
        let _nonce_guard = nonce_lock.lock().await;
        let nonce = self.balances.tx_count(&signer_addr).await?;
        let gas_price = self
            .balances
            .gas_price()
            .await?
            .checked_mul(2)
            .context("doubled gas price overflows u128")?;
        let raw = curvy_abi::sign_call_tx(curvy_abi::CallTx {
            signer_private_key: signer_priv,
            to,
            calldata,
            value,
            nonce,
            gas_limit,
            gas_price,
            chain_id: self.chain_id,
        })?;
        let sub = self.submitter(route);
        let ledger = TxLedger {
            label: label.to_string(),
            backend: sub.backend().to_string(),
            tx_hash: format!("0x{}", hex::encode(Keccak256::digest(&raw.0))),
        };
        let outcome = match sub.submit(&raw).await {
            Ok(outcome) => outcome,
            Err(
                source @ (ChainError::Transport(_)
                | ChainError::Ambiguous(_)
                | ChainError::Decode(_)),
            ) => {
                return Err(AmbiguousSubmission { ledger, source }.into());
            }
            Err(error) => return Err(anyhow::Error::new(error).context(format!("{label} submit"))),
        };
        if !outcome.tx_hash.eq_ignore_ascii_case(&ledger.tx_hash) {
            return Err(AmbiguousSubmission {
                source: ChainError::Decode(format!(
                    "backend returned tx hash {} for locally signed {}",
                    outcome.tx_hash, ledger.tx_hash
                )),
                ledger,
            }
            .into());
        }
        if !outcome.status {
            bail!("{label}: tx {} reverted", outcome.tx_hash);
        }
        Ok((outcome, ledger))
    }

    // Deposit.

    /// Fix the shield note and portal address without sending a transaction.
    pub async fn prepare_deposit(
        &self,
        recipient: &Account,
        gross: u128,
        token: u64,
        recovery: &str,
    ) -> Result<PreparedDeposit> {
        let fees = self.fees.fees().await?;
        let token_fr = Fr::from(token);
        let token_dec = token.to_string();
        let sealed = seal_note(&recipient.identity(), u128_fr(gross), token_fr)?;
        let owner_hash_dec = fr_to_dec(&sealed.owner_hash());
        let portal_deployment = fees
            .per_token_gas_fees
            .iter()
            .find(|fees| fees.token_id == token_dec)
            .map(|fees| {
                fees.portal_deployment.parse::<u128>().with_context(|| {
                    format!("parse portalDeployment gas fee for token {token_dec}")
                })
            })
            .transpose()?
            .unwrap_or(0);
        let pending_commit = parse_gas_fee(&fees, &token_dec)?;
        let net = shield_net_amount(
            gross,
            fees.deposit_fee_bps,
            portal_deployment,
            pending_commit,
        )?;
        let onchain_note = OnchainNote {
            owner_hash: owner_hash_dec.clone(),
            token: token_dec,
            amount: gross.to_string(),
            ephemeral_key: [
                fr_to_dec(&sealed.ephemeral_key.0),
                fr_to_dec(&sealed.ephemeral_key.1),
            ],
            view_tag: sealed.view_tag as u64,
        };
        let portal_address = self
            .portals
            .entry_portal_address(&owner_hash_dec, &recovery.to_string())
            .await?;
        Ok(PreparedDeposit {
            note: OwnedNote {
                amount: u128_fr(net),
                ..sealed
            },
            onchain_note,
            portal_address,
            gross,
            recovery: recovery.to_string(),
        })
    }

    /// Fund a persisted shield portal.
    pub async fn fund_prepared_deposit(
        &self,
        prepared: &PreparedDeposit,
        operator_priv: &str,
        route: Route,
    ) -> Result<TxLedger> {
        let funding = self
            .submit_call(
                operator_priv,
                &prepared.portal_address,
                vec![],
                &prepared.gross.to_string(),
                60_000,
                route,
                "shield:fund-portal",
            )
            .await;
        match funding {
            Ok((_outcome, ledger)) => Ok(ledger),
            Err(error) => {
                let Some(ambiguous) = ambiguous_submission(&error) else {
                    return Err(error);
                };
                let recovered = ambiguous.ledger.clone();
                for _ in 0..20 {
                    if self
                        .eth_balance(&prepared.portal_address)
                        .await
                        .is_ok_and(|balance| balance >= prepared.gross)
                    {
                        return Ok(recovered);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
                Err(error)
            }
        }
    }

    /// Deploy and shield a funded portal.
    pub async fn shield_prepared_deposit(
        &self,
        prepared: &PreparedDeposit,
        operator_priv: &str,
        route: Route,
    ) -> Result<TxLedger> {
        let calldata =
            curvy_abi::encode_deploy_shield_portal(&prepared.onchain_note, &prepared.recovery)?;
        let deployed = self
            .submit_call(
                operator_priv,
                &self.portal_factory,
                calldata,
                "0",
                2_000_000,
                route,
                "shield:deploy+shield",
            )
            .await;
        match deployed {
            Ok((_outcome, ledger)) => Ok(ledger),
            Err(error) => {
                let Some(ambiguous) = ambiguous_submission(&error) else {
                    return Err(error);
                };
                let recovered = ambiguous.ledger.clone();
                if self
                    .wait_for_note_statuses(&[prepared.note.note_id()], &[1, 2])
                    .await
                {
                    Ok(recovered)
                } else {
                    Err(error)
                }
            }
        }
    }

    /// Fund, deploy and shield a deterministic entry portal.
    ///
    /// This convenience method has no durable journal. Production callers must persist
    /// [`PreparedDeposit`] and use the two staged methods so a crash after funding does
    /// not lose the only handle to that portal.
    #[deprecated(note = "persist prepare_deposit, then call the two staged methods")]
    #[allow(clippy::too_many_arguments)]
    pub async fn deposit(
        &self,
        recipient: &Account,
        gross: u128,
        token: u64,
        operator_priv: &str,
        recovery: &str,
        funding_route: Route,
        protocol_route: Route,
    ) -> Result<(OwnedNote, Vec<TxLedger>)> {
        let prepared = self
            .prepare_deposit(recipient, gross, token, recovery)
            .await?;
        let funding = self
            .fund_prepared_deposit(&prepared, operator_priv, funding_route)
            .await?;
        let shield = self
            .shield_prepared_deposit(&prepared, operator_priv, protocol_route)
            .await?;
        Ok((prepared.note, vec![funding, shield]))
    }

    /// Compatibility wrapper that uses one backend for both deposit transactions.
    #[deprecated(note = "persist prepare_deposit, then call the two staged methods")]
    pub async fn shield(
        &self,
        recipient: &Account,
        gross: u128,
        token: u64,
        operator_priv: &str,
        recovery: &str,
        route: Route,
    ) -> Result<(OwnedNote, Vec<TxLedger>)> {
        let prepared = self
            .prepare_deposit(recipient, gross, token, recovery)
            .await?;
        let funding = self
            .fund_prepared_deposit(&prepared, operator_priv, route)
            .await?;
        let shield = self
            .shield_prepared_deposit(&prepared, operator_priv, route)
            .await?;
        Ok((prepared.note, vec![funding, shield]))
    }

    // Note-tree synchronization.

    /// Rebuild the local note tree and reconcile it against the chain root.
    pub async fn sync(&self) -> Result<Vec<Fr>> {
        let mut last_local_root = String::new();
        for _ in 0..20 {
            let leaves = match self.notes.notes_tree_snapshot().await? {
                Some(snapshot) => snapshot
                    .leaves
                    .iter()
                    .map(|id| parse_fr_decimal(id, "snapshot note id"))
                    .collect::<Result<Vec<_>>>()?,
                None => self.leaves_from_events().await?,
            };

            last_local_root = fr_to_dec(&Imt::from_leaves(TREE_DEPTH, &leaves).root());
            let state = self.anchor.state().await?;
            if state.current_notes_root == last_local_root {
                self.storage.lock().unwrap().tree_leaves = leaves.clone();
                return Ok(leaves);
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        bail!(
            "sync: configured index root {last_local_root} does not reconcile with the chain root after retries"
        )
    }

    /// Rebuild the leaf log from ordered `CommittedNotes` events.
    async fn leaves_from_events(&self) -> Result<Vec<Fr>> {
        let head = self.notes.head_block().await?;
        let mut committed = self.notes.committed_notes(0, head).await?;
        committed.sort_by_key(|event| event.batch_index);
        let mut leaves = Vec::new();
        for event in &committed {
            for note_id in &event.note_ids {
                let field = parse_fr_decimal(note_id, "committed note id")?;
                if field != Fr::from(0u64) {
                    leaves.push(field);
                }
            }
        }
        Ok(leaves)
    }

    // Pending-note commitments.

    /// Commit pending note ids into the notes tree.
    pub async fn commit(
        &self,
        pending_ids: &[Fr],
        operator_priv: &str,
        route: Route,
    ) -> Result<Vec<TxLedger>> {
        // The `(5,30)` profile accepts at most five note ids.
        if pending_ids.len() > BATCH_SIZE {
            bail!(
                "commit takes at most {BATCH_SIZE} note ids per proof, got {}",
                pending_ids.len()
            );
        }
        if pending_ids.is_empty() {
            return Ok(Vec::new());
        }
        if pending_ids.iter().any(|id| *id == Fr::from(0u64)) {
            bail!("commit note ids must be non-zero");
        }
        if pending_ids
            .iter()
            .enumerate()
            .any(|(index, id)| pending_ids[..index].contains(id))
        {
            bail!("commit cannot include the same note id twice");
        }

        let leaves = self.sync().await?;
        let tree = Imt::from_leaves(TREE_DEPTH, &leaves);

        let witness = build_pending_commitment(&tree, TREE_DEPTH, BATCH_SIZE, pending_ids);
        let note_ids = witness.pending_note_ids.clone(); // padded batch (order matters on-chain)
        let new_root = witness.new_notes_root.clone();
        let (input_json, _reduced) = curvy_witnesscalc::pending::to_circuit_input(&witness)?;

        let bundle = tokio::task::spawn_blocking(move || {
            curvy_witnesscalc::Circuit::pending().prove(&input_json)
        })
        .await
        .context("join prove")??;
        let proof = curvy_abi::proof_from_snarkjs(&bundle.proof_json)?;

        let calldata = curvy_abi::encode_commit_pending_notes(
            BATCH_SIZE as u64,
            &note_ids,
            &new_root,
            &proof,
        )?;
        let submitted = self
            .submit_call(
                operator_priv,
                &self.aggregator,
                calldata,
                "0",
                2_000_000,
                route,
                "commit",
            )
            .await;
        let ledger = match submitted {
            Ok((_outcome, ledger)) => ledger,
            Err(error) => {
                let Some(ambiguous) = ambiguous_submission(&error) else {
                    return Err(error);
                };
                let recovered = ambiguous.ledger.clone();
                if !self.wait_for_note_statuses(pending_ids, &[2]).await {
                    return Err(error);
                }
                recovered
            }
        };

        // The receipt confirms the signed call.
        Ok(vec![ledger])
    }

    /// Minimum aggregation input under the current fee configuration.
    pub async fn pix_minimum_input(
        &self,
        token: &Fr,
        allocation_total: u128,
        relayer_amount: u128,
    ) -> Result<u128> {
        let fees = self.fees.fees().await?;
        let token_decimal = fr_to_dec(token);
        minimum_pix_input_value(
            allocation_total,
            relayer_amount,
            parse_gas_fee(&fees, &token_decimal)?,
            parse_protocol_fee(&fees)?,
        )
    }

    // Aggregation.

    /// Aggregate a committed note into a recipient note, change and a fee note.
    #[allow(clippy::too_many_arguments)]
    pub async fn aggregate(
        &self,
        spender: &Account,
        note_a: &OwnedNote,
        recipient: &Identity,
        amount_to_b: u128,
        fee_recipient: Option<&Identity>,
        submitter_priv: &str,
        route: Route,
    ) -> Result<(OwnedNote, Vec<TxLedger>)> {
        let b_note = seal_note(recipient, u128_fr(amount_to_b), note_a.token)?;
        self.aggregate_with_output(
            spender,
            note_a,
            b_note,
            amount_to_b,
            fee_recipient,
            submitter_priv,
            route,
        )
        .await
    }

    /// Allocate value to a known BabyJubJub owner.
    #[allow(clippy::too_many_arguments)]
    pub async fn aggregate_to_known_owner(
        &self,
        spender: &Account,
        note_a: &OwnedNote,
        recipient: KnownOwner,
        amount_to_recipient: u128,
        fee_recipient: Option<&Identity>,
        submitter_priv: &str,
        route: Route,
    ) -> Result<(OwnedNote, Vec<TxLedger>)> {
        let output = seal_known_owner(recipient, u128_fr(amount_to_recipient), note_a.token);
        self.aggregate_with_output(
            spender,
            note_a,
            output,
            amount_to_recipient,
            fee_recipient,
            submitter_priv,
            route,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn aggregate_with_output(
        &self,
        spender: &Account,
        note_a: &OwnedNote,
        b_note: OwnedNote,
        amount_to_b: u128,
        fee_recipient: Option<&Identity>,
        submitter_priv: &str,
        route: Route,
    ) -> Result<(OwnedNote, Vec<TxLedger>)> {
        if note_a.amount == Fr::from(0u64) {
            bail!("aggregation input must have a non-zero amount");
        }
        if note_a.owner_pub != spender.bjj_pub {
            bail!("aggregation input is not owned by the spender");
        }
        if amount_to_b == 0 || b_note.amount != u128_fr(amount_to_b) {
            bail!("aggregation recipient amount must be non-zero and match its note");
        }
        if b_note.token != note_a.token {
            bail!("aggregation input and output must use one token");
        }
        let fees = self.fees.fees().await?;
        let token = note_a.token;
        let token_dec = fr_to_dec(&token);

        // Build the input inclusion proof.
        let leaves = self.sync().await?;
        let note_a_id = note_a.note_id();
        let idx = leaves
            .iter()
            .position(|l| *l == note_a_id)
            .context("aggregate: note A not found in committed tree (commit first?)")?;
        let tree = Imt::from_leaves(TREE_DEPTH, &leaves);
        let notes_root = tree.root();
        let a_proof = Proof {
            leaf_index: idx as u64,
            siblings: tree.create_proof(idx).siblings,
        };

        // Calculate circuit values.
        let net = fr_u128(&note_a.amount)?;
        let gas_fee = parse_gas_fee(&fees, &token_dec)?;
        let protocol_fee_per_thousand = parse_protocol_fee(&fees)?;
        let spent_to_others = amount_to_b; // B != spender
        let protocol_fee = spent_to_others
            .checked_mul(protocol_fee_per_thousand)
            .context("aggregate: protocol fee overflow")?
            / 1000;
        let fee_amount = gas_fee
            .checked_add(protocol_fee)
            .context("aggregate: total fee overflow")?;
        let outgoing = amount_to_b
            .checked_add(fee_amount)
            .context("aggregate: amount plus fee overflow")?;
        let change = net
            .checked_sub(outgoing)
            .context("aggregate: note value too small for amount+fee")?;

        // Derive distinct padding and fee notes.
        let seed = curvy_core::field::fr_to_be_32(&note_a.shared_secret);

        // Outputs: recipient, change, pad. Inputs: note and pad.
        let change_note = seal_note(&spender.identity(), u128_fr(change), token)?;
        let pad_out = zero_pad_note(spender.bjj_pub, token, &seed, 1);
        let output_notes = vec![b_note.to_core(), change_note.to_core(), pad_out.to_core()];

        let pad_in = zero_pad_note(spender.bjj_pub, token, &seed, 2);
        let input_notes = vec![note_a.to_core(), pad_in.to_core()];
        let input_proofs = vec![
            a_proof,
            Proof {
                leaf_index: 0,
                siblings: vec![Fr::from(0u64); TREE_DEPTH],
            },
        ];

        // Fee note owned by the on-chain feeNotePublicKey.
        let fee_pub = (
            parse_fr_decimal(&fees.fee_note_public_key[0], "fee public key x")?,
            parse_fr_decimal(&fees.fee_note_public_key[1], "fee public key y")?,
        );
        let fee_n = fee_note(fee_recipient, fee_pub, u128_fr(fee_amount), token, &seed)?;

        let w = build_aggregation(
            &input_notes,
            &input_proofs,
            &output_notes,
            &fee_n.to_core(),
            &spender.k,
            spender.bjj_pub,
            notes_root,
            u128_fr(protocol_fee_per_thousand),
            u128_fr(gas_fee),
            fee_pub,
        );
        let input_json = serde_json::to_string(&w)?;
        let bundle = tokio::task::spawn_blocking(move || {
            curvy_witnesscalc::Circuit::aggregation().prove(&input_json)
        })
        .await
        .context("join prove")??;
        let proof = curvy_abi::proof_from_snarkjs(&bundle.proof_json)?;

        let calldata = curvy_abi::encode_submit_aggregation(
            LEGACY_MAX_INPUTS,
            LEGACY_MAX_OUTPUTS,
            &proof,
            &bundle.public_signals,
        )?;
        let submitted = self
            .submit_call(
                submitter_priv,
                &self.aggregator,
                calldata,
                "0",
                3_000_000,
                route,
                "aggregate",
            )
            .await;
        let ledger = match submitted {
            Ok((_outcome, ledger)) => ledger,
            Err(error) => {
                let Some(ambiguous) = ambiguous_submission(&error) else {
                    return Err(error);
                };
                let recovered = ambiguous.ledger.clone();
                if !self
                    .wait_for_note_statuses(&[b_note.note_id()], &[1, 2])
                    .await
                {
                    return Err(error);
                }
                recovered
            }
        };
        Ok((b_note, vec![ledger]))
    }

    /// Execute verifier profile `(2, 9)` with allocations, change, an optional
    /// stealth relayer note and a fee note.
    #[allow(clippy::too_many_arguments)]
    pub async fn aggregate_pix_allocations(
        &self,
        spender: &Account,
        input_notes: &[OwnedNote],
        allocations: &[(KnownOwner, u128)],
        relayer: Option<(&Identity, u128)>,
        fee_recipient: Option<&Identity>,
        submitter_priv: &str,
        route: Route,
    ) -> Result<PixAggregationResult> {
        if input_notes.is_empty() || input_notes.len() > PIX_AGGREGATION_MAX_INPUTS as usize {
            bail!("PIX aggregation requires one or two committed input notes");
        }
        // Regular-output budget: allocations + change + (relayer).
        let reserved = if relayer.is_some() { 2 } else { 1 };
        let max_allocations = PIX_AGGREGATION_MAX_OUTPUTS as usize - reserved;
        if allocations.is_empty() || allocations.len() > max_allocations {
            bail!(
                "PIX aggregation requires between one and {max_allocations} allocations \
                 ({} regular outputs, {reserved} reserved for change{})",
                PIX_AGGREGATION_MAX_OUTPUTS,
                if relayer.is_some() {
                    " and the relayer"
                } else {
                    ""
                }
            );
        }
        if relayer.is_some_and(|(_, amount)| amount == 0) {
            bail!("PIX relayer note must carry a non-zero gas reimbursement");
        }

        let token = input_notes[0].token;
        for note in input_notes {
            if note.amount == Fr::from(0u64) {
                bail!("PIX aggregation inputs must have non-zero amounts");
            }
            if note.token != token {
                bail!("PIX aggregation inputs must use one token");
            }
            if note.owner_pub != spender.bjj_pub {
                bail!("PIX aggregation input is not owned by the funding account");
            }
        }
        for (owner, amount) in allocations {
            if *amount == 0 {
                bail!("PIX allocation amounts must be non-zero");
            }
            if owner.owner.as_tuple() == spender.bjj_pub {
                bail!("PIX allocation owner must differ from the funding account");
            }
        }
        // The relayer note contributes to the non-spender fee base.
        if relayer.is_some_and(|(identity, _)| identity.bjj_pub == spender.bjj_pub) {
            bail!("PIX relayer owner must differ from the funding account");
        }

        let leaves = self.sync().await?;
        let tree = Imt::from_leaves(TREE_DEPTH, &leaves);
        let notes_root = tree.root();
        let mut circuit_inputs = Vec::with_capacity(PIX_AGGREGATION_MAX_INPUTS as usize);
        let mut input_proofs = Vec::with_capacity(PIX_AGGREGATION_MAX_INPUTS as usize);
        for note in input_notes {
            let note_id = note.note_id();
            let index = leaves
                .iter()
                .position(|leaf| *leaf == note_id)
                .context("PIX aggregation input not found in committed tree")?;
            if circuit_inputs
                .iter()
                .any(|input: &curvy_core::witness::Note| input.id() == note_id)
            {
                bail!("PIX aggregation cannot spend the same note twice");
            }
            circuit_inputs.push(note.to_core());
            input_proofs.push(Proof {
                leaf_index: index as u64,
                siblings: tree.create_proof(index).siblings,
            });
        }

        let fees = self.fees.fees().await?;
        let token_decimal = fr_to_dec(&token);
        let gas_fee = parse_gas_fee(&fees, &token_decimal)?;
        let protocol_fee_per_thousand = parse_protocol_fee(&fees)?;
        let allocation_total = allocations.iter().try_fold(0u128, |total, (_, amount)| {
            total
                .checked_add(*amount)
                .context("PIX allocation total overflow")
        })?;
        let input_total = input_notes.iter().try_fold(0u128, |total, note| {
            total
                .checked_add(fr_u128(&note.amount)?)
                .context("PIX input total overflow")
        })?;
        let relayer_amount = relayer.map_or(0, |(_, amount)| amount);
        let PixValueSplit {
            fee_amount,
            change_amount,
            ..
        } = pix_value_split(
            input_total,
            allocation_total,
            relayer_amount,
            gas_fee,
            protocol_fee_per_thousand,
        )?;

        let allocation_notes = allocations
            .iter()
            .map(|(owner, amount)| seal_known_owner(*owner, u128_fr(*amount), token))
            .collect::<Vec<_>>();
        let change = seal_note(&spender.identity(), u128_fr(change_amount), token)?;
        // Stealth-sealed, so the operator's paymaster can discover it by scanning.
        let relayer_note = relayer
            .map(|(identity, amount)| seal_note(identity, u128_fr(amount), token))
            .transpose()?;
        let mut regular_outputs = allocation_notes.clone();
        regular_outputs.push(change.clone());
        if let Some(note) = &relayer_note {
            regular_outputs.push(note.clone());
        }

        let seed = curvy_core::field::fr_to_be_32(&input_notes[0].shared_secret);
        while regular_outputs.len() < PIX_AGGREGATION_MAX_OUTPUTS as usize {
            regular_outputs.push(zero_pad_note(
                spender.bjj_pub,
                token,
                &seed,
                0x5049_5800 + regular_outputs.len() as u64,
            ));
        }
        while circuit_inputs.len() < PIX_AGGREGATION_MAX_INPUTS as usize {
            circuit_inputs
                .push(zero_pad_note(spender.bjj_pub, token, &seed, 0x5049_5810).to_core());
            input_proofs.push(Proof {
                leaf_index: 0,
                siblings: vec![Fr::from(0u64); TREE_DEPTH],
            });
        }

        let fee_public_key = (
            parse_fr_decimal(&fees.fee_note_public_key[0], "fee public key x")?,
            parse_fr_decimal(&fees.fee_note_public_key[1], "fee public key y")?,
        );
        let fee = fee_note(
            fee_recipient,
            fee_public_key,
            u128_fr(fee_amount),
            token,
            &seed,
        )?;
        let signer = SeedNoteSigner::new(&spender.k);
        let core_outputs = regular_outputs
            .iter()
            .map(OwnedNote::to_core)
            .collect::<Vec<_>>();
        let mut witness = build_pix_aggregation_with_signer(
            &circuit_inputs,
            &input_proofs,
            &core_outputs,
            &fee.to_core(),
            &signer,
            notes_root,
            u128_fr(protocol_fee_per_thousand),
            u128_fr(gas_fee),
            fee_public_key,
        )?;
        let (gas_fee_siblings, gas_fee_root) = real_gas_fee_proof(&fees, &token_decimal)?;
        if gas_fee_root != fees.commitment_fee_root {
            bail!(
                "PIX aggregation: rebuilt gas-fee root {gas_fee_root} != on-chain commitmentFeeRoot {}",
                fees.commitment_fee_root
            );
        }
        witness.gas_fee_siblings = gas_fee_siblings;
        witness.commit_pending_notes_gas_fee_root = gas_fee_root;

        let input_json = serde_json::to_string(&witness)?;
        let bundle = tokio::task::spawn_blocking(move || {
            curvy_witnesscalc::Circuit::pix_aggregation().prove(&input_json)
        })
        .await
        .context("join PIX aggregation proof")??;
        let proof = curvy_abi::proof_from_snarkjs(&bundle.proof_json)?;
        let calldata = curvy_abi::encode_submit_aggregation(
            PIX_AGGREGATION_MAX_INPUTS,
            PIX_AGGREGATION_MAX_OUTPUTS,
            &proof,
            &bundle.public_signals,
        )?;
        let mut emitted_notes = regular_outputs;
        emitted_notes.push(fee);
        let submitted = self
            .submit_call(
                submitter_priv,
                &self.aggregator,
                calldata,
                "0",
                3_000_000,
                route,
                "pix-aggregate-2x9",
            )
            .await;
        let ledger = match submitted {
            Ok((_outcome, ledger)) => ledger,
            Err(error) => {
                let Some(ambiguous) = ambiguous_submission(&error) else {
                    return Err(error);
                };
                let recovered = ambiguous.ledger.clone();
                let output_ids = emitted_notes
                    .iter()
                    .filter(|note| note.amount != Fr::from(0u64))
                    .map(OwnedNote::note_id)
                    .collect::<Vec<_>>();
                if !self.wait_for_note_statuses(&output_ids, &[1, 2]).await {
                    return Err(AmbiguousPixAggregation {
                        result: PixAggregationResult {
                            allocations: allocation_notes,
                            change,
                            relayer: relayer_note,
                            emitted_notes,
                            ledger: vec![recovered],
                        },
                        source: error,
                    }
                    .into());
                }
                recovered
            }
        };

        Ok(PixAggregationResult {
            allocations: allocation_notes,
            change,
            relayer: relayer_note,
            emitted_notes,
            ledger: vec![ledger],
        })
    }

    // Withdrawal.

    /// Withdraw a committed note to an EOA.
    pub async fn withdraw(
        &self,
        spender: &Account,
        note: &OwnedNote,
        destination: &str,
        submitter_priv: &str,
        route: Route,
    ) -> Result<(u128, Vec<TxLedger>)> {
        if note.amount == Fr::from(0u64) {
            bail!("withdrawal input must have a non-zero amount");
        }
        if note.owner_pub != spender.bjj_pub {
            bail!("withdrawal input is not owned by the spender");
        }
        let fees = self.fees.fees().await?;
        let token = note.token;
        let token_dec = fr_to_dec(&token);

        let leaves = self.sync().await?;
        let nid = note.note_id();
        let idx = leaves
            .iter()
            .position(|l| *l == nid)
            .context("withdraw: note not found in committed tree (commit it first)")?;
        let tree = Imt::from_leaves(TREE_DEPTH, &leaves);
        let notes_root = tree.root();
        let proof = Proof {
            leaf_index: idx as u64,
            siblings: tree.create_proof(idx).siblings,
        };

        let dest_dec = curvy_abi::address_to_u160_dec(destination)?;
        let destination_fr = parse_fr_decimal(&dest_dec, "withdrawal destination")?;

        let seed = curvy_core::field::fr_to_be_32(&note.shared_secret);
        let pad = zero_pad_note(spender.bjj_pub, token, &seed, 7);
        let inputs = vec![note.to_core(), pad.to_core()];
        let proofs = vec![
            proof,
            Proof {
                leaf_index: 0,
                siblings: vec![Fr::from(0u64); TREE_DEPTH],
            },
        ];

        let w = curvy_core::witness::build_withdrawal(
            &inputs,
            &spender.k,
            spender.bjj_pub,
            &proofs,
            notes_root,
            destination_fr,
            token,
        );
        let input_json = serde_json::to_string(&w)?;
        let bundle = tokio::task::spawn_blocking(move || {
            curvy_witnesscalc::Circuit::withdrawal().prove(&input_json)
        })
        .await
        .context("join prove")??;
        let proof_oc = curvy_abi::proof_from_snarkjs(&bundle.proof_json)?;
        let calldata = curvy_abi::encode_submit_withdrawal(
            LEGACY_MAX_INPUTS,
            &proof_oc,
            &bundle.public_signals,
        )?;
        let amount = fr_u128(&note.amount)?;
        let gas = parse_withdrawal_gas(&fees, &token_dec)?;
        let delivered = withdrawal_net(amount, fees.withdrawal_fee_bps, gas)?;
        let submitted = self
            .submit_call(
                submitter_priv,
                &self.aggregator,
                calldata,
                "0",
                2_000_000,
                route,
                "withdraw",
            )
            .await;
        let ledger = match submitted {
            Ok((_outcome, ledger)) => ledger,
            Err(error) => {
                let Some(ambiguous) = ambiguous_submission(&error) else {
                    return Err(error);
                };
                let recovered = ambiguous.ledger.clone();
                if !self.wait_for_nullifiers(&[note.nullifier()]).await {
                    return Err(error);
                }
                recovered
            }
        };
        Ok((delivered, vec![ledger]))
    }

    /// Withdraw a committed note using its BabyJubJub scalar.
    pub async fn withdraw_with_scalar(
        &self,
        signer: &ScalarSigningKey,
        note: &OwnedNote,
        destination: &str,
        submitter_priv: &str,
        route: Route,
    ) -> Result<(u128, Vec<TxLedger>)> {
        if note.amount == Fr::from(0u64) {
            bail!("PIX withdrawal input must have a non-zero amount");
        }
        let fees = self.fees.fees().await?;
        let token = note.token;
        let token_dec = fr_to_dec(&token);
        let owner = signer.verifying_key().as_tuple();
        if note.owner_pub != owner {
            bail!("PIX withdrawal signer does not own the supplied note");
        }

        let leaves = self.sync().await?;
        let note_id = note.note_id();
        let index = leaves
            .iter()
            .position(|leaf| *leaf == note_id)
            .context("PIX withdrawal: note not found in committed tree")?;
        let tree = Imt::from_leaves(TREE_DEPTH, &leaves);
        let notes_root = tree.root();
        let proof = Proof {
            leaf_index: index as u64,
            siblings: tree.create_proof(index).siblings,
        };

        let destination_decimal = curvy_abi::address_to_u160_dec(destination)?;
        let destination_field = parse_fr_decimal(&destination_decimal, "withdrawal destination")?;
        let seed = curvy_core::field::fr_to_be_32(&note.shared_secret);
        let padding_note = zero_pad_note(owner, token, &seed, 0x5049_5807);
        let input_notes = vec![note.to_core(), padding_note.to_core()];
        let input_proofs = vec![
            proof,
            Proof {
                leaf_index: 0,
                siblings: vec![Fr::from(0u64); TREE_DEPTH],
            },
        ];

        let witness = build_withdrawal_with_signer(
            &input_notes,
            signer,
            &input_proofs,
            notes_root,
            destination_field,
            token,
        )?;
        let input_json = serde_json::to_string(&witness)?;
        let bundle = tokio::task::spawn_blocking(move || {
            curvy_witnesscalc::Circuit::withdrawal().prove(&input_json)
        })
        .await
        .context("join PIX withdrawal proof")??;
        let proof = curvy_abi::proof_from_snarkjs(&bundle.proof_json)?;
        let calldata =
            curvy_abi::encode_submit_withdrawal(LEGACY_MAX_INPUTS, &proof, &bundle.public_signals)?;
        let amount = fr_u128(&note.amount)?;
        let withdrawal_gas = parse_withdrawal_gas(&fees, &token_dec)?;
        let delivered = withdrawal_net(amount, fees.withdrawal_fee_bps, withdrawal_gas)?;
        let submitted = self
            .submit_call(
                submitter_priv,
                &self.aggregator,
                calldata,
                "0",
                2_000_000,
                route,
                "pix-withdraw",
            )
            .await;
        let ledger = match submitted {
            Ok((_outcome, ledger)) => ledger,
            Err(error) => {
                let Some(ambiguous) = ambiguous_submission(&error) else {
                    return Err(error);
                };
                let recovered = ambiguous.ledger.clone();
                if !self.wait_for_nullifiers(&[note.nullifier()]).await {
                    return Err(error);
                }
                recovered
            }
        };
        Ok((delivered, vec![ledger]))
    }

    /// Withdraw up to ten committed notes whose BabyJubJub signing scalars are
    /// unrelated. Each real slot is authorized by its own scalar and the fixed
    /// circuit is padded to ten slots before profile `(10)` is submitted.
    pub async fn withdraw_pix_multi_owner(
        &self,
        spends: &[(&ScalarSigningKey, &OwnedNote)],
        destination: &str,
        submitter_priv: &str,
        route: Route,
    ) -> Result<(u128, Vec<TxLedger>)> {
        if spends.is_empty() || spends.len() > PIX_WITHDRAWAL_MAX_INPUTS as usize {
            bail!("PIX multi-owner withdrawal requires between one and ten notes");
        }
        let token = spends[0].1.token;
        for (signer, note) in spends {
            if note.amount == Fr::from(0u64) {
                bail!("PIX withdrawal inputs must have non-zero amounts");
            }
            if note.token != token {
                bail!("PIX withdrawal inputs must use one token");
            }
            if signer.verifying_key().as_tuple() != note.owner_pub {
                bail!("PIX withdrawal signer does not own its paired note");
            }
        }

        let leaves = self.sync().await?;
        let tree = Imt::from_leaves(TREE_DEPTH, &leaves);
        let notes_root = tree.root();
        let mut input_notes = Vec::with_capacity(PIX_WITHDRAWAL_MAX_INPUTS as usize);
        let mut input_proofs = Vec::with_capacity(PIX_WITHDRAWAL_MAX_INPUTS as usize);
        for (_signer, note) in spends {
            let note_id = note.note_id();
            if input_notes
                .iter()
                .any(|input: &curvy_core::witness::Note| input.id() == note_id)
            {
                bail!("PIX withdrawal cannot spend the same note twice");
            }
            let index = leaves
                .iter()
                .position(|leaf| *leaf == note_id)
                .context("PIX withdrawal note not found in committed tree")?;
            input_notes.push(note.to_core());
            input_proofs.push(Proof {
                leaf_index: index as u64,
                siblings: tree.create_proof(index).siblings,
            });
        }

        let padding_signer = spends[0].0;
        let padding_owner = padding_signer.verifying_key().as_tuple();
        let seed = curvy_core::field::fr_to_be_32(&spends[0].1.shared_secret);
        while input_notes.len() < PIX_WITHDRAWAL_MAX_INPUTS as usize {
            input_notes.push(
                zero_pad_note(
                    padding_owner,
                    token,
                    &seed,
                    0x5049_5820 + input_notes.len() as u64,
                )
                .to_core(),
            );
            input_proofs.push(Proof {
                leaf_index: 0,
                siblings: vec![Fr::from(0u64); TREE_DEPTH],
            });
        }

        let destination_decimal = curvy_abi::address_to_u160_dec(destination)?;
        // Scope trait-object borrows so the future remains `Send`.
        let witness = {
            let mut signers =
                Vec::<&dyn NoteSigner>::with_capacity(PIX_WITHDRAWAL_MAX_INPUTS as usize);
            for (signer, _note) in spends {
                signers.push(*signer as &dyn NoteSigner);
            }
            while signers.len() < PIX_WITHDRAWAL_MAX_INPUTS as usize {
                signers.push(padding_signer as &dyn NoteSigner);
            }
            build_pix_multi_owner_withdrawal(
                &input_notes,
                &signers,
                &input_proofs,
                notes_root,
                parse_fr_decimal(&destination_decimal, "withdrawal destination")?,
                token,
            )?
        };
        let input_json = serde_json::to_string(&witness)?;
        let bundle = tokio::task::spawn_blocking(move || {
            curvy_witnesscalc::Circuit::pix_withdrawal().prove(&input_json)
        })
        .await
        .context("join PIX multi-owner withdrawal proof")??;
        let proof = curvy_abi::proof_from_snarkjs(&bundle.proof_json)?;
        let calldata = curvy_abi::encode_submit_withdrawal(
            PIX_WITHDRAWAL_MAX_INPUTS,
            &proof,
            &bundle.public_signals,
        )?;
        // Complete fallible calculations before submission.
        let total = spends.iter().try_fold(0u128, |total, (_, note)| {
            total
                .checked_add(fr_u128(&note.amount)?)
                .context("PIX withdrawal total overflow")
        })?;
        let fees = self.fees.fees().await?;
        let token_decimal = fr_to_dec(&token);
        let withdrawal_gas = parse_withdrawal_gas(&fees, &token_decimal)?;
        let delivered = withdrawal_net(total, fees.withdrawal_fee_bps, withdrawal_gas)?;
        let submitted = self
            .submit_call(
                submitter_priv,
                &self.aggregator,
                calldata,
                "0",
                3_000_000,
                route,
                "pix-withdraw-10-owner",
            )
            .await;
        let ledger = match submitted {
            Ok((_outcome, ledger)) => ledger,
            Err(error) => {
                let Some(ambiguous) = ambiguous_submission(&error) else {
                    return Err(error);
                };
                let recovered = ambiguous.ledger.clone();
                let nullifiers = spends
                    .iter()
                    .map(|(_, note)| note.nullifier())
                    .collect::<Vec<_>>();
                if !self.wait_for_nullifiers(&nullifiers).await {
                    return Err(error);
                }
                recovered
            }
        };
        Ok((delivered, vec![ledger]))
    }

    // Note scanning.

    /// Scan pending events for notes owned by `account`.
    pub async fn scan(&self, account: &Account) -> Result<Vec<Discovered>> {
        let head = self.notes.head_block().await?;
        let events = self.notes.pending_notes(0, head).await?;

        let mut rs = Vec::new();
        let mut tags = Vec::new();
        // (note_id, enc_amount, enc_token, is_plaintext, eph_x, eph_y)
        let mut meta: Vec<(String, String, String, bool, String, String)> = Vec::new();
        for ev in &events {
            let len = ev.note_ids.len();
            anyhow::ensure!(
                ev.ephemeral_keys[0].len() == len
                    && ev.ephemeral_keys[1].len() == len
                    && ev.view_tags.len() == len
                    && ev.amounts.len() == len
                    && ev.tokens.len() == len
                    && ev.is_plaintext.len() == len,
                "PendingNotes event {} has inconsistent parallel-array lengths",
                ev.tx_hash
            );
            anyhow::ensure!(
                ev.view_tags.iter().all(|tag| u16::try_from(*tag).is_ok()),
                "PendingNotes event {} has a view tag outside uint16",
                ev.tx_hash
            );
            for i in 0..ev.note_ids.len() {
                let ex = ev.ephemeral_keys[0][i].clone();
                let ey = ev.ephemeral_keys[1][i].clone();
                rs.push(format!("{ex}.{ey}"));
                tags.push(format!("{:02x}", ev.view_tags[i]));
                meta.push((
                    ev.note_ids[i].clone(),
                    ev.amounts[i].clone(),
                    ev.tokens[i].clone(),
                    ev.is_plaintext[i],
                    ex,
                    ey,
                ));
            }
        }

        let matches = stealth::scan(&account.k, &account.v, &rs, &tags)
            .map_err(|e| anyhow::anyhow!("stealth scan: {e}"))?;

        let mut out = Vec::new();
        for m in matches {
            let index: usize = m.index.try_into().context("stealth match index overflow")?;
            let (note_id_dec, enc_amount, enc_token, is_plain, ex, ey) = meta
                .get(index)
                .with_context(|| format!("stealth match index {index} is out of bounds"))?;
            let shared_secret = shared_secret_from_spending_pub_key(&m.spending_pub_key)
                .context("parse scanned shared-secret point")?;

            let (amount, token) = if *is_plain {
                (
                    parse_fr_decimal(enc_amount, "plaintext note amount")?,
                    parse_fr_decimal(enc_token, "plaintext note token")?,
                )
            } else {
                let ss = fr_to_biguint(&shared_secret);
                let ebx = fr_to_biguint(&parse_fr_decimal(ex, "ephemeral key x")?);
                let eby = fr_to_biguint(&parse_fr_decimal(ey, "ephemeral key y")?);
                decrypt_amount_token(
                    parse_fr_decimal(enc_amount, "encrypted note amount")?,
                    parse_fr_decimal(enc_token, "encrypted note token")?,
                    &ss,
                    (&ebx, &eby),
                )
            };

            // Verify the note id before returning a match.
            let oh = owner_hash(account.bjj_pub, shared_secret);
            let nid = note_id(oh, amount, token);
            if nid == parse_fr_decimal(note_id_dec, "pending note id")? {
                out.push(Discovered {
                    note_id: nid,
                    amount,
                    token,
                    shared_secret,
                    is_plaintext: *is_plain,
                });
            }
        }
        Ok(out)
    }
}

/// Aggregation value split.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PixValueSplit {
    /// Output value the spender does not own.
    pub spent_to_others: u128,
    /// The fee note's amount: `gasFee + floor(spent_to_others * rate / 1000)`.
    pub fee_amount: u128,
    /// What returns to the spender as change.
    pub change_amount: u128,
}

/// Calculate the amount delivered by a withdrawal.
fn withdrawal_net(total: u128, withdrawal_fee_bps: u64, withdrawal_gas: u128) -> Result<u128> {
    let withdrawal_fee = total
        .checked_mul(withdrawal_fee_bps as u128)
        .context("withdrawal fee multiplication overflow")?
        / 10_000;
    total
        .checked_sub(withdrawal_fee)
        .and_then(|amount| amount.checked_sub(withdrawal_gas))
        .context("withdrawal amount does not cover protocol and gas fees")
}

/// Calculate the `(2,9)` aggregation values.
fn pix_value_split(
    input_total: u128,
    allocation_total: u128,
    relayer_amount: u128,
    gas_fee: u128,
    protocol_fee_per_thousand: u128,
) -> Result<PixValueSplit> {
    let spent_to_others = allocation_total
        .checked_add(relayer_amount)
        .context("PIX spent-to-others total overflow")?;
    let protocol_fee = spent_to_others
        .checked_mul(protocol_fee_per_thousand)
        .context("PIX protocol fee overflow")?
        / 1000;
    let fee_amount = gas_fee
        .checked_add(protocol_fee)
        .context("PIX fee overflow")?;
    let change_amount = input_total
        .checked_sub(
            spent_to_others
                .checked_add(fee_amount)
                .context("PIX allocation plus fee overflow")?,
        )
        .context("PIX inputs do not cover allocations, the relayer note and fees")?;
    Ok(PixValueSplit {
        spent_to_others,
        fee_amount,
        change_amount,
    })
}

fn minimum_pix_input_value(
    allocation_total: u128,
    relayer_amount: u128,
    gas_fee: u128,
    protocol_fee_per_thousand: u128,
) -> Result<u128> {
    let split = pix_value_split(
        u128::MAX,
        allocation_total,
        relayer_amount,
        gas_fee,
        protocol_fee_per_thousand,
    )?;
    u128::MAX
        .checked_sub(split.change_amount)
        .context("PIX minimum input underflow")
}

/// Rebuild the real depth-6 per-token gas-fee tree and return `(siblings, root)` for
/// `token`. Leaf[tokenId] = that token's `pendingNoteCommitment`; the root must equal
/// the on-chain `commitmentFeeRoot`.
fn real_gas_fee_proof(fees: &FeeConfig, token_dec: &str) -> Result<(Vec<String>, String)> {
    const GAS_TREE_DEPTH: usize = 6;
    let n = 1usize << GAS_TREE_DEPTH;
    let mut leaves = vec![Fr::from(0u64); n];
    for g in &fees.per_token_gas_fees {
        let tid: usize = g.token_id.parse().context("gas-fee token id")?;
        anyhow::ensure!(
            tid < n,
            "gas-fee token id {tid} exceeds depth-{GAS_TREE_DEPTH} tree"
        );
        leaves[tid] = parse_fr_decimal(
            &g.pending_note_commitment,
            "pending-note commitment gas fee",
        )?;
    }
    let token_index: usize = token_dec.parse().context("token id")?;
    anyhow::ensure!(
        token_index < n,
        "token id {token_index} exceeds depth-{GAS_TREE_DEPTH} gas-fee tree"
    );
    let tree = Imt::from_leaves(GAS_TREE_DEPTH, &leaves);
    let proof = tree.create_proof(token_index);
    Ok((
        proof.siblings.iter().map(fr_to_dec).collect(),
        fr_to_dec(&tree.root()),
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use async_trait::async_trait;

    use super::*;

    const RATE: u128 = 10; // protocolFeePerThousand
    const GAS: u128 = 500;

    #[derive(Default)]
    struct SubmissionProbe {
        active: AtomicUsize,
        max_active: AtomicUsize,
        sequence: AtomicUsize,
        transport_failure: AtomicBool,
    }

    #[async_trait]
    impl TxSubmitter for SubmissionProbe {
        async fn submit(&self, raw: &curvy_types::RawTx) -> curvy_chain_api::Result<TxOutcome> {
            if self.transport_failure.load(Ordering::SeqCst) {
                return Err(ChainError::Transport("response lost".to_string()));
            }
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active.fetch_max(active, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            self.active.fetch_sub(1, Ordering::SeqCst);
            let sequence = self.sequence.fetch_add(1, Ordering::SeqCst);
            Ok(TxOutcome {
                tx_hash: format!("0x{}", hex::encode(Keccak256::digest(&raw.0))),
                block_number: Some(sequence as u64),
                status: true,
            })
        }

        fn backend(&self) -> &'static str {
            "probe"
        }
    }

    #[async_trait]
    impl BalanceReader for SubmissionProbe {
        async fn eth_balance(&self, _addr: &String) -> curvy_chain_api::Result<String> {
            Ok("0".to_string())
        }

        async fn vault_balance(
            &self,
            _owner: &String,
            _token_id: &String,
        ) -> curvy_chain_api::Result<String> {
            Ok("0".to_string())
        }

        async fn tx_count(&self, _addr: &String) -> curvy_chain_api::Result<u64> {
            Ok(0)
        }

        async fn gas_price(&self) -> curvy_chain_api::Result<u128> {
            Ok(1)
        }

        async fn chain_id(&self) -> curvy_chain_api::Result<u64> {
            Ok(31337)
        }
    }

    #[async_trait]
    impl NoteIndexSource for SubmissionProbe {
        async fn pending_notes(
            &self,
            _from_block: u64,
            _to_block: u64,
        ) -> curvy_chain_api::Result<Vec<curvy_types::PendingNotesEvent>> {
            Ok(Vec::new())
        }

        async fn committed_notes(
            &self,
            _from_block: u64,
            _to_block: u64,
        ) -> curvy_chain_api::Result<Vec<curvy_types::CommittedNotesEvent>> {
            Ok(Vec::new())
        }

        async fn committed_nullifiers(
            &self,
            _from_block: u64,
            _to_block: u64,
        ) -> curvy_chain_api::Result<Vec<curvy_types::CommittedNullifiersEvent>> {
            Ok(Vec::new())
        }

        async fn head_block(&self) -> curvy_chain_api::Result<u64> {
            Ok(0)
        }
    }

    #[async_trait]
    impl RootAnchor for SubmissionProbe {
        async fn state(&self) -> curvy_chain_api::Result<curvy_types::AggregatorState> {
            Ok(curvy_types::AggregatorState::default())
        }

        async fn is_valid_notes_root(&self, _root: &String) -> curvy_chain_api::Result<bool> {
            Ok(false)
        }

        async fn note_status(&self, _note_id: &String) -> curvy_chain_api::Result<u8> {
            Ok(0)
        }
    }

    #[async_trait]
    impl FeeConfigSource for SubmissionProbe {
        async fn fees(&self) -> curvy_chain_api::Result<FeeConfig> {
            Ok(FeeConfig::default())
        }
    }

    #[async_trait]
    impl PortalDirectory for SubmissionProbe {
        async fn entry_portal_address(
            &self,
            _owner_hash: &String,
            _recovery: &String,
        ) -> curvy_chain_api::Result<String> {
            Ok("0x0000000000000000000000000000000000000001".to_string())
        }

        async fn portal_is_registered(&self, _portal: &String) -> curvy_chain_api::Result<bool> {
            Ok(false)
        }
    }

    fn probe_client(probe: Arc<SubmissionProbe>) -> CurvyClient {
        CurvyClient::new(
            probe.clone(),
            probe.clone(),
            probe.clone(),
            probe.clone(),
            probe.clone(),
            probe.clone(),
            probe,
            "0x0000000000000000000000000000000000000001".to_string(),
            "0x0000000000000000000000000000000000000002".to_string(),
            31337,
        )
    }

    const TEST_SIGNER: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    #[tokio::test]
    async fn submissions_from_one_signer_are_nonce_serialized() {
        let probe = Arc::new(SubmissionProbe::default());
        let client = probe_client(probe.clone());
        let first = client.submit_call(
            TEST_SIGNER,
            "0x0000000000000000000000000000000000000001",
            Vec::new(),
            "0",
            21_000,
            Route::Direct,
            "first",
        );
        let second = client.submit_call(
            TEST_SIGNER,
            "0x0000000000000000000000000000000000000001",
            Vec::new(),
            "0",
            21_000,
            Route::Direct,
            "second",
        );
        let (first, second) = tokio::join!(first, second);
        first.unwrap();
        second.unwrap();
        assert_eq!(probe.max_active.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_lost_submit_response_is_explicitly_ambiguous() {
        let probe = Arc::new(SubmissionProbe::default());
        probe.transport_failure.store(true, Ordering::SeqCst);
        let client = probe_client(probe);
        let error = client
            .submit_call(
                TEST_SIGNER,
                "0x0000000000000000000000000000000000000001",
                Vec::new(),
                "0",
                21_000,
                Route::Direct,
                "lost",
            )
            .await
            .unwrap_err();
        let ambiguous = ambiguous_submission(&error).expect("must retain unknown outcome");
        assert_eq!(ambiguous.ledger.label, "lost");
        assert!(ambiguous.ledger.tx_hash.starts_with("0x"));
    }

    #[tokio::test]
    async fn commit_rejects_zero_and_duplicate_ids_before_chain_work() {
        let client = probe_client(Arc::new(SubmissionProbe::default()));
        assert!(
            client
                .commit(&[Fr::from(0u64)], TEST_SIGNER, Route::Direct)
                .await
                .unwrap_err()
                .to_string()
                .contains("non-zero")
        );
        assert!(
            client
                .commit(
                    &[Fr::from(7u64), Fr::from(7u64)],
                    TEST_SIGNER,
                    Route::Direct,
                )
                .await
                .unwrap_err()
                .to_string()
                .contains("twice")
        );
    }

    #[test]
    fn relayer_note_is_part_of_the_protocol_fee_base() {
        let without = pix_value_split(1_000_000, 100_000, 0, GAS, RATE).unwrap();
        let with = pix_value_split(1_000_000, 100_000, 10_000, GAS, RATE).unwrap();

        assert_eq!(without.spent_to_others, 100_000);
        assert_eq!(with.spent_to_others, 110_000);
        assert_eq!(without.fee_amount, GAS + 1_000);
        assert_eq!(with.fee_amount, GAS + 1_100);
        assert_eq!(without.change_amount - with.change_amount, 10_000 + 100);
    }

    #[test]
    fn value_conservation_matches_the_circuit_constraint() {
        let split = pix_value_split(2_000_000, 350_000, 1_000, GAS, RATE).unwrap();
        let outputs = 350_000 + 1_000 + split.change_amount;
        assert_eq!(outputs, 2_000_000 - split.fee_amount);
    }

    #[test]
    fn protocol_fee_floors_like_the_circuit_quotient() {
        let split = pix_value_split(1_000_000, 999, 0, 0, RATE).unwrap();
        assert_eq!(split.fee_amount, 9); // floor(999 * 10 / 1000) == 9
    }

    #[test]
    fn inputs_that_cannot_cover_outputs_are_rejected() {
        let error = pix_value_split(1_000, 900, 200, GAS, RATE).unwrap_err();
        assert!(
            error.to_string().contains("do not cover"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn minimum_input_includes_allocations_gas_and_protocol_fee() {
        assert_eq!(
            minimum_pix_input_value(100_000, 10_000, GAS, RATE).unwrap(),
            110_000 + GAS + 1_100
        );
    }

    #[test]
    fn absent_token_yields_a_zero_gas_fee_rather_than_an_error() {
        let fees = FeeConfig::default();
        assert_eq!(parse_gas_fee(&fees, "7").unwrap(), 0);
        assert_eq!(parse_withdrawal_gas(&fees, "7").unwrap(), 0);
    }

    #[test]
    fn malformed_fees_are_reported_instead_of_silently_zero() {
        let fees = FeeConfig {
            protocol_fee_per_thousand: "not-a-number".into(),
            per_token_gas_fees: vec![curvy_types::GasFees {
                token_id: "1".into(),
                portal_deployment: "0".into(),
                pending_note_commitment: "1e18".into(),
                withdrawal: "0".into(),
            }],
            ..FeeConfig::default()
        };
        assert!(parse_protocol_fee(&fees).is_err());
        assert!(parse_gas_fee(&fees, "1").is_err());
    }

    #[test]
    fn withdrawal_math_rejects_multiplication_overflow() {
        let error = withdrawal_net(u128::MAX, u64::MAX, 0).unwrap_err();
        assert!(error.to_string().contains("overflow"));
    }

    #[test]
    fn withdrawal_math_rejects_fees_larger_than_the_note() {
        let error = withdrawal_net(10, 0, 11).unwrap_err();
        assert!(error.to_string().contains("does not cover"));
    }
}
