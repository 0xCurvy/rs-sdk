//! Batched Curvy implementation of `hopr_api::chain::DepositPool`.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use curvy_core::babyjubjub::BabyJubPoint;
use curvy_core::field::{Bn254Fr, Fr};
use curvy_core::witness::KnownOwner;
use curvy_sdk::{Account, CurvyClient, OwnedNote, PreparedDeposit, Route};
use futures::future::BoxFuture;
use hopr_api::chain::{DepositPool, PixDepositAddress, PixDepositSecret};
use hopr_types::primitive::prelude::{Address, HoprBalance};

use crate::bjj;
use crate::store::{
    CorruptRecord, DepositStore, PersistedState, StoredAggregationOutputs, StoredAllocation,
    StoredInFlight, StoredNote, StoredShield, StoredShieldStage, address_from_hex, address_hex,
};

/// Recipients per aggregation proof: the `(2,9)` profile's nine regular outputs carry
/// seven allocations plus the change note and the relayer's gas-reimbursement note.
pub const MAX_ALLOCATIONS_PER_PROOF: usize = 7;
/// Inputs per withdrawal proof, from the `(10,30)` profile.
pub const MAX_WITHDRAWAL_INPUTS: usize = 10;
/// Note ids per pending-notes-commitment proof, from the `(5,30)` profile.
pub const COMMITMENTS_PER_PROOF: usize = 5;

#[derive(Debug, thiserror::Error)]
pub enum CurvyPoolError {
    /// The trait's stated contract: reject addresses this pool cannot represent.
    #[error("this pool only accepts BabyJubJub deposit addresses, got an Ethereum one")]
    UnsupportedAddress,
    #[error("deposit address is not a valid BabyJubJub point")]
    InvalidAddress,
    #[error("deposit secret is not a valid BabyJubJub scalar")]
    InvalidSecret,
    #[error("no deposit is recorded for this key")]
    UnknownDeposit,
    #[error("recorded deposits total {available} but {requested} was requested")]
    InsufficientDeposit { available: u128, requested: u128 },
    #[error("the pool holds no committed note able to fund this allocation")]
    NoFunding,
    #[error(
        "a previous aggregation of {allocations} allocation(s) was interrupted with an \
         unknown outcome; reconcile the pool against chain state before continuing"
    )]
    UnresolvedInFlight { allocations: usize },
    #[error("amount does not fit the pool's 128-bit value range")]
    AmountOutOfRange,
    #[error("invalid pool funding note: {0}")]
    InvalidFundingNote(&'static str),
    #[error("a zero allocation cannot be proved and would block every batch it joined")]
    ZeroAllocation,
    #[error(
        "a different pool-funding shield is already in progress; resume it before starting another"
    )]
    ShieldInProgress,
    #[error("prepared shield portal holds {actual}, expected exactly {required}")]
    UnexpectedShieldFunding { actual: u128, required: u128 },
    #[error("a previous commitment of {notes} note(s) still has an unknown outcome")]
    UnresolvedCommitment { notes: usize },
    #[error("a previous withdrawal of {notes} note(s) still has an unknown outcome")]
    UnresolvedWithdrawal { notes: usize },
    /// Persisted state that does not decode. Restoring fails closed rather than
    /// starting up with a partial picture of what the pool owes.
    #[error(transparent)]
    CorruptState(#[from] CorruptRecord),
    #[error(transparent)]
    Curvy(#[from] anyhow::Error),
}

type Result<T> = std::result::Result<T, CurvyPoolError>;

/// One queued allocation awaiting the next aggregation proof.
#[derive(Clone)]
struct Queued {
    owner: KnownOwner,
    compressed: [u8; 32],
    /// Persisted with the queued allocation.
    shared_secret: Fr,
    amount: u128,
}

#[derive(Default)]
struct PoolState {
    /// Committed notes the pool can spend to fund allocations.
    funding: Vec<OwnedNote>,
    /// Notes delivered to each deposit address, keyed by its compressed point.
    deposits: HashMap<[u8; 32], Vec<OwnedNote>>,
    queue: Vec<Queued>,
    /// Reserved-but-unresolved work: a proof was started and its outcome is unknown.
    in_flight: Option<InFlight>,
    /// Notes that exist on-chain but are not committed yet.
    uncommitted: Vec<StoredNote>,
    /// A pool-funding shield fixed before either of its two transactions.
    shield_in_flight: Option<ShieldInFlight>,
    /// Notes held aside while a commitment outcome is reconciled.
    commitment_in_flight: Vec<StoredNote>,
    /// Notes held aside while a withdrawal outcome is reconciled.
    withdrawal_in_flight: Vec<StoredNote>,
}

/// Allocations and the funding note reserved for an in-progress proof.
#[derive(Clone)]
struct InFlight {
    batch: Vec<Queued>,
    funding: OwnedNote,
    outputs: Option<AggregationOutputs>,
}

#[derive(Clone)]
struct AggregationOutputs {
    allocations: Vec<OwnedNote>,
    change: OwnedNote,
    /// Every circuit output in on-chain order, including relayer and fee notes.
    emitted_notes: Vec<OwnedNote>,
}

#[derive(Clone)]
struct ShieldInFlight {
    prepared: PreparedDeposit,
    stage: StoredShieldStage,
}

/// One queued allocation in its persisted form.
fn stored_allocation(queued: &Queued) -> StoredAllocation {
    StoredAllocation {
        address: address_hex(&queued.compressed),
        shared_secret: curvy_core::field::fr_to_dec(&queued.shared_secret),
        amount: queued.amount.to_string(),
    }
}

/// Inverse of [`stored_allocation`], rejecting anything that does not decode.
fn restore_allocation(entry: &StoredAllocation) -> Result<Queued> {
    let compressed = address_from_hex(&entry.address)
        .ok_or_else(|| corrupt("allocation address", &entry.address))?;
    let (x, y) = bjj::decompress(&compressed)
        .ok_or_else(|| corrupt("allocation address point", &entry.address))?;
    let point = BabyJubPoint::try_from_xy(x, y)
        .map_err(|_| corrupt("allocation address point", &entry.address))?;
    let shared_secret = crate::store::fr_from_dec_checked(&entry.shared_secret)
        .ok_or_else(|| corrupt("allocation shared_secret", &entry.shared_secret))?;
    let amount = entry
        .amount
        .parse()
        .map_err(|_| corrupt("allocation amount", &entry.amount))?;
    Ok(Queued {
        owner: KnownOwner::new(point, Bn254Fr::from_fr(shared_secret)),
        compressed,
        shared_secret,
        amount,
    })
}

fn corrupt(field: &'static str, value: &str) -> CurvyPoolError {
    CurvyPoolError::CorruptState(CorruptRecord {
        field,
        value: value.to_owned(),
    })
}

/// Apply a confirmed aggregation to durable state.
fn apply_aggregation_outputs(
    state: &mut PoolState,
    batch: &[Queued],
    outputs: &AggregationOutputs,
) -> Result<()> {
    if batch.len() != outputs.allocations.len() {
        return Err(corrupt(
            "aggregation output count",
            &outputs.allocations.len().to_string(),
        ));
    }
    for note in outputs
        .allocations
        .iter()
        .chain(std::iter::once(&outputs.change))
    {
        if !outputs
            .emitted_notes
            .iter()
            .any(|emitted| emitted.note_id() == note.note_id())
        {
            return Err(corrupt(
                "aggregation emitted note",
                &curvy_core::field::fr_to_dec(&note.note_id()),
            ));
        }
    }
    for (queued, note) in batch.iter().zip(&outputs.allocations) {
        state
            .deposits
            .entry(queued.compressed)
            .or_default()
            .push(note.clone());
    }
    for note in outputs
        .emitted_notes
        .iter()
        .filter(|note| note.amount != Fr::from(0u64))
    {
        let stored = StoredNote::from(note);
        if !state.uncommitted.contains(&stored) {
            state.uncommitted.push(stored);
        }
    }
    state.in_flight = None;
    if outputs.change.amount != Fr::from(0u64)
        && !state
            .funding
            .iter()
            .any(|note| note.note_id() == outputs.change.note_id())
    {
        state.funding.push(outputs.change.clone());
    }
    Ok(())
}

impl PoolState {
    /// Restore state and reject malformed records.
    fn restore(persisted: &PersistedState) -> Result<Self> {
        let mut deposits = HashMap::new();
        for (key, notes) in &persisted.deposits {
            let address = address_from_hex(key).ok_or_else(|| corrupt("deposit address", key))?;
            let notes = notes
                .iter()
                .map(OwnedNote::try_from)
                .collect::<std::result::Result<Vec<_>, _>>()?;
            deposits.insert(address, notes);
        }
        let queue = persisted
            .queue
            .iter()
            .map(restore_allocation)
            .collect::<Result<Vec<_>>>()?;
        let funding = persisted
            .funding
            .iter()
            .map(OwnedNote::try_from)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let in_flight = persisted
            .in_flight
            .as_ref()
            .map(|reserved| -> Result<InFlight> {
                Ok(InFlight {
                    batch: reserved
                        .batch
                        .iter()
                        .map(restore_allocation)
                        .collect::<Result<Vec<_>>>()?,
                    funding: OwnedNote::try_from(&reserved.funding)?,
                    outputs: reserved
                        .outputs
                        .as_ref()
                        .map(|outputs| -> Result<AggregationOutputs> {
                            let allocations = outputs
                                .allocations
                                .iter()
                                .map(OwnedNote::try_from)
                                .collect::<std::result::Result<Vec<_>, _>>()?;
                            let change = OwnedNote::try_from(&outputs.change)?;
                            let mut emitted_notes = outputs
                                .emitted_notes
                                .iter()
                                .map(OwnedNote::try_from)
                                .collect::<std::result::Result<Vec<_>, _>>()?;
                            if emitted_notes.is_empty() {
                                emitted_notes.extend(allocations.iter().cloned());
                                emitted_notes.push(change.clone());
                            }
                            Ok(AggregationOutputs {
                                allocations,
                                change,
                                emitted_notes,
                            })
                        })
                        .transpose()?,
                })
            })
            .transpose()?;
        let shield_in_flight = persisted
            .shield_in_flight
            .as_ref()
            .map(|shield| -> Result<ShieldInFlight> {
                let note = OwnedNote::try_from(&shield.note)?;
                let gross = shield
                    .gross
                    .parse()
                    .map_err(|_| corrupt("shield gross", &shield.gross))?;
                Ok(ShieldInFlight {
                    prepared: PreparedDeposit::from_recovery_parts(
                        note,
                        gross,
                        shield.recovery.clone(),
                        shield.portal_address.clone(),
                    ),
                    stage: shield.stage,
                })
            })
            .transpose()?;
        for note in persisted
            .commitment_in_flight
            .iter()
            .chain(&persisted.withdrawal_in_flight)
            .chain(&persisted.uncommitted)
        {
            OwnedNote::try_from(note)?;
        }
        Ok(Self {
            funding,
            deposits,
            queue,
            in_flight,
            uncommitted: persisted.uncommitted.clone(),
            shield_in_flight,
            commitment_in_flight: persisted.commitment_in_flight.clone(),
            withdrawal_in_flight: persisted.withdrawal_in_flight.clone(),
        })
    }

    fn persist(&self) -> PersistedState {
        PersistedState {
            deposits: self
                .deposits
                .iter()
                .map(|(address, notes)| {
                    (
                        address_hex(address),
                        notes.iter().map(StoredNote::from).collect(),
                    )
                })
                .collect(),
            funding: self.funding.iter().map(StoredNote::from).collect(),
            queue: self.queue.iter().map(stored_allocation).collect(),
            uncommitted: self.uncommitted.clone(),
            in_flight: self.in_flight.as_ref().map(|reserved| StoredInFlight {
                batch: reserved.batch.iter().map(stored_allocation).collect(),
                funding: StoredNote::from(&reserved.funding),
                outputs: reserved
                    .outputs
                    .as_ref()
                    .map(|outputs| StoredAggregationOutputs {
                        allocations: outputs.allocations.iter().map(StoredNote::from).collect(),
                        change: StoredNote::from(&outputs.change),
                        emitted_notes: outputs.emitted_notes.iter().map(StoredNote::from).collect(),
                    }),
            }),
            shield_in_flight: self.shield_in_flight.as_ref().map(|shield| StoredShield {
                note: StoredNote::from(&shield.prepared.note),
                gross: shield.prepared.gross.to_string(),
                recovery: shield.prepared.recovery.clone(),
                portal_address: shield.prepared.portal_address.clone(),
                stage: shield.stage,
            }),
            commitment_in_flight: self.commitment_in_flight.clone(),
            withdrawal_in_flight: self.withdrawal_in_flight.clone(),
        }
    }

    /// Whether this note is awaiting commitment.
    fn is_uncommitted(&self, note: &OwnedNote) -> bool {
        let stored = StoredNote::from(note);
        self.uncommitted.contains(&stored)
    }

    /// Value delivered and committed, hence actually withdrawable.
    fn recorded_committed(&self, address: &[u8; 32]) -> u128 {
        self.deposits
            .get(address)
            .map(|notes| {
                notes
                    .iter()
                    .filter(|note| !self.is_uncommitted(note))
                    .filter_map(note_amount)
                    .fold(0u128, u128::saturating_add)
            })
            .unwrap_or(0)
    }
}

/// Configuration the pool needs to act on-chain.
pub struct CurvyDepositPoolConfig {
    /// Account whose committed notes fund allocations and receive change.
    pub spender: Account,
    /// Key that signs and pays gas for aggregation/withdrawal submissions.
    pub submitter_private_key: String,
    /// Key that signs pending-note commitments.
    pub operator_private_key: String,
    /// Token id every note in this pool is denominated in.
    pub token: u64,
    pub route: Route,
    /// Flush once this many allocations are queued. Capped at
    /// [`MAX_ALLOCATIONS_PER_PROOF`], which is all one proof can carry.
    pub flush_threshold: usize,
    /// Stealth identity of the protocol fee collector.
    ///
    /// Required when the configured fee note is nonzero.
    pub fee_recipient: Option<curvy_sdk::Identity>,
}

impl CurvyDepositPoolConfig {
    /// Sensible defaults for everything except the identities and keys.
    pub fn new(
        spender: Account,
        submitter_private_key: String,
        operator_private_key: String,
        token: u64,
    ) -> Self {
        Self {
            spender,
            submitter_private_key,
            operator_private_key,
            token,
            route: Route::Blokli,
            flush_threshold: MAX_ALLOCATIONS_PER_PROOF,
            fee_recipient: None,
        }
    }
}

pub struct CurvyDepositPool {
    client: Arc<CurvyClient>,
    config: CurvyDepositPoolConfig,
    state: Arc<Mutex<PoolState>>,
    store: Arc<dyn DepositStore>,
    /// Serializes pool chain operations.
    chain: tokio::sync::Mutex<()>,
    /// State-change notifications for `notify_deposit`.
    changed: tokio::sync::watch::Sender<u64>,
}

impl CurvyDepositPool {
    /// Restore a pool from its store, or start empty if there is nothing to restore.
    pub fn new(
        client: Arc<CurvyClient>,
        config: CurvyDepositPoolConfig,
        store: Arc<dyn DepositStore>,
    ) -> anyhow::Result<Self> {
        let state = PoolState::restore(&store.load()?)?;
        let (changed, _) = tokio::sync::watch::channel(0);
        Ok(Self {
            client,
            config,
            state: Arc::new(Mutex::new(state)),
            store,
            chain: tokio::sync::Mutex::new(()),
            changed,
        })
    }

    /// Persist the current state and wake anything waiting on a change.
    fn checkpoint(&self, state: &PoolState) -> Result<()> {
        self.store
            .save(&state.persist())
            .map_err(CurvyPoolError::Curvy)?;
        self.changed.send_modify(|version| *version += 1);
        Ok(())
    }

    /// Hand the pool a committed note it may spend when funding allocations.
    pub fn add_funding_note(&self, note: OwnedNote) -> Result<()> {
        if note.owner_pub != self.config.spender.bjj_pub {
            return Err(CurvyPoolError::InvalidFundingNote(
                "owner does not match the pool spender",
            ));
        }
        if note.token != Fr::from(self.config.token) {
            return Err(CurvyPoolError::InvalidFundingNote(
                "token does not match the pool token",
            ));
        }
        if note_amount(&note).is_none_or(|amount| amount == 0) {
            return Err(CurvyPoolError::InvalidFundingNote(
                "amount must be non-zero and fit u128",
            ));
        }
        let mut state = self.state.lock().expect("pool state");
        if state
            .funding
            .iter()
            .any(|existing| existing.note_id() == note.note_id())
            || state
                .in_flight
                .as_ref()
                .is_some_and(|reserved| reserved.funding.note_id() == note.note_id())
        {
            return Err(CurvyPoolError::InvalidFundingNote(
                "note is already registered",
            ));
        }
        state.funding.push(note);
        self.checkpoint(&state)
    }

    /// Total committed funding available to spend.
    pub fn available_funding(&self) -> u128 {
        let state = self.state.lock().expect("pool state");
        state
            .funding
            .iter()
            .filter(|note| !state.is_uncommitted(note))
            .filter_map(note_amount)
            .fold(0u128, u128::saturating_add)
    }

    /// Total funding awaiting commitment.
    pub fn pending_funding(&self) -> u128 {
        let state = self.state.lock().expect("pool state");
        state
            .funding
            .iter()
            .filter(|note| state.is_uncommitted(note))
            .filter_map(note_amount)
            .fold(0u128, u128::saturating_add)
    }

    /// Retry outstanding note commitments.
    pub async fn recover_commitments(&self) -> Result<Vec<curvy_sdk::TxLedger>> {
        let _serialised = self.chain.lock().await;
        self.commit_outstanding().await
    }

    /// Resolve an ambiguous aggregation from persisted outputs and note statuses.
    pub async fn recover_aggregation(&self) -> Result<()> {
        let _serialised = self.chain.lock().await;
        let reserved = self.state.lock().expect("pool state").in_flight.clone();
        let Some(reserved) = reserved else {
            return Ok(());
        };
        let Some(outputs) = reserved.outputs.as_ref() else {
            return Err(CurvyPoolError::UnresolvedInFlight {
                allocations: reserved.batch.len(),
            });
        };
        let mut landed = true;
        for note in outputs
            .emitted_notes
            .iter()
            .filter(|note| note.amount != Fr::from(0u64))
        {
            if !matches!(self.client.note_status(&note.note_id()).await?, 1 | 2) {
                landed = false;
                break;
            }
        }
        if !landed {
            return Err(CurvyPoolError::UnresolvedInFlight {
                allocations: reserved.batch.len(),
            });
        }
        self.settle_aggregation(&reserved.batch, outputs)
    }

    /// Flush all queued allocations and outstanding commitments.
    pub async fn flush_pending(&self) -> Result<Vec<curvy_sdk::TxLedger>> {
        let mut ledger = Vec::new();
        if self.state.lock().expect("pool state").in_flight.is_some() {
            self.recover_aggregation().await?;
        }
        // Commit existing outputs before selecting funding.
        if !self
            .state
            .lock()
            .expect("pool state")
            .uncommitted
            .is_empty()
        {
            ledger.extend(self.recover_commitments().await?);
        }
        while !self.state.lock().expect("pool state").queue.is_empty() {
            ledger.extend(self.flush().await?);
        }
        Ok(ledger)
    }

    /// Run [`flush_pending`](Self::flush_pending) on a timer.
    pub fn spawn_flusher(
        self: &Arc<Self>,
        interval: std::time::Duration,
    ) -> tokio::task::JoinHandle<()> {
        let pool = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                if let Err(error) = pool.flush_pending().await {
                    tracing::warn!(%error, "curvy deposit pool: scheduled flush failed");
                }
            }
        })
    }

    /// Shield funds into the pool account and register the resulting note.
    pub async fn fund_from_deposit(
        &self,
        gross: u128,
        operator_private_key: &str,
        recovery_address: &str,
    ) -> Result<Vec<curvy_sdk::TxLedger>> {
        let _serialised = self.chain.lock().await;
        let existing = self
            .state
            .lock()
            .expect("pool state")
            .shield_in_flight
            .clone();
        let mut shield = if let Some(existing) = existing {
            if existing.prepared.gross != gross || existing.prepared.recovery != recovery_address {
                return Err(CurvyPoolError::ShieldInProgress);
            }
            existing
        } else {
            let prepared = self
                .client
                .prepare_deposit(
                    &self.config.spender,
                    gross,
                    self.config.token,
                    recovery_address,
                )
                .await?;
            let shield = ShieldInFlight {
                prepared,
                stage: StoredShieldStage::Prepared,
            };
            let mut state = self.state.lock().expect("pool state");
            state.shield_in_flight = Some(shield.clone());
            self.checkpoint(&state)?;
            shield
        };

        let mut ledger = Vec::new();
        let observed_status = self
            .client
            .note_status(&shield.prepared.note.note_id())
            .await?;
        if !matches!(observed_status, 1 | 2) {
            if shield.stage == StoredShieldStage::Prepared {
                let portal_balance = self
                    .client
                    .eth_balance(&shield.prepared.portal_address)
                    .await?;
                if portal_balance == 0 {
                    ledger.push(
                        self.client
                            .fund_prepared_deposit(
                                &shield.prepared,
                                operator_private_key,
                                self.config.route,
                            )
                            .await?,
                    );
                } else if portal_balance != shield.prepared.gross {
                    return Err(CurvyPoolError::UnexpectedShieldFunding {
                        actual: portal_balance,
                        required: shield.prepared.gross,
                    });
                }
                shield.stage = StoredShieldStage::Funded;
                let mut state = self.state.lock().expect("pool state");
                state.shield_in_flight = Some(shield.clone());
                self.checkpoint(&state)?;
            }

            ledger.push(
                self.client
                    .shield_prepared_deposit(
                        &shield.prepared,
                        operator_private_key,
                        self.config.route,
                    )
                    .await?,
            );
        }

        // Record the note before committing it.
        {
            let stored = StoredNote::from(&shield.prepared.note);
            let mut state = self.state.lock().expect("pool state");
            if !state
                .funding
                .iter()
                .any(|note| note.note_id() == shield.prepared.note.note_id())
            {
                state.funding.push(shield.prepared.note.clone());
            }
            if observed_status != 2 && !state.uncommitted.contains(&stored) {
                state.uncommitted.push(stored);
            }
            state.shield_in_flight = None;
            self.checkpoint(&state)?;
        }
        ledger.extend(self.commit_outstanding().await?);
        Ok(ledger)
    }

    /// Notes currently recorded against a deposit address.
    pub fn deposits_for(&self, address: &PixDepositAddress) -> Vec<OwnedNote> {
        compressed_key(address)
            .ok()
            .and_then(|key| {
                self.state
                    .lock()
                    .expect("pool state")
                    .deposits
                    .get(&key)
                    .cloned()
            })
            .unwrap_or_default()
    }

    /// Aggregate one allocation batch and commit its outputs.
    async fn flush(&self) -> Result<Vec<curvy_sdk::TxLedger>> {
        let _serialised = self.chain.lock().await;

        let (take, allocation_total) = {
            let state = self.state.lock().expect("pool state");
            // Keep unresolved reservations until reconciliation.
            if let Some(in_flight) = state.in_flight.as_ref() {
                return Err(CurvyPoolError::UnresolvedInFlight {
                    allocations: in_flight.batch.len(),
                });
            }
            if state.queue.is_empty() {
                return Ok(Vec::new());
            }
            let take = state.queue.len().min(MAX_ALLOCATIONS_PER_PROOF);
            let allocation_total =
                state
                    .queue
                    .iter()
                    .take(take)
                    .try_fold(0u128, |total, queued| {
                        total
                            .checked_add(queued.amount)
                            .ok_or(CurvyPoolError::AmountOutOfRange)
                    })?;
            (take, allocation_total)
        };
        let minimum_input = self
            .client
            .pix_minimum_input(&Fr::from(self.config.token), allocation_total, 0)
            .await?;
        if minimum_input > allocation_total && self.config.fee_recipient.is_none() {
            return Err(CurvyPoolError::Curvy(anyhow::anyhow!(
                "the current PIX aggregation fee is non-zero but the pool has no fee-recipient identity"
            )));
        }

        let (batch, funding) = {
            let mut state = self.state.lock().expect("pool state");
            let batch: Vec<Queued> = state.queue.drain(..take).collect();
            // Reserve one funding note; the second input slot is padding.
            let index = state.funding.iter().position(|note| {
                !state.is_uncommitted(note)
                    && note_amount(note).is_some_and(|value| value >= minimum_input)
            });
            let Some(index) = index else {
                // Restore the batch before returning.
                state.queue.splice(0..0, batch);
                self.checkpoint(&state)?;
                return Err(CurvyPoolError::NoFunding);
            };
            let funding = state.funding.remove(index);
            state.in_flight = Some(InFlight {
                batch: batch.clone(),
                funding: funding.clone(),
                outputs: None,
            });
            self.checkpoint(&state)?;
            (batch, funding)
        };

        let allocations: Vec<(KnownOwner, u128)> =
            batch.iter().map(|q| (q.owner, q.amount)).collect();
        let aggregated = self
            .client
            .aggregate_pix_allocations(
                &self.config.spender,
                std::slice::from_ref(&funding),
                &allocations,
                None,
                self.config.fee_recipient.as_ref(),
                &self.config.submitter_private_key,
                self.config.route,
            )
            .await;

        let result = match aggregated {
            Ok(result) => result,
            Err(error) => {
                // Keep ambiguous submissions reserved.
                if let Some(ambiguous) = curvy_sdk::ambiguous_pix_aggregation(&error) {
                    let mut state = self.state.lock().expect("pool state");
                    if let Some(in_flight) = state.in_flight.as_mut() {
                        in_flight.outputs = Some(AggregationOutputs {
                            allocations: ambiguous.result.allocations.clone(),
                            change: ambiguous.result.change.clone(),
                            emitted_notes: ambiguous.result.emitted_notes.clone(),
                        });
                    }
                    self.checkpoint(&state)?;
                    return Err(CurvyPoolError::Curvy(error));
                }
                if curvy_sdk::ambiguous_submission(&error).is_some() {
                    return Err(CurvyPoolError::Curvy(error));
                }
                let mut state = self.state.lock().expect("pool state");
                if let Some(in_flight) = state.in_flight.take() {
                    state.queue.splice(0..0, in_flight.batch);
                    state.funding.push(in_flight.funding);
                }
                self.checkpoint(&state)?;
                return Err(CurvyPoolError::Curvy(error));
            }
        };

        // Record outputs before committing them.
        self.settle_aggregation(
            &batch,
            &AggregationOutputs {
                allocations: result.allocations.clone(),
                change: result.change.clone(),
                emitted_notes: result.emitted_notes.clone(),
            },
        )?;

        let mut ledger = result.ledger.clone();
        ledger.extend(self.commit_outstanding().await?);
        Ok(ledger)
    }

    fn settle_aggregation(&self, batch: &[Queued], outputs: &AggregationOutputs) -> Result<()> {
        let mut state = self.state.lock().expect("pool state");
        apply_aggregation_outputs(&mut state, batch, outputs)?;
        self.checkpoint(&state)
    }

    /// Commit recorded notes in fixed-size chunks.
    async fn commit_outstanding(&self) -> Result<Vec<curvy_sdk::TxLedger>> {
        let reserved = self
            .state
            .lock()
            .expect("pool state")
            .commitment_in_flight
            .clone();
        if !reserved.is_empty() {
            let mut included = true;
            for stored in &reserved {
                let note = OwnedNote::try_from(stored)?;
                if self.client.note_status(&note.note_id()).await? != 2 {
                    included = false;
                    break;
                }
            }
            if !included {
                return Err(CurvyPoolError::UnresolvedCommitment {
                    notes: reserved.len(),
                });
            }
            let mut state = self.state.lock().expect("pool state");
            state.uncommitted.retain(|note| !reserved.contains(note));
            state.commitment_in_flight.clear();
            self.checkpoint(&state)?;
        }

        let outstanding: Vec<StoredNote> = {
            let state = self.state.lock().expect("pool state");
            state.uncommitted.clone()
        };
        if outstanding.is_empty() {
            return Ok(Vec::new());
        }
        let mut ledger = Vec::new();
        for chunk in outstanding.chunks(COMMITMENTS_PER_PROOF) {
            let ids: Vec<Fr> = chunk
                .iter()
                .map(|stored| Ok(OwnedNote::try_from(stored)?.note_id()))
                .collect::<Result<_>>()?;
            {
                let mut state = self.state.lock().expect("pool state");
                state.commitment_in_flight = chunk.to_vec();
                self.checkpoint(&state)?;
            }
            let submitted = self
                .client
                .commit(&ids, &self.config.operator_private_key, self.config.route)
                .await;
            match submitted {
                Ok(rows) => ledger.extend(rows),
                Err(error) => {
                    if curvy_sdk::ambiguous_submission(&error).is_none() {
                        let mut state = self.state.lock().expect("pool state");
                        state.commitment_in_flight.clear();
                        self.checkpoint(&state)?;
                    }
                    return Err(CurvyPoolError::Curvy(error));
                }
            }

            let mut state = self.state.lock().expect("pool state");
            state.uncommitted.retain(|note| !chunk.contains(note));
            state.commitment_in_flight.clear();
            self.checkpoint(&state)?;
        }
        Ok(ledger)
    }

    /// Reconcile a withdrawal reservation against committed nullifiers.
    async fn reconcile_withdrawal(&self) -> Result<()> {
        let reserved = self
            .state
            .lock()
            .expect("pool state")
            .withdrawal_in_flight
            .clone();
        if reserved.is_empty() {
            return Ok(());
        }
        let notes = reserved
            .iter()
            .map(OwnedNote::try_from)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let nullifiers = notes.iter().map(OwnedNote::nullifier).collect::<Vec<_>>();
        if !self.client.nullifiers_committed(&nullifiers).await? {
            return Err(CurvyPoolError::UnresolvedWithdrawal {
                notes: reserved.len(),
            });
        }
        let spent = notes.iter().map(OwnedNote::note_id).collect::<Vec<_>>();
        let mut state = self.state.lock().expect("pool state");
        for deposits in state.deposits.values_mut() {
            deposits.retain(|note| !spent.contains(&note.note_id()));
        }
        state.withdrawal_in_flight.clear();
        self.checkpoint(&state)
    }
}

/// The 32-byte compressed point identifying a BabyJubJub deposit address.
fn compressed_key(address: &PixDepositAddress) -> Result<[u8; 32]> {
    match address {
        PixDepositAddress::Eth(_) => Err(CurvyPoolError::UnsupportedAddress),
        PixDepositAddress::Bjj(key) => key
            .as_ref()
            .try_into()
            .map_err(|_| CurvyPoolError::InvalidAddress),
    }
}

fn note_amount(note: &OwnedNote) -> Option<u128> {
    curvy_core::field::fr_to_biguint(&note.amount)
        .try_into()
        .ok()
}

fn balance_to_u128(balance: HoprBalance) -> Result<u128> {
    balance
        .amount()
        .try_into()
        .map_err(|_| CurvyPoolError::AmountOutOfRange)
}

/// Maximum note count for exact subset selection.
const EXACT_SELECTION_LIMIT: usize = 20;

/// Select whole notes with the smallest total that covers the target.
fn select_notes(notes: &[OwnedNote], target: Option<u128>) -> Result<Vec<OwnedNote>> {
    let Some(target) = target else {
        return Ok(notes.to_vec());
    };
    let available = notes
        .iter()
        .filter_map(note_amount)
        .fold(0u128, u128::saturating_add);
    if available < target {
        return Err(CurvyPoolError::InsufficientDeposit {
            available,
            requested: target,
        });
    }
    if target == 0 {
        return Ok(Vec::new());
    }

    if notes.len() <= EXACT_SELECTION_LIMIT {
        return Ok(minimal_excess_subset(notes, target));
    }

    // Use largest-first selection beyond the exact-search limit.
    let mut ordered = notes.to_vec();
    ordered.sort_by_key(|note| std::cmp::Reverse(note_amount(note).unwrap_or(0)));
    let mut chosen = Vec::new();
    let mut total = 0u128;
    for note in ordered {
        if total >= target {
            break;
        }
        total = total.saturating_add(note_amount(&note).unwrap_or(0));
        chosen.push(note);
    }
    Ok(chosen)
}

/// Find the smallest covering subset, preferring fewer notes on ties.
fn minimal_excess_subset(notes: &[OwnedNote], target: u128) -> Vec<OwnedNote> {
    let amounts: Vec<u128> = notes.iter().map(|n| note_amount(n).unwrap_or(0)).collect();
    let mut best: Option<(u128, u32, usize)> = None;

    for mask in 1u32..(1u32 << notes.len()) {
        let mut total = 0u128;
        for (index, amount) in amounts.iter().enumerate() {
            if mask & (1 << index) != 0 {
                total = total.saturating_add(*amount);
            }
        }
        if total < target {
            continue;
        }
        let excess = total - target;
        let count = mask.count_ones();
        if best
            .is_none_or(|(best_excess, best_count, _)| (excess, count) < (best_excess, best_count))
        {
            best = Some((excess, count, mask as usize));
        }
    }

    let mask = best.map(|(_, _, mask)| mask).unwrap_or(0);
    notes
        .iter()
        .enumerate()
        .filter(|(index, _)| mask & (1 << index) != 0)
        .map(|(_, note)| note.clone())
        .collect()
}

#[async_trait]
impl DepositPool for CurvyDepositPool {
    type Error = CurvyPoolError;
    type Receipt = Vec<curvy_sdk::TxLedger>;

    /// Enqueue an allocation and flush a full batch.
    async fn deposit_funds_to(
        &self,
        dst: PixDepositAddress,
        amount: HoprBalance,
    ) -> Result<Self::Receipt> {
        let compressed = compressed_key(&dst)?;
        let (x, y) = bjj::decompress(&compressed).ok_or(CurvyPoolError::InvalidAddress)?;
        let point = BabyJubPoint::try_from_xy(x, y).map_err(|_| CurvyPoolError::InvalidAddress)?;

        // The aggregation circuit requires nonzero allocations.
        let amount = balance_to_u128(amount)?;
        if amount == 0 {
            return Err(CurvyPoolError::ZeroAllocation);
        }

        // Persist the shared secret with the allocation.
        let shared_secret = bjj::fresh_shared_secret();
        let full = {
            let mut state = self.state.lock().expect("pool state");
            state.queue.push(Queued {
                owner: KnownOwner::new(point, Bn254Fr::from_fr(shared_secret)),
                compressed,
                shared_secret,
                amount,
            });
            self.checkpoint(&state)?;
            state.queue.len()
                >= self
                    .config
                    .flush_threshold
                    .clamp(1, MAX_ALLOCATIONS_PER_PROOF)
        };

        if full {
            self.flush().await
        } else {
            Ok(Vec::new())
        }
    }

    /// Resolve when committed deposits reach `min_amount`.
    fn notify_deposit(
        &self,
        dst: PixDepositAddress,
        min_amount: HoprBalance,
    ) -> Result<BoxFuture<'static, (PixDepositAddress, HoprBalance)>> {
        let address = compressed_key(&dst)?;
        let target = balance_to_u128(min_amount)?;
        let state = Arc::clone(&self.state);
        let mut changed = self.changed.subscribe();

        Ok(Box::pin(async move {
            loop {
                let recorded = state
                    .lock()
                    .expect("pool state")
                    .recorded_committed(&address);
                if recorded >= target {
                    return (dst, HoprBalance::from(recorded));
                }
                // Do not report a deposit after shutdown.
                if changed.changed().await.is_err() {
                    futures::future::pending::<()>().await;
                }
            }
        }))
    }

    async fn withdraw_deposit(
        &self,
        key: &PixDepositSecret,
        dst: Address,
        amount: Option<HoprBalance>,
    ) -> Result<Self::Receipt> {
        let _serialised = self.chain.lock().await;
        self.reconcile_withdrawal().await?;
        let secret: [u8; 32] = key
            .0
            .as_ref()
            .try_into()
            .map_err(|_| CurvyPoolError::InvalidSecret)?;
        let signer = bjj::signing_key(&secret).ok_or(CurvyPoolError::InvalidSecret)?;
        let compressed =
            bjj::compressed_from_secret(&secret).ok_or(CurvyPoolError::InvalidSecret)?;

        let notes = {
            let state = self.state.lock().expect("pool state");
            state
                .deposits
                .get(&compressed)
                .map(|notes| {
                    notes
                        .iter()
                        .filter(|note| !state.is_uncommitted(note))
                        .cloned()
                        .collect::<Vec<_>>()
                })
                .ok_or(CurvyPoolError::UnknownDeposit)?
        };
        let target = amount.map(balance_to_u128).transpose()?;
        let selected = select_notes(&notes, target)?;
        let mut ledger = Vec::new();
        for chunk in selected.chunks(MAX_WITHDRAWAL_INPUTS) {
            {
                let mut state = self.state.lock().expect("pool state");
                state.withdrawal_in_flight = chunk.iter().map(StoredNote::from).collect();
                self.checkpoint(&state)?;
            }
            let spends = chunk.iter().map(|note| (&signer, note)).collect::<Vec<_>>();
            let submitted = self
                .client
                .withdraw_pix_multi_owner(
                    &spends,
                    &dst.to_string(),
                    &self.config.submitter_private_key,
                    self.config.route,
                )
                .await;
            let rows = match submitted {
                Ok((_delivered, rows)) => rows,
                Err(error) => {
                    if curvy_sdk::ambiguous_submission(&error).is_none() {
                        let mut state = self.state.lock().expect("pool state");
                        state.withdrawal_in_flight.clear();
                        self.checkpoint(&state)?;
                    }
                    return Err(CurvyPoolError::Curvy(error));
                }
            };
            ledger.extend(rows);

            // Checkpoint each completed proof.
            let spent = chunk.iter().map(OwnedNote::note_id).collect::<Vec<_>>();
            let mut state = self.state.lock().expect("pool state");
            if let Some(remaining) = state.deposits.get_mut(&compressed) {
                remaining.retain(|note| !spent.contains(&note.note_id()));
            }
            state.withdrawal_in_flight.clear();
            self.checkpoint(&state)?;
        }
        Ok(ledger)
    }

    /// Sweep deposits into one destination in batches of ten notes.
    async fn withdraw_multiple_deposits(
        &self,
        keys: &[PixDepositSecret],
        dst: Address,
    ) -> Result<Vec<std::result::Result<(Address, Self::Receipt), Self::Error>>> {
        let _serialised = self.chain.lock().await;
        self.reconcile_withdrawal().await?;
        // Resolve errors per deposit key.
        let mut resolved: Vec<(usize, curvy_core::eddsa::ScalarSigningKey, Vec<OwnedNote>)> =
            Vec::new();
        let mut outcomes: Vec<Option<std::result::Result<(Address, Self::Receipt), Self::Error>>> =
            (0..keys.len()).map(|_| None).collect();

        for (index, key) in keys.iter().enumerate() {
            let resolution = (|| {
                let secret: [u8; 32] = key
                    .0
                    .as_ref()
                    .try_into()
                    .map_err(|_| CurvyPoolError::InvalidSecret)?;
                let signer = bjj::signing_key(&secret).ok_or(CurvyPoolError::InvalidSecret)?;
                let compressed =
                    bjj::compressed_from_secret(&secret).ok_or(CurvyPoolError::InvalidSecret)?;
                let notes = self.state.lock().expect("pool state");
                let notes = notes
                    .deposits
                    .get(&compressed)
                    .map(|deposits| {
                        deposits
                            .iter()
                            .filter(|note| !notes.is_uncommitted(note))
                            .cloned()
                            .collect::<Vec<_>>()
                    })
                    .ok_or(CurvyPoolError::UnknownDeposit)?;
                Ok((signer, compressed, notes))
            })();
            match resolution {
                Ok((signer, _, notes)) => resolved.push((index, signer, notes)),
                Err(error) => outcomes[index] = Some(Err(error)),
            }
        }

        // Fill proofs across deposit-key boundaries.
        let mut slots: Vec<(usize, &curvy_core::eddsa::ScalarSigningKey, &OwnedNote)> = Vec::new();
        for (index, signer, notes) in &resolved {
            for note in notes {
                slots.push((*index, signer, note));
            }
        }

        let mut ledgers: Vec<Vec<curvy_sdk::TxLedger>> = vec![Vec::new(); keys.len()];
        let mut failures: Vec<Option<String>> = vec![None; keys.len()];
        for (chunk_index, chunk) in slots.chunks(MAX_WITHDRAWAL_INPUTS).enumerate() {
            {
                let mut state = self.state.lock().expect("pool state");
                state.withdrawal_in_flight = chunk
                    .iter()
                    .map(|(_, _, note)| StoredNote::from(*note))
                    .collect();
                self.checkpoint(&state)?;
            }
            let spends: Vec<(&curvy_core::eddsa::ScalarSigningKey, &OwnedNote)> = chunk
                .iter()
                .map(|(_, signer, note)| (*signer, *note))
                .collect();
            let submitted = self
                .client
                .withdraw_pix_multi_owner(
                    &spends,
                    &dst.to_string(),
                    &self.config.submitter_private_key,
                    self.config.route,
                )
                .await;
            match submitted {
                Ok((_delivered, rows)) => {
                    let mut credited = HashSet::new();
                    for (index, _, _) in chunk {
                        if credited.insert(*index) {
                            ledgers[*index].extend(rows.clone());
                        }
                    }

                    let settled = chunk
                        .iter()
                        .map(|(_, _, note)| note.note_id())
                        .collect::<Vec<_>>();
                    let mut state = self.state.lock().expect("pool state");
                    for notes in state.deposits.values_mut() {
                        notes.retain(|note| !settled.contains(&note.note_id()));
                    }
                    state.withdrawal_in_flight.clear();
                    self.checkpoint(&state)?;
                }
                Err(error) => {
                    // Report proof failures for every affected key.
                    for (index, _, _) in chunk {
                        failures[*index] = Some(error.to_string());
                    }
                    if curvy_sdk::ambiguous_submission(&error).is_some() {
                        let remaining = chunk_index * MAX_WITHDRAWAL_INPUTS;
                        for (index, _, _) in &slots[remaining..] {
                            failures[*index] = Some(error.to_string());
                        }
                        break;
                    }
                    let mut state = self.state.lock().expect("pool state");
                    state.withdrawal_in_flight.clear();
                    self.checkpoint(&state)?;
                }
            }
        }

        for (index, outcome) in outcomes.iter_mut().enumerate() {
            if outcome.is_some() {
                continue;
            }
            *outcome = Some(match &failures[index] {
                Some(message) => Err(CurvyPoolError::Curvy(anyhow::anyhow!(message.clone()))),
                None => Ok((dst, std::mem::take(&mut ledgers[index]))),
            });
        }
        Ok(outcomes.into_iter().map(|o| o.expect("filled")).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(amount: u128) -> OwnedNote {
        OwnedNote {
            owner_pub: (Fr::from(1u64), Fr::from(2u64)),
            shared_secret: Fr::from(3u64),
            ephemeral_key: (Fr::from(4u64), Fr::from(5u64)),
            view_tag: 0,
            amount: curvy_core::field::fr_from_biguint(&amount.into()),
            token: Fr::from(1u64),
        }
    }

    fn queued(address: [u8; 32], amount: u128) -> Queued {
        let point = curvy_core::babyjubjub::BabyJubPoint::try_from_xy(
            curvy_core::babyjubjub::BASE8.0,
            curvy_core::babyjubjub::BASE8.1,
        )
        .expect("base8 is on the curve");
        let shared_secret = Fr::from(7u64);
        Queued {
            owner: KnownOwner::new(point, Bn254Fr::from_fr(shared_secret)),
            compressed: address,
            shared_secret,
            amount,
        }
    }

    /// Settlement queues every nonzero circuit output for commitment.
    #[test]
    fn aggregation_settlement_tracks_every_nonzero_emitted_note() {
        let address = [9u8; 32];
        let allocation = note(100);
        let change = note(900);
        let fee = note(17);
        let zero_padding = note(0);
        let outputs = AggregationOutputs {
            allocations: vec![allocation.clone()],
            change: change.clone(),
            emitted_notes: vec![
                allocation.clone(),
                change.clone(),
                zero_padding,
                fee.clone(),
            ],
        };
        let mut state = PoolState::default();

        apply_aggregation_outputs(&mut state, &[queued(address, 100)], &outputs)
            .expect("valid aggregation");

        assert_eq!(state.deposits[&address][0].note_id(), allocation.note_id());
        assert_eq!(state.funding[0].note_id(), change.note_id());
        assert_eq!(state.uncommitted.len(), 3, "zero padding is not committed");
        assert!(state.uncommitted.contains(&StoredNote::from(&allocation)));
        assert!(state.uncommitted.contains(&StoredNote::from(&change)));
        assert!(
            state.uncommitted.contains(&StoredNote::from(&fee)),
            "fee output would otherwise remain pending forever"
        );
    }

    #[test]
    fn no_target_withdraws_every_recorded_note() {
        let notes = vec![note(10), note(20)];
        assert_eq!(select_notes(&notes, None).unwrap().len(), 2);
    }

    fn total(notes: &[OwnedNote]) -> u128 {
        notes.iter().filter_map(note_amount).sum()
    }

    #[test]
    fn a_partial_request_selects_whole_notes_not_a_fraction() {
        let notes = vec![note(10), note(20)];
        let chosen = select_notes(&notes, Some(15)).unwrap();
        assert_eq!(chosen.len(), 1);
        assert_eq!(note_amount(&chosen[0]), Some(20));
    }

    #[test]
    fn over_delivery_is_by_the_smallest_possible_margin() {
        let notes = vec![note(10), note(12), note(20), note(50)];
        let chosen = select_notes(&notes, Some(15)).unwrap();
        assert_eq!(total(&chosen), 20);

        let chosen = select_notes(&notes, Some(25)).unwrap();
        assert_eq!(total(&chosen), 30);
    }

    #[test]
    fn an_exact_match_is_preferred_and_costs_nothing_extra() {
        let notes = vec![note(5), note(10), note(20)];
        let chosen = select_notes(&notes, Some(15)).unwrap();
        assert_eq!(total(&chosen), 15, "5 + 10 covers 15 with no excess");
    }

    #[test]
    fn ties_on_excess_prefer_fewer_notes() {
        let notes = vec![note(10), note(5), note(5)];
        assert_eq!(select_notes(&notes, Some(10)).unwrap().len(), 1);
    }

    #[test]
    fn only_a_genuinely_insufficient_balance_fails() {
        let notes = vec![note(10), note(20)];
        let error = select_notes(&notes, Some(100)).unwrap_err();
        assert!(matches!(
            error,
            CurvyPoolError::InsufficientDeposit {
                available: 30,
                requested: 100
            }
        ));
    }

    /// Deposit records survive a restart.
    #[test]
    fn deposit_records_survive_a_restart() {
        let address = [9u8; 32];
        let mut before = PoolState::default();
        before.deposits.insert(address, vec![note(500), note(750)]);
        before.funding.push(note(10_000));

        let after = PoolState::restore(&before.persist()).expect("clean state must restore");

        assert_eq!(after.recorded_committed(&address), 1_250);
        assert_eq!(after.funding.len(), 1);
        assert_eq!(
            after.deposits[&address]
                .iter()
                .map(|n| n.note_id())
                .collect::<Vec<_>>(),
            before.deposits[&address]
                .iter()
                .map(|n| n.note_id())
                .collect::<Vec<_>>(),
            "restored notes must hash to the same ids or they are unspendable"
        );
    }

    /// Queued allocations survive a restart.
    #[test]
    fn a_queued_allocation_survives_a_restart() {
        let secret = Fr::from(123_456u64);
        let point = curvy_core::babyjubjub::BabyJubPoint::try_from_xy(
            curvy_core::babyjubjub::BASE8.0,
            curvy_core::babyjubjub::BASE8.1,
        )
        .expect("base8 is on the curve");
        let compressed = crate::bjj::compressed_from_secret(&{
            let mut bytes = [0u8; 32];
            bytes[31] = 1;
            bytes
        })
        .expect("derivable");

        let mut before = PoolState::default();
        before.queue.push(Queued {
            owner: KnownOwner::new(point, Bn254Fr::from_fr(secret)),
            compressed,
            shared_secret: secret,
            amount: 4_242,
        });

        let after = PoolState::restore(&before.persist()).expect("clean state must restore");
        assert_eq!(after.queue.len(), 1);
        assert_eq!(after.queue[0].amount, 4_242);
        assert_eq!(after.queue[0].shared_secret, secret);
        assert_eq!(after.queue[0].compressed, compressed);
    }

    /// In-flight reservations survive a restart.
    #[test]
    fn a_reservation_survives_a_restart() {
        let secret = Fr::from(777u64);
        let point = curvy_core::babyjubjub::BabyJubPoint::try_from_xy(
            curvy_core::babyjubjub::BASE8.0,
            curvy_core::babyjubjub::BASE8.1,
        )
        .expect("base8 is on the curve");
        let mut compressed = [0u8; 32];
        compressed[31] = 1;
        let compressed = crate::bjj::compressed_from_secret(&compressed).expect("derivable");

        let before = PoolState {
            in_flight: Some(InFlight {
                batch: vec![Queued {
                    owner: KnownOwner::new(point, Bn254Fr::from_fr(secret)),
                    compressed,
                    shared_secret: secret,
                    amount: 9_001,
                }],
                funding: note(50_000),
                outputs: None,
            }),
            ..PoolState::default()
        };

        let persisted = before.persist();
        assert!(
            persisted.queue.is_empty() && persisted.funding.is_empty(),
            "a reserved batch is not in the queue and its note is not in funding, \
             which is exactly why the reservation itself has to be written"
        );

        let after = PoolState::restore(&persisted).expect("clean state must restore");
        let reserved = after.in_flight.expect("the reservation must come back");
        assert_eq!(reserved.batch.len(), 1);
        assert_eq!(reserved.batch[0].amount, 9_001);
        assert_eq!(reserved.batch[0].shared_secret, secret);
        assert_eq!(
            reserved.funding.note_id(),
            before.in_flight.unwrap().funding.note_id(),
            "the funding note must hash the same or it cannot be spent or reconciled"
        );
    }

    /// Clean state restores without a reservation.
    #[test]
    fn a_clean_pool_restores_without_a_reservation() {
        let mut before = PoolState::default();
        before.funding.push(note(10));
        let after = PoolState::restore(&before.persist()).expect("clean state must restore");
        assert!(after.in_flight.is_none());
    }

    /// Corrupt records fail restoration.
    #[test]
    fn a_corrupt_record_refuses_to_restore() {
        let mut persisted = PersistedState::default();
        let mut stored = StoredNote::from(&note(5));
        stored.shared_secret = "not a number".to_owned();
        persisted.funding.push(stored);

        match PoolState::restore(&persisted) {
            Err(CurvyPoolError::CorruptState(record)) => assert_eq!(record.field, "shared_secret"),
            Err(other) => panic!("expected CorruptState, got {other}"),
            Ok(_) => panic!("must not start up half-read"),
        }
    }

    /// Invalid deposit keys fail restoration.
    #[test]
    fn an_unreadable_deposit_key_refuses_to_restore() {
        let mut persisted = PersistedState::default();
        persisted
            .deposits
            .insert("deadbeef".to_owned(), vec![StoredNote::from(&note(5))]);
        match PoolState::restore(&persisted) {
            Err(CurvyPoolError::CorruptState(record)) => {
                assert_eq!(record.field, "deposit address")
            }
            Err(other) => panic!("expected CorruptState, got {other}"),
            Ok(_) => panic!("an unreadable key must not be dropped"),
        }
    }

    /// Pending funding is excluded from spendable funding.
    #[test]
    fn uncommitted_value_is_reported_separately_from_spendable_value() {
        let committed = note(1_000);
        let pending = note(250);

        let state = PoolState {
            funding: vec![committed.clone(), pending.clone()],
            uncommitted: vec![StoredNote::from(&pending)],
            ..PoolState::default()
        };

        let spendable: u128 = state
            .funding
            .iter()
            .filter(|note| !state.is_uncommitted(note))
            .filter_map(note_amount)
            .sum();
        let waiting: u128 = state
            .funding
            .iter()
            .filter(|note| state.is_uncommitted(note))
            .filter_map(note_amount)
            .sum();

        assert_eq!(
            spendable, 1_000,
            "only the committed note can fund anything"
        );
        assert_eq!(waiting, 250);
    }

    /// Committed notes become spendable.
    #[test]
    fn clearing_the_uncommitted_list_releases_the_note() {
        let change = note(250);
        let mut state = PoolState {
            funding: vec![change.clone()],
            uncommitted: vec![StoredNote::from(&change)],
            ..PoolState::default()
        };
        assert!(state.is_uncommitted(&change));

        state.uncommitted.clear();
        assert!(!state.is_uncommitted(&change));
    }

    /// Zero balances convert without overflow.
    #[test]
    fn a_zero_balance_reaches_the_queue_unless_it_is_refused() {
        assert_eq!(
            balance_to_u128(HoprBalance::from(0_u32)).expect("zero is representable"),
            0
        );
    }

    #[test]
    fn committed_totals_only_count_the_named_address() {
        let mut state = PoolState::default();
        state.deposits.insert([1u8; 32], vec![note(10)]);
        state.deposits.insert([2u8; 32], vec![note(99)]);
        assert_eq!(state.recorded_committed(&[1u8; 32]), 10);
        assert_eq!(state.recorded_committed(&[3u8; 32]), 0);
    }

    #[test]
    fn uncommitted_notes_do_not_satisfy_a_deposit_notification() {
        let pending = note(10);
        let mut state = PoolState::default();
        state.deposits.insert([1u8; 32], vec![pending.clone()]);
        state.uncommitted.push(StoredNote::from(&pending));

        assert_eq!(state.recorded_committed(&[1u8; 32]), 0);
        state.uncommitted.clear();
        assert_eq!(state.recorded_committed(&[1u8; 32]), 10);
    }

    #[test]
    fn an_ethereum_address_is_refused_as_the_trait_requires() {
        let eth = PixDepositAddress::Eth(Address::default());
        assert!(matches!(
            compressed_key(&eth),
            Err(CurvyPoolError::UnsupportedAddress)
        ));
    }
}
