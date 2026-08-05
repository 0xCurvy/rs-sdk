//! [`CurvyDepositPool`] - HOPR's `DepositPool` backed by the Curvy privacy pool.
//!
//! HOPR's trait is per-deposit; the Curvy circuits are fixed-arity `(2,9)` and `(10)`.
//! Reconciling those is this type's whole job:
//!
//! * `deposit_funds_to` enqueues an allocation and flushes the queue as one aggregation
//!   proof carrying up to [`MAX_ALLOCATIONS_PER_PROOF`] recipients;
//! * `withdraw_multiple_deposits` overrides the trait's one-at-a-time default and
//!   spends up to [`MAX_WITHDRAWAL_INPUTS`] notes per proof - the trait explicitly
//!   invites "pool-native batching", and this is it.
//!
//! The pool also keeps the state HOPR cannot: a note's `ownerHash` is
//! `poseidon(ownerPub, sharedSecret)` and the shared secret is **our** choice at
//! allocation time, so without recording it a later `withdraw_deposit` cannot find the
//! note its key owns.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use curvy_core::babyjubjub::BabyJubPoint;
use curvy_core::field::{Bn254Fr, Fr};
use curvy_core::witness::KnownOwner;
use curvy_sdk::{Account, CurvyClient, OwnedNote, Route};
use futures::future::BoxFuture;
use hopr_api::chain::{DepositPool, PixDepositAddress, PixDepositSecret};
use hopr_types::primitive::prelude::{Address, HoprBalance};

use crate::bjj;
use crate::store::{
    DepositStore, PersistedState, StoredAllocation, StoredNote, address_from_hex, address_hex,
};

/// Recipients per aggregation proof: the `(2,9)` profile's nine regular outputs carry
/// seven allocations plus the change note and the relayer's gas-reimbursement note.
pub const MAX_ALLOCATIONS_PER_PROOF: usize = 7;
/// Inputs per withdrawal proof, from the `(10,30)` profile.
pub const MAX_WITHDRAWAL_INPUTS: usize = 10;

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
    #[error(transparent)]
    Curvy(#[from] anyhow::Error),
}

type Result<T> = std::result::Result<T, CurvyPoolError>;

/// One queued allocation awaiting the next aggregation proof.
#[derive(Clone)]
struct Queued {
    owner: KnownOwner,
    compressed: [u8; 32],
    /// Kept alongside the owner so the queue itself can be persisted: an accepted
    /// deposit must not evaporate if the process dies before its proof is built.
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
}

/// Allocations and the funding note reserved for an in-progress proof.
#[derive(Clone)]
struct InFlight {
    batch: Vec<Queued>,
    funding: OwnedNote,
}

impl PoolState {
    fn restore(persisted: &PersistedState) -> Self {
        let mut deposits = HashMap::new();
        for (key, notes) in &persisted.deposits {
            if let Some(address) = address_from_hex(key) {
                deposits.insert(address, notes.iter().map(OwnedNote::from).collect());
            }
        }
        let queue = persisted
            .queue
            .iter()
            .filter_map(|entry| {
                let compressed = address_from_hex(&entry.address)?;
                let (x, y) = bjj::decompress(&compressed)?;
                let point = BabyJubPoint::try_from_xy(x, y).ok()?;
                let shared_secret = curvy_core::field::fr_from_dec(&entry.shared_secret);
                Some(Queued {
                    owner: KnownOwner::new(point, Bn254Fr::from_fr(shared_secret)),
                    compressed,
                    shared_secret,
                    amount: entry.amount.parse().ok()?,
                })
            })
            .collect();
        Self {
            funding: persisted.funding.iter().map(OwnedNote::from).collect(),
            deposits,
            queue,
            in_flight: None,
            uncommitted: persisted.uncommitted.clone(),
        }
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
            queue: self
                .queue
                .iter()
                .map(|queued| StoredAllocation {
                    address: address_hex(&queued.compressed),
                    shared_secret: curvy_core::field::fr_to_dec(&queued.shared_secret),
                    amount: queued.amount.to_string(),
                })
                .collect(),
            uncommitted: self.uncommitted.clone(),
        }
    }

    /// Value already delivered to a deposit address.
    fn recorded(&self, address: &[u8; 32]) -> u128 {
        self.deposits
            .get(address)
            .map(|notes| notes.iter().filter_map(note_amount).sum())
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
    /// Required whenever the on-chain fees are non-zero: the fee note is a stealth note
    /// and without the collector's identity it is sealed to a random secret and becomes
    /// permanently uncollectable. `None` is only valid against a deployment whose
    /// protocol and per-token gas fees are both zero.
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
    /// Serialises on-chain work. Two submissions signed by one key must not read the
    /// same nonce, and a timer-driven flush must not race an inline one - both would
    /// produce a transaction that simply never lands.
    chain: tokio::sync::Mutex<()>,
    /// Bumped on every state change so `notify_deposit` can wait for one instead of
    /// polling on a timer.
    changed: tokio::sync::watch::Sender<u64>,
}

impl CurvyDepositPool {
    /// Restore a pool from its store, or start empty if there is nothing to restore.
    pub fn new(
        client: Arc<CurvyClient>,
        config: CurvyDepositPoolConfig,
        store: Arc<dyn DepositStore>,
    ) -> anyhow::Result<Self> {
        let state = PoolState::restore(&store.load()?);
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
        let mut state = self.state.lock().expect("pool state");
        state.funding.push(note);
        self.checkpoint(&state)
    }

    /// Total value the pool can currently allocate.
    pub fn available_funding(&self) -> u128 {
        self.state
            .lock()
            .expect("pool state")
            .funding
            .iter()
            .filter_map(note_amount)
            .sum()
    }

    /// Drain every queued allocation, however few. Deployments should call this on a
    /// timer (see [`spawn_flusher`](Self::spawn_flusher)); tests call it directly so a
    /// partial batch does not sit unproved forever.
    pub async fn flush_pending(&self) -> Result<Vec<curvy_sdk::TxLedger>> {
        let mut ledger = Vec::new();
        while !self.state.lock().expect("pool state").queue.is_empty() {
            ledger.extend(self.flush().await?);
        }
        Ok(ledger)
    }

    /// Drive [`flush_pending`](Self::flush_pending) on a timer.
    ///
    /// Without this - or an explicit flush - a batch that never reaches the threshold
    /// sits unproved and its `notify_deposit` never resolves. A deployment should run
    /// one of these; the interval is the worst-case latency a lone deposit sees.
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

    /// Shield `gross` into the pool's own account and register the resulting note as
    /// spendable funding.
    ///
    /// This is the deposit side of the pool's own balance sheet, kept deliberately
    /// explicit: allocations spend committed notes the pool already owns, so something
    /// has to put value in before any `deposit_funds_to` can succeed. Change flows back
    /// automatically after each aggregation, so one call is usually enough to seed a
    /// whole test run.
    pub async fn fund_from_deposit(
        &self,
        gross: u128,
        operator_private_key: &str,
        recovery_address: &str,
    ) -> Result<Vec<curvy_sdk::TxLedger>> {
        let (note, mut ledger) = self
            .client
            .deposit(
                &self.config.spender,
                gross,
                self.config.token,
                operator_private_key,
                recovery_address,
                self.config.route,
                self.config.route,
            )
            .await?;
        // A pending note cannot be spent; commit it before it counts as funding.
        ledger.extend(
            self.client
                .commit(
                    &[note.note_id()],
                    &self.config.operator_private_key,
                    self.config.route,
                )
                .await?,
        );
        self.add_funding_note(note)?;
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

    /// Drain the allocation queue into one aggregation proof, then commit its outputs
    /// so the allocations become spendable.
    ///
    /// The queued allocations and the funding note are *reserved* - moved into
    /// persisted in-flight state - before any chain work, and restored if the proof
    /// fails. Draining them outright would lose accepted liabilities on any error, and
    /// leaving them in place would let a retry double-spend the same funding note.
    async fn flush(&self) -> Result<Vec<curvy_sdk::TxLedger>> {
        let _serialised = self.chain.lock().await;

        let (batch, funding) = {
            let mut state = self.state.lock().expect("pool state");
            if let Some(in_flight) = state.in_flight.take() {
                // A previous attempt died between reserving and resolving. Its outcome
                // is unknown, so recovering it automatically risks re-spending a note
                // that already landed; surface it instead of guessing.
                self.checkpoint(&state)?;
                return Err(CurvyPoolError::UnresolvedInFlight {
                    allocations: in_flight.batch.len(),
                });
            }
            if state.queue.is_empty() {
                return Ok(Vec::new());
            }
            let take = state.queue.len().min(MAX_ALLOCATIONS_PER_PROOF);
            let batch: Vec<Queued> = state.queue.drain(..take).collect();
            let needed: u128 = batch.iter().map(|q| q.amount).sum();
            // One input note must cover the batch: the profile allows two inputs, but
            // picking a single sufficient note keeps selection obvious and leaves the
            // second slot for the zero pad.
            let index = state
                .funding
                .iter()
                .position(|note| note_amount(note).is_some_and(|value| value > needed));
            let Some(index) = index else {
                // Put the batch back before giving up - it is an accepted liability.
                state.queue.splice(0..0, batch);
                self.checkpoint(&state)?;
                return Err(CurvyPoolError::NoFunding);
            };
            let funding = state.funding.remove(index);
            state.in_flight = Some(InFlight {
                batch: batch.clone(),
                funding: funding.clone(),
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
                // Nothing was submitted, so the reservation can be safely undone.
                let mut state = self.state.lock().expect("pool state");
                if let Some(in_flight) = state.in_flight.take() {
                    state.queue.splice(0..0, in_flight.batch);
                    state.funding.push(in_flight.funding);
                }
                self.checkpoint(&state)?;
                return Err(CurvyPoolError::Curvy(error));
            }
        };

        // The proof landed: record the outputs BEFORE committing them. A commit failure
        // must not lose notes that already exist on-chain - they only need committing,
        // which the next flush retries.
        {
            let mut state = self.state.lock().expect("pool state");
            for (queued, note) in batch.iter().zip(result.allocations.iter()) {
                state
                    .deposits
                    .entry(queued.compressed)
                    .or_default()
                    .push(note.clone());
            }
            state.uncommitted.extend(
                result
                    .allocations
                    .iter()
                    .chain(std::iter::once(&result.change))
                    .map(StoredNote::from),
            );
            state.in_flight = None;
            self.checkpoint(&state)?;
        }

        let mut ledger = result.ledger.clone();
        ledger.extend(self.commit_outstanding().await?);

        let mut state = self.state.lock().expect("pool state");
        state.funding.push(result.change);
        self.checkpoint(&state)?;
        Ok(ledger)
    }

    /// Commit every recorded-but-uncommitted note, so an earlier commit failure heals
    /// on the next attempt instead of stranding spendable value.
    async fn commit_outstanding(&self) -> Result<Vec<curvy_sdk::TxLedger>> {
        let outstanding: Vec<Fr> = {
            let state = self.state.lock().expect("pool state");
            state
                .uncommitted
                .iter()
                .map(|stored| OwnedNote::from(stored).note_id())
                .collect()
        };
        if outstanding.is_empty() {
            return Ok(Vec::new());
        }
        let mut ledger = Vec::new();
        for chunk in outstanding.chunks(5) {
            ledger.extend(
                self.client
                    .commit(chunk, &self.config.operator_private_key, self.config.route)
                    .await?,
            );
        }
        let mut state = self.state.lock().expect("pool state");
        state.uncommitted.clear();
        self.checkpoint(&state)?;
        Ok(ledger)
    }

    /// Spend `notes` to `destination`, one `(10,30)` proof per chunk of ten.
    async fn withdraw_notes(
        &self,
        signer: &curvy_core::eddsa::ScalarSigningKey,
        notes: &[OwnedNote],
        destination: &str,
    ) -> Result<Vec<curvy_sdk::TxLedger>> {
        let mut ledger = Vec::new();
        for chunk in notes.chunks(MAX_WITHDRAWAL_INPUTS) {
            let spends: Vec<(&curvy_core::eddsa::ScalarSigningKey, &OwnedNote)> =
                chunk.iter().map(|note| (signer, note)).collect();
            let (_delivered, rows) = self
                .client
                .withdraw_pix_multi_owner(
                    &spends,
                    destination,
                    &self.config.submitter_private_key,
                    self.config.route,
                )
                .await?;
            ledger.extend(rows);
        }
        Ok(ledger)
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

/// Notes beyond which the exact minimal-excess search is skipped.
///
/// The search is exponential; a deposit address accumulates one note per allocation, so
/// realistic counts are tiny and this bound is never approached in practice. Past it the
/// greedy fallback still covers the target, just possibly less tightly.
const EXACT_SELECTION_LIMIT: usize = 20;

/// Choose which recorded notes to withdraw.
///
/// A "partial" withdrawal selects a **subset of notes**, never a fraction of one: Curvy
/// notes are atomic, and splitting one would need a whole extra aggregation proof
/// authorised by the depositor's key. So the pool cannot deliver an exact amount unless
/// some subset happens to sum to it - and rather than refusing, it delivers the
/// **smallest total that still covers the request**, minimising the excess.
///
/// Over-delivery is a deliberate trade: the alternative is failing a withdrawal the
/// depositor is entitled to, over a difference that is theirs anyway and lands at the
/// same destination.
fn select_notes(notes: &[OwnedNote], target: Option<u128>) -> Result<Vec<OwnedNote>> {
    let Some(target) = target else {
        return Ok(notes.to_vec());
    };
    let available: u128 = notes.iter().filter_map(note_amount).sum();
    if available < target {
        // The one case that must still fail: the pool cannot create value.
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

    // Fallback: largest-first covers the target in few notes, which also keeps the
    // proof count down.
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

/// The subset whose total covers `target` with the least excess, preferring fewer notes
/// when two subsets tie - each additional note consumes a slot in a ten-input proof.
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

    /// Accept an allocation into the next proof.
    ///
    /// This **enqueues and returns**; it does not wait for the aggregation proof. The
    /// trait pairs it with `notify_deposit` precisely so a pool can batch, and batching
    /// is what makes Curvy affordable - one `(2,9)` proof serves seven recipients
    /// instead of seven proofs serving one each. Callers that need to know the funds
    /// have landed must await `notify_deposit`, which is the only honest signal.
    ///
    /// A full batch is flushed inline by whichever call fills it, so throughput does not
    /// depend on a timer; a partial batch waits for [`flush_pending`](Self::flush_pending)
    /// or the periodic flusher.
    async fn deposit_funds_to(
        &self,
        dst: PixDepositAddress,
        amount: HoprBalance,
    ) -> Result<Self::Receipt> {
        let compressed = compressed_key(&dst)?;
        let (x, y) = bjj::decompress(&compressed).ok_or(CurvyPoolError::InvalidAddress)?;
        let point = BabyJubPoint::try_from_xy(x, y).map_err(|_| CurvyPoolError::InvalidAddress)?;

        // The shared secret is ours to pick and is what keeps two allocations to one
        // deposit address unlinkable; it is persisted with the queue entry because
        // without it the resulting note can never be located again.
        let shared_secret = bjj::fresh_shared_secret();
        let full = {
            let mut state = self.state.lock().expect("pool state");
            state.queue.push(Queued {
                owner: KnownOwner::new(point, Bn254Fr::from_fr(shared_secret)),
                compressed,
                shared_secret,
                amount: balance_to_u128(amount)?,
            });
            self.checkpoint(&state)?;
            state.queue.len() >= self.config.flush_threshold.min(MAX_ALLOCATIONS_PER_PROOF)
        };

        if full {
            self.flush().await
        } else {
            Ok(Vec::new())
        }
    }

    /// A future resolving once `min_amount` has actually been delivered to `dst`.
    ///
    /// Since `deposit_funds_to` only enqueues, this is where the caller learns the funds
    /// exist. It waits on a state-change signal rather than polling, and reports the
    /// amount genuinely recorded - which may exceed `min_amount`, because notes are
    /// atomic and the pool never splits one to hit an exact figure.
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
                let recorded = state.lock().expect("pool state").recorded(&address);
                if recorded >= target {
                    return (dst, HoprBalance::from(recorded));
                }
                // If every sender is gone the pool is being torn down; parking forever
                // is better than reporting an arrival that will never happen.
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
                .cloned()
                .ok_or(CurvyPoolError::UnknownDeposit)?
        };
        let target = amount.map(balance_to_u128).transpose()?;
        let selected = select_notes(&notes, target)?;
        let ledger = self
            .withdraw_notes(&signer, &selected, &dst.to_string())
            .await?;

        let spent: Vec<Fr> = selected.iter().map(|note| note.note_id()).collect();
        let mut state = self.state.lock().expect("pool state");
        if let Some(remaining) = state.deposits.get_mut(&compressed) {
            remaining.retain(|note| !spent.contains(&note.note_id()));
        }
        self.checkpoint(&state)?;
        Ok(ledger)
    }

    /// Sweep many deposits into one destination using pool-native batching.
    ///
    /// The trait's default fans out one `withdraw_deposit` per key, which for Curvy
    /// would mean one Groth16 proof per deposit. The `(10,30)` profile authorises ten
    /// independently-owned notes in a *single* proof, so ten deposits cost one proof
    /// instead of ten - the exact case the trait's "implementors may choose a more
    /// efficient pool-native batching" note anticipates.
    ///
    /// Every note is signed by its own scalar; nothing here assumes the keys are
    /// related. Results are reported per key so one bad secret cannot fail the sweep.
    async fn withdraw_multiple_deposits(
        &self,
        keys: &[PixDepositSecret],
        dst: Address,
    ) -> Result<Vec<std::result::Result<(Address, Self::Receipt), Self::Error>>> {
        // Resolve every key to its notes first, so a single unusable secret is reported
        // against that key rather than aborting the whole sweep.
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
                let notes = self
                    .state
                    .lock()
                    .expect("pool state")
                    .deposits
                    .get(&compressed)
                    .cloned()
                    .ok_or(CurvyPoolError::UnknownDeposit)?;
                Ok((signer, compressed, notes))
            })();
            match resolution {
                Ok((signer, _, notes)) => resolved.push((index, signer, notes)),
                Err(error) => outcomes[index] = Some(Err(error)),
            }
        }

        // Fill proofs to ten inputs across key boundaries - the circuit does not care
        // whether two inputs belong to the same depositor.
        let mut slots: Vec<(usize, &curvy_core::eddsa::ScalarSigningKey, &OwnedNote)> = Vec::new();
        for (index, signer, notes) in &resolved {
            for note in notes {
                slots.push((*index, signer, note));
            }
        }

        let mut ledgers: Vec<Vec<curvy_sdk::TxLedger>> = vec![Vec::new(); keys.len()];
        let mut failures: Vec<Option<String>> = vec![None; keys.len()];
        // Note ids whose proof actually landed, so pruning follows the chain rather
        // than the per-key verdict.
        let mut spent_note_ids: Vec<Fr> = Vec::new();
        for chunk in slots.chunks(MAX_WITHDRAWAL_INPUTS) {
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
                    for (index, _, note) in chunk {
                        ledgers[*index].extend(rows.clone());
                        spent_note_ids.push(note.note_id());
                    }
                }
                Err(error) => {
                    // A proof covers several depositors, so a failure is reported
                    // against every key that had a note in it.
                    for (index, _, _) in chunk {
                        failures[*index] = Some(error.to_string());
                    }
                }
            }
        }

        // Prune per NOTE, not per key. A depositor's notes can span several proofs, so
        // marking the whole depositor failed would leave notes that were genuinely spent
        // still recorded as spendable - and the next withdrawal would build a proof
        // against an already-nullified note.
        {
            let mut state = self.state.lock().expect("pool state");
            let settled: Vec<Fr> = spent_note_ids;
            for notes in state.deposits.values_mut() {
                notes.retain(|note| !settled.contains(&note.note_id()));
            }
            self.checkpoint(&state)?;
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
        // Notes are atomic, so an exact 15 is impossible from {10, 20}.
        let notes = vec![note(10), note(20)];
        let chosen = select_notes(&notes, Some(15)).unwrap();
        assert_eq!(chosen.len(), 1);
        assert_eq!(note_amount(&chosen[0]), Some(20));
    }

    #[test]
    fn over_delivery_is_by_the_smallest_possible_margin() {
        // Covering 15 from {10, 12, 20, 50}: the 20 alone (excess 5) beats 10+12
        // (excess 7) and every larger combination.
        let notes = vec![note(10), note(12), note(20), note(50)];
        let chosen = select_notes(&notes, Some(15)).unwrap();
        assert_eq!(total(&chosen), 20);

        // And a combination wins when no single note is closer: covering 25 from
        // {10, 12, 20, 50} is best served by 12+20 = 32? No - 10+20 = 30 is tighter.
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
        // {10, 5, 5} covering 10: both {10} and {5,5} have zero excess, but one note
        // consumes one slot of a ten-input proof instead of two.
        let notes = vec![note(10), note(5), note(5)];
        assert_eq!(select_notes(&notes, Some(10)).unwrap().len(), 1);
    }

    #[test]
    fn only_a_genuinely_insufficient_balance_fails() {
        // The pool cannot create value, so this is the one case that must still error.
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

    /// A pool that forgets a shared secret can never find the note again, so the
    /// mapping must survive a restart byte-for-byte.
    #[test]
    fn deposit_records_survive_a_restart() {
        let address = [9u8; 32];
        let mut before = PoolState::default();
        before.deposits.insert(address, vec![note(500), note(750)]);
        before.funding.push(note(10_000));

        let after = PoolState::restore(&before.persist());

        assert_eq!(after.recorded(&address), 1_250);
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

    /// An accepted-but-unproved allocation is a liability: HOPR was told the deposit
    /// was taken, so dropping it on restart silently loses someone's funds.
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

        let after = PoolState::restore(&before.persist());
        assert_eq!(after.queue.len(), 1);
        assert_eq!(after.queue[0].amount, 4_242);
        assert_eq!(after.queue[0].shared_secret, secret);
        assert_eq!(after.queue[0].compressed, compressed);
    }

    #[test]
    fn recorded_totals_only_count_the_named_address() {
        let mut state = PoolState::default();
        state.deposits.insert([1u8; 32], vec![note(10)]);
        state.deposits.insert([2u8; 32], vec![note(99)]);
        assert_eq!(state.recorded(&[1u8; 32]), 10);
        assert_eq!(state.recorded(&[3u8; 32]), 0);
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
