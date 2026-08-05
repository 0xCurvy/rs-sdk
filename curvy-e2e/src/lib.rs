//! Strict deposit → two PIX fan-outs → ten-owner withdrawal acceptance flow.
//!
//! The flow is deliberately one sequential run: each phase consumes committed state
//! the previous phase produced, and every aggregation is a real `(2,9,30,6)` Groth16
//! proof, so re-proving a prefix per test would cost minutes for no extra coverage.
//! Instead of a bare pass/fail, [`run`] returns an [`E2eReport`] carrying a per-phase
//! record (tx hashes, backend, wall time) that a reviewer can read as evidence.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use curvy_chain_api::NoteIndexSource;
use curvy_chain_blokli::BlokliChain;
use curvy_core::eddsa::ScalarSigningKey;
use curvy_core::field::{Bn254Fr, Fr, fr_to_biguint, fr_to_dec};
use curvy_core::witness::KnownOwner;
use curvy_sdk::{Account, CurvyClient, OwnedNote, Route, TxLedger};

const OPERATOR_PRIVATE_KEY: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const OPERATOR_ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const EXIT_SUBMITTER_PRIVATE_KEY: &str =
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const ENTRY_SEED: &str = "0x4444444444444444444444444444444444444444444444444444444444444444";
const DESTINATION: &str = "0x000000000000000000000000000000000000bEEF";
const ETH_TOKEN: u64 = 1;
const FUNDING_GROSS_WEI: u128 = 2_000_000_000_000_000_000;
const PIX_ALLOCATION_WEI: u128 = 50_000_000_000_000_000;
const PIX_OWNER_COUNT: usize = 10;
/// Seven allocations per proof: the `(2,9)` profile's nine regular outputs carry
/// `7 allocations + change + relayer`, with the protocol fee note in its own slot.
const FIRST_FANOUT: usize = 7;
/// Stands in for the relayer's gas reimbursement. Production sizes this from the
/// paymaster's live quote (`gasCostInToken` plus a client buffer) and the relayer
/// refuses to submit when the note under-covers it; on anvil the submitter pays its
/// own gas, so any non-zero amount exercises the same output slot.
const RELAYER_REIMBURSEMENT_WEI: u128 = 1_000_000_000_000_000;
/// The relayer is a full Curvy account, not a bare BabyJubJub owner: its note is
/// stealth-sealed so the operator's paymaster can discover it by scanning, which is
/// exactly what the production gate does before agreeing to relay.
const RELAYER_SEED: &str = "0x5555555555555555555555555555555555555555555555555555555555555555";
/// The localnet protocol-fee collector, whose BabyJubJub key the dev deployment writes
/// into `feeNotePublicKey`.
///
/// The fee note is a stealth note, so a non-zero protocol fee can only be made
/// collectable by sealing it to this identity — the aggregator publishes the owner key
/// but there is no on-chain channel for the collector's `S`/`V`. These are the
/// well-known localnet dev secrets and must never appear outside a local chain.
const FEE_COLLECTOR_SPEND_PRIV: &str =
    "0000000000000000000000000000000000000000000000000feec0117ec701";
const FEE_COLLECTOR_VIEW_PRIV: &str =
    "0000000000000000000000000000000000000000000000000feec0117ec702";

/// Addresses emitted by Blokli's Curvy-enabled local deployer.
pub struct Deployed {
    pub aggregator: String,
    pub vault: String,
    pub portal_factory: String,
}

/// One completed phase of the acceptance flow.
#[derive(Clone, Debug)]
pub struct PhaseOutcome {
    pub name: &'static str,
    /// What the phase established, in reviewer-facing terms.
    pub detail: String,
    pub elapsed: Duration,
    pub ledger: Vec<TxLedger>,
}

/// The evidence a completed run hands back: what ran, against what, and how.
#[derive(Clone, Debug)]
pub struct E2eReport {
    pub network: String,
    pub chain_id: u64,
    /// The per-run salt that made this run's PIX note commitments unique.
    pub salt: u64,
    pub delivered_wei: u128,
    pub phases: Vec<PhaseOutcome>,
}

impl E2eReport {
    pub fn total_elapsed(&self) -> Duration {
        self.phases.iter().map(|phase| phase.elapsed).sum()
    }

    /// Every transaction the run submitted, in order.
    pub fn transactions(&self) -> impl Iterator<Item = &TxLedger> {
        self.phases.iter().flat_map(|phase| phase.ledger.iter())
    }

    /// A human-readable summary — this is what a reviewer reads to decide the run
    /// actually exercised Blokli rather than quietly falling back to direct RPC.
    pub fn summary(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        let _ = writeln!(
            out,
            "\nPIX E2E on {} (chain {}), salt {}",
            self.network, self.chain_id, self.salt
        );
        let _ = writeln!(out, "{:-<74}", "");
        for (index, phase) in self.phases.iter().enumerate() {
            let _ = writeln!(
                out,
                "  {:>2}. PASS  {:<34} {:>7.1}s  {}",
                index + 1,
                phase.name,
                phase.elapsed.as_secs_f64(),
                phase.detail
            );
            for tx in &phase.ledger {
                let _ = writeln!(
                    out,
                    "         └─ {:<22} via {:<10} {}",
                    tx.label, tx.backend, tx.tx_hash
                );
            }
        }
        let _ = writeln!(out, "{:-<74}", "");
        let _ = writeln!(
            out,
            "  {} phases, {} transactions, {:.1}s total, {} wei delivered",
            self.phases.len(),
            self.transactions().count(),
            self.total_elapsed().as_secs_f64(),
            self.delivered_wei
        );
        out
    }
}

/// Accumulates phase results and times each one.
struct Recorder {
    phases: Vec<PhaseOutcome>,
    started: Instant,
}

impl Recorder {
    fn new() -> Self {
        Self {
            phases: Vec::new(),
            started: Instant::now(),
        }
    }

    /// Close the current phase. Printing as we go matters: these phases take minutes
    /// apiece, and a reviewer watching the run needs to see progress, not a silent gap.
    fn finish(&mut self, name: &'static str, detail: impl Into<String>, ledger: Vec<TxLedger>) {
        let outcome = PhaseOutcome {
            name,
            detail: detail.into(),
            elapsed: self.started.elapsed(),
            ledger,
        };
        println!(
            "[{}/13] PASS {} ({:.1}s) — {}",
            self.phases.len() + 1,
            outcome.name,
            outcome.elapsed.as_secs_f64(),
            outcome.detail
        );
        self.phases.push(outcome);
        self.started = Instant::now();
    }
}

fn address_file() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("CURVY_ADDRESSES") {
        return Ok(PathBuf::from(path));
    }
    let candidates = [
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../rs-core/poc/blokli-env/curvy_deployed_addresses.json"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../pix/blokli/curvy_deployed_addresses.json"),
    ];
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .context("set CURVY_ADDRESSES to Blokli's curvy_deployed_addresses.json")
}

pub fn deployed_addresses() -> Result<Deployed> {
    let path = address_file()?;
    let document: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&path).with_context(|| format!("read {}", path.display()))?,
    )
    .with_context(|| format!("parse {}", path.display()))?;
    let get = |name: &str| -> Result<String> {
        document[name]
            .as_str()
            .map(str::to_owned)
            .with_context(|| format!("missing {name} in {}", path.display()))
    };
    Ok(Deployed {
        aggregator: get("CurvyAggregator#ERC1967Proxy")?,
        vault: get("CurvyVault#ERC1967Proxy")?,
        portal_factory: get("PortalFactory#PortalFactory")?,
    })
}

/// blokli is the only endpoint the flow talks to; there is no direct RPC URL.
fn blokli_url() -> String {
    std::env::var("BLOKLI_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_owned())
}

/// A per-run salt for the PIX owners' shared secrets.
///
/// The ten allocation notes are sealed to *explicitly known* BabyJubJub owners, so
/// nothing about them is random: `ownerHash`, `noteId` and `nullifier` are pure
/// functions of `(owner point, shared secret, amount, token)`. With a fixed shared
/// secret every run would replay the same note ids into the same aggregator — the
/// second run reverts on already-committed notes and already-spent nullifiers. The
/// salt makes each run's commitments unique so the flow is re-runnable against a
/// long-lived stack. Set `CURVY_E2E_SALT` to replay a specific run while debugging
/// (against a fresh chain).
fn run_salt() -> Result<u64> {
    if let Some(value) = std::env::var_os("CURVY_E2E_SALT") {
        return value
            .to_string_lossy()
            .parse()
            .context("CURVY_E2E_SALT must be a u64");
    }
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the unix epoch")?
        .as_nanos() as u64)
}

fn amount(value: &Fr) -> Result<u128> {
    fr_to_biguint(value)
        .try_into()
        .context("field amount does not fit u128")
}

/// The ten independent BabyJubJub signing scalars the withdrawal profile authorizes
/// each slot with. Deliberately fixed and small: these stand in for the scalar keys a
/// PIX Exit reconstructs, and keeping them stable keeps runs comparable. Uniqueness
/// across runs comes from the salted shared secret, not from these.
fn scalar_key(index: usize) -> Result<ScalarSigningKey> {
    ScalarSigningKey::from_decimal(&(7 + index as u64).to_string())
        .map_err(|error| anyhow::anyhow!(error))
}

fn pix_owner(key: &ScalarSigningKey, index: usize, salt: u64) -> KnownOwner {
    KnownOwner::new(
        *key.verifying_key(),
        Bn254Fr::from_fr(Fr::from(salt.wrapping_add(index as u64))),
    )
}

/// Hash-check every graph and proving key the flow will need, before any chain state
/// is touched. Without this a missing `CURVY_ZK_KEYS_DIR` only surfaces after the
/// deposit and first commitment have already been submitted.
fn preflight_artifacts() -> Result<()> {
    for circuit in curvy_sdk::curvy_witnesscalc::Circuit::pix_flow() {
        circuit
            .verify_artifacts()
            .with_context(|| format!("{} artifacts are not usable", circuit.label))?;
    }
    Ok(())
}

async fn commit_notes(
    client: &CurvyClient,
    notes: &[&OwnedNote],
    operator_private_key: &str,
) -> Result<Vec<TxLedger>> {
    let mut ledger = Vec::new();
    for batch in notes.chunks(5) {
        let ids = batch.iter().map(|note| note.note_id()).collect::<Vec<_>>();
        let rows = client
            .commit(&ids, operator_private_key, Route::Blokli)
            .await?;
        if rows.iter().any(|row| row.backend != "blokli") {
            bail!("pending-note commitment bypassed Blokli");
        }
        ledger.extend(rows);
    }
    Ok(ledger)
}

async fn wait_for_nullifiers(blokli: &BlokliChain, wanted: &HashSet<String>) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let head = blokli.head_block().await?;
            let present = blokli
                .committed_nullifiers(0, head)
                .await?
                .into_iter()
                .flat_map(|event| event.nullifiers)
                .collect::<HashSet<_>>();
            if wanted.is_subset(&present) {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .context("timed out waiting for Blokli's PIX nullifier index")??;
    Ok(())
}

/// Run the complete local acceptance flow. Every protocol transaction is sent
/// through `sendTransactionSync`; only the plain ETH pre-fund transfer uses RPC.
pub async fn run() -> Result<E2eReport> {
    let mut record = Recorder::new();
    let blokli_url = blokli_url();
    let salt = run_salt()?;

    // ── 1. preflight ───────────────────────────────────────────────────────────
    preflight_artifacts()?;
    let deployed = deployed_addresses()?;
    let blokli = Arc::new(BlokliChain::new(&blokli_url));
    if !blokli.is_ready().await {
        bail!("Blokli is not ready at {blokli_url}");
    }
    let (network, chain_id) = blokli.chain_info().await?;
    if chain_id != 31_337 {
        bail!("unexpected chain id {chain_id}; expected 31337");
    }
    // Every seam is blokli: submission, the event index, the trust anchor, fees,
    // balances and portal derivation. Nothing here opens a direct RPC connection —
    // blokli's `curvy*` resolvers still perform real `eth_call`s, so the aggregator
    // state remains a chain read rather than indexed state; it is merely proxied.
    let client = Arc::new(CurvyClient::new(
        blokli.clone(),
        blokli.clone(),
        blokli.clone(),
        blokli.clone(),
        blokli.clone(),
        blokli.clone(),
        blokli.clone(),
        deployed.aggregator,
        deployed.portal_factory,
        chain_id,
    ));
    record.finish(
        "preflight",
        format!("3 circuits pinned, Blokli ready on {network}, salt {salt}"),
        Vec::new(),
    );

    // ── 2. deposit ─────────────────────────────────────────────────────────────
    let entry = Account::from_raw_private_key(ENTRY_SEED)?;
    let (funding, deposit_ledger) = client
        .deposit(
            &entry,
            FUNDING_GROSS_WEI,
            ETH_TOKEN,
            OPERATOR_PRIVATE_KEY,
            OPERATOR_ADDRESS,
            Route::Blokli,
            Route::Blokli,
        )
        .await?;
    if deposit_ledger.len() != 2 || deposit_ledger.iter().any(|row| row.backend != "blokli") {
        bail!("deposit did not submit both transactions through Blokli");
    }
    record.finish(
        "deposit",
        format!("{} wei net funding note", amount(&funding.amount)?),
        deposit_ledger,
    );

    let ledger = commit_notes(&client, &[&funding], OPERATOR_PRIVATE_KEY).await?;
    record.finish(
        "commit funding note",
        "funding note in the notes tree",
        ledger,
    );

    let keys = (0..PIX_OWNER_COUNT)
        .map(scalar_key)
        .collect::<Result<Vec<_>>>()?;
    let owners = keys
        .iter()
        .enumerate()
        .map(|(index, key)| pix_owner(key, index, salt))
        .collect::<Vec<_>>();

    // The relayer is a distinct account, not one of the ten withdrawal owners: its
    // note reimburses gas and is never withdrawn by this flow.
    let relayer_account = Account::from_raw_private_key(RELAYER_SEED)?;
    let relayer_identity = relayer_account.identity();
    let relayer = Some((&relayer_identity, RELAYER_REIMBURSEMENT_WEI));

    // Without this the protocol fee note is sealed to a random secret and the fee is
    // burned; the aggregation refuses to build rather than silently destroy it.
    let fee_collector = Account::from_meta_keys(FEE_COLLECTOR_SPEND_PRIV, FEE_COLLECTOR_VIEW_PRIV)?;
    let fee_identity = fee_collector.identity();

    // ── 3. first aggregation: profile (2,9) ────────────────────────────────────
    let first_allocations = owners[..FIRST_FANOUT]
        .iter()
        .copied()
        .map(|owner| (owner, PIX_ALLOCATION_WEI))
        .collect::<Vec<_>>();
    let first = client
        .aggregate_pix_allocations(
            &entry,
            std::slice::from_ref(&funding),
            &first_allocations,
            relayer,
            Some(&fee_identity),
            EXIT_SUBMITTER_PRIVATE_KEY,
            Route::Blokli,
        )
        .await?;
    if first.emitted_notes.len() != 10 || first.ledger[0].backend != "blokli" {
        bail!("first PIX aggregation did not emit ten notes through Blokli");
    }
    if first.relayer.is_none() {
        bail!("first PIX aggregation did not emit the relayer note");
    }
    record.finish(
        "aggregate (2,9) — 7 allocations",
        format!("1 input → {FIRST_FANOUT} allocations + change + relayer + fee"),
        first.ledger.clone(),
    );

    let mut first_to_commit = first.allocations.iter().collect::<Vec<_>>();
    first_to_commit.push(&first.change);
    let ledger = commit_notes(&client, &first_to_commit, OPERATOR_PRIVATE_KEY).await?;

    // Reproduce the production paymaster gate: a relayer only agrees to submit an
    // aggregation after it DISCOVERS an output note addressed to itself and checks the
    // amount covers its gas quote. Discovery is stealth trial-decryption, so this also
    // proves the note was sealed as an announcement rather than to a bare owner point.
    let discovered = client.scan(&relayer_account).await?;
    let reimbursement = discovered
        .iter()
        .find(|note| amount(&note.amount).is_ok_and(|value| value == RELAYER_REIMBURSEMENT_WEI))
        .context(
            "relayer could not discover its gas-reimbursement note — a real paymaster \
             would reject this aggregation as having no operator note",
        )?;
    record.finish(
        "commit first fan-out",
        format!(
            "{} notes committed; relayer discovered its {} wei note",
            first_to_commit.len(),
            amount(&reimbursement.amount)?
        ),
        ledger,
    );

    // ── 4. second aggregation: profile (2,9) from the committed change ─────────
    let second_allocations = owners[FIRST_FANOUT..]
        .iter()
        .copied()
        .map(|owner| (owner, PIX_ALLOCATION_WEI))
        .collect::<Vec<_>>();
    let second = client
        .aggregate_pix_allocations(
            &entry,
            std::slice::from_ref(&first.change),
            &second_allocations,
            relayer,
            Some(&fee_identity),
            EXIT_SUBMITTER_PRIVATE_KEY,
            Route::Blokli,
        )
        .await?;
    if second.emitted_notes.len() != 10 || second.ledger[0].backend != "blokli" {
        bail!("second PIX aggregation did not emit ten notes through Blokli");
    }
    record.finish(
        "aggregate (2,9) — 3 allocations",
        format!(
            "committed change → {} allocations + change + relayer + padded fan-out",
            second_allocations.len()
        ),
        second.ledger.clone(),
    );

    let ledger = commit_notes(
        &client,
        &second.allocations.iter().collect::<Vec<_>>(),
        OPERATOR_PRIVATE_KEY,
    )
    .await?;
    record.finish(
        "commit second fan-out",
        format!("{} notes committed", second.allocations.len()),
        ledger,
    );

    // ── 5. withdrawal: profile (10), ten unrelated scalar owners ───────────────
    let notes = first
        .allocations
        .iter()
        .chain(second.allocations.iter())
        .collect::<Vec<_>>();
    if notes.len() != PIX_OWNER_COUNT {
        bail!(
            "expected ten real PIX allocation notes, got {}",
            notes.len()
        );
    }
    let spends = keys
        .iter()
        .zip(notes.iter())
        .map(|(key, note)| (key, *note))
        .collect::<Vec<_>>();
    let expected_nullifiers = notes
        .iter()
        .map(|note| fr_to_dec(&note.nullifier()))
        .collect::<HashSet<_>>();

    let before = client.eth_balance(DESTINATION).await?;
    let (delivered, withdrawal_ledger) = client
        .withdraw_pix_multi_owner(
            &spends,
            DESTINATION,
            EXIT_SUBMITTER_PRIVATE_KEY,
            Route::Blokli,
        )
        .await?;
    let after = client.eth_balance(DESTINATION).await?;
    if withdrawal_ledger[0].backend != "blokli" || after.saturating_sub(before) != delivered {
        bail!("withdrawal balance delta or submission backend is incorrect");
    }
    if delivered >= PIX_ALLOCATION_WEI * PIX_OWNER_COUNT as u128 {
        bail!("withdrawal did not deduct the configured fee/gas");
    }
    record.finish(
        "withdraw (10) — 10 owners",
        format!("{delivered} wei to {DESTINATION}, balance delta matches"),
        withdrawal_ledger,
    );

    // ── 6. the index agrees ────────────────────────────────────────────────────
    wait_for_nullifiers(&blokli, &expected_nullifiers).await?;
    record.finish(
        "verify indexed nullifiers",
        format!("{} nullifiers indexed by Blokli", expected_nullifiers.len()),
        Vec::new(),
    );

    // ── 7. the interface HOPR actually consumes ────────────────────────────────
    run_deposit_pool_phase(
        Arc::clone(&client),
        &entry,
        &fee_identity,
        &mut record,
        salt,
    )
    .await?;

    Ok(E2eReport {
        network,
        chain_id,
        salt,
        delivered_wei: delivered,
        phases: record.phases,
    })
}

/// Number of PIX deposit addresses the pool phase serves. Below the seven-allocation
/// batch limit so the flush is driven explicitly rather than by hitting the threshold —
/// the interesting case, since a partial batch is what a real node usually holds.
const POOL_DEPOSIT_COUNT: usize = 4;
/// Value allocated to each pool deposit address.
const POOL_DEPOSIT_WEI: u128 = 20_000_000_000_000_000;

/// Drive `CurvyDepositPool` through the real `DepositPool` trait.
///
/// The rest of the flow calls `CurvyClient` directly, which proves the circuits and
/// Blokli forwarding but says nothing about the interface HOPR will actually use. This
/// phase exercises that interface end to end: HOPR-shaped BabyJubJub deposit addresses
/// in, one aggregation proof serving all of them, then a single ten-input withdrawal
/// proof sweeping them back out.
async fn run_deposit_pool_phase(
    client: Arc<CurvyClient>,
    spender: &Account,
    fee_identity: &curvy_sdk::Identity,
    record: &mut Recorder,
    salt: u64,
) -> Result<Vec<TxLedger>> {
    use curvy_deposit_pool::{CurvyDepositPool, CurvyDepositPoolConfig, MemoryStore};
    use hopr_api::chain::{DepositPool, PixDepositAddress, PixDepositSecret};
    use hopr_types::crypto::keypairs::{BjjKeypair, Keypair};
    use hopr_types::primitive::prelude::HoprBalance;

    let mut config = CurvyDepositPoolConfig::new(
        spender.clone(),
        EXIT_SUBMITTER_PRIVATE_KEY.to_string(),
        OPERATOR_PRIVATE_KEY.to_string(),
        ETH_TOKEN,
    );
    config.fee_recipient = Some(fee_identity.clone());
    let pool = Arc::new(CurvyDepositPool::new(
        Arc::clone(&client),
        config,
        Arc::new(MemoryStore::default()),
    )?);

    // Fund the pool from a fresh shield so it owns a committed note to allocate from.
    let funding_ledger = pool
        .fund_from_deposit(
            FUNDING_GROSS_WEI / 2,
            OPERATOR_PRIVATE_KEY,
            OPERATOR_ADDRESS,
        )
        .await?;
    if pool.available_funding() == 0 {
        bail!("deposit pool reported no funding after a successful shield");
    }
    record.finish(
        "pool: fund",
        format!("{} wei available to allocate", pool.available_funding()),
        funding_ledger,
    );

    // HOPR hands us BabyJubJub deposit addresses; the matching secrets are what the
    // Exit later reconstructs to withdraw. Salted so reruns cannot collide.
    let mut secrets = Vec::with_capacity(POOL_DEPOSIT_COUNT);
    let mut addresses = Vec::with_capacity(POOL_DEPOSIT_COUNT);
    for index in 0..POOL_DEPOSIT_COUNT {
        let mut secret = [0u8; 32];
        secret[24..].copy_from_slice(&salt.wrapping_add(index as u64 + 1).to_be_bytes());
        let keypair = BjjKeypair::from_secret(&secret)
            .map_err(|error| anyhow::anyhow!("dev deposit key: {error}"))?;
        addresses.push(PixDepositAddress::Bjj(*keypair.public()));
        secrets.push(PixDepositSecret(secret.into()));
    }

    for address in &addresses {
        pool.deposit_funds_to(*address, HoprBalance::from(POOL_DEPOSIT_WEI))
            .await?;
    }
    // Enqueued, not yet proved: a partial batch needs an explicit flush.
    let allocation_ledger = pool.flush_pending().await?;
    record.finish(
        "pool: deposit_funds_to",
        format!("{POOL_DEPOSIT_COUNT} deposit addresses funded in one (2,9) proof"),
        allocation_ledger,
    );

    // `notify_deposit` is the trait's only honest arrival signal; each must already be
    // resolvable now that the proof and its commitment have landed.
    for address in &addresses {
        let notified = pool
            .notify_deposit(*address, HoprBalance::from(POOL_DEPOSIT_WEI))
            .map_err(|error| anyhow::anyhow!("notify_deposit: {error}"))?;
        let (_address, observed) = tokio::time::timeout(Duration::from_secs(30), notified)
            .await
            .context("notify_deposit did not resolve for a funded deposit address")?;
        if observed < HoprBalance::from(POOL_DEPOSIT_WEI) {
            bail!("notify_deposit reported {observed} below the requested deposit");
        }
    }
    record.finish(
        "pool: notify_deposit",
        format!("{POOL_DEPOSIT_COUNT} arrivals confirmed"),
        Vec::new(),
    );

    // The batching override: every deposit swept in one (10,30) proof.
    let before = client.eth_balance(DESTINATION).await?;
    let destination: hopr_types::primitive::prelude::Address = DESTINATION
        .parse()
        .map_err(|error| anyhow::anyhow!("destination address: {error:?}"))?;
    let outcomes = pool
        .withdraw_multiple_deposits(&secrets, destination)
        .await
        .map_err(|error| anyhow::anyhow!("withdraw_multiple_deposits: {error}"))?;

    let mut ledger = Vec::new();
    for outcome in outcomes {
        let (_address, rows) =
            outcome.map_err(|error| anyhow::anyhow!("a pool withdrawal failed: {error}"))?;
        ledger.extend(rows);
    }
    let after = client.eth_balance(DESTINATION).await?;
    if after <= before {
        bail!("pool withdrawal did not increase the destination balance");
    }
    // Each address is emptied, so nothing may remain recorded as spendable.
    for address in &addresses {
        if !pool.deposits_for(address).is_empty() {
            bail!("a swept deposit address still records spendable notes");
        }
    }
    record.finish(
        "pool: withdraw_multiple_deposits",
        format!(
            "{POOL_DEPOSIT_COUNT} deposits swept in one (10,30) proof, +{} wei",
            after - before
        ),
        ledger.clone(),
    );
    Ok(ledger)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The circuit constrains the fee note's owner to the aggregator's
    /// `feeNotePublicKey`, so the collector identity the flow seals to must derive
    /// exactly that key — otherwise every aggregation fails at proving time with an
    /// unsatisfiable constraint rather than anything that names the cause.
    #[test]
    fn the_fee_collector_identity_owns_the_dev_fee_note_public_key() {
        const DEV_FEE_NOTE_PUBLIC_KEY_X: &str =
            "5509359784107808046541889973707062912186356978136525798140528612444721440004";
        const DEV_FEE_NOTE_PUBLIC_KEY_Y: &str =
            "5125768395023217094469327424244994953312297627197683956739233494456001838760";

        let collector = Account::from_meta_keys(FEE_COLLECTOR_SPEND_PRIV, FEE_COLLECTOR_VIEW_PRIV)
            .expect("dev fee-collector keys");
        assert_eq!(fr_to_dec(&collector.bjj_pub.0), DEV_FEE_NOTE_PUBLIC_KEY_X);
        assert_eq!(fr_to_dec(&collector.bjj_pub.1), DEV_FEE_NOTE_PUBLIC_KEY_Y);
    }
}
