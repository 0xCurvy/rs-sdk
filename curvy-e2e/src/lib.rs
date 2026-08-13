//! End-to-end deposit, aggregation, and multi-owner withdrawal flow.

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
const ALLOCATION_WEI: u128 = 50_000_000_000_000_000;
const OWNER_COUNT: usize = 10;
/// Allocations in the first fan-out proof.
const FIRST_FANOUT: usize = 7;
/// Test relayer reimbursement.
const RELAYER_REIMBURSEMENT_WEI: u128 = 1_000_000_000_000_000;
/// Test relayer account seed.
const RELAYER_SEED: &str = "0x5555555555555555555555555555555555555555555555555555555555555555";
/// Local fee-collector keys.
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

fn blokli_client(blokli: Arc<BlokliChain>, deployed: &Deployed, chain_id: u64) -> Arc<CurvyClient> {
    Arc::new(CurvyClient::new(
        blokli.clone(),
        blokli.clone(),
        blokli.clone(),
        blokli.clone(),
        blokli.clone(),
        blokli.clone(),
        blokli,
        deployed.aggregator.clone(),
        deployed.portal_factory.clone(),
        chain_id,
    ))
}

/// One completed phase of the acceptance flow.
#[derive(Clone, Debug)]
pub struct PhaseOutcome {
    pub name: &'static str,
    /// Phase result.
    pub detail: String,
    pub elapsed: Duration,
    pub ledger: Vec<TxLedger>,
}

/// Completed run report.
#[derive(Clone, Debug)]
pub struct E2eReport {
    pub network: String,
    pub chain_id: u64,
    /// Per-run note salt.
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

    /// Format the run summary.
    pub fn summary(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        let _ = writeln!(
            out,
            "\nCurvy E2E on {} (chain {}), salt {}",
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

    /// Close and print the current phase.
    fn finish(&mut self, name: &'static str, detail: impl Into<String>, ledger: Vec<TxLedger>) {
        let outcome = PhaseOutcome {
            name,
            detail: detail.into(),
            elapsed: self.started.elapsed(),
            ledger,
        };
        println!(
            "[{}/13] PASS {} ({:.1}s) - {}",
            self.phases.len() + 1,
            outcome.name,
            outcome.elapsed.as_secs_f64(),
            outcome.detail
        );
        self.phases.push(outcome);
        self.started = Instant::now();
    }
}

/// Resolve the deployment address manifest.
fn address_file() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("CURVY_ADDRESSES") {
        return Ok(PathBuf::from(path));
    }
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidates = [here.join("../../blokli-env/curvy_deployed_addresses.json")];
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
    // Accept both supported deployment module names.
    let get = |names: &[&str]| -> Result<String> {
        names
            .iter()
            .find_map(|name| document[*name].as_str())
            .map(str::to_owned)
            .with_context(|| {
                format!(
                    "none of {} present in {}",
                    names.join(" or "),
                    path.display()
                )
            })
    };
    Ok(Deployed {
        aggregator: get(&["CurvyAggregator#ERC1967Proxy"])?,
        vault: get(&["CurvyVault#ERC1967Proxy"])?,
        portal_factory: get(&[
            "PortalFactoryV2#PortalFactory",
            "PortalFactory#PortalFactory",
        ])?,
    })
}

/// Blokli endpoint.
fn blokli_url() -> String {
    std::env::var("BLOKLI_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_owned())
}

/// Resolve the per-run note salt.
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

/// Resolve a withdrawal owner key.
fn scalar_key(index: usize) -> Result<ScalarSigningKey> {
    ScalarSigningKey::from_decimal(&(7 + index as u64).to_string())
        .map_err(|error| anyhow::anyhow!(error))
}

fn allocation_owner(key: &ScalarSigningKey, index: usize, salt: u64) -> KnownOwner {
    KnownOwner::new(
        *key.verifying_key(),
        Bn254Fr::from_fr(Fr::from(salt.wrapping_add(index as u64))),
    )
}

/// Authenticate all required artifacts.
fn preflight_artifacts() -> Result<()> {
    for circuit in curvy_sdk::curvy_witnesscalc::Circuit::pix_flow() {
        circuit
            .verify_artifacts()
            .with_context(|| format!("{} artifacts are not usable", circuit.label))?;
    }
    Ok(())
}

/// Validated flow dependencies.
#[derive(Clone, Debug)]
pub struct Preflight {
    pub blokli_url: String,
    pub network: String,
    pub chain_id: u64,
    pub addresses: PathBuf,
    pub aggregator: String,
    pub vault: String,
    pub portal_factory: String,
    /// Authenticated graph and proving-key paths by circuit.
    pub artifacts: Vec<(String, PathBuf, PathBuf)>,
}

impl Preflight {
    /// Format the preflight summary.
    pub fn summary(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        let _ = writeln!(
            out,
            "blokli    {} ({}, chain {})",
            self.blokli_url, self.network, self.chain_id
        );
        let _ = writeln!(out, "addresses {}", self.addresses.display());
        let _ = writeln!(out, "  aggregator     {}", self.aggregator);
        let _ = writeln!(out, "  vault          {}", self.vault);
        let _ = writeln!(out, "  portalFactory  {}", self.portal_factory);
        for (label, graph, zkey) in &self.artifacts {
            let _ = writeln!(out, "{label}");
            let _ = writeln!(out, "  graph  {}", graph.display());
            let _ = writeln!(out, "  zkey   {}", zkey.display());
        }
        out
    }
}

/// Validate flow dependencies without submitting transactions.
pub async fn preflight() -> Result<Preflight> {
    let blokli_url = blokli_url();

    let mut artifacts = Vec::new();
    for circuit in curvy_sdk::curvy_witnesscalc::Circuit::pix_flow() {
        circuit
            .verify_artifacts()
            .with_context(|| format!("{} artifacts are not usable", circuit.label))?;
        artifacts.push((
            circuit.label.to_owned(),
            circuit.graph_path(),
            circuit.zkey_path()?,
        ));
    }

    let addresses = address_file()?;
    let deployed = deployed_addresses()?;

    let blokli = Arc::new(BlokliChain::new(&blokli_url));
    if !blokli.is_ready().await {
        bail!("Blokli is not ready at {blokli_url}");
    }
    let (network, chain_id) = blokli.chain_info().await?;
    if chain_id != 31_337 {
        bail!("unexpected chain id {chain_id}; expected 31337");
    }
    blokli_client(Arc::clone(&blokli), &deployed, chain_id)
        .sync()
        .await
        .context("Blokli notes index does not match the deployed aggregator")?;

    Ok(Preflight {
        blokli_url,
        network,
        chain_id,
        addresses,
        aggregator: deployed.aggregator,
        vault: deployed.vault,
        portal_factory: deployed.portal_factory,
        artifacts,
    })
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
    .context("timed out waiting for Blokli's nullifier index")??;
    Ok(())
}

/// Run the complete local acceptance flow. Every protocol transaction is sent
/// through `sendTransactionSync`; only the plain ETH pre-fund transfer uses RPC.
pub async fn run() -> Result<E2eReport> {
    let mut record = Recorder::new();
    let blokli_url = blokli_url();
    let salt = run_salt()?;

    // Preflight.
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
    // Use Blokli for all chain access.
    let client = blokli_client(blokli.clone(), &deployed, chain_id);
    client
        .sync()
        .await
        .context("Blokli notes index does not match the deployed aggregator")?;
    record.finish(
        "preflight",
        format!("3 circuits pinned, Blokli/index ready on {network}, salt {salt}"),
        Vec::new(),
    );

    // Deposit.
    let entry = Account::from_poc_raw_private_key(ENTRY_SEED)?;
    let prepared = client
        .prepare_deposit(&entry, FUNDING_GROSS_WEI, ETH_TOKEN, OPERATOR_ADDRESS)
        .await?;
    let deposit_ledger = vec![
        client
            .fund_prepared_deposit(&prepared, OPERATOR_PRIVATE_KEY, Route::Blokli)
            .await?,
        client
            .shield_prepared_deposit(&prepared, OPERATOR_PRIVATE_KEY, Route::Blokli)
            .await?,
    ];
    let funding = prepared.note;
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

    let keys = (0..OWNER_COUNT)
        .map(scalar_key)
        .collect::<Result<Vec<_>>>()?;
    let owners = keys
        .iter()
        .enumerate()
        .map(|(index, key)| allocation_owner(key, index, salt))
        .collect::<Vec<_>>();

    // Relayer reimbursement output.
    let relayer_account = Account::from_poc_raw_private_key(RELAYER_SEED)?;
    let relayer_identity = relayer_account.identity();
    let relayer = Some((&relayer_identity, RELAYER_REIMBURSEMENT_WEI));

    // Protocol fee recipient.
    let fee_collector = Account::from_meta_keys(FEE_COLLECTOR_SPEND_PRIV, FEE_COLLECTOR_VIEW_PRIV)?;
    let fee_identity = fee_collector.identity();

    // First aggregation.
    let first_allocations = owners[..FIRST_FANOUT]
        .iter()
        .copied()
        .map(|owner| (owner, ALLOCATION_WEI))
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
        bail!("first aggregation did not emit ten notes through Blokli");
    }
    if first.relayer.is_none() {
        bail!("first aggregation did not emit the relayer note");
    }
    record.finish(
        "aggregate (2,9) - 7 allocations",
        format!("1 input → {FIRST_FANOUT} allocations + change + relayer + fee"),
        first.ledger.clone(),
    );

    let mut first_to_commit = first.allocations.iter().collect::<Vec<_>>();
    first_to_commit.push(&first.change);
    let ledger = commit_notes(&client, &first_to_commit, OPERATOR_PRIVATE_KEY).await?;

    // Verify relayer-note discovery.
    let discovered = client.scan(&relayer_account).await?;
    let reimbursement = discovered
        .iter()
        .find(|note| amount(&note.amount).is_ok_and(|value| value == RELAYER_REIMBURSEMENT_WEI))
        .context(
            "relayer could not discover its gas-reimbursement note - a real paymaster \
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

    // Second aggregation.
    let second_allocations = owners[FIRST_FANOUT..]
        .iter()
        .copied()
        .map(|owner| (owner, ALLOCATION_WEI))
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
        bail!("second aggregation did not emit ten notes through Blokli");
    }
    record.finish(
        "aggregate (2,9) - 3 allocations",
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

    // Multi-owner withdrawal.
    let notes = first
        .allocations
        .iter()
        .chain(second.allocations.iter())
        .collect::<Vec<_>>();
    if notes.len() != OWNER_COUNT {
        bail!("expected ten allocation notes, got {}", notes.len());
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
    if delivered >= ALLOCATION_WEI * OWNER_COUNT as u128 {
        bail!("withdrawal did not deduct the configured fee/gas");
    }
    record.finish(
        "withdraw (10) - 10 owners",
        format!("{delivered} wei to {DESTINATION}, balance delta matches"),
        withdrawal_ledger,
    );

    // Indexed nullifiers.
    wait_for_nullifiers(&blokli, &expected_nullifiers).await?;
    record.finish(
        "verify indexed nullifiers",
        format!("{} nullifiers indexed by Blokli", expected_nullifiers.len()),
        Vec::new(),
    );

    Ok(E2eReport {
        network,
        chain_id,
        salt,
        delivered_wei: delivered,
        phases: record.phases,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The configured fee collector must match the on-chain key.
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
