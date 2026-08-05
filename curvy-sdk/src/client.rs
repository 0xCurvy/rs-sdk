//! `CurvyClient` - the thin facade that drives deposit → commit → PIX aggregation → scan
//! over the L2 trait objects, `curvy-abi` calldata/signing, and `curvy-witnesscalc`
//! proving. All crypto/proving runs under `spawn_blocking` so tokio is never blocked.
//! Minimal in-memory storage (the mirrored global IMT leaf log).

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};
use curvy_core::cipher::decrypt_amount_token;
use curvy_core::eddsa::ScalarSigningKey;
use curvy_core::field::{Fr, fr_from_biguint, fr_from_dec, fr_to_biguint, fr_to_dec};
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

use curvy_chain_api::{
    BalanceReader, FeeConfigSource, NoteIndexSource, PortalDirectory, RootAnchor, TxSubmitter,
};

use crate::account::{Account, Identity, OwnedNote};
use crate::send::{fee_note, seal_known_owner, seal_note, shield_net_amount, zero_pad_note};

const TREE_DEPTH: usize = 30;
const BATCH_SIZE: usize = 5;
const LEGACY_MAX_INPUTS: u64 = 2;
const LEGACY_MAX_OUTPUTS: u64 = 3;
const PIX_AGGREGATION_MAX_INPUTS: u64 = 2;
const PIX_AGGREGATION_MAX_OUTPUTS: u64 = 9;
const PIX_WITHDRAWAL_MAX_INPUTS: u64 = 10;

// ── fee-table accessors ────────────────────────────────────────────────────────
// A fee the chain reports but the SDK cannot parse must NOT silently become 0: the
// value math would then build a note whose amount the aggregator never agrees with,
// and the flow fails much later as an unrelated "noteId not found".

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

/// Result of one PIX fan-out proof. `emitted_notes` is the complete on-chain
/// order: nine regular outputs followed by the fee note. Commit all ten before
/// spending the change or any allocation.
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
    /// The committed global-IMT leaf log (note ids in insertion order) - mirrors chain.
    tree_leaves: Vec<Fr>,
}

/// The injected adapter mix. Kept as separate `Arc<dyn …>` so the seam is real: the
/// same `RpcChain` can back several of these, but the client only ever sees traits.
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
        }
    }

    /// The aggregator's live tree state (trust anchor), as an anyhow result.
    pub async fn anchor_state(&self) -> Result<curvy_types::AggregatorState> {
        self.anchor.state().await.map_err(|e| anyhow::anyhow!(e))
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

    /// Build, locally sign, and submit a call. Nonce/gas-price read via `BalanceReader`;
    /// signing in `curvy-abi` (no alloy here). Returns the outcome + a ledger row.
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
        let nonce = self.balances.tx_count(&signer_addr).await?;
        let gas_price = self.balances.gas_price().await?.saturating_mul(2);
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
        let outcome = sub
            .submit(&raw)
            .await
            .with_context(|| format!("{label} submit"))?;
        if !outcome.status {
            bail!("{label}: tx {} reverted", outcome.tx_hash);
        }
        let ledger = TxLedger {
            label: label.to_string(),
            backend: sub.backend().to_string(),
            tx_hash: outcome.tx_hash.clone(),
        };
        Ok((outcome, ledger))
    }

    // ── Deposit ─────────────────────────────────────────────────────────────────

    /// Enter the pool by funding the deterministic entry portal and asking the
    /// factory to deploy and shield it. Plain ETH portal funding can use direct
    /// RPC while the protocol call is independently submitted through Blokli.
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
        let fees = self.fees.fees().await?;
        let token_fr = Fr::from(token);
        let token_dec = token.to_string();

        // Seal a note to the recipient (ownerHash depends only on owner+sharedSecret,
        // not amount - so the gross here does not affect it).
        let sealed = seal_note(&recipient.identity(), u128_fr(gross), token_fr)?;
        let owner_hash_dec = fr_to_dec(&sealed.owner_hash());

        let portal_deployment = fees
            .per_token_gas_fees
            .iter()
            .find(|g| g.token_id == token_dec)
            .map(|g| {
                g.portal_deployment.parse::<u128>().with_context(|| {
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
        );

        let onchain = OnchainNote {
            owner_hash: owner_hash_dec.clone(),
            token: token_dec,
            amount: gross.to_string(),
            ephemeral_key: [
                fr_to_dec(&sealed.ephemeral_key.0),
                fr_to_dec(&sealed.ephemeral_key.1),
            ],
            view_tag: sealed.view_tag as u64,
        };

        // Pre-fund the predicted entry-portal address with the gross ETH.
        let portal_addr = self
            .portals
            .entry_portal_address(&owner_hash_dec, &recovery.to_string())
            .await?;
        let mut ledger = Vec::new();
        let (_f, l1) = self
            .submit_call(
                operator_priv,
                &portal_addr,
                vec![],
                &gross.to_string(),
                60_000,
                funding_route,
                "shield:fund-portal",
            )
            .await?;
        ledger.push(l1);

        // Deploy + shield (operator holds OPERATOR_ROLE).
        let calldata = curvy_abi::encode_deploy_shield_portal(&onchain, recovery)?;
        let (_d, l2) = self
            .submit_call(
                operator_priv,
                &self.portal_factory,
                calldata,
                "0",
                2_000_000,
                protocol_route,
                "shield:deploy+shield",
            )
            .await?;
        ledger.push(l2);

        // The committed note carries the NET amount (what autoShield's noteId hashes).
        let committed = OwnedNote {
            amount: u128_fr(net),
            ..sealed
        };

        // Verify: the aggregator emitted a PendingNotes with this noteId.
        let want = fr_to_dec(&committed.note_id());
        let mut seen = false;
        for _ in 0..20 {
            let head = self.notes.head_block().await?;
            seen = self
                .notes
                .pending_notes(0, head)
                .await?
                .iter()
                .any(|event| event.note_ids.contains(&want));
            if seen {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        if !seen {
            bail!("shield: PendingNotes for noteId {want} not found in the configured index");
        }
        Ok((committed, ledger))
    }

    /// Compatibility wrapper that uses one backend for both deposit transactions.
    pub async fn shield(
        &self,
        recipient: &Account,
        gross: u128,
        token: u64,
        operator_priv: &str,
        recovery: &str,
        route: Route,
    ) -> Result<(OwnedNote, Vec<TxLedger>)> {
        self.deposit(
            recipient,
            gross,
            token,
            operator_priv,
            recovery,
            route,
            route,
        )
        .await
    }

    // ── sync: rebuild the mirrored IMT from CommittedNotes + reconcile the root ───

    /// Rebuild the local IMT and reconcile it against the chain root (the trust
    /// anchor). Tolerates index-ahead-of-root on fast blocks (plan risk 8) with a
    /// short retry. Returns the reconciled leaf log.
    ///
    /// Leaves come from a checkpoint-pinned snapshot when the backend serves one, and
    /// otherwise from folding the `CommittedNotes` log. Reconciliation against the
    /// chain root is identical either way, so the snapshot is a robustness win rather
    /// than a change of trust model - see [`leaves_from_events`] for why the fold is
    /// the weaker of the two.
    pub async fn sync(&self) -> Result<Vec<Fr>> {
        let mut last_local_root = String::new();
        for _ in 0..20 {
            let leaves = match self.notes.notes_tree_snapshot().await? {
                Some(snapshot) => snapshot.leaves.iter().map(|id| fr_from_dec(id)).collect(),
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

    /// Rebuild the leaf log by folding the `CommittedNotes` event log.
    ///
    /// The fallback for backends that cannot serve a leaf-indexed snapshot (a plain
    /// `eth_getLogs` reader has no tree frontier to derive positions from). It infers
    /// each leaf's position from event arrival order - batch order, then position
    /// within the batch, skipping the zero-id padding slots exactly as the aggregator
    /// does. That reproduces the on-chain tree only while the index reports events in
    /// chain order, an assumption the event log itself never states; a wrong order
    /// yields a wrong root rather than an error, which the reconcile below then
    /// reports as an unexplained mismatch.
    async fn leaves_from_events(&self) -> Result<Vec<Fr>> {
        let head = self.notes.head_block().await?;
        let mut committed = self.notes.committed_notes(0, head).await?;
        committed.sort_by_key(|event| event.batch_index);
        let mut leaves = Vec::new();
        for event in &committed {
            for note_id in &event.note_ids {
                let field = fr_from_dec(note_id);
                if field != Fr::from(0u64) {
                    leaves.push(field);
                }
            }
        }
        Ok(leaves)
    }

    // ── Step 2: commit pending notes ──────────────────────────────────────────────

    /// Commit a batch of pending note ids into the notes tree (batch-prover role,
    /// client-side). Proves the pending-commitment circuit, calls `commitPendingNotes`,
    /// and verifies the chain root advanced to the new root.
    pub async fn commit(
        &self,
        pending_ids: &[Fr],
        operator_priv: &str,
        route: Route,
    ) -> Result<Vec<TxLedger>> {
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
        let (_o, ledger) = self
            .submit_call(
                operator_priv,
                &self.aggregator,
                calldata,
                "0",
                2_000_000,
                route,
                "commit",
            )
            .await?;

        // Verify the chain advanced to new_root and it is now a valid root.
        let state = self.anchor.state().await?;
        if state.current_notes_root != new_root {
            bail!(
                "commit: chain root {} != new root {new_root}",
                state.current_notes_root
            );
        }
        if !self.anchor.is_valid_notes_root(&new_root).await? {
            bail!("commit: new root {new_root} not marked valid");
        }
        Ok(vec![ledger])
    }

    // ── Aggregation ──────────────────────────────────────────────────────────────

    /// Spend `note_a` (owned by `spender`) against the committed notes root, sending
    /// `amount_to_b` to `recipient` (real stealth send) with change back to the
    /// spender and the protocol fee note. Proves aggregation(2,3,30,6), submits
    /// `submitAggregationRequest` through the chosen route (blokli for the M2 exit),
    /// and returns the sealed B-note (for the scan step) + the ledger.
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

    /// Allocate value from a committed note to an explicitly supplied
    /// BabyJubJub owner and shared secret.
    ///
    /// This is the Curvy realization of PIX `Allocate`: the recipient does not
    /// need a legacy Curvy seed or `(S, V)` stealth meta-address.
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
        let fees = self.fees.fees().await?;
        let token = note_a.token;
        let token_dec = fr_to_dec(&token);

        // Inclusion proof for note_a against the committed root.
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

        // Value math (mirror the circuit + TS witnessFromNotes).
        let net = fr_u128(&note_a.amount)?;
        let gas_fee = parse_gas_fee(&fees, &token_dec)?;
        let protocol_fee_per_thousand = parse_protocol_fee(&fees)?;
        let spent_to_others = amount_to_b; // B != spender
        let fee_amount = gas_fee + spent_to_others * protocol_fee_per_thousand / 1000;
        let change = net
            .checked_sub(amount_to_b + fee_amount)
            .context("aggregate: note value too small for amount+fee")?;

        // Seed pads/fee-note off the (random) note_a secret so they differ each run.
        let seed = curvy_core::field::fr_to_be_32(&note_a.shared_secret);

        // Outputs: [recipient, change→self, zero-pad→self]; inputs: [note_a, zero-pad→self].
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
            fr_from_dec(&fees.fee_note_public_key[0]),
            fr_from_dec(&fees.fee_note_public_key[1]),
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
            fr_from_dec(&fees.protocol_fee_per_thousand),
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
        let (_o, ledger) = self
            .submit_call(
                submitter_priv,
                &self.aggregator,
                calldata,
                "0",
                3_000_000,
                route,
                "aggregate",
            )
            .await?;

        // Verify: the B output note is now PENDING on-chain.
        let want = fr_to_dec(&b_note.note_id());
        if self.anchor.note_status(&want).await? != 1 {
            bail!("aggregate: B output note {want} not in PENDING status after submit");
        }
        Ok((b_note, vec![ledger]))
    }

    /// Execute the additive PIX aggregation profile: up to two committed notes owned
    /// by one legacy Curvy account fan out to explicitly known BabyJubJub owners, one
    /// change note, an optional relayer gas-reimbursement note, zero pads up to nine
    /// regular outputs, and one fee note. Submitted as verifier profile `(2, 9)`.
    ///
    /// The circuit emits `maxOutputs + 1` notes - nine regular outputs plus the fee
    /// note in its own constrained slot - so the ten-note shape PIX needs is
    /// `7 allocations + change + relayer` across the nine, with the protocol fee note
    /// separate. Passing a `relayer` therefore drops the allocation ceiling from eight
    /// to seven.
    ///
    /// The relayer note is an **ordinary** output: nothing in the circuit constrains
    /// its owner or amount (only the fee note is constrained). Production relies on
    /// the relayer checking it before relaying - it trial-decrypts the aggregation's
    /// output notes, refuses to submit when none is addressed to it, and refuses again
    /// when the amount is under its live gas quote plus tolerance. So `relayer_amount`
    /// must be sized against that quote, not guessed.
    ///
    /// That discovery step is why the relayer is an [`Identity`] rather than a
    /// [`KnownOwner`]: its note is **stealth-sealed** so the operator's scan can find
    /// it, matching the TS SDK, which routes the operator note through the same
    /// `sendNote` path as any other recipient. A `KnownOwner` note carries no
    /// announcement the relayer could trial-decrypt, so the paymaster would reject the
    /// aggregation as having no operator note at all.
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
        // Not cosmetic: the fee base below counts outputs the spender does not own, so
        // a relayer note owned by the spender would be excluded by the circuit while
        // this code counted it, and the fee-note constraint would fail.
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
            fr_from_dec(&fees.fee_note_public_key[0]),
            fr_from_dec(&fees.fee_note_public_key[1]),
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
            fr_from_dec(&fees.protocol_fee_per_thousand),
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
        let (_outcome, ledger) = self
            .submit_call(
                submitter_priv,
                &self.aggregator,
                calldata,
                "0",
                3_000_000,
                route,
                "pix-aggregate-2x9",
            )
            .await?;

        let mut emitted_notes = regular_outputs;
        emitted_notes.push(fee);
        for note in &emitted_notes {
            let note_id = fr_to_dec(&note.note_id());
            if self.anchor.note_status(&note_id).await? != 1 {
                bail!("PIX aggregation output {note_id} is not PENDING after submission");
            }
        }

        Ok(PixAggregationResult {
            allocations: allocation_notes,
            change,
            relayer: relayer_note,
            emitted_notes,
            ledger: vec![ledger],
        })
    }

    // ── Stretch: withdraw a committed note to an EOA ──────────────────────────────

    /// Withdraw a **committed** note owned by `spender` to a plain `destination` EOA.
    /// Proves withdrawal(2,30) (note + zero-pad), calls `submitWithdrawalRequest`, and
    /// returns the amount the vault delivers to the destination (net of the vault's
    /// `withdrawalFee` and the per-token withdrawal gas that reimburses the relayer).
    pub async fn withdraw(
        &self,
        spender: &Account,
        note: &OwnedNote,
        destination: &str,
        submitter_priv: &str,
        route: Route,
    ) -> Result<(u128, Vec<TxLedger>)> {
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
        let destination_fr = fr_from_dec(&dest_dec);

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
        let (_o, ledger) = self
            .submit_call(
                submitter_priv,
                &self.aggregator,
                calldata,
                "0",
                2_000_000,
                route,
                "withdraw",
            )
            .await?;

        let amount = fr_u128(&note.amount)?;
        let wfee = amount * fees.withdrawal_fee_bps as u128 / 10_000;
        let gas = parse_withdrawal_gas(&fees, &token_dec)?;
        let delivered = amount.saturating_sub(wfee).saturating_sub(gas);
        Ok((delivered, vec![ledger]))
    }

    /// Withdraw a committed note controlled by a scalar-native BabyJubJub key.
    ///
    /// PIX reconstructs the subgroup scalar itself, so this path deliberately
    /// bypasses the legacy seed hash/prune derivation used by [`Account`].
    pub async fn withdraw_with_scalar(
        &self,
        signer: &ScalarSigningKey,
        note: &OwnedNote,
        destination: &str,
        submitter_priv: &str,
        route: Route,
    ) -> Result<(u128, Vec<TxLedger>)> {
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
        let destination_field = fr_from_dec(&destination_decimal);
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
        let (_outcome, ledger) = self
            .submit_call(
                submitter_priv,
                &self.aggregator,
                calldata,
                "0",
                2_000_000,
                route,
                "pix-withdraw",
            )
            .await?;

        let amount = fr_u128(&note.amount)?;
        let withdrawal_fee = amount * fees.withdrawal_fee_bps as u128 / 10_000;
        let withdrawal_gas = parse_withdrawal_gas(&fees, &token_dec)?;
        let delivered = amount
            .saturating_sub(withdrawal_fee)
            .saturating_sub(withdrawal_gas);
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
        // The `&dyn NoteSigner` views live only for the witness build. Keeping them in
        // an inner scope is what makes this future `Send`: a trait object borrowed in
        // the enclosing scope stays part of the async state machine even after an
        // explicit drop, and `NoteSigner` is not `Sync`.
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
                fr_from_dec(&destination_decimal),
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
        let (_outcome, ledger) = self
            .submit_call(
                submitter_priv,
                &self.aggregator,
                calldata,
                "0",
                3_000_000,
                route,
                "pix-withdraw-10-owner",
            )
            .await?;

        let total = spends.iter().try_fold(0u128, |total, (_, note)| {
            total
                .checked_add(fr_u128(&note.amount)?)
                .context("PIX withdrawal total overflow")
        })?;
        let fees = self.fees.fees().await?;
        let withdrawal_fee = total * fees.withdrawal_fee_bps as u128 / 10_000;
        let token_decimal = fr_to_dec(&token);
        let withdrawal_gas = parse_withdrawal_gas(&fees, &token_decimal)?;
        let delivered = total
            .saturating_sub(withdrawal_fee)
            .saturating_sub(withdrawal_gas);
        Ok((delivered, vec![ledger]))
    }

    // ── Step 4: scan / receive ────────────────────────────────────────────────────

    /// Scan all `PendingNotes` for notes owned by `account`: real stealth discovery
    /// (ECDH + view-tag prefilter), `decrypt_amount_token` for encrypted leaves, then
    /// the integrity gate (recompute noteId; drop mismatches).
    pub async fn scan(&self, account: &Account) -> Result<Vec<Discovered>> {
        let head = self.notes.head_block().await?;
        let events = self.notes.pending_notes(0, head).await?;

        let mut rs = Vec::new();
        let mut tags = Vec::new();
        // (note_id, enc_amount, enc_token, is_plaintext, eph_x, eph_y)
        let mut meta: Vec<(String, String, String, bool, String, String)> = Vec::new();
        for ev in &events {
            for i in 0..ev.note_ids.len() {
                let ex = ev.ephemeral_keys[0].get(i).cloned().unwrap_or_default();
                let ey = ev.ephemeral_keys[1].get(i).cloned().unwrap_or_default();
                rs.push(format!("{ex}.{ey}"));
                tags.push(format!("{:02x}", ev.view_tags.get(i).copied().unwrap_or(0)));
                meta.push((
                    ev.note_ids[i].clone(),
                    ev.amounts.get(i).cloned().unwrap_or_default(),
                    ev.tokens.get(i).cloned().unwrap_or_default(),
                    ev.is_plaintext.get(i).copied().unwrap_or(false),
                    ex,
                    ey,
                ));
            }
        }

        let matches = stealth::scan(&account.k, &account.v, &rs, &tags)
            .map_err(|e| anyhow::anyhow!("stealth scan: {e}"))?;

        let mut out = Vec::new();
        for m in matches {
            let (note_id_dec, enc_amount, enc_token, is_plain, ex, ey) = &meta[m.index as usize];
            let shared_secret = fr_from_dec(m.spending_pub_key.split('.').next().unwrap_or("0"));

            let (amount, token) = if *is_plain {
                (fr_from_dec(enc_amount), fr_from_dec(enc_token))
            } else {
                let ss = fr_to_biguint(&shared_secret);
                let ebx = fr_to_biguint(&fr_from_dec(ex));
                let eby = fr_to_biguint(&fr_from_dec(ey));
                decrypt_amount_token(
                    fr_from_dec(enc_amount),
                    fr_from_dec(enc_token),
                    &ss,
                    (&ebx, &eby),
                )
            };

            // Integrity gate: recompute ownerHash + noteId, drop on mismatch.
            let oh = owner_hash(account.bjj_pub, shared_secret);
            let nid = note_id(oh, amount, token);
            if fr_to_dec(&nid) == *note_id_dec {
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

/// How one PIX aggregation splits its input value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PixValueSplit {
    /// Output value the spender does not own - the protocol fee base.
    pub spent_to_others: u128,
    /// The fee note's amount: `gasFee + floor(spent_to_others * rate / 1000)`.
    pub fee_amount: u128,
    /// What returns to the spender as change.
    pub change_amount: u128,
}

/// Mirror the `(2,9)` circuit's value arithmetic.
///
/// The circuit accumulates `totalSpentValue += amount * (1 - isSender)` over the
/// regular outputs, so the protocol fee is charged on every output the spender does
/// **not** own - allocations *and* the relayer's gas-reimbursement note - while change
/// and the zero pads (owned by the spender) are excluded. It then constrains
/// `feeNote.amount === gasFee + protocolFeeQ` and
/// `totalOutputValue === totalInputValue - feeNote.amount`.
///
/// Getting the base wrong does not fail loudly at build time: it produces a witness
/// the constraint system rejects, which surfaces as an opaque proving failure.
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

/// Rebuild the real depth-6 per-token gas-fee tree and return `(siblings, root)` for
/// `token`. Leaf[tokenId] = that token's `pendingNoteCommitment`; the root must equal
/// the on-chain `commitmentFeeRoot`.
fn real_gas_fee_proof(fees: &FeeConfig, token_dec: &str) -> Result<(Vec<String>, String)> {
    const GAS_TREE_DEPTH: usize = 6;
    let n = 1usize << GAS_TREE_DEPTH;
    let mut leaves = vec![Fr::from(0u64); n];
    for g in &fees.per_token_gas_fees {
        let tid: usize = g.token_id.parse().context("gas-fee token id")?;
        if tid < n {
            leaves[tid] = fr_from_dec(&g.pending_note_commitment);
        }
    }
    let token_index: usize = token_dec.parse().context("token id")?;
    let tree = Imt::from_leaves(GAS_TREE_DEPTH, &leaves);
    let proof = tree.create_proof(token_index);
    Ok((
        proof.siblings.iter().map(fr_to_dec).collect(),
        fr_to_dec(&tree.root()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RATE: u128 = 10; // protocolFeePerThousand
    const GAS: u128 = 500;

    #[test]
    fn relayer_note_is_part_of_the_protocol_fee_base() {
        // The circuit charges outputs the spender does not own, so adding a relayer
        // note must raise the fee - not merely reduce the change by its face value.
        let without = pix_value_split(1_000_000, 100_000, 0, GAS, RATE).unwrap();
        let with = pix_value_split(1_000_000, 100_000, 10_000, GAS, RATE).unwrap();

        assert_eq!(without.spent_to_others, 100_000);
        assert_eq!(with.spent_to_others, 110_000);
        assert_eq!(without.fee_amount, GAS + 1_000);
        assert_eq!(with.fee_amount, GAS + 1_100);
        // Change drops by the relayer note plus the extra protocol fee it attracts.
        assert_eq!(without.change_amount - with.change_amount, 10_000 + 100);
    }

    #[test]
    fn value_conservation_matches_the_circuit_constraint() {
        // totalOutputValue === totalInputValue - feeNote.amount, where the regular
        // outputs are allocations + relayer + change.
        let split = pix_value_split(2_000_000, 350_000, 1_000, GAS, RATE).unwrap();
        let outputs = 350_000 + 1_000 + split.change_amount;
        assert_eq!(outputs, 2_000_000 - split.fee_amount);
    }

    #[test]
    fn protocol_fee_floors_like_the_circuit_quotient() {
        // protocolFeeQ is a floored quotient with the remainder range-checked, so the
        // SDK must floor identically rather than round.
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
    fn absent_token_yields_a_zero_gas_fee_rather_than_an_error() {
        // gas_fee_for() reports "0" for unregistered tokens; that must parse, not fail.
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
}
