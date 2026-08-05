//! alloy bindings + calldata/signing/decoding for the deployed Curvy contracts.
//!
//! The four `sol!` modules ([`bindings`]) are generated at compile time from the
//! VENDORED `abi/*.abi.json` files (see `abi/README.md`) — the circuit repository is never read at
//! build or run time. Everything the SDK calls here speaks NEUTRAL types
//! (`curvy-types` decimal strings / `RawTx`), so `curvy-sdk` never names alloy.
//!
//! [`Groth16Proof::from_snarkjs`]
//! applies the `pi_b` G2 coordinate swap the on-chain pairing precompile expects
//! (get it wrong → off-chain verify passes but on-chain reverts).

use alloy::primitives::{Address, U256};
use anyhow::{Context, Result};
use curvy_types::{
    CommittedNotesEvent, CommittedNullifiersEvent, Dec, Groth16Proof, OnchainNote,
    PendingNotesEvent, RawTx,
};

/// The generated contract bindings, re-exported for `curvy-chain-rpc`'s typed reads.
///
/// Each contract lives in its own submodule: `sol!` hoists shared library structs
/// (`CurvyTypes.Note`, `CurvyTypes.GasFees`, …) into the *parent* module, so keeping
/// them separate avoids cross-contract name collisions.
pub mod bindings {
    pub mod aggregator {
        alloy::sol! {
            #[sol(rpc)]
            #[allow(missing_docs, clippy::too_many_arguments)]
            CurvyAggregatorAlphaV2,
            "abi/CurvyAggregatorAlphaV2.abi.json"
        }
    }
    pub mod vault {
        alloy::sol! {
            #[sol(rpc)]
            #[allow(missing_docs, clippy::too_many_arguments)]
            CurvyVaultV2,
            "abi/CurvyVaultV2.abi.json"
        }
    }
    pub mod portal_factory {
        alloy::sol! {
            #[sol(rpc)]
            #[allow(missing_docs, clippy::too_many_arguments)]
            PortalFactory,
            "abi/PortalFactory.abi.json"
        }
    }
    pub mod portal {
        alloy::sol! {
            #[sol(rpc)]
            #[allow(missing_docs, clippy::too_many_arguments)]
            Portal,
            "abi/Portal.abi.json"
        }
    }
}

use alloy::sol_types::SolCall;

// ── decimal-string ⇄ U256 helpers (the neutral boundary) ───────────────────────

/// Parse a non-negative decimal string into `U256`.
pub fn u256_dec(s: &str) -> Result<U256> {
    U256::from_str_radix(s, 10).map_err(|e| anyhow::anyhow!("parse U256 {s:?}: {e}"))
}
fn u256_arr2(a: &[Dec; 2]) -> Result<[U256; 2]> {
    Ok([u256_dec(&a[0])?, u256_dec(&a[1])?])
}

// ── snarkjs proof JSON → on-chain proof (the G2 swap) ──────────────────────────

/// Convert a snarkjs-shaped proof JSON + public-signals JSON into the on-chain proof
/// shape. `pi_a`/`pi_c` (G1) pass through; each `pi_b` (G2) coordinate pair is
/// swapped `[c0,c1] → [c1,c0]` — the Ethereum pairing precompile convention that
/// `snarkjs generatecall` encodes. Public signals pass through in witness order.
pub fn proof_from_snarkjs(proof_json: &str) -> Result<Groth16Proof> {
    let p: serde_json::Value = serde_json::from_str(proof_json).context("parse snarkjs proof")?;
    let g1 = |v: &serde_json::Value, i: usize| -> Result<Dec> {
        Ok(v[i]
            .as_str()
            .context("g1 coordinate not a string")?
            .to_string())
    };
    let b = |i: usize, j: usize| -> Result<Dec> {
        Ok(p["pi_b"][i][j]
            .as_str()
            .context("g2 coordinate not a string")?
            .to_string())
    };
    Ok(Groth16Proof {
        a: [g1(&p["pi_a"], 0)?, g1(&p["pi_a"], 1)?],
        b: [[b(0, 1)?, b(0, 0)?], [b(1, 1)?, b(1, 0)?]], // swap each pair
        c: [g1(&p["pi_c"], 0)?, g1(&p["pi_c"], 1)?],
    })
}

type SolidityProof = ([U256; 2], [[U256; 2]; 2], [U256; 2]);

fn proof_to_u256(p: &Groth16Proof) -> Result<SolidityProof> {
    Ok((
        u256_arr2(&p.a)?,
        [u256_arr2(&p.b[0])?, u256_arr2(&p.b[1])?],
        u256_arr2(&p.c)?,
    ))
}

// ── calldata encoders (neutral in → raw calldata bytes) ────────────────────────

/// `PortalFactory.deployShieldPortal(note, recovery)` calldata.
pub fn encode_deploy_shield_portal(note: &OnchainNote, recovery: &str) -> Result<Vec<u8>> {
    let n = bindings::portal_factory::CurvyTypes::Note {
        ownerHash: u256_dec(&note.owner_hash)?,
        token: u256_dec(&note.token)?,
        amount: u256_dec(&note.amount)?,
        ephemeralKey: u256_arr2(&note.ephemeral_key)?,
        viewTag: note.view_tag as u16,
    };
    let recovery: Address = recovery.parse().context("parse recovery address")?;
    Ok(
        bindings::portal_factory::PortalFactory::deployShieldPortalCall { note: n, recovery }
            .abi_encode(),
    )
}

/// `CurvyAggregatorAlphaV2.submitAggregationRequest(...)` calldata.
pub fn encode_submit_aggregation(
    max_inputs: u64,
    max_outputs: u64,
    proof: &Groth16Proof,
    public_signals: &[Dec],
) -> Result<Vec<u8>> {
    let (a, b, c) = proof_to_u256(proof)?;
    let pubs: Vec<U256> = public_signals
        .iter()
        .map(|s| u256_dec(s))
        .collect::<Result<_>>()?;
    Ok(
        bindings::aggregator::CurvyAggregatorAlphaV2::submitAggregationRequestCall {
            maxInputs: U256::from(max_inputs),
            maxOutputs: U256::from(max_outputs),
            proof_a: a,
            proof_b: b,
            proof_c: c,
            publicSignals: pubs,
        }
        .abi_encode(),
    )
}

/// `CurvyAggregatorAlphaV2.submitWithdrawalRequest(...)` calldata.
pub fn encode_submit_withdrawal(
    max_inputs: u64,
    proof: &Groth16Proof,
    public_signals: &[Dec],
) -> Result<Vec<u8>> {
    let (a, b, c) = proof_to_u256(proof)?;
    let pubs: Vec<U256> = public_signals
        .iter()
        .map(|s| u256_dec(s))
        .collect::<Result<_>>()?;
    Ok(
        bindings::aggregator::CurvyAggregatorAlphaV2::submitWithdrawalRequestCall {
            maxInputs: U256::from(max_inputs),
            proof_a: a,
            proof_b: b,
            proof_c: c,
            publicSignals: pubs,
        }
        .abi_encode(),
    )
}

/// The uint160 decimal value of a `0x…` address (the circuit's `destinationAddress`).
pub fn address_to_u160_dec(address: &str) -> Result<String> {
    let a: Address = address.parse().context("parse destination address")?;
    Ok(U256::from_be_slice(a.as_slice()).to_string())
}

/// `CurvyAggregatorAlphaV2.commitPendingNotes(...)` calldata.
pub fn encode_commit_pending_notes(
    batch_size: u64,
    note_ids: &[Dec],
    new_notes_root: &Dec,
    proof: &Groth16Proof,
) -> Result<Vec<u8>> {
    let (a, b, c) = proof_to_u256(proof)?;
    let ids: Vec<U256> = note_ids
        .iter()
        .map(|s| u256_dec(s))
        .collect::<Result<_>>()?;
    Ok(
        bindings::aggregator::CurvyAggregatorAlphaV2::commitPendingNotesCall {
            batchSize: U256::from(batch_size),
            noteIds: ids,
            newNotesRoot: u256_dec(new_notes_root)?,
            proof_a: a,
            proof_b: b,
            proof_c: c,
        }
        .abi_encode(),
    )
}

// ── local raw-tx signer (caller holds the key; nothing touches the network) ─────

use alloy::consensus::SignableTransaction;
use alloy::network::TxSignerSync;
use alloy::primitives::TxKind;
use alloy::signers::local::PrivateKeySigner;

/// Inputs for a locally signed legacy contract call.
pub struct CallTx<'a> {
    pub signer_private_key: &'a str,
    pub to: &'a str,
    pub calldata: Vec<u8>,
    pub value: &'a str,
    pub nonce: u64,
    pub gas_limit: u64,
    pub gas_price: u128,
    pub chain_id: u64,
}

/// Build a legacy (EIP-155) transaction, sign it locally, and
/// return the EIP-2718-encoded raw bytes — exactly what blokli `sendTransactionSync`
/// / `eth_sendRawTransaction` take. Purely local: nonce/gas/gas_price are supplied by
/// the caller (read via `BalanceReader`), so no provider is needed here.
pub fn sign_call_tx(call: CallTx<'_>) -> Result<RawTx> {
    use alloy::consensus::TxLegacy;
    use alloy::eips::eip2718::Encodable2718;

    let signer: PrivateKeySigner = call
        .signer_private_key
        .parse()
        .context("parse signer key")?;
    let to: Address = call.to.parse().context("parse to address")?;

    let mut tx = TxLegacy {
        chain_id: Some(call.chain_id),
        nonce: call.nonce,
        gas_price: call.gas_price,
        gas_limit: call.gas_limit,
        to: TxKind::Call(to),
        value: u256_dec(call.value)?,
        input: call.calldata.into(),
    };
    let sig = signer.sign_transaction_sync(&mut tx).context("sign tx")?;
    let signed = tx.into_signed(sig);
    Ok(RawTx(signed.encoded_2718()))
}

/// The EOA address for a private key (for nonce reads / balance asserts).
pub fn address_of(priv_key_hex: &str) -> Result<String> {
    let signer: PrivateKeySigner = priv_key_hex.parse().context("parse signer key")?;
    Ok(signer.address().to_string())
}

// ── event decoders (alloy log → neutral curvy-types events) ────────────────────

use alloy::rpc::types::Log;
use alloy::sol_types::SolEvent;

fn block_of(log: &Log) -> u64 {
    log.block_number.unwrap_or_default()
}
fn tx_hash_of(log: &Log) -> String {
    log.transaction_hash
        .map(|h| h.to_string())
        .unwrap_or_default()
}

/// Decode a `PendingNotes` log.
pub fn decode_pending_notes(log: &Log) -> Result<PendingNotesEvent> {
    let d = bindings::aggregator::CurvyAggregatorAlphaV2::PendingNotes::decode_log_data(log.data())
        .context("decode PendingNotes")?;
    Ok(PendingNotesEvent {
        note_ids: d.noteIds.iter().map(|x| x.to_string()).collect(),
        ephemeral_keys: [
            d.ephemeralKeys[0].iter().map(|x| x.to_string()).collect(),
            d.ephemeralKeys[1].iter().map(|x| x.to_string()).collect(),
        ],
        view_tags: d.viewTags.iter().map(|t| *t as u64).collect(),
        tokens: d.tokens.iter().map(|x| x.to_string()).collect(),
        amounts: d.amounts.iter().map(|x| x.to_string()).collect(),
        is_plaintext: d.isPlaintext.clone(),
        block_number: block_of(log),
        tx_hash: tx_hash_of(log),
    })
}

/// Decode a `CommittedNotes` log.
pub fn decode_committed_notes(log: &Log) -> Result<CommittedNotesEvent> {
    let d =
        bindings::aggregator::CurvyAggregatorAlphaV2::CommittedNotes::decode_log_data(log.data())
            .context("decode CommittedNotes")?;
    Ok(CommittedNotesEvent {
        batch_index: d.batchIndex.try_into().unwrap_or(u64::MAX),
        note_ids: d.noteIds.iter().map(|x| x.to_string()).collect(),
        block_number: block_of(log),
    })
}

/// Decode a `CommittedNullifiers` log.
pub fn decode_committed_nullifiers(log: &Log) -> Result<CommittedNullifiersEvent> {
    let d = bindings::aggregator::CurvyAggregatorAlphaV2::CommittedNullifiers::decode_log_data(
        log.data(),
    )
    .context("decode CommittedNullifiers")?;
    Ok(CommittedNullifiersEvent {
        batch_index: d.batchIndex.try_into().unwrap_or(u64::MAX),
        nullifiers: d.nullifiers.iter().map(|x| x.to_string()).collect(),
        block_number: block_of(log),
    })
}

/// The event signature hashes (topic0) for `eth_getLogs` filters.
pub mod topics {
    use super::bindings::aggregator::CurvyAggregatorAlphaV2 as A;
    use alloy::primitives::B256;
    use alloy::sol_types::SolEvent;

    pub fn pending_notes() -> B256 {
        A::PendingNotes::SIGNATURE_HASH
    }
    pub fn committed_notes() -> B256 {
        A::CommittedNotes::SIGNATURE_HASH
    }
    pub fn committed_nullifiers() -> B256 {
        A::CommittedNullifiers::SIGNATURE_HASH
    }
}
