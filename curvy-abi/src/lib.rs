//! Curvy contract bindings, calldata, signing and event decoding.

use alloy::primitives::{Address, U256};
use anyhow::{Context, Result};
/// The shared wire types these encoders speak, re-exported so a caller building a payload for
/// [`relay_request_key`] need not depend on `curvy-types` directly.
pub use curvy_types;
use curvy_types::{
    CircuitRef, CommittedNotesEvent, CommittedNullifiersEvent, Dec, Groth16Proof, OnchainNote,
    PendingNotesEvent, RawTx,
};

/// Generated contract bindings grouped by contract.
pub mod bindings {
    pub mod erc20 {
        alloy::sol! {
            #[sol(rpc)]
            interface IERC20 {
                function transfer(address to, uint256 amount) external returns (bool);
                function balanceOf(address owner) external view returns (uint256);
                function allowance(address owner, address spender) external view returns (uint256);
                function approve(address spender, uint256 amount) external returns (bool);
            }
        }
    }
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

// Decimal and U256 conversion.

/// Parse a non-negative decimal string into `U256`.
pub fn u256_dec(s: &str) -> Result<U256> {
    U256::from_str_radix(s, 10).map_err(|e| anyhow::anyhow!("parse U256 {s:?}: {e}"))
}
fn u256_arr2(a: &[Dec; 2]) -> Result<[U256; 2]> {
    Ok([u256_dec(&a[0])?, u256_dec(&a[1])?])
}

// Proof conversion.

/// Convert snarkjs proof JSON into the on-chain proof shape.
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

// Calldata encoders.

/// `IERC20.transfer(to, amount)` calldata.
pub fn encode_erc20_transfer(to: &str, amount: u128) -> Result<Vec<u8>> {
    let to: Address = to.parse().context("parse ERC-20 transfer recipient")?;
    Ok(bindings::erc20::IERC20::transferCall {
        to,
        amount: U256::from(amount),
    }
    .abi_encode())
}

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

/// `IERC20.approve(spender, amount)` calldata.
///
/// The direct-shield flow approves the **vault**, not the aggregator: the aggregator forwards the
/// caller as `from` and the vault is what calls `safeTransferFrom` on it.
pub fn encode_erc20_approve(spender: &str, amount: u128) -> Result<Vec<u8>> {
    let spender: Address = spender.parse().context("parse ERC-20 approve spender")?;
    Ok(bindings::erc20::IERC20::approveCall {
        spender,
        amount: U256::from(amount),
    }
    .abi_encode())
}

/// `CurvyAggregatorAlphaV2.directShield(note)` calldata.
///
/// The portal-free deposit: the caller supplies the funds itself, so no entry portal is deployed
/// and the deployment's `portalDeployment` gas-fee leg is not charged. Requires
/// `directShieldEnabled` on the aggregator, and — for an ERC-20 — an allowance to the vault from
/// the same address that sends this call.
pub fn encode_direct_shield(note: &OnchainNote) -> Result<Vec<u8>> {
    let n = bindings::aggregator::CurvyTypes::Note {
        ownerHash: u256_dec(&note.owner_hash)?,
        token: u256_dec(&note.token)?,
        amount: u256_dec(&note.amount)?,
        ephemeralKey: u256_arr2(&note.ephemeral_key)?,
        viewTag: note.view_tag as u16,
    };
    Ok(bindings::aggregator::CurvyAggregatorAlphaV2::directShieldCall { note: n }.abi_encode())
}

fn u256_vec(values: &[Dec]) -> Result<Vec<U256>> {
    values.iter().map(|s| u256_dec(s)).collect()
}

fn circuit_arg(circuit: CircuitRef) -> bindings::aggregator::ICurvyAggregatorAlpha::CircuitRef {
    bindings::aggregator::ICurvyAggregatorAlpha::CircuitRef {
        family: circuit.family.id(),
        version: circuit.version,
    }
}

/// `CurvyAggregatorAlphaV2.submitAggregationRequest(...)` calldata.
///
/// `circuit` is the circuit family version the proof was made for; the aggregator checks the proof
/// with that version's verifier and refuses a version it has not released or that has expired.
/// `words` are the values the proof is bound to, in the entry point's order. `commitment` is the
/// proof's commitment to them; the contract derives the other two public signals, `y` and `x`,
/// from both.
pub fn encode_submit_aggregation(
    max_inputs: u64,
    max_outputs: u64,
    circuit: CircuitRef,
    words: &[Dec],
    commitment: &Dec,
    proof: &Groth16Proof,
) -> Result<Vec<u8>> {
    let (a, b, c) = proof_to_u256(proof)?;
    Ok(
        bindings::aggregator::CurvyAggregatorAlphaV2::submitAggregationRequestCall {
            maxInputs: U256::from(max_inputs),
            maxOutputs: U256::from(max_outputs),
            circuit: circuit_arg(circuit),
            words: u256_vec(words)?,
            commitment: u256_dec(commitment)?,
            proof_a: a,
            proof_b: b,
            proof_c: c,
        }
        .abi_encode(),
    )
}

/// `CurvyAggregatorAlphaV2.submitWithdrawalRequest(...)` calldata, with `circuit`, `words` and
/// `commitment` as in [`encode_submit_aggregation`].
pub fn encode_submit_withdrawal(
    max_inputs: u64,
    circuit: CircuitRef,
    words: &[Dec],
    commitment: &Dec,
    proof: &Groth16Proof,
) -> Result<Vec<u8>> {
    let (a, b, c) = proof_to_u256(proof)?;
    Ok(
        bindings::aggregator::CurvyAggregatorAlphaV2::submitWithdrawalRequestCall {
            maxInputs: U256::from(max_inputs),
            circuit: circuit_arg(circuit),
            words: u256_vec(words)?,
            commitment: u256_dec(commitment)?,
            proof_a: a,
            proof_b: b,
            proof_c: c,
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
///
/// `circuit` is as in [`encode_submit_aggregation`]. `note_ids` are only the notes being
/// committed, without the zeros that pad the circuit's batch of `batch_size`: the contract hashes
/// the padding itself. `commitment` is the proof's commitment to
/// `[paddedNoteIds..., currentRoot, newRoot, currentIndex, newIndex]`.
pub fn encode_commit_pending_notes(
    batch_size: u64,
    circuit: CircuitRef,
    note_ids: &[Dec],
    new_notes_root: &Dec,
    commitment: &Dec,
    proof: &Groth16Proof,
) -> Result<Vec<u8>> {
    let (a, b, c) = proof_to_u256(proof)?;
    Ok(
        bindings::aggregator::CurvyAggregatorAlphaV2::commitPendingNotesCall {
            batchSize: U256::from(batch_size),
            circuit: circuit_arg(circuit),
            noteIds: u256_vec(note_ids)?,
            newNotesRoot: u256_dec(new_notes_root)?,
            commitment: u256_dec(commitment)?,
            proof_a: a,
            proof_b: b,
            proof_c: c,
        }
        .abi_encode(),
    )
}

// Raw transaction signing.

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

/// Sign a legacy EIP-155 transaction and return EIP-2718 bytes.
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

// Relayer submission keys.

/// Which relayer action a submission is, as it appears in the wire payload and in the leading
/// byte of [`relay_request_key`]'s preimage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayAction {
    Aggregation,
    Withdrawal,
}

impl RelayAction {
    /// The `action` field's wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Aggregation => "aggregation",
            Self::Withdrawal => "withdrawal",
        }
    }

    fn tag(self) -> u8 {
        match self {
            Self::Aggregation => 0,
            Self::Withdrawal => 1,
        }
    }

    /// Where this action's nullifiers start in the words.
    ///
    /// A withdrawal's word 0 is the withdrawn amount; an aggregation's nullifiers lead.
    fn nullifier_offset(self) -> usize {
        match self {
            Self::Aggregation => 0,
            Self::Withdrawal => 1,
        }
    }
}

fn keccak_hex(preimage: &[u8]) -> String {
    // Lowercase, `0x`-prefixed: the relayer compares these by exact string equality against its
    // own derivation, so casing is part of the contract.
    format!("0x{:x}", alloy::primitives::keccak256(preimage))
}

/// The relayer's idempotency key: `keccak256` over the standard, non-packed ABI encoding of the
/// whole submission.
///
/// Must match `deriveRelayRequestKey` in Curvy's TypeScript SDK byte for byte — the relayer
/// recomputes it and rejects a mismatch — so the encoding is spelled out rather than derived from
/// a struct that could drift.
///
/// `network_id` is the EVM chain id, not an indexer's internal network row. `circuit` is the
/// circuit family version the proof was made for, which the payload carries as `circuitFamily` and
/// `circuitVersion`. `public_signals` is the payload's field of that name, which holds the calldata
/// words. The proof's commitment is not sent, and is not part of the key.
pub fn relay_request_key(
    action: RelayAction,
    network_id: u64,
    max_inputs: usize,
    circuit: CircuitRef,
    proof: &Groth16Proof,
    public_signals: &[String],
) -> Result<String> {
    let mut out = Vec::with_capacity(14 * 32 + 32 + public_signals.len() * 32);
    out.extend_from_slice(&U256::from(action.tag()).to_be_bytes::<32>());
    out.extend_from_slice(&U256::from(network_id).to_be_bytes::<32>());
    out.extend_from_slice(&U256::from(max_inputs).to_be_bytes::<32>());
    out.extend_from_slice(&U256::from(circuit.family.id()).to_be_bytes::<32>());
    out.extend_from_slice(&U256::from(circuit.version).to_be_bytes::<32>());
    for value in [&proof.a[0], &proof.a[1]] {
        out.extend_from_slice(&u256_dec(value)?.to_be_bytes::<32>());
    }
    for row in &proof.b {
        for value in row {
            out.extend_from_slice(&u256_dec(value)?.to_be_bytes::<32>());
        }
    }
    for value in [&proof.c[0], &proof.c[1]] {
        out.extend_from_slice(&u256_dec(value)?.to_be_bytes::<32>());
    }
    // Offset to the one dynamic argument: fourteen head words.
    out.extend_from_slice(&U256::from(14 * 32).to_be_bytes::<32>());
    out.extend_from_slice(&U256::from(public_signals.len()).to_be_bytes::<32>());
    for signal in public_signals {
        out.extend_from_slice(&u256_dec(signal)?.to_be_bytes::<32>());
    }
    Ok(keccak_hex(&out))
}

/// The non-padding nullifiers of a submission, ascending.
///
/// Zeros are the circuit's padding slots and are dropped; duplicates are **not** removed, since
/// the reference implementation does not remove them either and the key must match.
pub fn relay_nullifiers(
    action: RelayAction,
    max_inputs: usize,
    public_signals: &[String],
) -> Result<Vec<U256>> {
    let start = action.nullifier_offset();
    let end = start
        .checked_add(max_inputs)
        .context("nullifier window overflows")?;
    if public_signals.len() < end {
        anyhow::bail!(
            "relay submission has {} public signals; {} with maxInputs={max_inputs} needs at least {end}",
            public_signals.len(),
            action.as_str()
        );
    }
    let mut nullifiers = public_signals[start..end]
        .iter()
        .map(|signal| u256_dec(signal))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|value| !value.is_zero())
        .collect::<Vec<_>>();
    if nullifiers.is_empty() {
        anyhow::bail!("relay submission contains no non-padding nullifiers");
    }
    nullifiers.sort_unstable();
    Ok(nullifiers)
}

/// The relayer's spend key, identifying the note set a submission spends.
///
/// Deliberately **excludes** the action: an aggregation and a withdrawal over the same nullifiers
/// are the same spend, and the relayer's conflict check is meant to catch exactly that.
pub fn relay_spend_key(
    action: RelayAction,
    network_id: u64,
    max_inputs: usize,
    public_signals: &[String],
) -> Result<String> {
    let nullifiers = relay_nullifiers(action, max_inputs, public_signals)?;
    let mut out = Vec::with_capacity(3 * 32 + nullifiers.len() * 32);
    out.extend_from_slice(&U256::from(network_id).to_be_bytes::<32>());
    // Offset to the one dynamic argument: two head words.
    out.extend_from_slice(&U256::from(64).to_be_bytes::<32>());
    out.extend_from_slice(&U256::from(nullifiers.len()).to_be_bytes::<32>());
    for nullifier in nullifiers {
        out.extend_from_slice(&nullifier.to_be_bytes::<32>());
    }
    Ok(keccak_hex(&out))
}

/// An EIP-1559 call to sign with raw key bytes.
///
/// The counterpart to [`CallTx`] for callers whose key is not a hex string: a node's signing key
/// generally lives in a zeroizing container, and formatting it into a `String` to pass here would
/// put a copy on the heap that nothing wipes.
pub struct Eip1559Call<'a> {
    /// The signer's 32 secret bytes.
    pub signer_secret: &'a [u8],
    pub to: [u8; 20],
    pub calldata: Vec<u8>,
    pub value: u128,
    pub nonce: u64,
    pub gas_limit: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub chain_id: u64,
}

/// Sign an EIP-1559 transaction and return EIP-2718 bytes.
pub fn sign_eip1559_call(call: Eip1559Call<'_>) -> Result<RawTx> {
    use alloy::consensus::{SignableTransaction, TxEip1559};
    use alloy::eips::eip2718::Encodable2718;

    let signer = PrivateKeySigner::from_slice(call.signer_secret).context("parse signer secret")?;
    let mut tx = TxEip1559 {
        chain_id: call.chain_id,
        nonce: call.nonce,
        gas_limit: call.gas_limit,
        max_fee_per_gas: call.max_fee_per_gas,
        max_priority_fee_per_gas: call.max_priority_fee_per_gas,
        to: TxKind::Call(Address::from(call.to)),
        value: U256::from(call.value),
        access_list: Default::default(),
        input: call.calldata.into(),
    };
    let sig = signer.sign_transaction_sync(&mut tx).context("sign tx")?;
    Ok(RawTx(tx.into_signed(sig).encoded_2718()))
}

/// The EOA address for a private key (for nonce reads / balance asserts).
pub fn address_of(priv_key_hex: &str) -> Result<String> {
    let signer: PrivateKeySigner = priv_key_hex.parse().context("parse signer key")?;
    Ok(signer.address().to_string())
}

// Event decoders.

use alloy::rpc::types::Log;
use alloy::sol_types::SolEvent;

fn block_of(log: &Log) -> Result<u64> {
    log.block_number.context("log has no block number")
}
fn tx_hash_of(log: &Log) -> Result<String> {
    log.transaction_hash
        .map(|h| h.to_string())
        .context("log has no transaction hash")
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
        block_number: block_of(log)?,
        tx_hash: tx_hash_of(log)?,
    })
}

/// Decode a `CommittedNotes` log.
pub fn decode_committed_notes(log: &Log) -> Result<CommittedNotesEvent> {
    let d =
        bindings::aggregator::CurvyAggregatorAlphaV2::CommittedNotes::decode_log_data(log.data())
            .context("decode CommittedNotes")?;
    Ok(CommittedNotesEvent {
        batch_index: d
            .batchIndex
            .try_into()
            .context("batchIndex does not fit u64")?,
        note_ids: d.noteIds.iter().map(|x| x.to_string()).collect(),
        block_number: block_of(log)?,
    })
}

/// Decode a `CommittedNullifiers` log.
pub fn decode_committed_nullifiers(log: &Log) -> Result<CommittedNullifiersEvent> {
    let d = bindings::aggregator::CurvyAggregatorAlphaV2::CommittedNullifiers::decode_log_data(
        log.data(),
    )
    .context("decode CommittedNullifiers")?;
    Ok(CommittedNullifiersEvent {
        batch_index: d
            .batchIndex
            .try_into()
            .context("batchIndex does not fit u64")?,
        nullifiers: d.nullifiers.iter().map(|x| x.to_string()).collect(),
        block_number: block_of(log)?,
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

#[cfg(test)]
mod relay_key_tests {
    use super::*;
    use curvy_types::CircuitFamily;

    const CORE_1: CircuitRef = CircuitRef {
        family: CircuitFamily::Core,
        version: 1,
    };
    const PIX_1: CircuitRef = CircuitRef {
        family: CircuitFamily::Pix,
        version: 1,
    };

    /// The fixture from Curvy's own `relayKeys.test.ts`, so the shapes line up with the
    /// reference implementation's.
    fn proof() -> Groth16Proof {
        Groth16Proof {
            a: ["1".into(), "2".into()],
            b: [["3".into(), "4".into()], ["5".into(), "6".into()]],
            c: ["7".into(), "8".into()],
        }
    }

    fn signals(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    // The expected digests below come from independent ABI encoders (Foundry's `cast` and viem,
    // as the relayer uses it), not from this code.

    #[test]
    fn request_and_spend_keys_match_the_reference_implementation() -> Result<()> {
        assert_eq!(
            relay_request_key(
                RelayAction::Aggregation,
                1,
                2,
                CORE_1,
                &proof(),
                &signals(&["11", "12", "21"])
            )?,
            "0x2fed373703df894b261ceab4f8bed071f67b925ffdcacede9e0a841709de387f"
        );
        assert_eq!(
            relay_spend_key(
                RelayAction::Aggregation,
                1,
                2,
                &signals(&["11", "12", "21"])
            )?,
            "0xd790e59d3d7b988d7061a7ddf659169c980d364c0efb073ba790973f81f272e2"
        );
        Ok(())
    }

    #[test]
    fn a_local_chain_aggregation_matches_the_reference_implementation() -> Result<()> {
        assert_eq!(
            relay_request_key(
                RelayAction::Aggregation,
                31337,
                2,
                PIX_1,
                &proof(),
                &signals(&["9", "10", "11"])
            )?,
            "0x057314e8a34a674be35ab50126cb8dbd943210ffecf5d90c332c92c1add7adc9"
        );
        assert_eq!(
            relay_spend_key(
                RelayAction::Aggregation,
                31337,
                2,
                &signals(&["9", "10", "11"])
            )?,
            "0xf2e039982eaf14681fdd5b0a9492f949ea97787c30c2032f7a10586bcf95e211"
        );
        Ok(())
    }

    #[test]
    fn a_withdrawal_skips_the_amount_signal() -> Result<()> {
        let public = signals(&["100", "11", "0", "12", "99"]);
        // Signal 0 is the withdrawn amount, and the zero in the window is circuit padding.
        assert_eq!(
            relay_nullifiers(RelayAction::Withdrawal, 3, &public)?,
            vec![U256::from(11), U256::from(12)]
        );
        assert_eq!(
            relay_request_key(RelayAction::Withdrawal, 31337, 3, PIX_1, &proof(), &public)?,
            "0x42aa65583bd1496ae26ac8297864c169df3aa1d4be2f12857c2cad1578e3ec40"
        );
        assert_eq!(
            relay_spend_key(RelayAction::Withdrawal, 31337, 3, &public)?,
            "0x3f56ab4653d6c8abb2a4d055f8a0714f2ad1a4f0123145b64467171a1eed0579"
        );
        Ok(())
    }

    #[test]
    fn reproving_changes_the_request_key_but_not_the_spend_key() -> Result<()> {
        let public = signals(&["11", "12", "21"]);
        let reproved = Groth16Proof {
            c: ["9".into(), "10".into()],
            ..proof()
        };
        assert_ne!(
            relay_request_key(RelayAction::Aggregation, 1, 2, PIX_1, &proof(), &public)?,
            relay_request_key(RelayAction::Aggregation, 1, 2, PIX_1, &reproved, &public)?,
        );
        // The same notes under a newer root: a new request, the same spend.
        let rebuilt = signals(&["11", "12", "22"]);
        assert_ne!(
            relay_request_key(RelayAction::Aggregation, 1, 2, PIX_1, &proof(), &public)?,
            relay_request_key(RelayAction::Aggregation, 1, 2, PIX_1, &proof(), &rebuilt)?,
        );
        assert_eq!(
            relay_spend_key(RelayAction::Aggregation, 1, 2, &public)?,
            relay_spend_key(RelayAction::Aggregation, 1, 2, &rebuilt)?,
        );
        Ok(())
    }

    // The family version changes the request key, not the spend key.
    #[test]
    fn the_circuit_version_keys_the_request_but_not_the_spend() -> Result<()> {
        let public = signals(&["11", "12", "21"]);
        let key =
            |circuit| relay_request_key(RelayAction::Aggregation, 1, 2, circuit, &proof(), &public);
        assert_eq!(
            key(PIX_1)?,
            "0xa683c771a05ce115785c18035ea20ab3d284ce1047d4d92d0e7e859646ea1bef"
        );
        assert_eq!(
            key(CircuitRef {
                version: 2,
                ..CORE_1
            })?,
            "0x84a60fdaa15f1bafd9eef4b51ecbd7e355519c28c23a3abaff15f5268b89a1d4"
        );
        assert_ne!(key(CORE_1)?, key(PIX_1)?);
        Ok(())
    }

    #[test]
    fn nullifier_order_does_not_change_the_spend_key() -> Result<()> {
        assert_eq!(
            relay_spend_key(
                RelayAction::Aggregation,
                1,
                2,
                &signals(&["11", "12", "21"])
            )?,
            relay_spend_key(
                RelayAction::Aggregation,
                1,
                2,
                &signals(&["12", "11", "21"])
            )?,
        );
        Ok(())
    }

    #[test]
    fn an_all_padding_submission_is_refused() {
        let error = relay_nullifiers(RelayAction::Aggregation, 2, &signals(&["0", "0", "5"]))
            .expect_err("a submission that spends nothing has no spend key");
        assert!(
            error.to_string().contains("no non-padding nullifiers"),
            "{error}"
        );
    }

    #[test]
    fn too_few_signals_names_the_window_it_needed() {
        let error = relay_nullifiers(RelayAction::Withdrawal, 10, &signals(&["1", "2"]))
            .expect_err("the nullifier window runs past the signals");
        let message = error.to_string();
        assert!(message.contains("at least 11"), "{message}");
    }
}

#[cfg(test)]
mod bound_entry_point_tests {
    use super::*;
    use bindings::aggregator::CurvyAggregatorAlphaV2 as A;
    use curvy_types::CircuitFamily;

    const PIX_1: CircuitRef = CircuitRef {
        family: CircuitFamily::Pix,
        version: 1,
    };

    fn proof() -> Groth16Proof {
        Groth16Proof {
            a: ["1".into(), "2".into()],
            b: [["3".into(), "4".into()], ["5".into(), "6".into()]],
            c: ["7".into(), "8".into()],
        }
    }

    fn decimals(values: &[u64]) -> Vec<String> {
        values.iter().map(u64::to_string).collect()
    }

    fn u256s(values: &[u64]) -> Vec<U256> {
        values.iter().copied().map(U256::from).collect()
    }

    // The selectors of the versioned entry points, from their Solidity signatures.
    fn selector(signature: &str) -> [u8; 4] {
        alloy::primitives::keccak256(signature.as_bytes())[..4]
            .try_into()
            .unwrap()
    }

    #[test]
    fn commit_posts_the_note_ids_with_the_commitment() -> Result<()> {
        let calldata = encode_commit_pending_notes(
            256,
            PIX_1,
            &decimals(&[11, 12]),
            &"99".into(),
            &"77".into(),
            &proof(),
        )?;
        assert_eq!(
            calldata[..4],
            selector(
                "commitPendingNotes(uint256,(uint8,uint64),uint256[],uint256,uint256,uint256[2],uint256[2][2],uint256[2])"
            )
        );
        let call = A::commitPendingNotesCall::abi_decode(&calldata)?;
        assert_eq!(call.batchSize, U256::from(256));
        assert_eq!((call.circuit.family, call.circuit.version), (1, 1));
        assert_eq!(call.noteIds, u256s(&[11, 12]));
        assert_eq!(call.newNotesRoot, U256::from(99));
        assert_eq!(call.commitment, U256::from(77));
        // The proof's G2 pairs go through as given.
        assert_eq!(
            call.proof_b,
            [
                [U256::from(3), U256::from(4)],
                [U256::from(5), U256::from(6)]
            ]
        );
        Ok(())
    }

    #[test]
    fn aggregation_and_withdrawal_post_words_and_commitment() -> Result<()> {
        let calldata =
            encode_submit_aggregation(2, 9, PIX_1, &decimals(&[1, 2, 3]), &"44".into(), &proof())?;
        assert_eq!(
            calldata[..4],
            selector(
                "submitAggregationRequest(uint256,uint256,(uint8,uint64),uint256[],uint256,uint256[2],uint256[2][2],uint256[2])"
            )
        );
        let call = A::submitAggregationRequestCall::abi_decode(&calldata)?;
        assert_eq!(
            (call.maxInputs, call.maxOutputs),
            (U256::from(2), U256::from(9))
        );
        assert_eq!((call.circuit.family, call.circuit.version), (1, 1));
        assert_eq!(call.words, u256s(&[1, 2, 3]));
        assert_eq!(call.commitment, U256::from(44));

        let calldata =
            encode_submit_withdrawal(10, PIX_1, &decimals(&[5, 6]), &"55".into(), &proof())?;
        assert_eq!(
            calldata[..4],
            selector(
                "submitWithdrawalRequest(uint256,(uint8,uint64),uint256[],uint256,uint256[2],uint256[2][2],uint256[2])"
            )
        );
        let call = A::submitWithdrawalRequestCall::abi_decode(&calldata)?;
        assert_eq!(call.maxInputs, U256::from(10));
        assert_eq!((call.circuit.family, call.circuit.version), (1, 1));
        assert_eq!(call.words, u256s(&[5, 6]));
        assert_eq!(call.commitment, U256::from(55));
        Ok(())
    }
}
