//! Note sealing, padding, fee notes and shield value calculations.

use anyhow::{Context, Result};
use curvy_core::field::{Fr, fr_from_biguint, fr_to_be_32};
use curvy_core::witness::KnownOwner;
use curvy_core::{eddsa, stealth};
use num_bigint::BigUint;
use sha3::{Digest, Keccak256};

use crate::account::{
    Identity, OwnedNote, ViewerIdentity, parse_xy, shared_secret_from_spending_pub_key,
};

/// Seal an output note to a stealth recipient.
pub fn seal_note(recipient: &Identity, amount: Fr, token: Fr) -> Result<OwnedNote> {
    seal_note_for_owner(
        &ViewerIdentity {
            big_k: recipient.big_k.clone(),
            big_v: recipient.big_v.clone(),
        },
        recipient.bjj_pub,
        amount,
        token,
    )
}

/// Seals a note using `recipient` only for private discovery while assigning
/// spending authority to the independent BabyJubJub `owner_pub`.
///
/// This is the PIX boundary: the Curvy viewer may discover the note before the
/// SSA finishes, but only the separately reconstructed SSA key matching
/// `owner_pub` can sign its withdrawal.
pub fn seal_note_for_owner(
    recipient: &ViewerIdentity,
    owner_pub: (Fr, Fr),
    amount: Fr,
    token: Fr,
) -> Result<OwnedNote> {
    let (_r, out) = stealth::send(&recipient.big_k, &recipient.big_v)
        .map_err(|e| anyhow::anyhow!("stealth send: {e}"))?;
    let shared_secret = shared_secret_from_spending_pub_key(&out.spending_pub_key)
        .context("parse stealth shared-secret point")?;
    let ephemeral_key = parse_xy(&out.big_r)?;
    let view_tag = u16::from_str_radix(&out.view_tag, 16).context("parse stealth view tag")?;
    Ok(OwnedNote {
        owner_pub,
        shared_secret,
        ephemeral_key,
        view_tag,
        amount,
        token,
    })
}

/// Construct an output note for a known BabyJubJub owner.
pub fn seal_known_owner(recipient: KnownOwner, amount: Fr, token: Fr) -> OwnedNote {
    let seed = fr_to_be_32(recipient.shared_secret.as_fr());
    let ephemeral_key = eddsa::ephemeral_pub_key(&fresh_scalar(&seed, 0x5049_5801));
    let note = recipient.note(amount, token, ephemeral_key, Fr::from(0u64));
    OwnedNote {
        owner_pub: note.owner_pub,
        shared_secret: note.shared_secret,
        ephemeral_key: note.ephemeral_key,
        view_tag: 0,
        amount: note.amount,
        token: note.token,
    }
}

/// Derive a scalar from `(seed, counter)`.
fn fresh_scalar(seed: &[u8], counter: u64) -> BigUint {
    let mut h = Keccak256::new();
    h.update(seed);
    h.update(counter.to_le_bytes());
    BigUint::from_bytes_be(&h.finalize())
}

/// Construct a distinct zero-value note for fixed-arity padding.
pub fn zero_pad_note(owner_pub: (Fr, Fr), token: Fr, seed: &[u8], counter: u64) -> OwnedNote {
    OwnedNote {
        owner_pub,
        shared_secret: fr_from_biguint(&fresh_scalar(seed, counter)),
        ephemeral_key: eddsa::ephemeral_pub_key(&fresh_scalar(seed, counter.wrapping_add(1 << 20))),
        view_tag: 0,
        amount: Fr::from(0u64),
        token,
    }
}

/// Construct a protocol fee note owned by `feeNotePublicKey`.
/// A nonzero fee requires the collector's stealth identity.
pub fn fee_note(
    fee_recipient: Option<&Identity>,
    fee_pub: (Fr, Fr),
    amount: Fr,
    token: Fr,
    seed: &[u8],
) -> Result<OwnedNote> {
    if amount == Fr::from(0u64) {
        return Ok(OwnedNote {
            owner_pub: fee_pub,
            shared_secret: fr_from_biguint(&fresh_scalar(seed, 0xFEE1)),
            ephemeral_key: eddsa::ephemeral_pub_key(&fresh_scalar(seed, 0xFEE2)),
            view_tag: 0,
            amount,
            token,
        });
    }

    let recipient = fee_recipient.ok_or_else(|| {
        anyhow::anyhow!(
            "aggregation carries a non-zero protocol fee but no fee-collector identity: \
             the fee note would be sealed to a random shared secret and be permanently \
             uncollectable. Supply the collector's stealth identity, or set the on-chain \
             protocol fee and per-token gas fee to zero."
        )
    })?;
    let sealed = seal_note(recipient, amount, token)?;
    // The circuit constrains the fee note owner.
    if sealed.owner_pub != fee_pub {
        anyhow::bail!(
            "fee-collector identity does not own the aggregator's feeNotePublicKey; \
             the resulting fee note would violate the circuit's owner constraint"
        );
    }
    Ok(sealed)
}

/// The net note amount an `autoShield` will commit, mirroring the contract exactly:
/// `net = gross - (gross*depositFeeBps/10000 + portalDeployment + pendingNoteCommitment)`
/// (integer floor).
///
/// Returns an error when the gross amount cannot cover fees.
pub fn shield_net_amount(
    gross: u128,
    deposit_fee_bps: u64,
    portal_deployment: u128,
    pending_note_commitment: u128,
) -> Result<u128> {
    let deposit_fee = gross
        .checked_mul(deposit_fee_bps as u128)
        .context("deposit fee multiplication overflow")?
        / 10_000;
    let fee_amount = deposit_fee
        .checked_add(portal_deployment)
        .and_then(|amount| amount.checked_add(pending_note_commitment))
        .context("deposit fee total overflow")?;
    gross.checked_sub(fee_amount).with_context(|| {
        format!(
            "deposit of {gross} does not cover its fees: {deposit_fee} deposit fee + \
             {portal_deployment} portal deployment + {pending_note_commitment} commitment"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fee_pub() -> (Fr, Fr) {
        (Fr::from(11u64), Fr::from(22u64))
    }

    #[test]
    fn a_zero_fee_needs_no_collector_identity() {
        let note = fee_note(None, fee_pub(), Fr::from(0u64), Fr::from(1u64), b"seed")
            .expect("zero fee is always constructible");
        assert_eq!(note.owner_pub, fee_pub());
        assert_eq!(note.amount, Fr::from(0u64));
    }

    #[test]
    fn a_non_zero_fee_without_a_collector_is_refused_rather_than_burned() {
        let error = fee_note(None, fee_pub(), Fr::from(5u64), Fr::from(1u64), b"seed")
            .expect_err("a non-zero fee with no collector must not be constructible");
        let message = error.to_string();
        assert!(
            message.contains("uncollectable"),
            "the error must name the consequence, got: {message}"
        );
    }

    #[test]
    fn shield_fee_overflow_is_reported() {
        let error = shield_net_amount(u128::MAX, u64::MAX, 0, 0).unwrap_err();
        assert!(error.to_string().contains("overflow"));
    }

    #[test]
    fn shield_fee_addition_overflow_is_reported() {
        let error = shield_net_amount(u128::MAX, 0, u128::MAX, 1).unwrap_err();
        assert!(error.to_string().contains("overflow"));
    }

    #[test]
    fn viewer_identity_does_not_choose_the_note_owner() -> Result<()> {
        let (_k, _v, big_k, big_v) = stealth::new_meta()
            .map_err(|error| anyhow::anyhow!("generate viewer fixture: {error}"))?;
        let viewer = ViewerIdentity::new(big_k, big_v)?;
        let owner = (Fr::from(41_u64), Fr::from(42_u64));

        let note = seal_note_for_owner(&viewer, owner, Fr::from(5_u64), Fr::from(1_u64))?;

        assert_eq!(note.owner_pub, owner);
        Ok(())
    }
}
