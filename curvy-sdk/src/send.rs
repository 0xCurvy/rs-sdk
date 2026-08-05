//! Note sealing (stealth send → an on-chain-shaped note), padding notes, the fee
//! note, and the value math - all mirroring the TS `witnessFromNotes` /
//! `buildAggregateRequest`.

use anyhow::Result;
use curvy_core::field::{Fr, fr_from_biguint, fr_to_be_32};
use curvy_core::witness::KnownOwner;
use curvy_core::{eddsa, stealth};
use num_bigint::BigUint;
use sha3::{Digest, Keccak256};

use crate::account::{Identity, OwnedNote, parse_xy};

/// Seal an output note to `recipient` via a real stealth send. The note's owner is
/// the recipient's account BabyJubJub key; `sharedSecret` is the x-coordinate of the
/// stealth spending pubkey, `ephemeralKey` is the announcement `R`, and `viewTag` is
/// the 2-hex-char stealth tag as a `u16`. This is the real ECDH the recipient's scan
/// rediscovers.
pub fn seal_note(recipient: &Identity, amount: Fr, token: Fr) -> Result<OwnedNote> {
    let (_r, out) = stealth::send(&recipient.big_k, &recipient.big_v)
        .map_err(|e| anyhow::anyhow!("stealth send: {e}"))?;
    let ss_x = out.spending_pub_key.split('.').next().unwrap_or("0");
    let shared_secret = curvy_core::field::fr_from_dec(ss_x);
    let ephemeral_key = parse_xy(&out.big_r)?;
    let view_tag = u16::from_str_radix(&out.view_tag, 16).unwrap_or(0);
    Ok(OwnedNote {
        owner_pub: recipient.bjj_pub,
        shared_secret,
        ephemeral_key,
        view_tag,
        amount,
        token,
    })
}

/// Construct an output note for an explicitly known BabyJubJub owner.
///
/// PIX supplies the note-owner point independently from Curvy's legacy stealth
/// meta-address keys. The settlement profile supplies the separate shared
/// secret; it is never derived from the BabyJubJub signing scalar.
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

/// A deterministic-but-run-fresh scalar from `(seed, counter)`. Seeded with the
/// shield note's random `sharedSecret`, so pads/fee-notes differ every run (avoiding
/// noteId collisions) while staying reproducible within a run for debugging.
fn fresh_scalar(seed: &[u8], counter: u64) -> BigUint {
    let mut h = Keccak256::new();
    h.update(seed);
    h.update(counter.to_le_bytes());
    BigUint::from_bytes_be(&h.finalize())
}

/// A zero-amount padding note owned by `owner_pub` (fresh secret + real ephemeral so
/// its nullifier/noteId are distinct and it is indistinguishable on-chain). Used to
/// pad inputs/outputs to the circuit's fixed arity; the circuit skips its inclusion
/// proof (amount 0).
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

/// The protocol fee note, owned by the on-chain `feeNotePublicKey` (BabyJubJub).
///
/// The fee note is a **stealth** note: its `noteId`/`nullifier` depend on
/// `sharedSecret`, and the collector recovers it by recomputing `ECDH(feeViewKey, R)`.
/// Owning `feeNotePublicKey` is therefore not enough to spend it - with a random
/// `sharedSecret`/`R` there is nothing for the collector to recompute and the fee is
/// **permanently uncollectable**.
///
/// So a non-zero fee requires `fee_recipient`, the collector's stealth identity, and is
/// refused without it rather than silently minting dead value. A zero fee needs no
/// recipient: the note carries nothing to lose and only exists to satisfy the circuit.
/// This mirrors the TypeScript builder's `sealFee` contract.
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
    // The circuit constrains the fee note's owner to the on-chain `feeNotePublicKey`,
    // so a recipient whose BabyJubJub key is anything else cannot be the collector -
    // catch that here rather than as an unsatisfiable constraint during proving.
    if sealed.owner_pub != fee_pub {
        anyhow::bail!(
            "fee-collector identity does not own the aggregator's feeNotePublicKey; \
             the resulting fee note would violate the circuit's owner constraint"
        );
    }
    Ok(sealed)
}

/// The net note amount an `autoShield` will commit, mirroring the contract exactly:
/// `net = gross − (gross*depositFeeBps/10000 + portalDeployment + pendingNoteCommitment)`
/// (integer floor). Panics only if the gross is too small to cover fees (caller picks it).
pub fn shield_net_amount(
    gross: u128,
    deposit_fee_bps: u64,
    portal_deployment: u128,
    pending_note_commitment: u128,
) -> u128 {
    let deposit_fee = gross * deposit_fee_bps as u128 / 10_000;
    let fee_amount = deposit_fee + portal_deployment + pending_note_commitment;
    gross
        .checked_sub(fee_amount)
        .expect("shield gross must exceed fees")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fee_pub() -> (Fr, Fr) {
        (Fr::from(11u64), Fr::from(22u64))
    }

    #[test]
    fn a_zero_fee_needs_no_collector_identity() {
        // Nothing is at stake in a zero-value note; it exists only to satisfy the
        // circuit's fixed arity.
        let note = fee_note(None, fee_pub(), Fr::from(0u64), Fr::from(1u64), b"seed")
            .expect("zero fee is always constructible");
        assert_eq!(note.owner_pub, fee_pub());
        assert_eq!(note.amount, Fr::from(0u64));
    }

    #[test]
    fn a_non_zero_fee_without_a_collector_is_refused_rather_than_burned() {
        // The regression that matters: a random shared secret makes the fee
        // permanently uncollectable, so this must fail loudly instead of minting
        // dead value that looks like a successful aggregation.
        let error = fee_note(None, fee_pub(), Fr::from(5u64), Fr::from(1u64), b"seed")
            .expect_err("a non-zero fee with no collector must not be constructible");
        let message = error.to_string();
        assert!(
            message.contains("uncollectable"),
            "the error must name the consequence, got: {message}"
        );
    }
}
