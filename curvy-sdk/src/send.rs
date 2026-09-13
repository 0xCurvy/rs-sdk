//! Note sealing, padding, fee notes and shield value calculations.

use anyhow::{Context, Result};
use curvy_core::field::{Fr, fr_from_biguint, fr_to_be_32};
use curvy_core::witness::KnownOwner;
use curvy_core::{eddsa, stealth};
use num_bigint::BigUint;
use sha3::{Digest, Keccak256};

use crate::account::{
    Identity, OwnedNote, ViewerIdentity, field_modulus, parse_xy, spending_pub_key_x,
};

/// Stealth-send attempts before giving up on an in-field shared secret. Each attempt lands in
/// the field with probability about 0.19, so 256 misses is a broken RNG, not bad luck.
const IN_FIELD_SEND_ATTEMPTS: usize = 256;

/// A stealth send to `(K, V)` whose shared secret — the spending key's x coordinate — lies in
/// the BN254 scalar field, so its raw and field-reduced spellings are one value.
///
/// The circuit hashes the secret reduced into `Fr`, but the note-data cipher is keyed with the
/// raw 256-bit coordinate: `balanceCipher.ts`, the relayer's paymaster and the fee collector all
/// decrypt with it, while `curvy_core` encrypts with the reduced one. A secret outside the field
/// therefore yields a ciphertext no other client can open, and an output note the relayer's gate
/// cannot recognise as its own. Redrawing the ephemeral key until the secret is in the field
/// removes the divergence at the source without changing any wire format; it costs about five
/// pairings per note on average.
pub(crate) fn send_in_field(big_k: &str, big_v: &str) -> Result<(BigUint, stealth::SendOutput)> {
    let modulus = field_modulus();
    for _ in 0..IN_FIELD_SEND_ATTEMPTS {
        let (_r, out) =
            stealth::send(big_k, big_v).map_err(|e| anyhow::anyhow!("stealth send: {e}"))?;
        let x = spending_pub_key_x(&out.spending_pub_key)
            .context("parse stealth shared-secret point")?;
        if x < modulus {
            return Ok((x, out));
        }
    }
    anyhow::bail!(
        "no in-field stealth shared secret in {IN_FIELD_SEND_ATTEMPTS} attempts; the ephemeral \
         key source is not random"
    )
}

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
    let (shared_secret_raw, out) = send_in_field(&recipient.big_k, &recipient.big_v)?;
    let shared_secret = fr_from_biguint(&shared_secret_raw);
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

/// Which shield entry point a note is destined for, and therefore which gas-fee legs the vault
/// charges it.
///
/// The vault takes this as `isPortalShield` and adds the portal-deployment leg only for a portal
/// shield (`CurvyVaultV2._deposit`); a direct shield deploys nothing, so it pays only the
/// pending-note commitment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ShieldKind {
    /// `CurvyAggregatorAlphaV2.directShield` — the caller supplies the funds itself.
    #[default]
    Direct,
    /// `CurvyAggregatorAlphaV2.portalShield`, reached through a deployed entry portal.
    Portal,
}

impl ShieldKind {
    /// Whether the vault charges the portal-deployment gas-fee leg.
    pub fn charges_portal_deployment(self) -> bool {
        matches!(self, Self::Portal)
    }
}

/// The net note amount a shield will commit, mirroring `CurvyVaultV2._deposit` exactly:
/// `net = gross - (gross*depositFeeBps/10000 + [portalDeployment] + pendingNoteCommitment)`
/// (integer floor), where the portal-deployment leg is charged only for a portal shield.
///
/// Returns an error when the gross amount cannot cover fees — the contract's
/// `NetAmountNonPositive`, caught before the transaction is built. Note the contract reverts when
/// `amount <= totalFees`, so an exactly-break-even gross is *not* acceptable there; this returns
/// `Ok(0)` for that case, and callers that build a real note must reject a zero net themselves.
pub fn shield_net_amount(
    gross: u128,
    deposit_fee_bps: u64,
    portal_deployment: u128,
    pending_note_commitment: u128,
    kind: ShieldKind,
) -> Result<u128> {
    let deposit_fee = gross
        .checked_mul(deposit_fee_bps as u128)
        .context("deposit fee multiplication overflow")?
        / 10_000;
    let portal_deployment = if kind.charges_portal_deployment() {
        portal_deployment
    } else {
        0
    };
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
        let error = shield_net_amount(u128::MAX, u64::MAX, 0, 0, ShieldKind::Portal).unwrap_err();
        assert!(error.to_string().contains("overflow"));
    }

    #[test]
    fn shield_fee_addition_overflow_is_reported() {
        let error = shield_net_amount(u128::MAX, 0, u128::MAX, 1, ShieldKind::Portal).unwrap_err();
        assert!(error.to_string().contains("overflow"));
    }

    /// The stealth tag as the announcement carries it: the unpadded hex prefix `view_tag`
    /// derives, which is what the `u16` in an [`OwnedNote`] was parsed from.
    fn tag_hex(view_tag: u16) -> String {
        format!("{view_tag:x}")
    }

    #[test]
    fn a_sealed_note_keeps_its_stealth_secret_inside_the_field() -> Result<()> {
        let (k, v, big_k, big_v) = stealth::new_meta()
            .map_err(|error| anyhow::anyhow!("generate recipient fixture: {error}"))?;
        let recipient = crate::account::Account::from_meta_keys(&k, &v)?.identity();
        assert_eq!(
            (recipient.big_k.as_str(), recipient.big_v.as_str()),
            (big_k.as_str(), big_v.as_str())
        );
        let modulus = field_modulus();
        // Enough draws that an unconstrained send would almost surely have left the field.
        for _ in 0..12 {
            let note = seal_note(&recipient, Fr::from(5_u64), Fr::from(1_u64))?;
            let announced_r = format!(
                "{}.{}",
                curvy_core::field::fr_to_dec(&note.ephemeral_key.0),
                curvy_core::field::fr_to_dec(&note.ephemeral_key.1)
            );
            // The recipient scans exactly as the TypeScript SDK and the relayer do, and takes
            // the raw x coordinate as the cipher key.
            let matches = stealth::scan(&k, &v, &[announced_r], &[tag_hex(note.view_tag)])
                .map_err(|error| anyhow::anyhow!("scan: {error}"))?;
            let found = matches
                .first()
                .expect("the recipient discovers its own note");
            let raw = spending_pub_key_x(&found.spending_pub_key)?;
            assert!(raw < modulus, "the raw secret must lie in the field");
            assert_eq!(
                curvy_core::field::fr_to_biguint(&note.shared_secret),
                raw,
                "raw and field-reduced secrets must be the same value"
            );
        }
        Ok(())
    }

    #[test]
    fn an_in_field_send_never_returns_an_out_of_field_secret() -> Result<()> {
        let (_k, _v, big_k, big_v) = stealth::new_meta()
            .map_err(|error| anyhow::anyhow!("generate recipient fixture: {error}"))?;
        let modulus = field_modulus();
        for _ in 0..24 {
            let (x, out) = send_in_field(&big_k, &big_v)?;
            assert!(x < modulus);
            assert_eq!(x, spending_pub_key_x(&out.spending_pub_key)?);
        }
        Ok(())
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
