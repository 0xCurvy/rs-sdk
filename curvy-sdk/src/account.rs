//! Curvy accounts and the note model.
//!
//! Accounts contain stealth spend/view keys and a BabyJubJub note-owner key.

use anyhow::{Context, Result};
use curvy_core::eddsa::pub_from_private_key_hex;
use curvy_core::field::{Fr, fr_from_biguint, fr_to_biguint};
use curvy_core::stealth;
use num_bigint::BigUint;
use sha3::{Digest, Keccak256};

/// A full Curvy account (holds the private spend/view keys).
#[derive(Clone)]
pub struct Account {
    /// secp256k1 spend private key (hex) - also the BabyJubJub note-owner private key.
    pub k: String,
    /// BN254 view private key (hex).
    pub v: String,
    /// Public spend meta-key `S` as `"x.y"` (secp256k1).
    pub big_k: String,
    /// Public view meta-key `V` as `"x.y"` (BN254).
    pub big_v: String,
    /// BabyJubJub note-owner public key `(x, y)` = `derivePublicKey(k)`.
    pub bjj_pub: (Fr, Fr),
}

/// The PUBLIC identity a sender needs to seal a note to this account.
#[derive(Clone)]
pub struct Identity {
    pub big_k: String,
    pub big_v: String,
    pub bjj_pub: (Fr, Fr),
}

impl Account {
    /// From explicit stealth private keys `(k, v)` (hex). Derives the public meta-keys
    /// and the BabyJubJub owner key.
    pub fn from_meta_keys(k: &str, v: &str) -> Result<Self> {
        let (big_k, big_v) =
            stealth::get_meta(k, v).map_err(|e| anyhow::anyhow!("get_meta: {e}"))?;
        let bjj_pub = pub_from_private_key_hex(k);
        Ok(Self {
            k: k.to_string(),
            v: v.to_string(),
            big_k,
            big_v,
            bjj_pub,
        })
    }

    /// Derive an account from EVM signature components in decimal or hexadecimal.
    ///
    /// The spend key hashes `[s, r]`; the view key hashes `[r, s]`. Each digest is
    /// restricted to 252 bits.
    pub fn from_signature_components(r_decimal: &str, s_decimal: &str) -> Result<Self> {
        let r = parse_signature_component(r_decimal).context("parse EVM signature r")?;
        let s = parse_signature_component(s_decimal).context("parse EVM signature s")?;
        let hash_pair = |left: &BigUint, right: &BigUint| -> String {
            let mut preimage = even_length_bytes(left);
            preimage.extend(even_length_bytes(right));
            let digest = hex::encode(Keccak256::digest(preimage));
            format!("0{}", &digest[1..])
        };
        let spend = hash_pair(&s, &r);
        let view = hash_pair(&r, &s);
        let minimum = BigUint::from(10u8).pow(70);
        anyhow::ensure!(
            BigUint::parse_bytes(spend.as_bytes(), 16).is_some_and(|value| value >= minimum),
            "EVM signature derives a spend key below the validity bound"
        );
        anyhow::ensure!(
            BigUint::parse_bytes(view.as_bytes(), 16).is_some_and(|value| value >= minimum),
            "EVM signature derives a view key below the validity bound"
        );
        anyhow::ensure!(
            spend != view,
            "EVM signature derives identical spend and view keys"
        );
        Self::from_meta_keys(&spend, &view)
    }

    /// Derive an account using the legacy raw-key KDF.
    /// `k = keccak256(raw ‖ "curvy/spend/v1")`, `v = keccak256(raw ‖ "curvy/view/v1")`;
    /// `get_meta` reduces each into its curve's scalar field.
    pub fn from_poc_raw_private_key(raw_hex: &str) -> Result<Self> {
        let raw =
            hex::decode(raw_hex.trim_start_matches("0x")).context("decode raw private key")?;
        let derive = |label: &[u8]| -> String {
            let mut h = Keccak256::new();
            h.update(&raw);
            h.update(label);
            hex::encode(h.finalize())
        };
        Self::from_meta_keys(&derive(b"curvy/spend/v1"), &derive(b"curvy/view/v1"))
    }

    #[deprecated(note = "legacy raw-key derivation; use from_signature_components")]
    pub fn from_raw_private_key(raw_hex: &str) -> Result<Self> {
        Self::from_poc_raw_private_key(raw_hex)
    }

    pub fn identity(&self) -> Identity {
        Identity {
            big_k: self.big_k.clone(),
            big_v: self.big_v.clone(),
            bjj_pub: self.bjj_pub,
        }
    }

    /// The BabyJubJub owner pubkey as a `"x.y"`-free `[dec, dec]`.
    pub fn bjj_pub_dec(&self) -> [String; 2] {
        [
            curvy_core::field::fr_to_dec(&self.bjj_pub.0),
            curvy_core::field::fr_to_dec(&self.bjj_pub.1),
        ]
    }
}

/// Encode a bigint as minimal big-endian bytes.
fn even_length_bytes(value: &BigUint) -> Vec<u8> {
    let bytes = value.to_bytes_be();
    if bytes.is_empty() { vec![0] } else { bytes }
}

fn parse_signature_component(value: &str) -> Result<BigUint> {
    let (digits, radix) = value
        .strip_prefix("0x")
        .map_or((value, 10), |digits| (digits, 16));
    BigUint::parse_bytes(digits.as_bytes(), radix)
        .ok_or_else(|| anyhow::anyhow!("invalid signature component"))
}

/// Parse an external decimal field element without the panic-and-reduce behaviour of
/// `curvy_core::field::fr_from_dec`.
pub(crate) fn parse_fr_decimal(value: &str, name: &str) -> Result<Fr> {
    let parsed = BigUint::parse_bytes(value.as_bytes(), 10)
        .with_context(|| format!("{name} is not a non-negative decimal integer: {value:?}"))?;
    let field = fr_from_biguint(&parsed);
    anyhow::ensure!(
        fr_to_biguint(&field) == parsed,
        "{name} is outside the BN254 scalar field: {value}"
    );
    Ok(field)
}

/// A note this SDK owns/represents. Mirrors `curvy_core::witness::Note` but keeps
/// `view_tag` as the 16-bit on-chain integer and carries no proof.
#[derive(Clone, Debug)]
pub struct OwnedNote {
    pub owner_pub: (Fr, Fr),
    pub shared_secret: Fr,
    pub ephemeral_key: (Fr, Fr),
    pub view_tag: u16,
    pub amount: Fr,
    pub token: Fr,
}

impl OwnedNote {
    pub fn to_core(&self) -> curvy_core::witness::Note {
        curvy_core::witness::Note {
            amount: self.amount,
            token: self.token,
            owner_pub: self.owner_pub,
            shared_secret: self.shared_secret,
            ephemeral_key: self.ephemeral_key,
            view_tag: Fr::from(self.view_tag as u64),
        }
    }
    pub fn owner_hash(&self) -> Fr {
        curvy_core::note::owner_hash(self.owner_pub, self.shared_secret)
    }
    pub fn note_id(&self) -> Fr {
        curvy_core::note::note_id(self.owner_hash(), self.amount, self.token)
    }
    pub fn nullifier(&self) -> Fr {
        curvy_core::note::nullifier(self.shared_secret, self.owner_pub)
    }
}

/// Parse a stealth `"x.y"` point-string into a canonical BN254 field pair.
pub fn parse_xy(s: &str) -> Result<(Fr, Fr)> {
    let (x, y) = s
        .split_once('.')
        .with_context(|| format!("point not \"x.y\": {s:?}"))?;
    Ok((
        parse_fr_decimal(x, "point x")?,
        parse_fr_decimal(y, "point y")?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_components_match_the_typescript_sdk_fixture() {
        let account = Account::from_signature_components("1", "2").unwrap();
        assert_eq!(
            account.k,
            "014a3fe82a0219fcc31abd15617966a125f12b0fd3409105fc83b487a9d82de4"
        );
        assert_eq!(
            account.v,
            "02ae6da6b482f9b1b19b0b897c3fd43884180a1c5ee361e1107a1bc635649dda"
        );
    }

    #[test]
    fn signature_components_accept_viem_hex_values() {
        let account = Account::from_signature_components("0x01", "0x02").unwrap();
        assert_eq!(
            account.k,
            "014a3fe82a0219fcc31abd15617966a125f12b0fd3409105fc83b487a9d82de4"
        );
    }

    #[test]
    fn equal_signature_components_are_rejected() {
        let error = Account::from_signature_components("5", "5")
            .err()
            .expect("equal components must be rejected");
        assert!(error.to_string().contains("identical"));
    }

    #[test]
    fn external_field_values_are_checked_not_reduced_or_panicked() {
        let modulus = fr_to_biguint(&-Fr::from(1u64)) + 1u64;
        assert!(parse_fr_decimal("not-a-number", "fixture").is_err());
        assert!(parse_fr_decimal(&modulus.to_string(), "fixture").is_err());
        assert_eq!(
            parse_fr_decimal(&(&modulus - 1u64).to_string(), "fixture").unwrap(),
            -Fr::from(1u64)
        );
    }
}
