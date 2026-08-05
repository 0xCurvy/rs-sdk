//! Curvy accounts and the note model.
//!
//! An account carries the dual-curve stealth meta-keys `(k, v, K, V)` - secp256k1
//! spend + BN254 view - **and** a BabyJubJub note-owner key. Per the TS SDK
//! (`getBabyJubjubPublicKey`), the note-owner key is NOT per-note: its private key IS
//! the spend key `k`, and the public key is `derivePublicKey(k)`. Per-note
//! unlinkability comes entirely from each note's `sharedSecret` (the stealth ECDH
//! x-coordinate), mixed into `ownerHash`.

use anyhow::{Context, Result};
use curvy_core::eddsa::pub_from_private_key_hex;
use curvy_core::field::{Fr, fr_from_dec};
use curvy_core::stealth;
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

    /// Login from a raw EOA-style private key via a keccak KDF (the plan's
    /// "keccak-KDF from raw private keys" - a PoC stand-in for the TS SDK's exact
    /// signature-derived KDF; the shape, `get_meta(kdf(raw))`, is what matters).
    /// `k = keccak256(raw ‖ "curvy/spend/v1")`, `v = keccak256(raw ‖ "curvy/view/v1")`;
    /// `get_meta` reduces each into its curve's scalar field.
    pub fn from_raw_private_key(raw_hex: &str) -> Result<Self> {
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

/// Parse a stealth `"x.y"` point-string into a BabyJubJub/field pair (each reduced
/// mod the BN254 scalar field - lossless in practice for a real ephemeral `R`,
/// whose coordinates are `< r` with overwhelming probability).
pub fn parse_xy(s: &str) -> Result<(Fr, Fr)> {
    let (x, y) = s
        .split_once('.')
        .with_context(|| format!("point not \"x.y\": {s:?}"))?;
    Ok((fr_from_dec(x), fr_from_dec(y)))
}
