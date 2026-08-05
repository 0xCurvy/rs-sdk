//! Durable state for [`CurvyDepositPool`](crate::CurvyDepositPool).
//!
//! Losing this state loses money. A note's `ownerHash` is
//! `poseidon(ownerPub, sharedSecret)` and the shared secret is chosen by the pool at
//! allocation time — it is never derivable from the deposit key HOPR later hands back.
//! So a pool that forgets its mapping cannot locate the notes it owes, and the funds sit
//! on-chain, provably unspent and permanently unreachable.
//!
//! Records are stored as decimal strings rather than raw field elements: the encoding is
//! then independent of the arkworks version and readable when something needs debugging
//! by hand.

use std::collections::HashMap;
use std::path::PathBuf;

use curvy_core::field::{Fr, fr_from_dec, fr_to_dec};
use curvy_sdk::OwnedNote;
use serde::{Deserialize, Serialize};

/// A note in its persisted form.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredNote {
    pub owner_pub: [String; 2],
    pub shared_secret: String,
    pub ephemeral_key: [String; 2],
    pub view_tag: u16,
    pub amount: String,
    pub token: String,
}

impl From<&OwnedNote> for StoredNote {
    fn from(note: &OwnedNote) -> Self {
        Self {
            owner_pub: [fr_to_dec(&note.owner_pub.0), fr_to_dec(&note.owner_pub.1)],
            shared_secret: fr_to_dec(&note.shared_secret),
            ephemeral_key: [
                fr_to_dec(&note.ephemeral_key.0),
                fr_to_dec(&note.ephemeral_key.1),
            ],
            view_tag: note.view_tag,
            amount: fr_to_dec(&note.amount),
            token: fr_to_dec(&note.token),
        }
    }
}

impl From<&StoredNote> for OwnedNote {
    fn from(stored: &StoredNote) -> Self {
        let pair = |v: &[String; 2]| -> (Fr, Fr) { (fr_from_dec(&v[0]), fr_from_dec(&v[1])) };
        OwnedNote {
            owner_pub: pair(&stored.owner_pub),
            shared_secret: fr_from_dec(&stored.shared_secret),
            ephemeral_key: pair(&stored.ephemeral_key),
            view_tag: stored.view_tag,
            amount: fr_from_dec(&stored.amount),
            token: fr_from_dec(&stored.token),
        }
    }
}

/// An allocation that was accepted but whose proof has not been submitted yet.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredAllocation {
    /// Compressed BabyJubJub deposit address, hex.
    pub address: String,
    /// The shared secret the pool picked for this allocation.
    pub shared_secret: String,
    pub amount: String,
}

/// Everything the pool must remember across a restart.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedState {
    /// Notes delivered to each deposit address, keyed by its compressed point in hex.
    pub deposits: HashMap<String, Vec<StoredNote>>,
    /// Committed notes the pool can spend.
    pub funding: Vec<StoredNote>,
    /// Accepted-but-unproved allocations, so an enqueued deposit is not silently lost
    /// when the process dies between accepting it and proving it.
    pub queue: Vec<StoredAllocation>,
    /// Notes that exist on-chain but whose commitment has not landed yet.
    #[serde(default)]
    pub uncommitted: Vec<StoredNote>,
}

/// Where a pool keeps its state.
///
/// A seam rather than a hard-coded file so a node can put this in whatever it already
/// trusts — an encrypted store, a database, a test's memory.
pub trait DepositStore: Send + Sync {
    fn load(&self) -> anyhow::Result<PersistedState>;
    fn save(&self, state: &PersistedState) -> anyhow::Result<()>;
}

/// Non-durable store for tests and throwaway runs.
#[derive(Default)]
pub struct MemoryStore(std::sync::Mutex<PersistedState>);

impl DepositStore for MemoryStore {
    fn load(&self) -> anyhow::Result<PersistedState> {
        Ok(self.0.lock().expect("memory store").clone())
    }

    fn save(&self, state: &PersistedState) -> anyhow::Result<()> {
        *self.0.lock().expect("memory store") = state.clone();
        Ok(())
    }
}

/// A JSON file, written atomically.
pub struct JsonFileStore {
    path: PathBuf,
}

impl JsonFileStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    fn temp_path(&self) -> PathBuf {
        let mut path = self.path.clone().into_os_string();
        path.push(".tmp");
        PathBuf::from(path)
    }
}

impl DepositStore for JsonFileStore {
    fn load(&self) -> anyhow::Result<PersistedState> {
        match std::fs::read(&self.path) {
            // A missing file is a first run, not a failure.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(PersistedState::default())
            }
            Err(error) => Err(error.into()),
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        }
    }

    fn save(&self, state: &PersistedState) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Write-then-rename: a crash mid-save must not leave a half-written file where
        // the shared secrets used to be. Rename is atomic on the same filesystem.
        let temp = self.temp_path();
        std::fs::write(&temp, serde_json::to_vec_pretty(state)?)?;
        std::fs::rename(&temp, &self.path)?;
        Ok(())
    }
}

/// Hex for a compressed deposit address, used as the persisted map key.
pub fn address_hex(compressed: &[u8; 32]) -> String {
    compressed.iter().fold(String::new(), |mut out, byte| {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// Inverse of [`address_hex`].
pub fn address_from_hex(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(hex.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(amount: u128) -> OwnedNote {
        OwnedNote {
            owner_pub: (Fr::from(11u64), Fr::from(12u64)),
            shared_secret: Fr::from(13u64),
            ephemeral_key: (Fr::from(14u64), Fr::from(15u64)),
            view_tag: 7,
            amount: curvy_core::field::fr_from_biguint(&amount.into()),
            token: Fr::from(1u64),
        }
    }

    #[test]
    fn a_note_survives_the_round_trip_exactly() {
        // Every field matters: a mangled shared secret silently orphans the note.
        let original = note(1_234_567_890_123_456_789);
        let restored: OwnedNote = (&StoredNote::from(&original)).into();
        assert_eq!(restored.owner_pub, original.owner_pub);
        assert_eq!(restored.shared_secret, original.shared_secret);
        assert_eq!(restored.ephemeral_key, original.ephemeral_key);
        assert_eq!(restored.view_tag, original.view_tag);
        assert_eq!(restored.amount, original.amount);
        assert_eq!(restored.token, original.token);
        assert_eq!(restored.note_id(), original.note_id());
    }

    #[test]
    fn address_hex_round_trips() {
        let mut address = [0u8; 32];
        address[0] = 0xde;
        address[31] = 0xff;
        let hex = address_hex(&address);
        assert_eq!(hex.len(), 64);
        assert_eq!(address_from_hex(&hex), Some(address));
        assert_eq!(address_from_hex("nothex"), None);
    }

    #[test]
    fn a_missing_file_reads_as_empty_rather_than_failing() {
        let dir = std::env::temp_dir().join("curvy-pool-store-missing");
        let _ = std::fs::remove_dir_all(&dir);
        let store = JsonFileStore::new(dir.join("state.json"));
        assert_eq!(store.load().unwrap(), PersistedState::default());
    }

    #[test]
    fn state_survives_a_save_and_reload() {
        let dir = std::env::temp_dir().join("curvy-pool-store-roundtrip");
        let _ = std::fs::remove_dir_all(&dir);
        let store = JsonFileStore::new(dir.join("nested/state.json"));

        let mut state = PersistedState::default();
        state
            .deposits
            .insert(address_hex(&[3u8; 32]), vec![StoredNote::from(&note(42))]);
        state.funding.push(StoredNote::from(&note(1_000)));
        store.save(&state).unwrap();

        assert_eq!(store.load().unwrap(), state);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
