//! Durable deposit-pool state using decimal field encodings.

use std::collections::HashMap;
use std::path::PathBuf;

use curvy_core::field::{Fr, fr_to_biguint, fr_to_dec};
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

/// Parse a canonical persisted field element.
pub fn fr_from_dec_checked(value: &str) -> Option<Fr> {
    let parsed = value.parse::<num_bigint::BigUint>().ok()?;
    let element = curvy_core::field::fr_from_biguint(&parsed);
    (curvy_core::field::fr_to_biguint(&element) == parsed).then_some(element)
}

/// A persisted record that does not decode.
#[derive(Debug, thiserror::Error)]
#[error("corrupt persisted state: {field} is not a canonical field element ({value:?})")]
pub struct CorruptRecord {
    pub field: &'static str,
    pub value: String,
}

fn field(value: &str, name: &'static str) -> Result<Fr, CorruptRecord> {
    fr_from_dec_checked(value).ok_or_else(|| CorruptRecord {
        field: name,
        value: value.to_owned(),
    })
}

impl TryFrom<&StoredNote> for OwnedNote {
    type Error = CorruptRecord;

    fn try_from(stored: &StoredNote) -> Result<Self, Self::Error> {
        let amount = field(&stored.amount, "amount")?;
        let amount_fits: std::result::Result<u128, _> = fr_to_biguint(&amount).try_into();
        if amount_fits.is_err() {
            return Err(CorruptRecord {
                field: "amount (u128)",
                value: stored.amount.clone(),
            });
        }
        Ok(OwnedNote {
            owner_pub: (
                field(&stored.owner_pub[0], "owner_pub.x")?,
                field(&stored.owner_pub[1], "owner_pub.y")?,
            ),
            shared_secret: field(&stored.shared_secret, "shared_secret")?,
            ephemeral_key: (
                field(&stored.ephemeral_key[0], "ephemeral_key.x")?,
                field(&stored.ephemeral_key[1], "ephemeral_key.y")?,
            ),
            view_tag: stored.view_tag,
            amount,
            token: field(&stored.token, "token")?,
        })
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

/// Reservation for an aggregation with an unknown outcome.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredInFlight {
    pub batch: Vec<StoredAllocation>,
    pub funding: StoredNote,
    /// Exact random outputs, once transaction submission became ambiguous.
    #[serde(default)]
    pub outputs: Option<StoredAggregationOutputs>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredAggregationOutputs {
    pub allocations: Vec<StoredNote>,
    pub change: StoredNote,
    /// Circuit outputs in on-chain order.
    #[serde(default)]
    pub emitted_notes: Vec<StoredNote>,
}

/// Durable stage of the pool's two-transaction shield operation.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StoredShieldStage {
    /// The note/portal is fixed, but funding has not been confirmed.
    Prepared,
    /// Portal funding is confirmed; deploy-and-shield may be resumed safely.
    Funded,
}

/// Recovery handle for a pool-funding shield.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredShield {
    pub note: StoredNote,
    pub gross: String,
    pub recovery: String,
    pub portal_address: String,
    pub stage: StoredShieldStage,
}

/// Everything the pool must remember across a restart.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedState {
    /// Notes delivered to each deposit address, keyed by its compressed point in hex.
    pub deposits: HashMap<String, Vec<StoredNote>>,
    /// Committed notes the pool can spend.
    pub funding: Vec<StoredNote>,
    /// Accepted allocations awaiting a proof.
    pub queue: Vec<StoredAllocation>,
    /// Notes that exist on-chain but whose commitment has not landed yet.
    #[serde(default)]
    pub uncommitted: Vec<StoredNote>,
    /// Aggregation reservation awaiting reconciliation.
    #[serde(default)]
    pub in_flight: Option<StoredInFlight>,
    /// A shield whose random note was fixed before its portal was funded.
    #[serde(default)]
    pub shield_in_flight: Option<StoredShield>,
    /// Notes reserved for a commitment whose submission outcome is unresolved.
    #[serde(default)]
    pub commitment_in_flight: Vec<StoredNote>,
    /// Notes reserved for a withdrawal whose submission outcome is unresolved.
    #[serde(default)]
    pub withdrawal_in_flight: Vec<StoredNote>,
}

/// Deposit-pool persistence interface.
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
        // Rename the complete temporary file atomically.
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
        let original = note(1_234_567_890_123_456_789);
        let restored = OwnedNote::try_from(&StoredNote::from(&original)).expect("round trip");
        assert_eq!(restored.owner_pub, original.owner_pub);
        assert_eq!(restored.shared_secret, original.shared_secret);
        assert_eq!(restored.ephemeral_key, original.ephemeral_key);
        assert_eq!(restored.view_tag, original.view_tag);
        assert_eq!(restored.amount, original.amount);
        assert_eq!(restored.token, original.token);
        assert_eq!(restored.note_id(), original.note_id());
    }

    /// Out-of-range field values are rejected.
    #[test]
    fn an_out_of_range_value_is_rejected_rather_than_reduced() {
        let modulus = curvy_core::field::fr_to_biguint(&-Fr::from(1u64)) + 1u64;
        let past_the_end = (&modulus + 5u64).to_string();

        assert!(
            fr_from_dec_checked(&past_the_end).is_none(),
            "modulus + 5 must be refused, not silently read back as 5"
        );
        assert!(fr_from_dec_checked(&modulus.to_string()).is_none());
        assert_eq!(
            fr_from_dec_checked(&(&modulus - 1u64).to_string()),
            Some(-Fr::from(1u64)),
            "the largest canonical value is still valid"
        );
    }

    #[test]
    fn a_non_numeric_value_is_refused_rather_than_panicking() {
        assert!(fr_from_dec_checked("not a number").is_none());
        assert!(fr_from_dec_checked("").is_none());
        assert!(
            fr_from_dec_checked("-1").is_none(),
            "signs are not canonical"
        );
        assert_eq!(fr_from_dec_checked("0"), Some(Fr::from(0u64)));
    }

    #[test]
    fn a_canonical_amount_outside_the_pool_value_range_is_rejected() {
        let mut stored = StoredNote::from(&note(1));
        stored.amount = (num_bigint::BigUint::from(u128::MAX) + 1u64).to_string();
        let error = OwnedNote::try_from(&stored).unwrap_err();
        assert_eq!(error.field, "amount (u128)");
    }

    /// Reservations survive serialization.
    #[test]
    fn a_reservation_survives_the_json_round_trip() {
        let state = PersistedState {
            in_flight: Some(StoredInFlight {
                batch: vec![StoredAllocation {
                    address: address_hex(&[7u8; 32]),
                    shared_secret: "12345".to_owned(),
                    amount: "999".to_owned(),
                }],
                funding: StoredNote::from(&note(4_000)),
                outputs: Some(StoredAggregationOutputs {
                    allocations: vec![StoredNote::from(&note(999))],
                    change: StoredNote::from(&note(3_001)),
                    emitted_notes: vec![
                        StoredNote::from(&note(999)),
                        StoredNote::from(&note(3_001)),
                        StoredNote::from(&note(17)),
                    ],
                }),
            }),
            commitment_in_flight: vec![StoredNote::from(&note(999))],
            withdrawal_in_flight: vec![StoredNote::from(&note(500))],
            ..PersistedState::default()
        };

        let encoded = serde_json::to_vec(&state).expect("encode");
        let decoded: PersistedState = serde_json::from_slice(&encoded).expect("decode");
        assert_eq!(decoded, state);
    }

    #[test]
    fn a_prepared_shield_survives_the_json_round_trip() {
        let state = PersistedState {
            shield_in_flight: Some(StoredShield {
                note: StoredNote::from(&note(4_000)),
                gross: "5000".to_string(),
                recovery: "0x0000000000000000000000000000000000000001".to_string(),
                portal_address: "0x0000000000000000000000000000000000000002".to_string(),
                stage: StoredShieldStage::Funded,
            }),
            ..PersistedState::default()
        };

        let encoded = serde_json::to_vec(&state).expect("encode");
        let decoded: PersistedState = serde_json::from_slice(&encoded).expect("decode");
        assert_eq!(decoded, state);
    }

    /// Missing optional fields use their defaults.
    #[test]
    fn state_without_a_reservation_field_still_loads() {
        let legacy = br#"{"deposits":{},"funding":[],"queue":[]}"#;
        let decoded: PersistedState = serde_json::from_slice(legacy).expect("decode legacy state");
        assert!(decoded.in_flight.is_none());
        assert!(decoded.uncommitted.is_empty());
        assert!(decoded.shield_in_flight.is_none());
        assert!(decoded.commitment_in_flight.is_empty());
        assert!(decoded.withdrawal_in_flight.is_empty());
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
