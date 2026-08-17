//! Pure pending-note ownership detection.
//!
//! These functions operate on already-decoded note data. They require neither a
//! [`CurvyClient`](crate::CurvyClient) nor any chain/indexer/transaction trait.

use anyhow::{Context, Result};
use curvy_core::{
    cipher::decrypt_amount_token,
    field::{Fr, fr_to_biguint},
    note::{note_id, owner_hash},
    stealth,
};
use curvy_types::{PendingNote, PendingNotesEvent};

use crate::account::{
    Account, OwnedNote, Viewer, parse_fr_decimal, shared_secret_from_spending_pub_key,
};

/// A discovered note that passed ownership and note-ID integrity checks.
#[derive(Clone, Debug)]
pub struct Discovered {
    /// Recomputed identifier of `owned_note`, retained as a convenient lookup key.
    pub note_id: Fr,
    /// Complete private note material to persist until commitment and later spend.
    pub owned_note: OwnedNote,
    pub is_plaintext: bool,
}

impl Discovered {
    /// Consumes the discovery result and returns the spendable note material.
    pub fn into_owned_note(self) -> OwnedNote {
        self.owned_note
    }
}

impl std::ops::Deref for Discovered {
    type Target = OwnedNote;

    fn deref(&self) -> &Self::Target {
        &self.owned_note
    }
}

impl AsRef<OwnedNote> for Discovered {
    fn as_ref(&self) -> &OwnedNote {
        &self.owned_note
    }
}

impl From<Discovered> for OwnedNote {
    fn from(discovered: Discovered) -> Self {
        discovered.into_owned_note()
    }
}

/// Checks one already-decoded pending note for ownership by `account`.
///
/// This is the smallest scanning boundary: it performs no indexer query and does
/// not require a transaction-capable [`CurvyClient`](crate::CurvyClient). A stealth
/// tag match is returned only after the encrypted fields are decoded and the note
/// ID is recomputed successfully.
pub fn scan_pending_note(account: &Account, note: &PendingNote) -> Result<Option<Discovered>> {
    Ok(scan_pending_notes(account, std::slice::from_ref(note))?
        .into_iter()
        .next())
}

/// Checks one pending note using a scan-only Curvy capability and an independent
/// BabyJubJub note owner.
///
/// `viewer` can identify and decrypt the note but cannot sign a withdrawal.
/// Spending requires the private key corresponding to `owner_pub`, which PIX
/// reconstructs separately from SSA shares.
pub fn scan_pending_note_with_viewer(
    viewer: &Viewer,
    owner_pub: (Fr, Fr),
    note: &PendingNote,
) -> Result<Option<Discovered>> {
    Ok(
        scan_pending_notes_with_viewer(viewer, owner_pub, std::slice::from_ref(note))?
            .into_iter()
            .next(),
    )
}

/// Scans every note item contained in one contract event.
///
/// [`PendingNotesEvent`] uses parallel arrays and can contain more than one note,
/// so this batch-shaped API returns every owned note rather than silently choosing
/// the first. Malformed array lengths are rejected before any cryptography runs.
pub fn scan_pending_event(account: &Account, event: &PendingNotesEvent) -> Result<Vec<Discovered>> {
    scan_pending_notes(account, &event.notes()?)
}

pub(crate) fn scan_pending_events(
    account: &Account,
    events: &[PendingNotesEvent],
) -> Result<Vec<Discovered>> {
    let notes = events
        .iter()
        .map(PendingNotesEvent::notes)
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    scan_pending_notes(account, &notes)
}

fn scan_pending_notes(account: &Account, notes: &[PendingNote]) -> Result<Vec<Discovered>> {
    let matches = scan_matches(notes, |ephemeral_keys, scan_view_tags| {
        stealth::scan(&account.k, &account.v, ephemeral_keys, scan_view_tags)
            .map(|matches| {
                matches
                    .into_iter()
                    .map(|matched| (matched.index, matched.spending_pub_key))
                    .collect()
            })
            .map_err(|error| anyhow::anyhow!("stealth scan: {error}"))
    })?;
    discover_pending_notes(account.bjj_pub, notes, matches)
}

fn scan_pending_notes_with_viewer(
    viewer: &Viewer,
    owner_pub: (Fr, Fr),
    notes: &[PendingNote],
) -> Result<Vec<Discovered>> {
    let matches = scan_matches(notes, |ephemeral_keys, scan_view_tags| {
        stealth::viewer_scan(&viewer.v, &viewer.big_k, ephemeral_keys, scan_view_tags)
            .map(|matches| {
                matches
                    .into_iter()
                    .map(|matched| (matched.index, matched.spending_pub_key))
                    .collect()
            })
            .map_err(|error| anyhow::anyhow!("Curvy viewer scan: {error}"))
    })?;
    discover_pending_notes(owner_pub, notes, matches)
}

fn scan_matches(
    notes: &[PendingNote],
    scan: impl FnOnce(&[String], &[String]) -> Result<Vec<(u32, String)>>,
) -> Result<Vec<(u32, String)>> {
    let ephemeral_keys = notes
        .iter()
        .map(|note| format!("{}.{}", note.ephemeral_key[0], note.ephemeral_key[1]))
        .collect::<Vec<_>>();
    let view_tags = notes
        .iter()
        .map(|note| u16::try_from(note.view_tag).context("pending note view tag is outside uint16"))
        .collect::<Result<Vec<_>>>()?;
    let scan_view_tags = view_tags
        .iter()
        .map(|tag| format!("{tag:02x}"))
        .collect::<Vec<_>>();

    scan(&ephemeral_keys, &scan_view_tags)
}

fn discover_pending_notes(
    owner_pub: (Fr, Fr),
    notes: &[PendingNote],
    matches: Vec<(u32, String)>,
) -> Result<Vec<Discovered>> {
    let mut discovered = Vec::with_capacity(matches.len());
    for (matched_index, spending_pub_key) in matches {
        let index: usize = matched_index
            .try_into()
            .context("stealth match index overflow")?;
        let note = notes
            .get(index)
            .with_context(|| format!("stealth match index {index} is out of bounds"))?;
        let shared_secret = shared_secret_from_spending_pub_key(&spending_pub_key)
            .context("parse scanned shared-secret point")?;
        let ephemeral_key = (
            parse_fr_decimal(&note.ephemeral_key[0], "ephemeral key x")?,
            parse_fr_decimal(&note.ephemeral_key[1], "ephemeral key y")?,
        );

        let (amount, token) = if note.is_plaintext {
            (
                parse_fr_decimal(&note.amount, "plaintext note amount")?,
                parse_fr_decimal(&note.token, "plaintext note token")?,
            )
        } else {
            let shared_secret_bytes = fr_to_biguint(&shared_secret);
            let ephemeral_x = fr_to_biguint(&ephemeral_key.0);
            let ephemeral_y = fr_to_biguint(&ephemeral_key.1);
            decrypt_amount_token(
                parse_fr_decimal(&note.amount, "encrypted note amount")?,
                parse_fr_decimal(&note.token, "encrypted note token")?,
                &shared_secret_bytes,
                (&ephemeral_x, &ephemeral_y),
            )
        };

        // A view-tag match is only a cheap candidate filter. Recomputing the ID is
        // the integrity gate that prevents false positives and corrupted ciphertext
        // from becoming an owned note.
        let discovered_id = note_id(owner_hash(owner_pub, shared_secret), amount, token);
        if discovered_id == parse_fr_decimal(&note.note_id, "pending note id")? {
            discovered.push(Discovered {
                note_id: discovered_id,
                owned_note: OwnedNote {
                    owner_pub,
                    shared_secret,
                    ephemeral_key,
                    view_tag: u16::try_from(note.view_tag)
                        .context("pending note view tag is outside uint16")?,
                    amount,
                    token,
                },
                is_plaintext: note.is_plaintext,
            });
        }
    }
    Ok(discovered)
}

#[cfg(test)]
mod tests {
    use curvy_core::{
        cipher::encrypt_amount_token,
        field::{fr_to_biguint, fr_to_dec},
    };

    use super::*;
    use crate::send::{seal_note, seal_note_for_owner};

    fn account(byte: u8) -> Account {
        Account::from_poc_raw_private_key(&hex::encode([byte; 32])).expect("valid account fixture")
    }

    fn encrypted_pending_note(account: &Account, amount: u64, token: u64) -> PendingNote {
        let owned = seal_note(&account.identity(), Fr::from(amount), Fr::from(token))
            .expect("seal fixture note");
        let encrypted = encrypt_amount_token(
            owned.amount,
            owned.token,
            &fr_to_biguint(&owned.shared_secret),
            (
                &fr_to_biguint(&owned.ephemeral_key.0),
                &fr_to_biguint(&owned.ephemeral_key.1),
            ),
        );
        PendingNote {
            note_id: fr_to_dec(&owned.note_id()),
            ephemeral_key: [
                fr_to_dec(&owned.ephemeral_key.0),
                fr_to_dec(&owned.ephemeral_key.1),
            ],
            view_tag: owned.view_tag.into(),
            token: fr_to_dec(&encrypted.encrypted_token),
            amount: fr_to_dec(&encrypted.encrypted_amount),
            is_plaintext: false,
        }
    }

    fn event(notes: &[PendingNote]) -> PendingNotesEvent {
        PendingNotesEvent {
            note_ids: notes.iter().map(|note| note.note_id.clone()).collect(),
            ephemeral_keys: [
                notes
                    .iter()
                    .map(|note| note.ephemeral_key[0].clone())
                    .collect(),
                notes
                    .iter()
                    .map(|note| note.ephemeral_key[1].clone())
                    .collect(),
            ],
            view_tags: notes.iter().map(|note| note.view_tag).collect(),
            tokens: notes.iter().map(|note| note.token.clone()).collect(),
            amounts: notes.iter().map(|note| note.amount.clone()).collect(),
            is_plaintext: notes.iter().map(|note| note.is_plaintext).collect(),
            block_number: 1,
            tx_hash: "0xabc".into(),
        }
    }

    #[test]
    fn one_pending_note_can_be_scanned_without_a_client() -> Result<()> {
        let owner = account(1);
        let note = encrypted_pending_note(&owner, 42, 7);

        let discovered =
            scan_pending_note(&owner, &note)?.context("owner must discover its note")?;

        assert_eq!(
            discovered.note_id,
            parse_fr_decimal(&note.note_id, "fixture note id")?
        );
        assert_eq!(discovered.amount, Fr::from(42_u64));
        assert_eq!(discovered.token, Fr::from(7_u64));
        assert!(!discovered.is_plaintext);
        let owned_note = discovered.into_owned_note();
        assert_eq!(owned_note.owner_pub, owner.bjj_pub);
        assert_eq!(
            owned_note.note_id(),
            parse_fr_decimal(&note.note_id, "fixture note id")?
        );
        assert_eq!(owned_note.view_tag, u16::try_from(note.view_tag)?);
        assert_eq!(
            owned_note.ephemeral_key.0,
            parse_fr_decimal(&note.ephemeral_key[0], "fixture x")?
        );
        assert_eq!(
            owned_note.ephemeral_key.1,
            parse_fr_decimal(&note.ephemeral_key[1], "fixture y")?
        );
        assert!(scan_pending_note(&account(2), &note)?.is_none());
        Ok(())
    }

    #[test]
    fn a_view_tag_match_with_the_wrong_note_id_is_not_owned() -> Result<()> {
        let owner = account(3);
        let mut note = encrypted_pending_note(&owner, 12, 1);
        note.note_id = "0".into();

        assert!(scan_pending_note(&owner, &note)?.is_none());
        Ok(())
    }

    #[test]
    fn event_scanning_returns_all_owned_notes_and_rejects_bad_shapes() -> Result<()> {
        let owner = account(4);
        let other = account(5);
        let owner_note_a = encrypted_pending_note(&owner, 10, 1);
        let other_note = encrypted_pending_note(&other, 20, 1);
        let owner_note_b = encrypted_pending_note(&owner, 30, 1);
        let mut pending_event = event(&[owner_note_a, other_note, owner_note_b]);

        let discovered = scan_pending_event(&owner, &pending_event)?;
        assert_eq!(discovered.len(), 2);
        assert_eq!(discovered[0].amount, Fr::from(10_u64));
        assert_eq!(discovered[1].amount, Fr::from(30_u64));

        pending_event.tokens.pop();
        assert!(scan_pending_event(&owner, &pending_event).is_err());
        Ok(())
    }

    #[test]
    fn viewer_discovers_a_note_but_does_not_own_it() -> Result<()> {
        let (k, v, big_k, big_v) = stealth::new_meta()
            .map_err(|error| anyhow::anyhow!("generate viewer fixture: {error}"))?;
        let viewer = Viewer::new(v, big_k.clone())?;
        let viewer_identity = crate::account::ViewerIdentity::new(big_k, big_v)?;
        let owner = account(9);
        let owned = seal_note_for_owner(
            &viewer_identity,
            owner.bjj_pub,
            Fr::from(77_u64),
            Fr::from(3_u64),
        )?;
        let encrypted = encrypt_amount_token(
            owned.amount,
            owned.token,
            &fr_to_biguint(&owned.shared_secret),
            (
                &fr_to_biguint(&owned.ephemeral_key.0),
                &fr_to_biguint(&owned.ephemeral_key.1),
            ),
        );
        let note = PendingNote {
            note_id: fr_to_dec(&owned.note_id()),
            ephemeral_key: [
                fr_to_dec(&owned.ephemeral_key.0),
                fr_to_dec(&owned.ephemeral_key.1),
            ],
            view_tag: owned.view_tag.into(),
            token: fr_to_dec(&encrypted.encrypted_token),
            amount: fr_to_dec(&encrypted.encrypted_amount),
            is_plaintext: false,
        };

        let discovered = scan_pending_note_with_viewer(&viewer, owner.bjj_pub, &note)?
            .context("viewer must discover the SSA-owned note")?;

        assert_eq!(discovered.owner_pub, owner.bjj_pub);
        assert_eq!(discovered.amount, Fr::from(77_u64));
        assert_ne!(
            discovered.owner_pub,
            curvy_core::eddsa::pub_from_private_key_hex(&k),
            "the viewer must not become the note owner",
        );
        Ok(())
    }
}
