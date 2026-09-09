//! Client facade for deposits, aggregation, scanning, and withdrawal.
//!
//! Chain access and proving are supplied through adapter crates.

pub mod account;
pub mod client;
pub mod scan;
pub mod send;

pub use account::{Account, Identity, OwnedNote, ScanRecipient, Viewer, ViewerIdentity};
pub use client::{
    AmbiguousPixAggregation, AmbiguousSubmission, CurvyClient, PixAggregationResult,
    PreparedDeposit, PreparedDirectShield, Route, TxLedger, ambiguous_pix_aggregation,
    ambiguous_submission,
};
pub use send::ShieldKind;
pub use curvy_types::{PendingNote, PendingNotesEvent};
pub use scan::{Discovered, scan_pending_event, scan_pending_note, scan_pending_note_with_viewer};

/// Re-export the shared field and cryptography types.
pub use curvy_core;

/// Re-export proving artifact configuration.
pub use curvy_witnesscalc;
