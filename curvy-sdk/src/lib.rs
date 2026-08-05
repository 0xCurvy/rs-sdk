//! The thin `CurvyClient` facade used by the PIX end-to-end test.
//!
//! It assembles chain-api trait objects with `curvy-abi`
//! calldata/signing and `curvy-witnesscalc` proving to run, entirely from Rust:
//! **shield → commit → aggregate → scan/withdraw**. All crypto is `curvy-core`; there is no
//! second implementation, and no direct alloy/blokli/reqwest dependency here - the
//! seam is reached only through the adapter crates.
//!
//! Deliberately out of scope: planner, relayer +
//! Privacy Pass, portals-recovery, Solana, and production at-rest allocation storage.

pub mod account;
pub mod client;
pub mod send;

pub use account::{Account, Identity, OwnedNote};
pub use client::{CurvyClient, Discovered, PixAggregationResult, Route, TxLedger};

/// Re-export `curvy-core` so consumers can name its `Fr`/field API
/// (the same crate instance whose `Fr` appears in [`OwnedNote`]/[`Discovered`]) without
/// declaring another direct dependency.
pub use curvy_core;

/// Re-export `curvy-witnesscalc` so consumers can pin-check the proving artifacts
/// (`Circuit::pix_flow()` / `Circuit::verify_artifacts()`) up front, without taking a
/// second direct dependency on the crate the client already proves through.
pub use curvy_witnesscalc;
