//! `hopr_api::chain::DepositPool` implementation over `CurvyClient`.

pub mod bjj;
pub mod pool;
pub mod store;

pub use pool::{CurvyDepositPool, CurvyDepositPoolConfig, CurvyPoolError};
pub use store::{DepositStore, JsonFileStore, MemoryStore, PersistedState};
