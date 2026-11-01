//! BackVault service library: vault-access, backup-cycle, scheduler-retention.
//!
//! The binary in `main.rs` is a thin shell over these modules so that integration
//! tests under `tests/` can drive the real code through injected transports, clocks,
//! sleepers, and environments.

pub mod cycle;
pub mod env;
pub mod logging;
pub mod scheduler;
pub mod vault;
