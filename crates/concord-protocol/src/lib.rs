//! Public, implementation-independent contracts for Concord scientific work.
//!
//! This crate is the first executable boundary between the open Concord protocol and harness
//! layers and the closed product runtime. It must not depend on `concord-core`, product storage,
//! the desktop application, provider SDKs, or private services.

pub mod effects;

pub use effects::*;
