//! Public, implementation-independent contracts for Concord scientific work.
//!
//! This crate is the first executable boundary between the open Concord protocol and harness
//! layers and the closed product runtime. It must not depend on `concord-core`, product storage,
//! the desktop application, provider SDKs, or private services.

pub mod agent;
pub mod dispatch;
pub mod effects;
pub mod epact;
pub mod model;

pub use agent::*;
pub use dispatch::*;
pub use effects::*;
pub use epact::*;
pub use model::*;
