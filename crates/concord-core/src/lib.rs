//! Integrated portable runtime for Concord scientific work.
//!
//! This crate composes public protocol, harness, Epact, authority, storage, artifact, review, and
//! supervision mechanisms. Product interfaces and provider transports consume this runtime; they
//! do not redefine its durable scientific state.

pub mod agent_progression;
pub mod agent_runtime;
pub mod artifacts;
pub mod campaign_supervision;
pub mod capability_packages;
pub mod epact;
pub mod execution_control;
pub mod model_harness;
pub mod models;
pub mod project_inputs;
mod public_runtime;
pub mod research_session;
pub mod science_artifacts;
pub mod source_gate;
pub mod standing_review;
pub mod store;

pub use agent_progression::*;
pub use agent_runtime::*;
pub use artifacts::ArtifactStore;
pub use campaign_supervision::*;
pub use capability_packages::*;
pub use concord_harness::{DispatchAllocation, DispatchAllocator, DispatchKernel};
pub use concord_protocol as protocol;
pub use concord_protocol::{EpactResourceEnvelope, KernelOperation};
pub use epact::*;
pub use execution_control::*;
pub use model_harness::*;
pub use models::*;
pub use project_inputs::*;
pub use research_session::*;
pub use science_artifacts::*;
pub use source_gate::*;
pub use standing_review::*;
pub use store::Database;
