//! Public, model-neutral harness mechanics for Concord scientific work.
//!
//! Provider credentials, network clients, persistence, and product authority remain outside this
//! crate. Adapters translate between provider envelopes and the canonical protocol contracts.

mod openai_compatible;

pub use openai_compatible::*;
