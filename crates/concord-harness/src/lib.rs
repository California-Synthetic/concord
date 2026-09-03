//! Public, model-neutral harness mechanics for Concord scientific work.
//!
//! Provider credentials, network clients, persistence, and product authority remain outside this
//! crate. Adapters translate between provider envelopes and the canonical protocol contracts.

mod epact_runtime;
mod openai_compatible;
mod runtime;

pub use epact_compiler::{
    compile_program as compile_epact_program, require_activatable as require_epact_activatable,
    verify_amendment_record as verify_epact_amendment_record,
    verify_program_image as verify_epact_program_image,
    verify_program_successor as verify_epact_program_successor, EpactCompileError,
    EPACT_COMPILER_VERSION,
};
pub use epact_runtime::*;
pub use openai_compatible::*;
pub use runtime::*;
