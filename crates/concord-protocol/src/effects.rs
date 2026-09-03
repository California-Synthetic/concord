use serde::{Deserialize, Serialize};

pub use epact_protocol::{EffectClass, EffectPolicyError, ReversibilityClass, ReversibilityPolicy};

/// The minimum operator approval cadence required for a capability invocation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    EveryCall,
    Session,
    Never,
}

/// A portable permission declaration. Credential values and product policy are deliberately not
/// part of this contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityPermission {
    /// Exact tool name or `*` for the package default.
    pub selector: String,
    pub effect: EffectClass,
    pub approval: ApprovalMode,
    #[serde(default)]
    pub data_classes: Vec<String>,
}
