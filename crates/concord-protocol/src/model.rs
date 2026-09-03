use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MODEL_PROVIDER_CONTRACT: &str = "concord.model-provider/1";
pub const MODEL_REQUEST_CONTRACT: &str = "concord.model-execution-request/1";
pub const MODEL_RESPONSE_CONTRACT: &str = "concord.model-execution-response/1";
pub const MODEL_ROUTE_CONTRACT: &str = "concord.model-route/1";
pub const CONTEXT_COMPILATION_RECEIPT_CONTRACT: &str = "concord.context-compilation-receipt/1";
pub const CONTEXT_COMPILER_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextCompilationPolicy {
    pub recent_object_limit: u32,
    pub recent_action_limit: u32,
    pub history_message_limit: u32,
    pub program_character_limit: u32,
    pub history_message_character_limit: u32,
    pub lineage_traversal_limit: u32,
    pub retained_lineage_checkpoint_limit: u32,
    pub excluded_type_names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextOmission {
    pub source_ref: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextTruncation {
    pub source_ref: String,
    pub original_characters: u64,
    pub retained_characters: u64,
    pub reason: String,
}

/// A non-authoritative proof of the exact canonical material projected into one model request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextCompilationReceipt {
    pub contract: String,
    pub id: String,
    pub campaign_id: String,
    pub request_id: String,
    pub task_class: String,
    pub compiler_version: String,
    pub source_snapshot_sha256: String,
    pub policy: ContextCompilationPolicy,
    pub included_context_refs: Vec<String>,
    pub omissions: Vec<ContextOmission>,
    pub truncations: Vec<ContextTruncation>,
    pub compiled_message_count: u32,
    pub compiled_message_sha256: String,
    pub built_from_canonical_records: bool,
    pub recursive_summary_generation: u32,
    pub authoritative: bool,
    pub created_at: String,
    pub receipt_sha256: String,
}

impl ContextCompilationReceipt {
    pub fn seal(mut self) -> Result<Self, ModelContractError> {
        self.receipt_sha256.clear();
        self.validate_content()?;
        self.receipt_sha256 = self.recompute_sha256()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), ModelContractError> {
        self.validate_content()?;
        if self.receipt_sha256 != self.recompute_sha256()? {
            return Err(ModelContractError::ContextReceiptHashMismatch);
        }
        Ok(())
    }

    fn validate_content(&self) -> Result<(), ModelContractError> {
        if self.contract != CONTEXT_COMPILATION_RECEIPT_CONTRACT
            || self.compiler_version != CONTEXT_COMPILER_VERSION
        {
            return Err(ModelContractError::UnsupportedContextReceipt);
        }
        require_nonempty(&self.id, "receipt id")?;
        require_nonempty(&self.campaign_id, "campaign id")?;
        require_nonempty(&self.request_id, "request id")?;
        require_nonempty(&self.task_class, "task class")?;
        require_nonempty(&self.created_at, "creation time")?;
        if self.id != format!("context_receipt_{}", self.request_id) {
            return Err(ModelContractError::InvalidContextReceiptId);
        }
        if !is_sha256(&self.source_snapshot_sha256) {
            return Err(ModelContractError::InvalidSha256("source snapshot hash"));
        }
        if !is_sha256(&self.compiled_message_sha256) {
            return Err(ModelContractError::InvalidSha256("compiled message hash"));
        }
        if self.compiled_message_count == 0
            || self.policy.recent_object_limit == 0
            || self.policy.recent_action_limit == 0
            || self.policy.history_message_limit == 0
            || self.policy.program_character_limit == 0
            || self.policy.history_message_character_limit == 0
            || self.policy.lineage_traversal_limit == 0
            || self.policy.retained_lineage_checkpoint_limit == 0
        {
            return Err(ModelContractError::InvalidContextLimits);
        }
        ensure_unique_nonempty(&self.policy.excluded_type_names, "excluded context type")?;
        ensure_unique_nonempty(&self.included_context_refs, "included context reference")?;
        let included = self
            .included_context_refs
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let mut omitted = BTreeSet::new();
        for omission in &self.omissions {
            require_nonempty(&omission.source_ref, "omitted context reference")?;
            require_nonempty(&omission.reason, "context omission reason")?;
            if included.contains(omission.source_ref.as_str()) {
                return Err(ModelContractError::ContextIncludedAndOmitted(
                    omission.source_ref.clone(),
                ));
            }
            if !omitted.insert(omission.source_ref.as_str()) {
                return Err(ModelContractError::DuplicateValue {
                    label: "omitted context reference",
                    value: omission.source_ref.clone(),
                });
            }
        }
        let mut truncated = BTreeSet::new();
        for truncation in &self.truncations {
            if !included.contains(truncation.source_ref.as_str())
                || truncation.reason.trim().is_empty()
                || truncation.retained_characters >= truncation.original_characters
            {
                return Err(ModelContractError::InvalidContextTruncation(
                    truncation.source_ref.clone(),
                ));
            }
            if !truncated.insert(truncation.source_ref.as_str()) {
                return Err(ModelContractError::DuplicateValue {
                    label: "context truncation",
                    value: truncation.source_ref.clone(),
                });
            }
        }
        if !self.built_from_canonical_records
            || self.recursive_summary_generation != 0
            || self.authoritative
        {
            return Err(ModelContractError::ContextReceiptAuthorityViolation);
        }
        Ok(())
    }

    fn recompute_sha256(&self) -> Result<String, ModelContractError> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .ok_or(ModelContractError::ContextReceiptNotObject)?
            .remove("receiptSha256");
        Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(&value)?)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelTransport {
    OpenAiCompatible,
    TinkerNative,
    Deterministic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelLocality {
    Local,
    Remote,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelProviderSpec {
    pub contract: String,
    pub provider_id: String,
    pub transport: ModelTransport,
    pub locality: ModelLocality,
    pub base_url: Option<String>,
    pub model: String,
    pub secret_ref: Option<String>,
    #[serde(default)]
    pub advertised_capabilities: Vec<String>,
}

impl ModelProviderSpec {
    pub fn validate(&self) -> Result<(), ModelContractError> {
        if self.contract != MODEL_PROVIDER_CONTRACT {
            return Err(ModelContractError::UnsupportedContract {
                kind: "model provider",
                value: self.contract.clone(),
            });
        }
        require_nonempty(&self.provider_id, "provider id")?;
        require_nonempty(&self.model, "model")?;
        if self.transport == ModelTransport::OpenAiCompatible {
            let base_url = self
                .base_url
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or(ModelContractError::MissingNetworkBaseUrl)?;
            if !base_url.starts_with("http://") && !base_url.starts_with("https://") {
                return Err(ModelContractError::InvalidNetworkBaseUrl);
            }
        }
        if self.transport == ModelTransport::TinkerNative
            && self.model != "thinkingmachines/Inkling"
        {
            return Err(ModelContractError::UnsupportedTinkerModel);
        }
        if self.secret_ref.as_deref().is_some_and(|secret_ref| {
            !secret_ref.starts_with("env:") && !secret_ref.starts_with("keychain:")
        }) {
            return Err(ModelContractError::RawCredentialForbidden);
        }
        ensure_unique_nonempty(&self.advertised_capabilities, "advertised capability")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelRole {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelMessage {
    pub role: ModelRole,
    pub content: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub tool_call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ModelMessageToolCall>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelMessageToolCall {
    pub id: String,
    pub name: String,
    pub arguments: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelExecutionLimits {
    pub max_output_tokens: u64,
    pub max_tool_calls: u32,
    pub max_elapsed_seconds: u64,
    #[serde(default)]
    pub max_cost_usd: Option<f64>,
}

impl ModelExecutionLimits {
    pub fn validate(&self) -> Result<(), ModelContractError> {
        if self.max_output_tokens == 0 || self.max_elapsed_seconds == 0 {
            return Err(ModelContractError::InvalidExecutionLimits);
        }
        if self
            .max_cost_usd
            .is_some_and(|value| !value.is_finite() || value < 0.0)
        {
            return Err(ModelContractError::InvalidCostLimit);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelExecutionRequest {
    pub contract: String,
    pub request_id: String,
    pub campaign_id: String,
    pub task_class: String,
    pub messages: Vec<ModelMessage>,
    #[serde(default)]
    pub tools: Vec<ModelToolDefinition>,
    #[serde(default)]
    pub response_schema: Option<Value>,
    #[serde(default)]
    pub context_refs: Vec<String>,
    #[serde(default)]
    pub context_receipt_sha256: Option<String>,
    #[serde(default)]
    pub required_capabilities: Vec<String>,
    pub limits: ModelExecutionLimits,
}

impl ModelExecutionRequest {
    pub fn validate(&self) -> Result<(), ModelContractError> {
        if self.contract != MODEL_REQUEST_CONTRACT {
            return Err(ModelContractError::UnsupportedContract {
                kind: "model request",
                value: self.contract.clone(),
            });
        }
        require_nonempty(&self.request_id, "request id")?;
        require_nonempty(&self.campaign_id, "campaign id")?;
        require_nonempty(&self.task_class, "task class")?;
        if self.messages.is_empty() {
            return Err(ModelContractError::MissingMessages);
        }
        for message in &self.messages {
            if message.content.trim().is_empty()
                && !(message.role == ModelRole::Assistant && !message.tool_calls.is_empty())
            {
                return Err(ModelContractError::InvalidMessageContent);
            }
            if !message.tool_calls.is_empty() && message.role != ModelRole::Assistant {
                return Err(ModelContractError::ToolCallsRequireAssistant);
            }
            if message.role == ModelRole::Tool && message.tool_call_id.is_none() {
                return Err(ModelContractError::ToolMessageRequiresCallId);
            }
            if message.role != ModelRole::Tool && message.tool_call_id.is_some() {
                return Err(ModelContractError::CallIdRequiresToolMessage);
            }
            let mut call_ids = BTreeSet::new();
            for call in &message.tool_calls {
                require_nonempty(&call.id, "tool-call id")?;
                require_nonempty(&call.name, "tool-call name")?;
                if !call.arguments.is_object() {
                    return Err(ModelContractError::ToolArgumentsNotObject(call.id.clone()));
                }
                if !call_ids.insert(call.id.as_str()) {
                    return Err(ModelContractError::DuplicateValue {
                        label: "tool-call id",
                        value: call.id.clone(),
                    });
                }
            }
        }
        let tool_names = self
            .tools
            .iter()
            .map(|tool| tool.name.clone())
            .collect::<Vec<_>>();
        ensure_unique_nonempty(&tool_names, "tool")?;
        if !self.tools.is_empty() && self.limits.max_tool_calls == 0 {
            return Err(ModelContractError::ToolsRequireCallLimit);
        }
        for tool in &self.tools {
            require_nonempty(&tool.description, "tool description")?;
            if !tool.input_schema.is_object() {
                return Err(ModelContractError::ToolSchemaNotObject(tool.name.clone()));
            }
        }
        ensure_unique_nonempty(&self.context_refs, "context reference")?;
        if self
            .context_receipt_sha256
            .as_deref()
            .is_some_and(|value| !is_sha256(value))
        {
            return Err(ModelContractError::InvalidSha256("context receipt hash"));
        }
        ensure_unique_nonempty(&self.required_capabilities, "required capability")?;
        self.limits.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ModelOutputBlock {
    Text {
        text: String,
    },
    ToolCall {
        id: String,
        name: String,
        arguments: Value,
    },
    Citation {
        uri: String,
        title: Option<String>,
    },
    ArtifactRef {
        artifact_id: String,
        media_type: String,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelUsage {
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelExecutionResponse {
    pub contract: String,
    pub request_id: String,
    pub provider_id: String,
    pub model: String,
    pub output: Vec<ModelOutputBlock>,
    pub finish_reason: Option<String>,
    pub usage: ModelUsage,
}

impl ModelExecutionResponse {
    pub fn validate(&self) -> Result<(), ModelContractError> {
        if self.contract != MODEL_RESPONSE_CONTRACT {
            return Err(ModelContractError::UnsupportedContract {
                kind: "model response",
                value: self.contract.clone(),
            });
        }
        require_nonempty(&self.request_id, "request id")?;
        require_nonempty(&self.provider_id, "provider id")?;
        require_nonempty(&self.model, "model")?;
        if self.output.is_empty() {
            return Err(ModelContractError::MissingOutput);
        }
        for block in &self.output {
            match block {
                ModelOutputBlock::Text { text } => require_nonempty(text, "output text")?,
                ModelOutputBlock::ToolCall {
                    id,
                    name,
                    arguments,
                } => {
                    require_nonempty(id, "tool-call id")?;
                    require_nonempty(name, "tool-call name")?;
                    if !arguments.is_object() {
                        return Err(ModelContractError::ToolArgumentsNotObject(id.clone()));
                    }
                }
                ModelOutputBlock::Citation { uri, .. } => require_nonempty(uri, "citation URI")?,
                ModelOutputBlock::ArtifactRef {
                    artifact_id,
                    media_type,
                } => {
                    require_nonempty(artifact_id, "artifact id")?;
                    require_nonempty(media_type, "artifact media type")?;
                }
            }
        }
        if let (Some(input), Some(output), Some(total)) = (
            self.usage.input_tokens,
            self.usage.output_tokens,
            self.usage.total_tokens,
        ) {
            if input.saturating_add(output) != total {
                return Err(ModelContractError::InconsistentTokenUsage);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelRouteDecision {
    pub contract: String,
    pub request_id: String,
    pub provider_id: String,
    pub model: String,
    pub qualification_refs: Vec<String>,
    pub reasons: Vec<String>,
}

impl ModelRouteDecision {
    pub fn validate(&self) -> Result<(), ModelContractError> {
        if self.contract != MODEL_ROUTE_CONTRACT {
            return Err(ModelContractError::UnsupportedContract {
                kind: "model route",
                value: self.contract.clone(),
            });
        }
        require_nonempty(&self.request_id, "request id")?;
        require_nonempty(&self.provider_id, "provider id")?;
        require_nonempty(&self.model, "model")?;
        if self.qualification_refs.is_empty() || self.reasons.is_empty() {
            return Err(ModelContractError::MissingRouteEvidence);
        }
        ensure_unique_nonempty(&self.qualification_refs, "qualification reference")?;
        ensure_unique_nonempty(&self.reasons, "route reason")
    }
}

#[derive(Debug, Error)]
pub enum ModelContractError {
    #[error("unsupported {kind} contract {value}")]
    UnsupportedContract { kind: &'static str, value: String },
    #[error("{0} is required")]
    MissingValue(&'static str),
    #[error("duplicate {label} {value}")]
    DuplicateValue { label: &'static str, value: String },
    #[error("network model provider requires a base URL")]
    MissingNetworkBaseUrl,
    #[error("model provider base URL must use http or https")]
    InvalidNetworkBaseUrl,
    #[error("Tinker native v0.1 supports only thinkingmachines/Inkling")]
    UnsupportedTinkerModel,
    #[error("credentials must use an env: or keychain: reference")]
    RawCredentialForbidden,
    #[error("at least one message is required")]
    MissingMessages,
    #[error("messages require content unless an assistant message carries a tool call")]
    InvalidMessageContent,
    #[error("only assistant messages may carry tool calls")]
    ToolCallsRequireAssistant,
    #[error("tool messages require a tool-call id")]
    ToolMessageRequiresCallId,
    #[error("only tool messages may carry a tool-call id")]
    CallIdRequiresToolMessage,
    #[error("tool-call {0} arguments must be an object")]
    ToolArgumentsNotObject(String),
    #[error("tool {0} input schema must be an object")]
    ToolSchemaNotObject(String),
    #[error("requests with tools require a positive tool-call limit")]
    ToolsRequireCallLimit,
    #[error("output-token and elapsed-time limits must be positive")]
    InvalidExecutionLimits,
    #[error("cost limit must be finite and non-negative")]
    InvalidCostLimit,
    #[error("model response contains no normalized output")]
    MissingOutput,
    #[error("input and output token counts do not equal total token count")]
    InconsistentTokenUsage,
    #[error("route requires qualification evidence and a rationale")]
    MissingRouteEvidence,
    #[error("unsupported context compilation receipt")]
    UnsupportedContextReceipt,
    #[error("context receipt id must be derived from its request id")]
    InvalidContextReceiptId,
    #[error("context {0} is invalid")]
    InvalidSha256(&'static str),
    #[error("context compilation limits and message count must be positive")]
    InvalidContextLimits,
    #[error("context source cannot be both included and omitted: {0}")]
    ContextIncludedAndOmitted(String),
    #[error("context truncation is invalid: {0}")]
    InvalidContextTruncation(String),
    #[error("context receipt must remain a non-authoritative canonical projection")]
    ContextReceiptAuthorityViolation,
    #[error("context compilation receipt hash mismatch")]
    ContextReceiptHashMismatch,
    #[error("context receipt must serialize as an object")]
    ContextReceiptNotObject,
    #[error("model contract serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn require_nonempty(value: &str, label: &'static str) -> Result<(), ModelContractError> {
    if value.trim().is_empty() {
        Err(ModelContractError::MissingValue(label))
    } else {
        Ok(())
    }
}

fn ensure_unique_nonempty(
    values: &[String],
    label: &'static str,
) -> Result<(), ModelContractError> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_nonempty(value, label)?;
        let normalized = value.trim();
        if !seen.insert(normalized) {
            return Err(ModelContractError::DuplicateValue {
                label,
                value: normalized.to_owned(),
            });
        }
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
