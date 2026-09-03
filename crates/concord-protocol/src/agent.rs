use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const AGENT_RUN_CONTRACT: &str = "concord.agent-run/1";
pub const AGENT_EVENT_CONTRACT: &str = "concord.agent-event/1";

/// A durable agent run is a proposal-producing process scoped to one frozen Epact obligation.
/// Effects and resources remain call-specific and are checked again at each kernel boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpactAgentBinding {
    pub program_image_sha256: String,
    pub obligation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
}

impl EpactAgentBinding {
    pub fn validate(&self) -> Result<(), AgentContractError> {
        if !is_epact_sha256(&self.program_image_sha256) {
            return Err(AgentContractError::InvalidEpactBinding);
        }
        require_nonempty(&self.obligation_id, "Epact obligation id")?;
        if self
            .capability_id
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(AgentContractError::InvalidEpactBinding);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRunStatus {
    Ready,
    AwaitingModel,
    AwaitingApproval,
    ReadyForTool,
    ExecutingTool,
    AwaitingReview,
    Interrupted,
    Completed,
    Failed,
    Cancelled,
}

impl AgentRunStatus {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentEventKind {
    RunCreated,
    ModelRequested,
    ModelResponded,
    ModelInterrupted,
    RetryAuthorized,
    ToolProposed,
    ToolApproved,
    ToolRejected,
    ToolStarted,
    ToolCompleted,
    ToolInterrupted,
    ReviewRequested,
    ReviewCompleted,
    Checkpointed,
    Forked,
    Completed,
    Failed,
    Cancelled,
}

impl AgentEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RunCreated => "run_created",
            Self::ModelRequested => "model_requested",
            Self::ModelResponded => "model_responded",
            Self::ModelInterrupted => "model_interrupted",
            Self::RetryAuthorized => "retry_authorized",
            Self::ToolProposed => "tool_proposed",
            Self::ToolApproved => "tool_approved",
            Self::ToolRejected => "tool_rejected",
            Self::ToolStarted => "tool_started",
            Self::ToolCompleted => "tool_completed",
            Self::ToolInterrupted => "tool_interrupted",
            Self::ReviewRequested => "review_requested",
            Self::ReviewCompleted => "review_completed",
            Self::Checkpointed => "checkpointed",
            Self::Forked => "forked",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn parse(value: &str) -> Result<Self, AgentContractError> {
        match value {
            "run_created" => Ok(Self::RunCreated),
            "model_requested" => Ok(Self::ModelRequested),
            "model_responded" => Ok(Self::ModelResponded),
            "model_interrupted" => Ok(Self::ModelInterrupted),
            "retry_authorized" => Ok(Self::RetryAuthorized),
            "tool_proposed" => Ok(Self::ToolProposed),
            "tool_approved" => Ok(Self::ToolApproved),
            "tool_rejected" => Ok(Self::ToolRejected),
            "tool_started" => Ok(Self::ToolStarted),
            "tool_completed" => Ok(Self::ToolCompleted),
            "tool_interrupted" => Ok(Self::ToolInterrupted),
            "review_requested" => Ok(Self::ReviewRequested),
            "review_completed" => Ok(Self::ReviewCompleted),
            "checkpointed" => Ok(Self::Checkpointed),
            "forked" => Ok(Self::Forked),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            other => Err(AgentContractError::UnknownEventKind(other.to_owned())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentBudget {
    pub max_model_calls: u32,
    pub max_tool_calls: u32,
    pub max_elapsed_seconds: u64,
    #[serde(default)]
    pub budget_id: Option<String>,
    #[serde(default)]
    pub max_cost_usd: Option<f64>,
}

impl Default for AgentBudget {
    fn default() -> Self {
        Self {
            max_model_calls: 8,
            max_tool_calls: 8,
            max_elapsed_seconds: 1_800,
            budget_id: None,
            max_cost_usd: Some(0.0),
        }
    }
}

impl AgentBudget {
    pub fn validate(&self) -> Result<(), AgentContractError> {
        if self.max_model_calls == 0 || self.max_elapsed_seconds == 0 {
            return Err(AgentContractError::InvalidBudgetLimits);
        }
        if self
            .max_cost_usd
            .is_some_and(|value| !value.is_finite() || value < 0.0)
        {
            return Err(AgentContractError::InvalidCostLimit);
        }
        if self
            .budget_id
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(AgentContractError::EmptyBudgetId);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentRun {
    pub contract: String,
    pub id: String,
    pub campaign_id: String,
    pub provider_id: String,
    pub model: String,
    pub task: String,
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    pub budget: AgentBudget,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epact: Option<EpactAgentBinding>,
    pub status: AgentRunStatus,
    pub revision: u64,
    pub model_calls: u32,
    pub tool_calls: u32,
    #[serde(default)]
    pub parent_run_id: Option<String>,
    #[serde(default)]
    pub parent_event_hash: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl AgentRun {
    pub fn validate(&self) -> Result<(), AgentContractError> {
        if self.contract != AGENT_RUN_CONTRACT {
            return Err(AgentContractError::UnsupportedRunContract(
                self.contract.clone(),
            ));
        }
        for (value, label) in [
            (&self.id, "run id"),
            (&self.campaign_id, "campaign id"),
            (&self.provider_id, "provider id"),
            (&self.model, "model"),
            (&self.task, "task"),
            (&self.created_at, "creation time"),
            (&self.updated_at, "update time"),
        ] {
            require_nonempty(value, label)?;
        }
        if self.task.chars().count() > 32_000 {
            return Err(AgentContractError::TaskTooLong);
        }
        ensure_unique_tools(&self.allowed_tools)?;
        self.budget.validate()?;
        if let Some(binding) = &self.epact {
            binding.validate()?;
        }
        if self.model_calls > self.budget.max_model_calls
            || self.tool_calls > self.budget.max_tool_calls
        {
            return Err(AgentContractError::BudgetCounterExceeded);
        }
        if self.parent_run_id.is_some() != self.parent_event_hash.is_some() {
            return Err(AgentContractError::IncompleteParentLink);
        }
        if self
            .parent_event_hash
            .as_deref()
            .is_some_and(|value| !is_sha256(value))
        {
            return Err(AgentContractError::InvalidEventHash);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAgentRunRequest {
    pub campaign_id: String,
    pub provider_id: String,
    #[serde(default)]
    pub model: Option<String>,
    pub task: String,
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    #[serde(default)]
    pub budget: AgentBudget,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epact: Option<EpactAgentBinding>,
    #[serde(default)]
    pub parent_run_id: Option<String>,
    #[serde(default)]
    pub parent_event_hash: Option<String>,
}

impl CreateAgentRunRequest {
    pub fn validate(&self) -> Result<(), AgentContractError> {
        require_nonempty(&self.campaign_id, "campaign id")?;
        require_nonempty(&self.provider_id, "provider id")?;
        require_nonempty(&self.task, "task")?;
        if self
            .model
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(AgentContractError::MissingValue("model"));
        }
        if self.task.chars().count() > 32_000 {
            return Err(AgentContractError::TaskTooLong);
        }
        ensure_unique_tools(&self.allowed_tools)?;
        self.budget.validate()?;
        if let Some(binding) = &self.epact {
            binding.validate()?;
        }
        if self.parent_run_id.is_some() != self.parent_event_hash.is_some() {
            return Err(AgentContractError::IncompleteParentLink);
        }
        if self
            .parent_event_hash
            .as_deref()
            .is_some_and(|value| !is_sha256(value))
        {
            return Err(AgentContractError::InvalidEventHash);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentEvent {
    pub contract: String,
    pub id: String,
    pub agent_run_id: String,
    pub sequence: u64,
    pub idempotency_key: String,
    pub kind: AgentEventKind,
    pub from_status: AgentRunStatus,
    pub to_status: AgentRunStatus,
    pub payload: Value,
    #[serde(default)]
    pub previous_event_sha256: Option<String>,
    pub event_sha256: String,
    pub created_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AgentEventHashInput<'a> {
    contract: &'a str,
    id: &'a str,
    agent_run_id: &'a str,
    sequence: u64,
    idempotency_key: &'a str,
    kind: AgentEventKind,
    from_status: AgentRunStatus,
    to_status: AgentRunStatus,
    payload: &'a Value,
    previous_event_sha256: &'a Option<String>,
    created_at: &'a str,
}

impl AgentEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        id: String,
        agent_run_id: String,
        sequence: u64,
        idempotency_key: String,
        kind: AgentEventKind,
        from_status: AgentRunStatus,
        payload: Value,
        previous_event_sha256: Option<String>,
        created_at: String,
    ) -> Result<Self, AgentContractError> {
        require_nonempty(&id, "event id")?;
        require_nonempty(&agent_run_id, "agent run id")?;
        require_nonempty(&idempotency_key, "agent event idempotency key")?;
        require_nonempty(&created_at, "creation time")?;
        if previous_event_sha256
            .as_deref()
            .is_some_and(|value| !is_sha256(value))
        {
            return Err(AgentContractError::InvalidEventHash);
        }
        let to_status = transition(from_status, kind)?;
        let mut event = Self {
            contract: AGENT_EVENT_CONTRACT.to_owned(),
            id,
            agent_run_id,
            sequence,
            idempotency_key,
            kind,
            from_status,
            to_status,
            payload,
            previous_event_sha256,
            event_sha256: String::new(),
            created_at,
        };
        event.event_sha256 = event.expected_sha256()?;
        Ok(event)
    }

    pub fn validate(&self) -> Result<(), AgentContractError> {
        if self.contract != AGENT_EVENT_CONTRACT {
            return Err(AgentContractError::UnsupportedEventContract(
                self.contract.clone(),
            ));
        }
        require_nonempty(&self.id, "event id")?;
        require_nonempty(&self.agent_run_id, "agent run id")?;
        require_nonempty(&self.idempotency_key, "agent event idempotency key")?;
        require_nonempty(&self.created_at, "creation time")?;
        if self.to_status != transition(self.from_status, self.kind)? {
            return Err(AgentContractError::RecordedTransitionMismatch);
        }
        if self.event_sha256 != self.expected_sha256()? {
            return Err(AgentContractError::EventHashMismatch);
        }
        Ok(())
    }

    fn expected_sha256(&self) -> Result<String, AgentContractError> {
        let input = AgentEventHashInput {
            contract: &self.contract,
            id: &self.id,
            agent_run_id: &self.agent_run_id,
            sequence: self.sequence,
            idempotency_key: &self.idempotency_key,
            kind: self.kind,
            from_status: self.from_status,
            to_status: self.to_status,
            payload: &self.payload,
            previous_event_sha256: &self.previous_event_sha256,
            created_at: &self.created_at,
        };
        Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(&input)?)))
    }
}

pub fn transition(
    status: AgentRunStatus,
    event: AgentEventKind,
) -> Result<AgentRunStatus, AgentContractError> {
    use AgentEventKind as E;
    use AgentRunStatus as S;
    if status.is_terminal() {
        return Err(AgentContractError::TerminalTransition { status, event });
    }
    match (status, event) {
        (S::Ready, E::RunCreated | E::Checkpointed | E::Forked) => Ok(S::Ready),
        (S::Ready, E::ModelRequested) => Ok(S::AwaitingModel),
        (S::AwaitingModel, E::ModelResponded) => Ok(S::Ready),
        (S::AwaitingModel, E::ModelInterrupted) => Ok(S::Interrupted),
        (S::AwaitingModel | S::Interrupted, E::RetryAuthorized) => Ok(S::Ready),
        (S::Ready, E::ToolProposed) => Ok(S::AwaitingApproval),
        (S::AwaitingApproval, E::ToolApproved) => Ok(S::ReadyForTool),
        (S::AwaitingApproval, E::ToolRejected) => Ok(S::Ready),
        (S::ReadyForTool, E::ToolStarted) => Ok(S::ExecutingTool),
        (S::ExecutingTool, E::RetryAuthorized) => Ok(S::ReadyForTool),
        (S::ExecutingTool, E::ToolCompleted) => Ok(S::Ready),
        (S::ExecutingTool, E::ToolInterrupted) => Ok(S::Interrupted),
        (S::Ready, E::ReviewRequested) => Ok(S::AwaitingReview),
        (S::AwaitingReview, E::ReviewCompleted) => Ok(S::Ready),
        (current, E::Checkpointed | E::Forked) => Ok(current),
        (S::Ready, E::Completed) => Ok(S::Completed),
        (_, E::Failed) => Ok(S::Failed),
        (_, E::Cancelled) => Ok(S::Cancelled),
        _ => Err(AgentContractError::InvalidTransition { status, event }),
    }
}

/// Verify event identity, status transitions, ordering, and the complete previous-hash chain.
pub fn verify_agent_event_chain(
    agent_run_id: &str,
    events: &[AgentEvent],
) -> Result<AgentRunStatus, AgentContractError> {
    require_nonempty(agent_run_id, "agent run id")?;
    if events.is_empty() {
        return Err(AgentContractError::EmptyEventChain);
    }
    let mut prior_hash: Option<&str> = None;
    let mut prior_status: Option<AgentRunStatus> = None;
    for (expected_sequence, event) in events.iter().enumerate() {
        event.validate()?;
        if event.agent_run_id != agent_run_id {
            return Err(AgentContractError::RunIdentityMismatch);
        }
        if event.sequence != expected_sequence as u64 {
            return Err(AgentContractError::SequenceMismatch {
                expected: expected_sequence as u64,
                actual: event.sequence,
            });
        }
        if event.previous_event_sha256.as_deref() != prior_hash {
            return Err(AgentContractError::PreviousHashMismatch(event.sequence));
        }
        if prior_status.is_some_and(|status| status != event.from_status) {
            return Err(AgentContractError::StatusChainMismatch(event.sequence));
        }
        prior_hash = Some(&event.event_sha256);
        prior_status = Some(event.to_status);
    }
    Ok(prior_status.expect("non-empty event chain has a terminal status"))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentRunEnvelope {
    pub run: AgentRun,
    pub events: Vec<AgentEvent>,
}

impl AgentRunEnvelope {
    pub fn verify(&self) -> Result<(), AgentContractError> {
        self.run.validate()?;
        let observed = verify_agent_event_chain(&self.run.id, &self.events)?;
        if observed != self.run.status {
            return Err(AgentContractError::EnvelopeStatusMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum AgentContractError {
    #[error("unknown agent event kind {0}")]
    UnknownEventKind(String),
    #[error("unsupported agent run contract {0}")]
    UnsupportedRunContract(String),
    #[error("unsupported agent event contract {0}")]
    UnsupportedEventContract(String),
    #[error("{0} is required")]
    MissingValue(&'static str),
    #[error("agent task exceeds 32000 characters")]
    TaskTooLong,
    #[error("agent tools must be non-empty and unique")]
    InvalidTools,
    #[error("agent model-call and elapsed-time limits must be positive")]
    InvalidBudgetLimits,
    #[error("agent cost limit must be finite and non-negative")]
    InvalidCostLimit,
    #[error("agent budget id cannot be empty")]
    EmptyBudgetId,
    #[error("agent counters exceed the declared budget")]
    BudgetCounterExceeded,
    #[error("agent parent run id and event hash must be declared together")]
    IncompleteParentLink,
    #[error("agent event hash is not a SHA-256 digest")]
    InvalidEventHash,
    #[error("agent Epact binding is invalid")]
    InvalidEpactBinding,
    #[error("terminal agent run {status:?} cannot accept {event:?}")]
    TerminalTransition {
        status: AgentRunStatus,
        event: AgentEventKind,
    },
    #[error("invalid agent transition from {status:?} via {event:?}")]
    InvalidTransition {
        status: AgentRunStatus,
        event: AgentEventKind,
    },
    #[error("recorded agent transition does not match the state machine")]
    RecordedTransitionMismatch,
    #[error("agent event digest mismatch")]
    EventHashMismatch,
    #[error("agent event chain cannot be empty")]
    EmptyEventChain,
    #[error("agent event belongs to a different run")]
    RunIdentityMismatch,
    #[error("agent event sequence mismatch: expected {expected}, found {actual}")]
    SequenceMismatch { expected: u64, actual: u64 },
    #[error("agent event {0} does not reference the preceding digest")]
    PreviousHashMismatch(u64),
    #[error("agent event {0} does not continue the preceding status")]
    StatusChainMismatch(u64),
    #[error("agent envelope status does not equal its verified event status")]
    EnvelopeStatusMismatch,
    #[error("agent contract serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn require_nonempty(value: &str, label: &'static str) -> Result<(), AgentContractError> {
    if value.trim().is_empty() {
        Err(AgentContractError::MissingValue(label))
    } else {
        Ok(())
    }
}

fn ensure_unique_tools(tools: &[String]) -> Result<(), AgentContractError> {
    let mut seen = BTreeSet::new();
    for tool in tools {
        if tool.trim().is_empty() || !seen.insert(tool.trim()) {
            return Err(AgentContractError::InvalidTools);
        }
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_epact_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
