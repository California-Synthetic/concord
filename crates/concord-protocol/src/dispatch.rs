use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CAMPAIGN_DISPATCH_PERMIT_CONTRACT: &str = "concord.campaign-dispatch-permit/1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchOperation {
    ExecutionRun,
    AgentModelCall,
    ResearchPhase,
    ExternalJob,
}

impl DispatchOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExecutionRun => "execution_run",
            Self::AgentModelCall => "agent_model_call",
            Self::ResearchPhase => "research_phase",
            Self::ExternalJob => "external_job",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchPermitStatus {
    #[default]
    Authorized,
    Consumed,
    Settled,
    Interrupted,
    Released,
}

impl DispatchPermitStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authorized => "authorized",
            Self::Consumed => "consumed",
            Self::Settled => "settled",
            Self::Interrupted => "interrupted",
            Self::Released => "released",
        }
    }

    pub fn parse(value: &str) -> Result<Self, DispatchContractError> {
        match value {
            "authorized" => Ok(Self::Authorized),
            "consumed" => Ok(Self::Consumed),
            "settled" => Ok(Self::Settled),
            "interrupted" => Ok(Self::Interrupted),
            "released" => Ok(Self::Released),
            other => Err(DispatchContractError::UnknownPermitStatus(other.to_owned())),
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Released)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DispatchAccountingSummary {
    pub authorized: u64,
    pub consumed: u64,
    pub settled: u64,
    pub interrupted: u64,
    pub released: u64,
    pub reserved_usd: f64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DispatchReapSummary {
    pub released: u64,
    pub interrupted: u64,
}

/// Requests a bounded right to cross an external execution boundary.
///
/// Authorization and reservation are one atomic kernel operation. `reserve_budget` asks the
/// implementation to hold `maximum_cost_usd`; `budget_pre_reserved` binds authority to an existing
/// reservation. Neither flag proves that a provider started work.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizeCampaignDispatchRequest {
    pub generation: u64,
    pub idempotency_key: String,
    pub actor: String,
    pub operation: DispatchOperation,
    pub target_id: String,
    #[serde(default)]
    pub budget_id: Option<String>,
    #[serde(default)]
    pub maximum_cost_usd: f64,
    #[serde(default)]
    pub reserve_budget: bool,
    #[serde(default)]
    pub budget_pre_reserved: bool,
    pub maximum_elapsed_seconds: u64,
}

impl AuthorizeCampaignDispatchRequest {
    pub fn validate(&self) -> Result<(), DispatchContractError> {
        validate_text("idempotencyKey", &self.idempotency_key, 240)?;
        validate_text("actor", &self.actor, 160)?;
        validate_text("targetId", &self.target_id, 512)?;
        if let Some(budget_id) = &self.budget_id {
            validate_text("budgetId", budget_id, 160)?;
        }
        if !self.maximum_cost_usd.is_finite() || self.maximum_cost_usd < 0.0 {
            return Err(DispatchContractError::InvalidMaximumCost);
        }
        if self.maximum_cost_usd > 0.0 && self.budget_id.is_none() {
            return Err(DispatchContractError::PaidDispatchMissingBudget);
        }
        if self.reserve_budget && self.maximum_cost_usd <= 0.0 {
            return Err(DispatchContractError::ReservationMissingPositiveCost);
        }
        if self.reserve_budget && self.budget_pre_reserved {
            return Err(DispatchContractError::ConflictingReservationModes);
        }
        if self.budget_pre_reserved && self.budget_id.is_none() {
            return Err(DispatchContractError::PreReservationMissingBudget);
        }
        if !(5..=86_400).contains(&self.maximum_elapsed_seconds) {
            return Err(DispatchContractError::InvalidElapsedLimit);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CampaignDispatchPermit {
    pub contract: String,
    pub token: String,
    pub campaign_id: String,
    pub generation: u64,
    pub idempotency_key: String,
    pub actor: String,
    pub operation: DispatchOperation,
    pub target_id: String,
    #[serde(default)]
    pub budget_id: Option<String>,
    pub maximum_cost_usd: f64,
    #[serde(default)]
    pub reserve_budget: bool,
    #[serde(default)]
    pub budget_pre_reserved: bool,
    pub reconciliation_sha256: String,
    #[serde(default)]
    pub status: DispatchPermitStatus,
    pub issued_at: String,
    #[serde(default)]
    pub deadline_at: String,
    #[serde(default)]
    pub consumed_at: Option<String>,
    #[serde(default)]
    pub settled_at: Option<String>,
    #[serde(default)]
    pub actual_cost_usd: Option<f64>,
    #[serde(default)]
    pub settlement_basis: Option<String>,
    #[serde(default)]
    pub interruption: Option<String>,
    #[serde(default)]
    pub released_at: Option<String>,
    #[serde(default)]
    pub resolution_evidence_sha256: Option<String>,
    #[serde(default)]
    pub resolved_by: Option<String>,
}

impl CampaignDispatchPermit {
    pub fn validate(&self) -> Result<(), DispatchContractError> {
        if self.contract != CAMPAIGN_DISPATCH_PERMIT_CONTRACT {
            return Err(DispatchContractError::UnsupportedPermitContract(
                self.contract.clone(),
            ));
        }
        validate_text("token", &self.token, 512)?;
        validate_text("campaignId", &self.campaign_id, 512)?;
        validate_text("idempotencyKey", &self.idempotency_key, 240)?;
        validate_text("actor", &self.actor, 160)?;
        validate_text("targetId", &self.target_id, 512)?;
        validate_text("issuedAt", &self.issued_at, 160)?;
        validate_text("deadlineAt", &self.deadline_at, 160)?;
        validate_sha256("reconciliationSha256", &self.reconciliation_sha256)?;
        if !self.maximum_cost_usd.is_finite() || self.maximum_cost_usd < 0.0 {
            return Err(DispatchContractError::InvalidMaximumCost);
        }
        if self.reserve_budget && self.budget_pre_reserved {
            return Err(DispatchContractError::ConflictingReservationModes);
        }
        if self.maximum_cost_usd > 0.0 && self.budget_id.is_none() {
            return Err(DispatchContractError::PaidDispatchMissingBudget);
        }
        if self
            .actual_cost_usd
            .is_some_and(|cost| !cost.is_finite() || cost < 0.0)
        {
            return Err(DispatchContractError::InvalidActualCost);
        }
        match self.status {
            DispatchPermitStatus::Authorized => {
                if self.consumed_at.is_some()
                    || self.settled_at.is_some()
                    || self.released_at.is_some()
                {
                    return Err(DispatchContractError::InconsistentPermitState);
                }
            }
            DispatchPermitStatus::Consumed => {
                if self.consumed_at.is_none()
                    || self.settled_at.is_some()
                    || self.released_at.is_some()
                {
                    return Err(DispatchContractError::InconsistentPermitState);
                }
            }
            DispatchPermitStatus::Settled => {
                if self.consumed_at.is_none()
                    || self.settled_at.is_none()
                    || self.actual_cost_usd.is_none()
                    || self.released_at.is_some()
                {
                    return Err(DispatchContractError::InconsistentPermitState);
                }
            }
            DispatchPermitStatus::Interrupted => {
                if self.consumed_at.is_none()
                    || self.interruption.as_deref().is_none_or(str::is_empty)
                    || self.settled_at.is_some()
                    || self.released_at.is_some()
                {
                    return Err(DispatchContractError::InconsistentPermitState);
                }
            }
            DispatchPermitStatus::Released => {
                if self.released_at.is_none() || self.settled_at.is_some() {
                    return Err(DispatchContractError::InconsistentPermitState);
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterruptedDispatchResolution {
    NoProviderStart,
    ProviderSettled,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolveInterruptedDispatchRequest {
    pub actor: String,
    pub resolution: InterruptedDispatchResolution,
    pub evidence_sha256: String,
    #[serde(default)]
    pub actual_cost_usd: Option<f64>,
    #[serde(default)]
    pub settlement_basis: Option<String>,
}

impl ResolveInterruptedDispatchRequest {
    pub fn validate(&self) -> Result<(), DispatchContractError> {
        validate_text("actor", &self.actor, 160)?;
        validate_sha256("evidenceSha256", &self.evidence_sha256)?;
        match self.resolution {
            InterruptedDispatchResolution::NoProviderStart => {
                if self.actual_cost_usd.is_some() {
                    return Err(DispatchContractError::UnexpectedActualCost);
                }
            }
            InterruptedDispatchResolution::ProviderSettled => {
                if !self
                    .actual_cost_usd
                    .is_some_and(|cost| cost.is_finite() && cost >= 0.0)
                {
                    return Err(DispatchContractError::ProviderSettlementMissingCost);
                }
                validate_text(
                    "settlementBasis",
                    self.settlement_basis.as_deref().unwrap_or_default(),
                    240,
                )?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum DispatchContractError {
    #[error("unsupported dispatch permit contract {0}")]
    UnsupportedPermitContract(String),
    #[error("unknown dispatch permit status {0}")]
    UnknownPermitStatus(String),
    #[error("{field} must contain 1-{max_chars} characters")]
    InvalidText {
        field: &'static str,
        max_chars: usize,
    },
    #[error("{0} must be a lowercase SHA-256 digest")]
    InvalidSha256(&'static str),
    #[error("maximumCostUsd must be finite and non-negative")]
    InvalidMaximumCost,
    #[error("actualCostUsd must be finite and non-negative")]
    InvalidActualCost,
    #[error("paid dispatch requires a budgetId")]
    PaidDispatchMissingBudget,
    #[error("permit budget reservation requires a positive maximumCostUsd")]
    ReservationMissingPositiveCost,
    #[error("dispatch budget cannot be both permit-reserved and pre-reserved")]
    ConflictingReservationModes,
    #[error("pre-reserved dispatch requires a budgetId")]
    PreReservationMissingBudget,
    #[error("maximumElapsedSeconds must be between 5 and 86400")]
    InvalidElapsedLimit,
    #[error("dispatch permit fields do not agree with its lifecycle status")]
    InconsistentPermitState,
    #[error("no-provider-start resolution cannot include actualCostUsd")]
    UnexpectedActualCost,
    #[error("provider-settled resolution requires a finite non-negative actualCostUsd")]
    ProviderSettlementMissingCost,
}

fn validate_text(
    field: &'static str,
    value: &str,
    max_chars: usize,
) -> Result<(), DispatchContractError> {
    if value.trim().is_empty() || value.chars().count() > max_chars {
        return Err(DispatchContractError::InvalidText { field, max_chars });
    }
    Ok(())
}

fn validate_sha256(field: &'static str, value: &str) -> Result<(), DispatchContractError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(DispatchContractError::InvalidSha256(field));
    }
    Ok(())
}
