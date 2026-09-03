use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{EffectClass, ReversibilityPolicy};

pub const EPACT_PROGRAM_CONTRACT: &str = "epact.program/0.1-alpha";
pub const EPACT_PROGRAM_IMAGE_CONTRACT: &str = "epact.program-image/0.1-alpha";
pub const EPACT_RUNTIME_EVENT_CONTRACT: &str = "epact.runtime-event/0.1-alpha";
pub const EPACT_AMENDMENT_CONTRACT: &str = "epact.amendment/0.1-alpha";

/// Epact 0.1 canonical JSON: UTF-8, no insignificant whitespace, and recursively sorted object
/// keys. The 0.1 schema uses fixed ASCII field names and finite JSON numbers, making this encoding
/// independently reproducible without depending on Rust struct-field declaration order.
pub fn canonical_epact_json_bytes(value: &impl Serialize) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&serde_json::to_value(value)?)
}

/// Validate the intentionally narrow Epact 0.1 timestamp form: `YYYY-MM-DDTHH:MM:SSZ`.
///
/// Restricting timestamps to UTC seconds makes lexical ordering and independent replay
/// deterministic. The kernel, not an untrusted model or client, supplies request and event time.
pub fn validate_epact_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| ![4, 7, 10, 13, 16, 19].contains(&index) && !byte.is_ascii_digit())
    {
        return false;
    }
    let number = |start: usize, end: usize| {
        value[start..end]
            .parse::<u32>()
            .expect("validated ASCII digits")
    };
    let year = number(0, 4);
    let month = number(5, 7);
    let day = number(8, 10);
    let hour = number(11, 13);
    let minute = number(14, 16);
    let second = number(17, 19);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let maximum_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    year > 0 && (1..=maximum_day).contains(&day) && hour <= 23 && minute <= 59 && second <= 59
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    Human,
    Agent,
    Institution,
    Service,
}

/// The small transition vocabulary that a compiled Epact program may authorize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelOperation {
    Declare,
    Freeze,
    Authorize,
    Delegate,
    Propose,
    Reserve,
    Dispatch,
    Observe,
    Attest,
    Evaluate,
    Decide,
    Amend,
    Publish,
    Retract,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramLifecycle {
    Draft,
    Frozen,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpactProgramRef {
    pub id: String,
    pub version: String,
    pub program_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpactImport {
    pub id: String,
    pub version: String,
    pub content_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpactPrincipal {
    pub id: String,
    pub kind: PrincipalKind,
    pub display_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpactObjectDeclaration {
    pub id: String,
    pub type_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_sha256: Option<String>,
    #[serde(default)]
    pub data_classes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpactCapabilityRequirement {
    pub id: String,
    pub capability_type: String,
    pub contract: String,
    #[serde(default)]
    pub required_effects: Vec<EffectClass>,
    #[serde(default)]
    pub required_data_classes: Vec<String>,
}

/// A closed program-wide ceiling. Zero means that the corresponding resource is not authorized.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpactResourceEnvelope {
    #[serde(default)]
    pub maximum_cost_usd: f64,
    #[serde(default)]
    pub maximum_elapsed_seconds: u64,
    #[serde(default)]
    pub maximum_model_calls: u32,
    #[serde(default)]
    pub maximum_tool_calls: u32,
    #[serde(default)]
    pub maximum_external_jobs: u32,
    #[serde(default)]
    pub maximum_cpu_cores: f64,
    #[serde(default)]
    pub maximum_ram_gb: f64,
    #[serde(default)]
    pub maximum_gpu_count: u32,
    #[serde(default)]
    pub maximum_vram_gb: f64,
    #[serde(default)]
    pub maximum_storage_gb: f64,
    #[serde(default)]
    pub maximum_data_movement_gb: f64,
}

impl EpactResourceEnvelope {
    pub fn is_finite_and_non_negative(&self) -> bool {
        [
            self.maximum_cost_usd,
            self.maximum_cpu_cores,
            self.maximum_ram_gb,
            self.maximum_vram_gb,
            self.maximum_storage_gb,
            self.maximum_data_movement_gb,
        ]
        .into_iter()
        .all(|value| value.is_finite() && value >= 0.0)
    }

    pub fn fits_within(&self, ceiling: &Self) -> bool {
        const EPSILON: f64 = 1e-9;
        self.maximum_cost_usd <= ceiling.maximum_cost_usd + EPSILON
            && self.maximum_elapsed_seconds <= ceiling.maximum_elapsed_seconds
            && self.maximum_model_calls <= ceiling.maximum_model_calls
            && self.maximum_tool_calls <= ceiling.maximum_tool_calls
            && self.maximum_external_jobs <= ceiling.maximum_external_jobs
            && self.maximum_cpu_cores <= ceiling.maximum_cpu_cores + EPSILON
            && self.maximum_ram_gb <= ceiling.maximum_ram_gb + EPSILON
            && self.maximum_gpu_count <= ceiling.maximum_gpu_count
            && self.maximum_vram_gb <= ceiling.maximum_vram_gb + EPSILON
            && self.maximum_storage_gb <= ceiling.maximum_storage_gb + EPSILON
            && self.maximum_data_movement_gb <= ceiling.maximum_data_movement_gb + EPSILON
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpactAuthorityScope {
    #[serde(default)]
    pub whole_program: bool,
    #[serde(default)]
    pub obligation_ids: Vec<String>,
    #[serde(default)]
    pub capability_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpactAuthorityGrant {
    pub id: String,
    pub principal_id: String,
    pub operations: Vec<KernelOperation>,
    pub scope: EpactAuthorityScope,
    #[serde(default)]
    pub maximum_cost_usd: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_before: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EpactDischarge {
    /// A finite set of independently sufficient discharge paths. Effects and resources remain
    /// declared on the enclosing obligation and therefore bind every alternative conservatively.
    AnyOf {
        alternatives: Vec<EpactDischarge>,
    },
    Capability {
        capability_id: String,
    },
    Decision {
        decision_object_id: String,
    },
    Evidence {
        evidence_rule_ids: Vec<String>,
    },
    Review {
        capability_id: String,
        review_object_id: String,
        #[serde(default)]
        independent_principal_required: bool,
    },
    Publication {
        artifact_object_ids: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpactObligation {
    pub id: String,
    pub label: String,
    pub description: String,
    #[serde(default)]
    pub dependency_ids: Vec<String>,
    #[serde(default)]
    pub gate_ids: Vec<String>,
    pub discharge: EpactDischarge,
    #[serde(default)]
    pub output_object_ids: Vec<String>,
    #[serde(default)]
    pub effects: Vec<EffectClass>,
    #[serde(default)]
    pub resources: EpactResourceEnvelope,
    #[serde(default)]
    pub reversibility: ReversibilityPolicy,
    #[serde(default)]
    pub retry_limit: u32,
    pub terminal_receipt_contract: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EpactPredicate {
    All { predicates: Vec<EpactPredicate> },
    Any { predicates: Vec<EpactPredicate> },
    Not { predicate: Box<EpactPredicate> },
    ObligationSatisfied { obligation_id: String },
    EvidenceSatisfied { evidence_rule_id: String },
    ObjectPresent { object_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpactGate {
    pub id: String,
    pub label: String,
    pub predicate: EpactPredicate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpactEvidenceRule {
    pub id: String,
    pub claim_object_id: String,
    pub evidence_object_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluator_capability_id: Option<String>,
    #[serde(default = "default_minimum_observations")]
    pub minimum_observations: u32,
    #[serde(default)]
    pub independent_review_required: bool,
}

fn default_minimum_observations() -> u32 {
    1
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpactAmendmentPolicy {
    pub authorized_principal_ids: Vec<String>,
    pub rationale_required: bool,
    pub effective_causal_head_required: bool,
    pub preserve_prior_interpretation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpactTerminalRule {
    pub required_obligation_ids: Vec<String>,
    #[serde(default)]
    pub required_object_ids: Vec<String>,
    pub required_receipt_contracts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpactProgram {
    pub contract: String,
    pub id: String,
    pub version: String,
    pub title: String,
    pub lifecycle: ProgramLifecycle,
    pub created_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor: Option<EpactProgramRef>,
    #[serde(default)]
    pub imports: Vec<EpactImport>,
    pub principals: Vec<EpactPrincipal>,
    #[serde(default)]
    pub objects: Vec<EpactObjectDeclaration>,
    #[serde(default)]
    pub capabilities: Vec<EpactCapabilityRequirement>,
    #[serde(default)]
    pub authorities: Vec<EpactAuthorityGrant>,
    pub resources: EpactResourceEnvelope,
    pub obligations: Vec<EpactObligation>,
    #[serde(default)]
    pub gates: Vec<EpactGate>,
    #[serde(default)]
    pub evidence_rules: Vec<EpactEvidenceRule>,
    pub amendment_policy: EpactAmendmentPolicy,
    pub terminal: EpactTerminalRule,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompiledAuthority {
    pub principal_id: String,
    pub operation: KernelOperation,
    pub whole_program: bool,
    #[serde(default)]
    pub obligation_ids: Vec<String>,
    #[serde(default)]
    pub capability_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_cost_microusd: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_before: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpactCompilerFinding {
    pub code: String,
    pub subject_id: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpactProgramImage {
    pub contract: String,
    pub compiler_version: String,
    pub program_sha256: String,
    pub image_sha256: String,
    pub program: EpactProgram,
    pub obligation_order: Vec<String>,
    pub authorities: Vec<CompiledAuthority>,
    pub maximum_effects: Vec<EffectClass>,
    pub activation_findings: Vec<EpactCompilerFinding>,
    pub activatable: bool,
}

/// A prospective link between two independently immutable program images.
///
/// This record does not mutate or reinterpret predecessor events. A kernel activates the successor
/// only after binding this link to the predecessor's exact causal head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpactAmendment {
    pub contract: String,
    pub predecessor_image_sha256: String,
    pub successor_image_sha256: String,
    pub principal_id: String,
    pub rationale: String,
    pub effective_event_head_sha256: String,
    pub amendment_sha256: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpactObligationState {
    #[default]
    Pending,
    Satisfied,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EpactRuntimeEventKind {
    ObjectRecorded {
        object_id: String,
    },
    EvidenceAccepted {
        evidence_rule_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        independent_review_receipt_sha256: Option<String>,
    },
    ReviewAccepted {
        obligation_id: String,
        review_object_id: String,
        reviewer_principal_id: String,
        independent_review_receipt_sha256: String,
    },
    ObligationSatisfied {
        obligation_id: String,
        receipt_contract: String,
    },
    ObligationFailed {
        obligation_id: String,
        reason: String,
    },
    ObligationCancelled {
        obligation_id: String,
        reason: String,
    },
}

/// One hash-chained runtime fact. A valid digest proves integrity and order, not authority or truth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpactRuntimeEvent {
    pub contract: String,
    pub id: String,
    pub program_image_sha256: String,
    pub sequence: u64,
    pub actor: String,
    pub idempotency_key: String,
    pub kind: EpactRuntimeEventKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_event_sha256: Option<String>,
    pub created_at: String,
    pub event_sha256: String,
}

impl EpactRuntimeEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        id: String,
        program_image_sha256: String,
        sequence: u64,
        actor: String,
        idempotency_key: String,
        kind: EpactRuntimeEventKind,
        receipt_sha256: Option<String>,
        previous_event_sha256: Option<String>,
        created_at: String,
    ) -> Result<Self, EpactRuntimeEventError> {
        let mut event = Self {
            contract: EPACT_RUNTIME_EVENT_CONTRACT.to_owned(),
            id,
            program_image_sha256,
            sequence,
            actor,
            idempotency_key,
            kind,
            receipt_sha256,
            previous_event_sha256,
            created_at,
            event_sha256: String::new(),
        };
        event.validate_content()?;
        event.event_sha256 = event.recompute_sha256()?;
        Ok(event)
    }

    pub fn validate(&self) -> Result<(), EpactRuntimeEventError> {
        self.validate_content()?;
        if self.event_sha256 != self.recompute_sha256()? {
            return Err(EpactRuntimeEventError::HashMismatch);
        }
        Ok(())
    }

    fn validate_content(&self) -> Result<(), EpactRuntimeEventError> {
        if self.contract != EPACT_RUNTIME_EVENT_CONTRACT {
            return Err(EpactRuntimeEventError::UnsupportedContract(
                self.contract.clone(),
            ));
        }
        for (label, value) in [
            ("event id", self.id.as_str()),
            ("actor", self.actor.as_str()),
            ("idempotency key", self.idempotency_key.as_str()),
            ("creation time", self.created_at.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(EpactRuntimeEventError::MissingValue(label));
            }
        }
        if !validate_epact_timestamp(&self.created_at) {
            return Err(EpactRuntimeEventError::InvalidTimestamp);
        }
        require_event_sha256("program image hash", &self.program_image_sha256)?;
        if let Some(value) = &self.receipt_sha256 {
            require_event_sha256("receipt hash", value)?;
        }
        if let Some(value) = &self.previous_event_sha256 {
            require_event_sha256("previous event hash", value)?;
        }
        match &self.kind {
            EpactRuntimeEventKind::ObjectRecorded { object_id } => {
                require_event_text("object id", object_id)?;
                if self.receipt_sha256.is_none() {
                    return Err(EpactRuntimeEventError::MissingReceipt);
                }
            }
            EpactRuntimeEventKind::EvidenceAccepted {
                evidence_rule_id,
                independent_review_receipt_sha256,
            } => {
                require_event_text("evidence rule id", evidence_rule_id)?;
                if self.receipt_sha256.is_none() {
                    return Err(EpactRuntimeEventError::MissingReceipt);
                }
                if let Some(value) = independent_review_receipt_sha256 {
                    require_event_sha256("independent review receipt hash", value)?;
                }
            }
            EpactRuntimeEventKind::ReviewAccepted {
                obligation_id,
                review_object_id,
                reviewer_principal_id,
                independent_review_receipt_sha256,
            } => {
                require_event_text("obligation id", obligation_id)?;
                require_event_text("review object id", review_object_id)?;
                require_event_text("reviewer principal id", reviewer_principal_id)?;
                require_event_sha256(
                    "independent review receipt hash",
                    independent_review_receipt_sha256,
                )?;
                if self.receipt_sha256.is_none() {
                    return Err(EpactRuntimeEventError::MissingReceipt);
                }
            }
            EpactRuntimeEventKind::ObligationSatisfied {
                obligation_id,
                receipt_contract,
            } => {
                require_event_text("obligation id", obligation_id)?;
                require_event_text("receipt contract", receipt_contract)?;
                if self.receipt_sha256.is_none() {
                    return Err(EpactRuntimeEventError::MissingReceipt);
                }
            }
            EpactRuntimeEventKind::ObligationFailed {
                obligation_id,
                reason,
            }
            | EpactRuntimeEventKind::ObligationCancelled {
                obligation_id,
                reason,
            } => {
                require_event_text("obligation id", obligation_id)?;
                require_event_text("terminal reason", reason)?;
            }
        }
        Ok(())
    }

    fn recompute_sha256(&self) -> Result<String, EpactRuntimeEventError> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .ok_or(EpactRuntimeEventError::NotObject)?
            .remove("eventSha256");
        Ok(format!(
            "{:x}",
            Sha256::digest(canonical_epact_json_bytes(&value)?)
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpactObligationProjection {
    pub obligation_id: String,
    pub state: EpactObligationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_event_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpactAcceptedReview {
    pub obligation_id: String,
    pub review_object_id: String,
    pub reviewer_principal_id: String,
    pub independent_review_receipt_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpactRuntimeState {
    pub program_image_sha256: String,
    pub next_sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_head_sha256: Option<String>,
    pub obligations: Vec<EpactObligationProjection>,
    #[serde(default)]
    pub present_object_ids: Vec<String>,
    #[serde(default)]
    pub satisfied_evidence_rule_ids: Vec<String>,
    #[serde(default)]
    pub accepted_reviews: Vec<EpactAcceptedReview>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpactOperationRequest {
    pub principal_id: String,
    pub operation: KernelOperation,
    /// Kernel-observed request time in canonical Epact UTC-second form.
    pub requested_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obligation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(default)]
    pub effects: Vec<EffectClass>,
    #[serde(default)]
    pub resources: EpactResourceEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpactEligibilityBlocker {
    pub code: String,
    pub subject_id: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpactEligibility {
    pub allowed: bool,
    pub blockers: Vec<EpactEligibilityBlocker>,
}

#[derive(Debug, thiserror::Error)]
pub enum EpactRuntimeEventError {
    #[error("unsupported Epact runtime event contract {0}")]
    UnsupportedContract(String),
    #[error("missing {0}")]
    MissingValue(&'static str),
    #[error("invalid {0}")]
    InvalidSha256(&'static str),
    #[error("runtime event time must use canonical Epact UTC-second form")]
    InvalidTimestamp,
    #[error("runtime event requires a receipt hash")]
    MissingReceipt,
    #[error("runtime event hash mismatch")]
    HashMismatch,
    #[error("runtime event did not serialize as an object")]
    NotObject,
    #[error("runtime event serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn require_event_text(label: &'static str, value: &str) -> Result<(), EpactRuntimeEventError> {
    if value.trim().is_empty() {
        return Err(EpactRuntimeEventError::MissingValue(label));
    }
    Ok(())
}

fn require_event_sha256(label: &'static str, value: &str) -> Result<(), EpactRuntimeEventError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(EpactRuntimeEventError::InvalidSha256(label));
    }
    Ok(())
}
