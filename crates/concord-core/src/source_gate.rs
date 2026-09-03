//! Pure, deterministic compiler for source-evidence readiness.

use anyhow::{bail, ensure, Context, Result};
use concord_harness::{compile_epact_program, require_epact_activatable};
use concord_protocol::{
    EpactAmendmentPolicy, EpactAuthorityGrant, EpactAuthorityScope, EpactDischarge,
    EpactEvidenceRule, EpactGate, EpactImport, EpactObjectDeclaration, EpactObligation,
    EpactPredicate, EpactPrincipal, EpactProgram, EpactProgramImage, EpactResourceEnvelope,
    EpactTerminalRule, KernelOperation, PrincipalKind, ProgramLifecycle, ReversibilityPolicy,
    EPACT_PROGRAM_CONTRACT,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const SOURCE_GATE_PROGRAM_CONTRACT: &str = "concord.source-gate-program/1";
pub const SOURCE_GATE_ASSERTION_CONTRACT: &str = "concord.source-gate-assertion/1";
pub const SOURCE_GATE_DECISION_CONTRACT: &str = "concord.source-gate-decision/1";
pub const SOURCE_GATE_AUTHORITY_CONTRACT: &str = "concord.source-gate-authority/1";
pub const SOURCE_GATE_INPUT_CONTRACT: &str = "concord.source-gate-input/1";
pub const SOURCE_GATE_PROJECTION_CONTRACT: &str = "concord.source-gate-projection/1";
pub const SOURCE_GATE_COMPILER_VERSION: &str = "0.1.0";
pub const SOURCE_GATE_EPACT_BINDING_CONTRACT: &str = "concord.source-gate-epact-binding/1";
const SOURCE_GATE_EPACT_PRINCIPAL_ID: &str = "principal:concord-source-gate";
const SOURCE_REQUIREMENT_RECEIPT_CONTRACT: &str = "concord.source-gate-requirement-receipt/1";
const SOURCE_TRANCHE_RECEIPT_CONTRACT: &str = "concord.source-gate-tranche-receipt/1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceGateScope {
    pub id: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub dimensions: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceRequirementClass {
    Mandatory,
    TrancheSpecific,
    Optional,
    Deferrable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceGateRequirement {
    pub id: String,
    pub source_id: String,
    pub scope_id: String,
    pub label: String,
    pub class: SourceRequirementClass,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub accepted_evidence_classes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceGateTranche {
    pub id: String,
    pub label: String,
    pub requirement_ids: Vec<String>,
    #[serde(default)]
    pub historical_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceGateProgram {
    pub contract: String,
    pub id: String,
    pub version: String,
    pub campaign_id: String,
    pub sources: Vec<String>,
    pub scopes: Vec<SourceGateScope>,
    pub requirements: Vec<SourceGateRequirement>,
    pub tranches: Vec<SourceGateTranche>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceEvidenceState {
    Unobserved,
    ObservedUnqualified,
    Unresolved,
    PartiallyVerified,
    Verified,
    Contradicted,
    AmbiguousEffect,
    Deferred,
    Waived,
    Superseded,
    Invalid,
}
impl SourceEvidenceState {
    fn positive(&self) -> bool {
        matches!(self, Self::PartiallyVerified | Self::Verified)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceAmendmentKind {
    Narrows,
    Corrects,
    Supersedes,
    Contradicts,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceGateAssertion {
    pub contract: String,
    pub id: String,
    pub campaign_id: String,
    pub source_id: String,
    pub requirement_id: String,
    pub scope_id: String,
    pub state: SourceEvidenceState,
    #[serde(default)]
    pub value: Option<Value>,
    #[serde(default)]
    pub limitations: Vec<String>,
    #[serde(default)]
    pub evidence_object_ids: Vec<String>,
    pub method: String,
    pub evidence_class: String,
    pub effective_sequence: u64,
    #[serde(default)]
    pub parent_assertion_id: Option<String>,
    #[serde(default)]
    pub amendment_kind: Option<SourceAmendmentKind>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SourceGateDecisionKind {
    Acquisition,
    Waiver,
    Deferral,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceGateDecision {
    pub contract: String,
    pub id: String,
    pub campaign_id: String,
    pub kind: SourceGateDecisionKind,
    pub requirement_id: String,
    pub source_id: String,
    pub scope_id: String,
    pub tranche_ids: Vec<String>,
    pub authority_id: String,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceGateAuthority {
    pub contract: String,
    pub id: String,
    pub campaign_id: String,
    pub actor: String,
    pub decision_kinds: Vec<SourceGateDecisionKind>,
    #[serde(default)]
    pub requirement_ids: Vec<String>,
    #[serde(default)]
    pub tranche_ids: Vec<String>,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceGateInput {
    pub contract: String,
    pub campaign_id: String,
    pub campaign_snapshot_sha256: String,
    pub program: SourceGateProgram,
    #[serde(default)]
    pub assertions: Vec<SourceGateAssertion>,
    #[serde(default)]
    pub decisions: Vec<SourceGateDecision>,
    #[serde(default)]
    pub authorities: Vec<SourceGateAuthority>,
    #[serde(default)]
    pub authorized_tranche_ids: Vec<String>,
    #[serde(default)]
    pub previous_projection: Option<Box<SourceGateProjection>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceObligationState {
    SatisfiedByEvidence,
    SatisfiedByWaiver,
    DeferredFromTranche,
    Open,
    BlockedExternal,
    Contradicted,
    InvalidProgram,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceAssertionResolution {
    pub requirement_id: String,
    pub source_id: String,
    pub scope_id: String,
    pub state: SourceEvidenceState,
    #[serde(default)]
    pub value: Option<Value>,
    #[serde(default)]
    pub limitations: Vec<String>,
    pub current_assertion_ids: Vec<String>,
    pub superseded_assertion_ids: Vec<String>,
    pub evidence_object_ids: Vec<String>,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceObligationResult {
    pub requirement_id: String,
    pub source_id: String,
    pub scope_id: String,
    pub state: SourceObligationState,
    pub assertion_ids: Vec<String>,
    pub decision_ids: Vec<String>,
    pub decisive_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceTrancheState {
    Ineligible,
    EligibleUnapproved,
    Authorized,
    HistoricalOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceTrancheResult {
    pub tranche_id: String,
    pub label: String,
    pub state: SourceTrancheState,
    pub open_requirement_ids: Vec<String>,
    pub discharged_requirement_ids: Vec<String>,
    pub missing_authority: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceProjectionChange {
    pub requirement_id: String,
    #[serde(default)]
    pub previous_state: Option<SourceEvidenceState>,
    #[serde(default)]
    pub current_state: Option<SourceEvidenceState>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceGateProjection {
    pub contract: String,
    pub compiler_version: String,
    pub campaign_id: String,
    pub campaign_snapshot_sha256: String,
    pub program_id: String,
    pub program_version: String,
    pub input_sha256: String,
    #[serde(default)]
    pub previous_projection_sha256: Option<String>,
    pub assertions: Vec<SourceAssertionResolution>,
    pub obligations: Vec<SourceObligationResult>,
    pub tranches: Vec<SourceTrancheResult>,
    pub changes: Vec<SourceProjectionChange>,
    pub projection_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SourceGateCompilation {
    pub input: SourceGateInput,
    pub projection: SourceGateProjection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epact: Option<SourceGateEpactBinding>,
    pub compiled_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceGateEpactTrancheRequirementBinding {
    pub tranche_id: String,
    pub obligation_id: String,
    pub waiver_object_id: String,
    pub deferral_object_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceGateEpactRequirementBinding {
    pub requirement_id: String,
    pub program_obligation_id: String,
    pub claim_object_id: String,
    pub evidence_receipt_object_id: String,
    pub evidence_rule_id: String,
    pub tranche_bindings: Vec<SourceGateEpactTrancheRequirementBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceGateEpactTrancheBinding {
    pub tranche_id: String,
    pub eligibility_gate_id: String,
    pub authorization_obligation_id: String,
    pub authorization_object_id: String,
    pub requirement_obligation_ids: Vec<String>,
}

/// Deterministic facts that the kernel may materialize only from the accepted source-gate
/// projection and its authority records. This is a plan, not an event log: receipts and event
/// identity remain kernel-owned.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceGateEpactFactPlan {
    pub record_object_ids: Vec<String>,
    pub accept_evidence_rule_ids: Vec<String>,
    pub satisfy_obligation_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceGateEpactBinding {
    pub contract: String,
    pub source_gate_projection_sha256: String,
    pub source_gate_input_sha256: String,
    pub epact_program_sha256: String,
    pub epact_image_sha256: String,
    pub requirements: Vec<SourceGateEpactRequirementBinding>,
    pub tranches: Vec<SourceGateEpactTrancheBinding>,
    pub fact_plan: SourceGateEpactFactPlan,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceGateEpactCompilation {
    pub projection: SourceGateProjection,
    pub image: EpactProgramImage,
    pub binding: SourceGateEpactBinding,
}

pub fn compile_source_gate(mut input: SourceGateInput) -> Result<SourceGateProjection> {
    normalize(&mut input);
    validate(&input)?;
    let input_sha256 = hash_json(&serde_json::json!({
        "contract": input.contract, "campaignId": input.campaign_id, "campaignSnapshotSha256": input.campaign_snapshot_sha256,
        "program": input.program, "assertions": input.assertions, "decisions": input.decisions, "authorities": input.authorities,
        "authorizedTrancheIds": input.authorized_tranche_ids,
        "previousProjectionSha256": input.previous_projection.as_ref().map(|p| &p.projection_sha256),
    }))?;
    let assertions = resolve(&input);
    let obligations = obligations(&input, &assertions)?;
    let tranches = tranches(&input, &obligations)?;
    let changes = changes(input.previous_projection.as_deref(), &assertions);
    let mut output = SourceGateProjection {
        contract: SOURCE_GATE_PROJECTION_CONTRACT.into(),
        compiler_version: SOURCE_GATE_COMPILER_VERSION.into(),
        campaign_id: input.campaign_id.clone(),
        campaign_snapshot_sha256: input.campaign_snapshot_sha256.clone(),
        program_id: input.program.id.clone(),
        program_version: input.program.version.clone(),
        input_sha256,
        previous_projection_sha256: input
            .previous_projection
            .as_ref()
            .map(|p| p.projection_sha256.clone()),
        assertions,
        obligations,
        tranches,
        changes,
        projection_sha256: String::new(),
    };
    output.projection_sha256 = projection_hash(&output)?;
    Ok(output)
}

pub fn verify_source_gate_projection(
    input: SourceGateInput,
    expected: &SourceGateProjection,
) -> Result<()> {
    ensure!(
        compile_source_gate(input)? == *expected,
        "source gate replay differs from projection"
    );
    ensure!(
        projection_hash(expected)? == expected.projection_sha256,
        "source gate projection hash mismatch"
    );
    Ok(())
}

/// Lower the source-gate language into the canonical Epact IR without collapsing tranche-scoped
/// waiver or deferral decisions into global requirement state.
pub fn compile_source_gate_epact(mut input: SourceGateInput) -> Result<SourceGateEpactCompilation> {
    normalize(&mut input);
    let projection = compile_source_gate(input.clone())?;
    let mut objects = Vec::new();
    let mut evidence_rules = Vec::new();
    let mut obligations = Vec::new();
    let mut gates = Vec::new();
    let mut requirement_bindings = Vec::new();
    let mut tranche_bindings = Vec::new();

    let requirement_map = input
        .program
        .requirements
        .iter()
        .map(|requirement| (requirement.id.as_str(), requirement))
        .collect::<BTreeMap<_, _>>();

    for requirement in &input.program.requirements {
        let claim_object_id = lowered_id("object:source-claim", &requirement.id);
        let evidence_receipt_object_id = lowered_id("object:source-evidence", &requirement.id);
        let evidence_rule_id = lowered_id("evidence:source-requirement", &requirement.id);
        let program_obligation_id = lowered_id("obligation:source-requirement", &requirement.id);
        objects.extend([
            epact_object(&claim_object_id, "concord.source-gate-claim/1"),
            epact_object(
                &evidence_receipt_object_id,
                SOURCE_REQUIREMENT_RECEIPT_CONTRACT,
            ),
        ]);
        evidence_rules.push(EpactEvidenceRule {
            id: evidence_rule_id.clone(),
            claim_object_id: claim_object_id.clone(),
            evidence_object_ids: vec![evidence_receipt_object_id.clone()],
            evaluator_capability_id: None,
            minimum_observations: 1,
            independent_review_required: false,
        });
        obligations.push(EpactObligation {
            id: program_obligation_id.clone(),
            label: requirement.label.clone(),
            description: format!(
                "Verify source requirement {} for source {} and scope {}.",
                requirement.id, requirement.source_id, requirement.scope_id
            ),
            dependency_ids: requirement
                .dependencies
                .iter()
                .map(|dependency| lowered_id("obligation:source-requirement", dependency))
                .collect(),
            gate_ids: Vec::new(),
            discharge: EpactDischarge::Evidence {
                evidence_rule_ids: vec![evidence_rule_id.clone()],
            },
            output_object_ids: vec![evidence_receipt_object_id.clone()],
            effects: Vec::new(),
            resources: EpactResourceEnvelope::default(),
            reversibility: ReversibilityPolicy::default(),
            retry_limit: 0,
            terminal_receipt_contract: SOURCE_REQUIREMENT_RECEIPT_CONTRACT.to_owned(),
        });
        requirement_bindings.push(SourceGateEpactRequirementBinding {
            requirement_id: requirement.id.clone(),
            program_obligation_id,
            claim_object_id,
            evidence_receipt_object_id,
            evidence_rule_id,
            tranche_bindings: Vec::new(),
        });
    }

    for tranche in &input.program.tranches {
        let requirement_ids = requirement_closure(tranche, &requirement_map)?;
        let mut requirement_obligation_ids = Vec::new();
        for requirement_id in &requirement_ids {
            let requirement = requirement_map
                .get(requirement_id.as_str())
                .context("missing source-gate requirement during Epact lowering")?;
            let key = format!("{}\u{0}{}", tranche.id, requirement.id);
            let obligation_id = lowered_id("obligation:source-tranche", &key);
            let waiver_object_id = lowered_id("object:source-waiver", &key);
            let deferral_object_id = lowered_id("object:source-deferral", &key);
            let requirement_binding = requirement_bindings
                .iter_mut()
                .find(|binding| binding.requirement_id == requirement.id)
                .context("missing requirement binding during Epact lowering")?;
            objects.extend([
                epact_object(&waiver_object_id, SOURCE_GATE_DECISION_CONTRACT),
                epact_object(&deferral_object_id, SOURCE_GATE_DECISION_CONTRACT),
            ]);
            obligations.push(EpactObligation {
                id: obligation_id.clone(),
                label: format!("{} / {}", tranche.label, requirement.label),
                description: format!(
                    "Discharge source requirement {} for tranche {} by verified evidence, an authorized waiver, or an authorized deferral.",
                    requirement.id, tranche.id
                ),
                dependency_ids: requirement
                    .dependencies
                    .iter()
                    .map(|dependency| {
                        lowered_id(
                            "obligation:source-tranche",
                            &format!("{}\u{0}{}", tranche.id, dependency),
                        )
                    })
                    .collect(),
                gate_ids: Vec::new(),
                discharge: EpactDischarge::AnyOf {
                    alternatives: vec![
                        EpactDischarge::Evidence {
                            evidence_rule_ids: vec![requirement_binding.evidence_rule_id.clone()],
                        },
                        EpactDischarge::Decision {
                            decision_object_id: waiver_object_id.clone(),
                        },
                        EpactDischarge::Decision {
                            decision_object_id: deferral_object_id.clone(),
                        },
                    ],
                },
                output_object_ids: Vec::new(),
                effects: Vec::new(),
                resources: EpactResourceEnvelope::default(),
                reversibility: ReversibilityPolicy::default(),
                retry_limit: 0,
                terminal_receipt_contract: SOURCE_REQUIREMENT_RECEIPT_CONTRACT.to_owned(),
            });
            requirement_binding
                .tranche_bindings
                .push(SourceGateEpactTrancheRequirementBinding {
                    tranche_id: tranche.id.clone(),
                    obligation_id: obligation_id.clone(),
                    waiver_object_id,
                    deferral_object_id,
                });
            requirement_obligation_ids.push(obligation_id);
        }

        let eligibility_gate_id = lowered_id("gate:source-tranche", &tranche.id);
        let authorization_obligation_id =
            lowered_id("obligation:source-authorization", &tranche.id);
        let authorization_object_id = lowered_id("object:source-authorization", &tranche.id);
        objects.push(epact_object(
            &authorization_object_id,
            SOURCE_GATE_AUTHORITY_CONTRACT,
        ));
        gates.push(EpactGate {
            id: eligibility_gate_id.clone(),
            label: format!("{} source requirements discharged", tranche.label),
            predicate: EpactPredicate::All {
                predicates: requirement_obligation_ids
                    .iter()
                    .map(|obligation_id| EpactPredicate::ObligationSatisfied {
                        obligation_id: obligation_id.clone(),
                    })
                    .collect(),
            },
        });
        obligations.push(EpactObligation {
            id: authorization_obligation_id.clone(),
            label: format!("Authorize {}", tranche.label),
            description: if tranche.historical_only {
                format!(
                    "Record the historical-only disposition for source tranche {} after its source gate is satisfied.",
                    tranche.id
                )
            } else {
                format!(
                    "Record explicit acquisition authority for source tranche {} after its source gate is satisfied.",
                    tranche.id
                )
            },
            dependency_ids: Vec::new(),
            gate_ids: vec![eligibility_gate_id.clone()],
            discharge: EpactDischarge::Decision {
                decision_object_id: authorization_object_id.clone(),
            },
            output_object_ids: vec![authorization_object_id.clone()],
            effects: Vec::new(),
            resources: EpactResourceEnvelope::default(),
            reversibility: ReversibilityPolicy::default(),
            retry_limit: 0,
            terminal_receipt_contract: SOURCE_TRANCHE_RECEIPT_CONTRACT.to_owned(),
        });
        tranche_bindings.push(SourceGateEpactTrancheBinding {
            tranche_id: tranche.id.clone(),
            eligibility_gate_id,
            authorization_obligation_id,
            authorization_object_id,
            requirement_obligation_ids,
        });
    }

    requirement_bindings.sort_by(|left, right| left.requirement_id.cmp(&right.requirement_id));
    for binding in &mut requirement_bindings {
        binding
            .tranche_bindings
            .sort_by(|left, right| left.tranche_id.cmp(&right.tranche_id));
    }
    tranche_bindings.sort_by(|left, right| left.tranche_id.cmp(&right.tranche_id));
    let terminal_tranches = input
        .program
        .tranches
        .iter()
        .filter(|tranche| !tranche.historical_only)
        .map(|tranche| tranche.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut terminal_obligation_ids = tranche_bindings
        .iter()
        .filter(|binding| terminal_tranches.contains(binding.tranche_id.as_str()))
        .map(|binding| binding.authorization_obligation_id.clone())
        .collect::<Vec<_>>();
    let mut terminal_object_ids = tranche_bindings
        .iter()
        .filter(|binding| terminal_tranches.contains(binding.tranche_id.as_str()))
        .map(|binding| binding.authorization_object_id.clone())
        .collect::<Vec<_>>();
    let terminal_receipt_contract = if terminal_obligation_ids.is_empty() {
        terminal_obligation_ids = requirement_bindings
            .iter()
            .map(|binding| binding.program_obligation_id.clone())
            .collect();
        terminal_object_ids.clear();
        SOURCE_REQUIREMENT_RECEIPT_CONTRACT
    } else {
        SOURCE_TRANCHE_RECEIPT_CONTRACT
    };
    let program = EpactProgram {
        contract: EPACT_PROGRAM_CONTRACT.to_owned(),
        id: lowered_id("program:source-gate", &input.program.id),
        version: input.program.version.clone(),
        title: format!("{} source gate", input.program.id),
        lifecycle: ProgramLifecycle::Frozen,
        created_by: SOURCE_GATE_EPACT_PRINCIPAL_ID.to_owned(),
        predecessor: None,
        imports: vec![EpactImport {
            id: "concord.source-gate-input".to_owned(),
            version: SOURCE_GATE_COMPILER_VERSION.to_owned(),
            content_sha256: projection.input_sha256.clone(),
        }],
        principals: vec![EpactPrincipal {
            id: SOURCE_GATE_EPACT_PRINCIPAL_ID.to_owned(),
            kind: PrincipalKind::Service,
            display_name: "Concord source-gate compiler".to_owned(),
        }],
        objects,
        capabilities: Vec::new(),
        authorities: vec![EpactAuthorityGrant {
            id: "authority:concord-source-gate".to_owned(),
            principal_id: SOURCE_GATE_EPACT_PRINCIPAL_ID.to_owned(),
            operations: vec![
                KernelOperation::Freeze,
                KernelOperation::Authorize,
                KernelOperation::Propose,
                KernelOperation::Evaluate,
                KernelOperation::Decide,
                KernelOperation::Amend,
            ],
            scope: EpactAuthorityScope {
                whole_program: true,
                obligation_ids: Vec::new(),
                capability_ids: Vec::new(),
            },
            maximum_cost_usd: 0.0,
            valid_after: None,
            valid_before: None,
        }],
        resources: EpactResourceEnvelope::default(),
        obligations,
        gates,
        evidence_rules,
        amendment_policy: EpactAmendmentPolicy {
            authorized_principal_ids: vec![SOURCE_GATE_EPACT_PRINCIPAL_ID.to_owned()],
            rationale_required: true,
            effective_causal_head_required: true,
            preserve_prior_interpretation: true,
        },
        terminal: EpactTerminalRule {
            required_obligation_ids: terminal_obligation_ids,
            required_object_ids: terminal_object_ids,
            required_receipt_contracts: vec![terminal_receipt_contract.to_owned()],
        },
    };
    let image = compile_epact_program(program)?;
    require_epact_activatable(&image)?;
    let fact_plan = epact_fact_plan(
        &input,
        &projection,
        &requirement_bindings,
        &tranche_bindings,
    )?;
    let binding = SourceGateEpactBinding {
        contract: SOURCE_GATE_EPACT_BINDING_CONTRACT.to_owned(),
        source_gate_projection_sha256: projection.projection_sha256.clone(),
        source_gate_input_sha256: projection.input_sha256.clone(),
        epact_program_sha256: image.program_sha256.clone(),
        epact_image_sha256: image.image_sha256.clone(),
        requirements: requirement_bindings,
        tranches: tranche_bindings,
        fact_plan,
    };
    verify_source_gate_epact_binding(&input, &projection, &image, &binding)?;
    Ok(SourceGateEpactCompilation {
        projection,
        image,
        binding,
    })
}

fn requirement_closure(
    tranche: &SourceGateTranche,
    requirements: &BTreeMap<&str, &SourceGateRequirement>,
) -> Result<Vec<String>> {
    let mut closure = tranche
        .requirement_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut pending = tranche.requirement_ids.clone();
    while let Some(requirement_id) = pending.pop() {
        let requirement = requirements
            .get(requirement_id.as_str())
            .context("missing source-gate requirement while computing tranche closure")?;
        for dependency in &requirement.dependencies {
            if closure.insert(dependency.clone()) {
                pending.push(dependency.clone());
            }
        }
    }
    Ok(closure.into_iter().collect())
}

fn lowered_id(namespace: &str, source_id: &str) -> String {
    let digest = format!("{:x}", Sha256::digest(source_id.as_bytes()));
    format!("{namespace}:{}", &digest[..32])
}

fn epact_object(id: &str, type_name: &str) -> EpactObjectDeclaration {
    EpactObjectDeclaration {
        id: id.to_owned(),
        type_name: type_name.to_owned(),
        schema_sha256: None,
        data_classes: vec!["source_gate".to_owned()],
    }
}

fn epact_fact_plan(
    input: &SourceGateInput,
    projection: &SourceGateProjection,
    requirements: &[SourceGateEpactRequirementBinding],
    tranches: &[SourceGateEpactTrancheBinding],
) -> Result<SourceGateEpactFactPlan> {
    let projection_obligations = projection
        .obligations
        .iter()
        .map(|obligation| (obligation.requirement_id.as_str(), obligation))
        .collect::<BTreeMap<_, _>>();
    let requirement_map = input
        .program
        .requirements
        .iter()
        .map(|requirement| (requirement.id.as_str(), requirement))
        .collect::<BTreeMap<_, _>>();
    let binding_map = requirements
        .iter()
        .map(|binding| (binding.requirement_id.as_str(), binding))
        .collect::<BTreeMap<_, _>>();
    let mut plan = SourceGateEpactFactPlan::default();

    for binding in requirements {
        let obligation = projection_obligations
            .get(binding.requirement_id.as_str())
            .context("source-gate projection lacks a lowered requirement")?;
        if obligation.state == SourceObligationState::SatisfiedByEvidence {
            plan.record_object_ids
                .push(binding.evidence_receipt_object_id.clone());
            plan.accept_evidence_rule_ids
                .push(binding.evidence_rule_id.clone());
        }
    }

    for binding in requirements {
        if requirement_ready_for_program(
            &binding.requirement_id,
            &projection_obligations,
            &requirement_map,
            &mut BTreeMap::new(),
        )? {
            plan.satisfy_obligation_ids
                .push(binding.program_obligation_id.clone());
        }
    }

    for tranche in tranches {
        for requirement_id in &requirement_closure(
            input
                .program
                .tranches
                .iter()
                .find(|candidate| candidate.id == tranche.tranche_id)
                .context("missing source-gate tranche during fact planning")?,
            &requirement_map,
        )? {
            let binding = binding_map
                .get(requirement_id.as_str())
                .context("missing source-gate requirement binding during fact planning")?;
            let tranche_requirement = binding
                .tranche_bindings
                .iter()
                .find(|candidate| candidate.tranche_id == tranche.tranche_id)
                .context("missing tranche requirement binding during fact planning")?;
            if let Some(decision) = input.decisions.iter().find(|decision| {
                decision.requirement_id == *requirement_id
                    && decision.tranche_ids.contains(&tranche.tranche_id)
            }) {
                plan.record_object_ids.push(match decision.kind {
                    SourceGateDecisionKind::Waiver => tranche_requirement.waiver_object_id.clone(),
                    SourceGateDecisionKind::Deferral => {
                        tranche_requirement.deferral_object_id.clone()
                    }
                    SourceGateDecisionKind::Acquisition => continue,
                });
            }
            if requirement_ready_for_tranche(
                &requirement_id,
                &tranche.tranche_id,
                input,
                &projection_obligations,
                &requirement_map,
                &mut BTreeMap::new(),
            )? {
                plan.satisfy_obligation_ids
                    .push(tranche_requirement.obligation_id.clone());
            }
        }
        if input.authorized_tranche_ids.contains(&tranche.tranche_id) {
            plan.record_object_ids
                .push(tranche.authorization_object_id.clone());
            plan.satisfy_obligation_ids
                .push(tranche.authorization_obligation_id.clone());
        }
    }
    plan.record_object_ids.sort();
    plan.record_object_ids.dedup();
    plan.accept_evidence_rule_ids.sort();
    plan.accept_evidence_rule_ids.dedup();
    plan.satisfy_obligation_ids.sort();
    plan.satisfy_obligation_ids.dedup();
    Ok(plan)
}

fn requirement_ready_for_program(
    requirement_id: &str,
    projection: &BTreeMap<&str, &SourceObligationResult>,
    requirements: &BTreeMap<&str, &SourceGateRequirement>,
    memo: &mut BTreeMap<String, bool>,
) -> Result<bool> {
    if let Some(ready) = memo.get(requirement_id) {
        return Ok(*ready);
    }
    let requirement = requirements
        .get(requirement_id)
        .context("missing source-gate requirement during Epact fact planning")?;
    let own_ready = projection
        .get(requirement_id)
        .is_some_and(|obligation| obligation.state == SourceObligationState::SatisfiedByEvidence);
    let mut ready = own_ready;
    for dependency in &requirement.dependencies {
        ready &= requirement_ready_for_program(dependency, projection, requirements, memo)?;
    }
    memo.insert(requirement_id.to_owned(), ready);
    Ok(ready)
}

fn requirement_ready_for_tranche(
    requirement_id: &str,
    tranche_id: &str,
    input: &SourceGateInput,
    projection: &BTreeMap<&str, &SourceObligationResult>,
    requirements: &BTreeMap<&str, &SourceGateRequirement>,
    memo: &mut BTreeMap<String, bool>,
) -> Result<bool> {
    if let Some(ready) = memo.get(requirement_id) {
        return Ok(*ready);
    }
    let requirement = requirements
        .get(requirement_id)
        .context("missing source-gate requirement during tranche fact planning")?;
    let evidence_ready = projection
        .get(requirement_id)
        .is_some_and(|obligation| obligation.state == SourceObligationState::SatisfiedByEvidence);
    let decision_ready = input.decisions.iter().any(|decision| {
        decision.requirement_id == requirement_id
            && decision.tranche_ids.iter().any(|id| id == tranche_id)
            && matches!(
                decision.kind,
                SourceGateDecisionKind::Waiver | SourceGateDecisionKind::Deferral
            )
    });
    let mut ready = evidence_ready || decision_ready;
    for dependency in &requirement.dependencies {
        ready &= requirement_ready_for_tranche(
            dependency,
            tranche_id,
            input,
            projection,
            requirements,
            memo,
        )?;
    }
    memo.insert(requirement_id.to_owned(), ready);
    Ok(ready)
}

pub fn verify_source_gate_epact_binding(
    input: &SourceGateInput,
    projection: &SourceGateProjection,
    image: &EpactProgramImage,
    binding: &SourceGateEpactBinding,
) -> Result<()> {
    ensure!(
        binding.contract == SOURCE_GATE_EPACT_BINDING_CONTRACT
            && binding.source_gate_projection_sha256 == projection.projection_sha256
            && binding.source_gate_input_sha256 == projection.input_sha256
            && binding.epact_program_sha256 == image.program_sha256
            && binding.epact_image_sha256 == image.image_sha256,
        "source-gate Epact binding identity mismatch"
    );
    let source_requirements = input
        .program
        .requirements
        .iter()
        .map(|requirement| requirement.id.as_str())
        .collect::<BTreeSet<_>>();
    let bound_requirements = binding
        .requirements
        .iter()
        .map(|requirement| requirement.requirement_id.as_str())
        .collect::<BTreeSet<_>>();
    ensure!(
        source_requirements == bound_requirements
            && binding.requirements.len() == source_requirements.len(),
        "source-gate Epact binding does not map every requirement exactly once"
    );
    let source_tranches = input
        .program
        .tranches
        .iter()
        .map(|tranche| tranche.id.as_str())
        .collect::<BTreeSet<_>>();
    let bound_tranches = binding
        .tranches
        .iter()
        .map(|tranche| tranche.tranche_id.as_str())
        .collect::<BTreeSet<_>>();
    ensure!(
        source_tranches == bound_tranches && binding.tranches.len() == source_tranches.len(),
        "source-gate Epact binding does not map every tranche exactly once"
    );
    let image_objects = image
        .program
        .objects
        .iter()
        .map(|object| object.id.as_str())
        .collect::<BTreeSet<_>>();
    let image_rules = image
        .program
        .evidence_rules
        .iter()
        .map(|rule| rule.id.as_str())
        .collect::<BTreeSet<_>>();
    let image_obligations = image
        .program
        .obligations
        .iter()
        .map(|obligation| (obligation.id.as_str(), obligation))
        .collect::<BTreeMap<_, _>>();
    for requirement in &binding.requirements {
        ensure!(
            image_objects.contains(requirement.claim_object_id.as_str())
                && image_objects.contains(requirement.evidence_receipt_object_id.as_str())
                && image_rules.contains(requirement.evidence_rule_id.as_str()),
            "source-gate requirement {} references missing Epact objects",
            requirement.requirement_id
        );
        let source = input
            .program
            .requirements
            .iter()
            .find(|candidate| candidate.id == requirement.requirement_id)
            .context("missing source requirement during Epact verification")?;
        let obligation = image_obligations
            .get(requirement.program_obligation_id.as_str())
            .context("missing Epact program requirement obligation")?;
        let expected_dependencies = source
            .dependencies
            .iter()
            .map(|dependency| lowered_id("obligation:source-requirement", dependency))
            .collect::<BTreeSet<_>>();
        ensure!(
            obligation
                .dependency_ids
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
                == expected_dependencies,
            "source-gate requirement {} lost dependency semantics",
            requirement.requirement_id
        );
    }
    ensure!(
        binding
            .fact_plan
            .record_object_ids
            .iter()
            .all(|id| image_objects.contains(id.as_str()))
            && binding
                .fact_plan
                .accept_evidence_rule_ids
                .iter()
                .all(|id| image_rules.contains(id.as_str()))
            && binding
                .fact_plan
                .satisfy_obligation_ids
                .iter()
                .all(|id| image_obligations.contains_key(id.as_str())),
        "source-gate Epact fact plan references undeclared program members"
    );
    for tranche in &binding.tranches {
        let projection_tranche = projection
            .tranches
            .iter()
            .find(|candidate| candidate.tranche_id == tranche.tranche_id)
            .context("missing projected source-gate tranche")?;
        let all_requirements_ready = tranche.requirement_obligation_ids.iter().all(|id| {
            binding
                .fact_plan
                .satisfy_obligation_ids
                .binary_search(id)
                .is_ok()
        });
        ensure!(
            all_requirements_ready
                == !matches!(projection_tranche.state, SourceTrancheState::Ineligible),
            "Epact readiness diverges from source-gate tranche {}",
            tranche.tranche_id
        );
        let authorized = binding
            .fact_plan
            .satisfy_obligation_ids
            .binary_search(&tranche.authorization_obligation_id)
            .is_ok();
        ensure!(
            authorized == matches!(projection_tranche.state, SourceTrancheState::Authorized),
            "Epact authority state diverges from source-gate tranche {}",
            tranche.tranche_id
        );
    }
    Ok(())
}

fn normalize(input: &mut SourceGateInput) {
    input.program.sources.sort();
    input.program.sources.dedup();
    input.program.scopes.sort_by(|a, b| a.id.cmp(&b.id));
    input.program.requirements.sort_by(|a, b| a.id.cmp(&b.id));
    input.program.tranches.sort_by(|a, b| a.id.cmp(&b.id));
    for r in &mut input.program.requirements {
        r.dependencies.sort();
        r.dependencies.dedup();
        r.accepted_evidence_classes.sort();
        r.accepted_evidence_classes.dedup();
    }
    for t in &mut input.program.tranches {
        t.requirement_ids.sort();
        t.requirement_ids.dedup();
    }
    input.assertions.sort_by(|a, b| a.id.cmp(&b.id));
    for a in &mut input.assertions {
        a.evidence_object_ids.sort();
        a.evidence_object_ids.dedup();
        a.limitations.sort();
        a.limitations.dedup();
    }
    input.decisions.sort_by(|a, b| a.id.cmp(&b.id));
    for d in &mut input.decisions {
        d.tranche_ids.sort();
        d.tranche_ids.dedup();
    }
    input.authorities.sort_by(|a, b| a.id.cmp(&b.id));
    for a in &mut input.authorities {
        a.decision_kinds.sort();
        a.decision_kinds.dedup();
        a.requirement_ids.sort();
        a.requirement_ids.dedup();
        a.tranche_ids.sort();
        a.tranche_ids.dedup();
    }
    input.authorized_tranche_ids.sort();
    input.authorized_tranche_ids.dedup();
}

fn validate(input: &SourceGateInput) -> Result<()> {
    ensure!(
        input.contract == SOURCE_GATE_INPUT_CONTRACT,
        "source gate input contract mismatch"
    );
    ensure!(
        input.campaign_snapshot_sha256.len() == 64
            && input
                .campaign_snapshot_sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "campaign snapshot sha256 is invalid"
    );
    let p = &input.program;
    ensure!(
        p.contract == SOURCE_GATE_PROGRAM_CONTRACT && p.campaign_id == input.campaign_id,
        "source gate program identity mismatch"
    );
    let sources = unique(p.sources.iter().map(String::as_str), "source")?;
    let scopes = unique(p.scopes.iter().map(|v| v.id.as_str()), "scope")?;
    let requirements = unique(p.requirements.iter().map(|v| v.id.as_str()), "requirement")?;
    let tranches = unique(p.tranches.iter().map(|v| v.id.as_str()), "tranche")?;
    for r in &p.requirements {
        ensure!(
            sources.contains(r.source_id.as_str()) && scopes.contains(r.scope_id.as_str()),
            "requirement {} has unknown source or scope",
            r.id
        );
        for d in &r.dependencies {
            ensure!(
                requirements.contains(d.as_str()) && d != &r.id,
                "requirement {} has invalid dependency",
                r.id
            );
        }
    }
    validate_requirement_cycles(&p.requirements)?;
    for t in &p.tranches {
        ensure!(!t.requirement_ids.is_empty(), "tranche {} is empty", t.id);
        for id in &t.requirement_ids {
            ensure!(
                requirements.contains(id.as_str()),
                "tranche {} names unknown requirement",
                t.id
            );
        }
    }
    let assertions = map_unique(&input.assertions, |a| a.id.as_str(), "assertion")?;
    for a in &input.assertions {
        ensure!(
            a.contract == SOURCE_GATE_ASSERTION_CONTRACT && a.campaign_id == input.campaign_id,
            "assertion {} identity mismatch",
            a.id
        );
        let r = p
            .requirements
            .iter()
            .find(|r| r.id == a.requirement_id)
            .with_context(|| format!("assertion {} has unknown requirement", a.id))?;
        ensure!(
            a.source_id == r.source_id && a.scope_id == r.scope_id,
            "assertion {} source or scope differs from requirement",
            a.id
        );
        ensure!(
            !a.method.trim().is_empty() && !a.evidence_class.trim().is_empty(),
            "assertion {} lacks method",
            a.id
        );
        ensure!(
            r.accepted_evidence_classes.is_empty()
                || r.accepted_evidence_classes.contains(&a.evidence_class),
            "assertion {} has unaccepted evidence class",
            a.id
        );
        if a.state.positive() {
            ensure!(
                !a.evidence_object_ids.is_empty(),
                "assertion {} lacks evidence objects",
                a.id
            );
        }
        match (&a.parent_assertion_id, &a.amendment_kind) {
            (None, None) => (),
            (Some(parent), Some(_)) => {
                let parent = assertions
                    .get(parent.as_str())
                    .with_context(|| format!("assertion {} has missing parent", a.id))?;
                ensure!(
                    parent.source_id == a.source_id
                        && parent.requirement_id == a.requirement_id
                        && parent.scope_id == a.scope_id,
                    "assertion {} parent has a different source, requirement, or scope",
                    a.id
                );
                ensure!(
                    parent.effective_sequence < a.effective_sequence,
                    "assertion {} is not prospective",
                    a.id
                );
            }
            _ => bail!(
                "assertion {} must declare parent and amendment kind together",
                a.id
            ),
        }
    }
    validate_assertion_cycles(&input.assertions, &assertions)?;
    let authorities = map_unique(&input.authorities, |a| a.id.as_str(), "authority")?;
    for a in &input.authorities {
        ensure!(
            a.contract == SOURCE_GATE_AUTHORITY_CONTRACT && a.campaign_id == input.campaign_id,
            "authority {} identity mismatch",
            a.id
        );
        ensure!(
            !a.actor.trim().is_empty() && !a.decision_kinds.is_empty(),
            "authority {} lacks actor or decision kinds",
            a.id
        );
        ensure!(
            a.requirement_ids
                .iter()
                .all(|id| requirements.contains(id.as_str())),
            "authority {} names an unknown requirement",
            a.id
        );
        ensure!(
            a.tranche_ids
                .iter()
                .all(|id| tranches.contains(id.as_str())),
            "authority {} names an unknown tranche",
            a.id
        );
    }
    unique(input.decisions.iter().map(|d| d.id.as_str()), "decision")?;
    for d in &input.decisions {
        ensure!(
            d.contract == SOURCE_GATE_DECISION_CONTRACT && d.campaign_id == input.campaign_id,
            "decision {} identity mismatch",
            d.id
        );
        ensure!(
            matches!(
                d.kind,
                SourceGateDecisionKind::Waiver | SourceGateDecisionKind::Deferral
            ),
            "decision {} uses acquisition authority as an obligation decision",
            d.id
        );
        ensure!(
            !d.rationale.trim().is_empty(),
            "decision {} lacks rationale",
            d.id
        );
        let r = p
            .requirements
            .iter()
            .find(|r| r.id == d.requirement_id)
            .with_context(|| format!("decision {} has unknown requirement", d.id))?;
        ensure!(
            d.source_id == r.source_id && d.scope_id == r.scope_id && !d.tranche_ids.is_empty(),
            "decision {} scope mismatch",
            d.id
        );
        for id in &d.tranche_ids {
            ensure!(
                tranches.contains(id.as_str()),
                "decision {} has unknown tranche",
                d.id
            );
        }
        let a = authorities
            .get(d.authority_id.as_str())
            .with_context(|| format!("decision {} lacks authority", d.id))?;
        ensure!(
            a.active && a.decision_kinds.contains(&d.kind),
            "decision {} exceeds authority kind",
            d.id
        );
        ensure!(
            a.requirement_ids.is_empty() || a.requirement_ids.contains(&d.requirement_id),
            "decision {} exceeds requirement authority",
            d.id
        );
        ensure!(
            d.tranche_ids
                .iter()
                .all(|id| a.tranche_ids.is_empty() || a.tranche_ids.contains(id)),
            "decision {} exceeds tranche authority",
            d.id
        );
    }
    for id in &input.authorized_tranche_ids {
        ensure!(
            tranches.contains(id.as_str()),
            "unknown authorized tranche {id}"
        );
        ensure!(
            input.authorities.iter().any(|authority| {
                authority.active
                    && authority
                        .decision_kinds
                        .contains(&SourceGateDecisionKind::Acquisition)
                    && authority.tranche_ids.contains(id)
            }),
            "authorized tranche {id} lacks active acquisition authority"
        );
    }
    if let Some(previous) = input.previous_projection.as_deref() {
        ensure!(
            previous.contract == SOURCE_GATE_PROJECTION_CONTRACT
                && previous.campaign_id == input.campaign_id,
            "previous projection identity mismatch"
        );
        ensure!(
            projection_hash(previous)? == previous.projection_sha256,
            "previous projection hash mismatch"
        );
    }
    Ok(())
}

fn resolve(input: &SourceGateInput) -> Vec<SourceAssertionResolution> {
    input
        .program
        .requirements
        .iter()
        .map(|r| {
            let all: Vec<_> = input
                .assertions
                .iter()
                .filter(|a| a.requirement_id == r.id)
                .collect();
            let parents: BTreeSet<_> = all
                .iter()
                .filter_map(|a| a.parent_assertion_id.as_ref())
                .collect();
            let leaves: Vec<_> = all
                .iter()
                .filter(|a| !parents.contains(&a.id))
                .copied()
                .collect();
            if leaves.is_empty() {
                return SourceAssertionResolution {
                    requirement_id: r.id.clone(),
                    source_id: r.source_id.clone(),
                    scope_id: r.scope_id.clone(),
                    state: SourceEvidenceState::Unobserved,
                    value: None,
                    limitations: vec![],
                    current_assertion_ids: vec![],
                    superseded_assertion_ids: vec![],
                    evidence_object_ids: vec![],
                    explanation: "No accepted assertion bears on this requirement.".into(),
                };
            }
            let current: Vec<_> = leaves.iter().map(|a| a.id.clone()).collect();
            let current_set: BTreeSet<_> = current.iter().collect();
            let superseded = all
                .iter()
                .filter(|a| !current_set.contains(&a.id))
                .map(|a| a.id.clone())
                .collect();
            if leaves.len() > 1 {
                return SourceAssertionResolution {
                    requirement_id: r.id.clone(),
                    source_id: r.source_id.clone(),
                    scope_id: r.scope_id.clone(),
                    state: SourceEvidenceState::Contradicted,
                    value: None,
                    limitations: vec!["Multiple causally valid assertion leaves remain.".into()],
                    current_assertion_ids: current,
                    superseded_assertion_ids: superseded,
                    evidence_object_ids: leaves
                        .iter()
                        .flat_map(|a| a.evidence_object_ids.clone())
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect(),
                    explanation: "Conflicting sibling branches fail closed.".into(),
                };
            }
            let a = leaves[0];
            SourceAssertionResolution {
                requirement_id: r.id.clone(),
                source_id: r.source_id.clone(),
                scope_id: r.scope_id.clone(),
                state: a.state.clone(),
                value: a.value.clone(),
                limitations: a.limitations.clone(),
                current_assertion_ids: current,
                superseded_assertion_ids: superseded,
                evidence_object_ids: a.evidence_object_ids.clone(),
                explanation: if a.parent_assertion_id.is_some() {
                    "Current state follows the single valid causal amendment lineage."
                } else {
                    "Current state follows the accepted root assertion."
                }
                .into(),
            }
        })
        .collect()
}

fn obligations(
    input: &SourceGateInput,
    resolutions: &[SourceAssertionResolution],
) -> Result<Vec<SourceObligationResult>> {
    input
        .program
        .requirements
        .iter()
        .map(|r| {
            let resolution = resolutions
                .iter()
                .find(|v| v.requirement_id == r.id)
                .unwrap();
            let decisions: Vec<_> = input
                .decisions
                .iter()
                .filter(|d| d.requirement_id == r.id)
                .collect();
            let waivers: Vec<_> = decisions
                .iter()
                .filter(|d| d.kind == SourceGateDecisionKind::Waiver)
                .collect();
            let deferrals: Vec<_> = decisions
                .iter()
                .filter(|d| d.kind == SourceGateDecisionKind::Deferral)
                .collect();
            ensure!(
                waivers.len() <= 1
                    && deferrals.len() <= 1
                    && !(waivers.len() == 1 && deferrals.len() == 1),
                "requirement {} has conflicting decisions",
                r.id
            );
            let (state, reason) = if let Some(d) = waivers.first() {
                (
                    SourceObligationState::SatisfiedByWaiver,
                    format!(
                        "Authorized waiver {} discharges this obligation without verification.",
                        d.id
                    ),
                )
            } else if let Some(d) = deferrals.first() {
                (
                    SourceObligationState::DeferredFromTranche,
                    format!(
                        "Authorized deferral {} applies only to named tranches.",
                        d.id
                    ),
                )
            } else {
                match resolution.state {
                    SourceEvidenceState::Verified => (
                        SourceObligationState::SatisfiedByEvidence,
                        "Complete declared scope is verified.".into(),
                    ),
                    SourceEvidenceState::Contradicted => (
                        SourceObligationState::Contradicted,
                        "Evidence branches conflict.".into(),
                    ),
                    SourceEvidenceState::AmbiguousEffect => (
                        SourceObligationState::BlockedExternal,
                        "External effect is ambiguous.".into(),
                    ),
                    SourceEvidenceState::Invalid => (
                        SourceObligationState::InvalidProgram,
                        "Assertion is invalid under the program.".into(),
                    ),
                    _ => (
                        SourceObligationState::Open,
                        format!("Current evidence state is {:?}.", resolution.state)
                            .to_ascii_lowercase(),
                    ),
                }
            };
            Ok(SourceObligationResult {
                requirement_id: r.id.clone(),
                source_id: r.source_id.clone(),
                scope_id: r.scope_id.clone(),
                state,
                assertion_ids: resolution.current_assertion_ids.clone(),
                decision_ids: decisions.iter().map(|d| d.id.clone()).collect(),
                decisive_reason: reason,
            })
        })
        .collect()
}

fn tranches(
    input: &SourceGateInput,
    obligations: &[SourceObligationResult],
) -> Result<Vec<SourceTrancheResult>> {
    input
        .program
        .tranches
        .iter()
        .map(|t| {
            let mut open = vec![];
            let mut discharged = vec![];
            let mut requirement_ids = t.requirement_ids.iter().cloned().collect::<BTreeSet<_>>();
            let mut pending = t.requirement_ids.clone();
            while let Some(requirement_id) = pending.pop() {
                let requirement = input
                    .program
                    .requirements
                    .iter()
                    .find(|requirement| requirement.id == requirement_id)
                    .context("missing tranche requirement")?;
                for dependency in &requirement.dependencies {
                    if requirement_ids.insert(dependency.clone()) {
                        pending.push(dependency.clone());
                    }
                }
            }
            for id in requirement_ids {
                let o = obligations
                    .iter()
                    .find(|o| o.requirement_id == id)
                    .context("missing obligation")?;
                let decision_applies = |kind| {
                    input.decisions.iter().any(|d| {
                        d.requirement_id == id && d.kind == kind && d.tranche_ids.contains(&t.id)
                    })
                };
                let waived = o.state == SourceObligationState::SatisfiedByWaiver
                    && decision_applies(SourceGateDecisionKind::Waiver);
                let deferred = o.state == SourceObligationState::DeferredFromTranche
                    && decision_applies(SourceGateDecisionKind::Deferral);
                if o.state == SourceObligationState::SatisfiedByEvidence || waived || deferred {
                    discharged.push(id)
                } else {
                    open.push(id)
                }
            }
            let authorized = input.authorized_tranche_ids.contains(&t.id);
            let state = if !open.is_empty() {
                SourceTrancheState::Ineligible
            } else if t.historical_only {
                SourceTrancheState::HistoricalOnly
            } else if authorized {
                SourceTrancheState::Authorized
            } else {
                SourceTrancheState::EligibleUnapproved
            };
            Ok(SourceTrancheResult {
                tranche_id: t.id.clone(),
                label: t.label.clone(),
                state,
                open_requirement_ids: open,
                discharged_requirement_ids: discharged,
                missing_authority: !authorized,
            })
        })
        .collect()
}

fn changes(
    previous: Option<&SourceGateProjection>,
    current: &[SourceAssertionResolution],
) -> Vec<SourceProjectionChange> {
    let old: BTreeMap<_, _> = previous
        .map(|p| {
            p.assertions
                .iter()
                .map(|r| (r.requirement_id.as_str(), r.state.clone()))
                .collect()
        })
        .unwrap_or_default();
    let ids: BTreeSet<_> = current.iter().map(|r| r.requirement_id.as_str()).collect();
    let mut out: Vec<_> = current
        .iter()
        .filter_map(|r| {
            let before = old.get(r.requirement_id.as_str()).cloned();
            (before.as_ref() != Some(&r.state)).then(|| SourceProjectionChange {
                requirement_id: r.requirement_id.clone(),
                previous_state: before,
                current_state: Some(r.state.clone()),
            })
        })
        .collect();
    for (id, state) in old {
        if !ids.contains(id) {
            out.push(SourceProjectionChange {
                requirement_id: id.into(),
                previous_state: Some(state),
                current_state: None,
            })
        }
    }
    out.sort_by(|a, b| a.requirement_id.cmp(&b.requirement_id));
    out
}

fn projection_hash(p: &SourceGateProjection) -> Result<String> {
    hash_json(
        &serde_json::json!({"contract":p.contract,"compilerVersion":p.compiler_version,"campaignId":p.campaign_id,"campaignSnapshotSha256":p.campaign_snapshot_sha256,"programId":p.program_id,"programVersion":p.program_version,"inputSha256":p.input_sha256,"previousProjectionSha256":p.previous_projection_sha256,"assertions":p.assertions,"obligations":p.obligations,"tranches":p.tranches,"changes":p.changes}),
    )
}
fn hash_json(v: &impl Serialize) -> Result<String> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(v)?)))
}
fn unique<'a>(it: impl Iterator<Item = &'a str>, label: &str) -> Result<BTreeSet<&'a str>> {
    let mut set = BTreeSet::new();
    for id in it {
        ensure!(!id.trim().is_empty(), "{label} identity empty");
        ensure!(set.insert(id), "duplicate {label} {id}");
    }
    Ok(set)
}
fn map_unique<'a, T>(
    items: &'a [T],
    key: impl Fn(&'a T) -> &'a str,
    label: &str,
) -> Result<BTreeMap<&'a str, &'a T>> {
    let mut out = BTreeMap::new();
    for item in items {
        let id = key(item);
        ensure!(out.insert(id, item).is_none(), "duplicate {label} {id}");
    }
    Ok(out)
}
fn validate_assertion_cycles<'a>(
    items: &'a [SourceGateAssertion],
    map: &BTreeMap<&'a str, &'a SourceGateAssertion>,
) -> Result<()> {
    for item in items {
        let mut seen = BTreeSet::new();
        let mut current = item;
        while let Some(parent) = current.parent_assertion_id.as_deref() {
            ensure!(
                seen.insert(current.id.as_str()),
                "assertion lineage cycle at {}",
                current.id
            );
            current = map
                .get(parent)
                .copied()
                .context("missing assertion parent")?;
        }
    }
    Ok(())
}
fn validate_requirement_cycles(items: &[SourceGateRequirement]) -> Result<()> {
    let map: BTreeMap<_, _> = items.iter().map(|r| (r.id.as_str(), r)).collect();
    fn visit<'a>(
        id: &'a str,
        map: &BTreeMap<&'a str, &'a SourceGateRequirement>,
        active: &mut BTreeSet<&'a str>,
        done: &mut BTreeSet<&'a str>,
    ) -> Result<()> {
        if done.contains(id) {
            return Ok(());
        }
        ensure!(active.insert(id), "requirement dependency cycle at {id}");
        for dep in &map.get(id).context("unknown requirement")?.dependencies {
            visit(dep, map, active, done)?
        }
        active.remove(id);
        done.insert(id);
        Ok(())
    }
    let (mut active, mut done) = (BTreeSet::new(), BTreeSet::new());
    for id in map.keys() {
        visit(id, &map, &mut active, &mut done)?
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn assertion(
        id: &str,
        state: SourceEvidenceState,
        seq: u64,
        parent: Option<&str>,
    ) -> SourceGateAssertion {
        SourceGateAssertion {
            contract: SOURCE_GATE_ASSERTION_CONTRACT.into(),
            id: id.into(),
            campaign_id: "atr".into(),
            source_id: "landfire".into(),
            requirement_id: "landfire.replacement".into(),
            scope_id: "lf2024".into(),
            value: state.positive().then(|| json!("documented")),
            evidence_object_ids: state
                .positive()
                .then(|| "evidence:pdf".into())
                .into_iter()
                .collect(),
            state,
            limitations: vec![],
            method: "bounded extraction".into(),
            evidence_class: "official_document".into(),
            effective_sequence: seq,
            parent_assertion_id: parent.map(Into::into),
            amendment_kind: parent.map(|_| SourceAmendmentKind::Supersedes),
        }
    }
    fn input() -> SourceGateInput {
        SourceGateInput {
            contract: SOURCE_GATE_INPUT_CONTRACT.into(),
            campaign_id: "atr".into(),
            campaign_snapshot_sha256: "a".repeat(64),
            program: SourceGateProgram {
                contract: SOURCE_GATE_PROGRAM_CONTRACT.into(),
                id: "sources".into(),
                version: "1".into(),
                campaign_id: "atr".into(),
                sources: vec!["landfire".into()],
                scopes: vec![SourceGateScope {
                    id: "lf2024".into(),
                    description: "".into(),
                    dimensions: BTreeMap::new(),
                }],
                requirements: vec![SourceGateRequirement {
                    id: "landfire.replacement".into(),
                    source_id: "landfire".into(),
                    scope_id: "lf2024".into(),
                    label: "Replacement".into(),
                    class: SourceRequirementClass::Mandatory,
                    dependencies: vec![],
                    accepted_evidence_classes: vec!["official_document".into()],
                }],
                tranches: vec![SourceGateTranche {
                    id: "diagnostic".into(),
                    label: "Diagnostic".into(),
                    requirement_ids: vec!["landfire.replacement".into()],
                    historical_only: false,
                }],
            },
            assertions: vec![assertion("base", SourceEvidenceState::Unresolved, 1, None)],
            decisions: vec![],
            authorities: vec![],
            authorized_tranche_ids: vec![],
            previous_projection: None,
        }
    }
    #[test]
    fn amendment_supersedes_exact_scope() {
        let mut i = input();
        i.assertions.push(assertion(
            "new",
            SourceEvidenceState::Verified,
            2,
            Some("base"),
        ));
        let p = compile_source_gate(i).unwrap();
        assert_eq!(p.assertions[0].state, SourceEvidenceState::Verified);
        assert_eq!(p.assertions[0].superseded_assertion_ids, vec!["base"]);
        assert_eq!(p.tranches[0].state, SourceTrancheState::EligibleUnapproved)
    }
    #[test]
    fn acquisition_authority_is_required_and_tranche_scoped() {
        let mut ambient = input();
        ambient.assertions.push(assertion(
            "new",
            SourceEvidenceState::Verified,
            2,
            Some("base"),
        ));
        ambient.authorized_tranche_ids = vec!["diagnostic".into()];
        assert!(compile_source_gate(ambient.clone()).is_err());

        ambient.authorities.push(SourceGateAuthority {
            contract: SOURCE_GATE_AUTHORITY_CONTRACT.into(),
            id: "operator-acquisition".into(),
            campaign_id: "atr".into(),
            actor: "operator".into(),
            decision_kinds: vec![SourceGateDecisionKind::Acquisition],
            requirement_ids: vec![],
            tranche_ids: vec!["diagnostic".into()],
            active: true,
        });
        assert_eq!(
            compile_source_gate(ambient.clone()).unwrap().tranches[0].state,
            SourceTrancheState::Authorized
        );

        ambient.authorities[0].tranche_ids = vec![];
        assert!(compile_source_gate(ambient).is_err());
    }
    #[test]
    fn sibling_branches_fail_closed() {
        let mut i = input();
        i.assertions.push(assertion(
            "a",
            SourceEvidenceState::Verified,
            2,
            Some("base"),
        ));
        i.assertions.push(assertion(
            "b",
            SourceEvidenceState::Unresolved,
            3,
            Some("base"),
        ));
        assert_eq!(
            compile_source_gate(i).unwrap().assertions[0].state,
            SourceEvidenceState::Contradicted
        )
    }
    #[test]
    fn wrong_scope_rejected() {
        let mut i = input();
        let mut a = assertion("bad", SourceEvidenceState::Verified, 2, Some("base"));
        a.scope_id = "broad".into();
        i.assertions.push(a);
        assert!(compile_source_gate(i).is_err())
    }
    #[test]
    fn replay_hash_stable_across_order() {
        let mut a = input();
        a.assertions.push(assertion(
            "new",
            SourceEvidenceState::Verified,
            2,
            Some("base"),
        ));
        let mut b = a.clone();
        b.assertions.reverse();
        assert_eq!(
            compile_source_gate(a).unwrap().projection_sha256,
            compile_source_gate(b).unwrap().projection_sha256
        )
    }
    #[test]
    fn waiver_not_verification() {
        let mut i = input();
        i.authorities.push(SourceGateAuthority {
            contract: SOURCE_GATE_AUTHORITY_CONTRACT.into(),
            id: "op".into(),
            campaign_id: "atr".into(),
            actor: "primary".into(),
            decision_kinds: vec![SourceGateDecisionKind::Waiver],
            requirement_ids: vec![],
            tranche_ids: vec![],
            active: true,
        });
        i.decisions.push(SourceGateDecision {
            contract: SOURCE_GATE_DECISION_CONTRACT.into(),
            id: "w".into(),
            campaign_id: "atr".into(),
            kind: SourceGateDecisionKind::Waiver,
            requirement_id: "landfire.replacement".into(),
            source_id: "landfire".into(),
            scope_id: "lf2024".into(),
            tranche_ids: vec!["diagnostic".into()],
            authority_id: "op".into(),
            rationale: "diagnostic".into(),
        });
        let p = compile_source_gate(i).unwrap();
        assert_eq!(p.assertions[0].state, SourceEvidenceState::Unresolved);
        assert_eq!(
            p.obligations[0].state,
            SourceObligationState::SatisfiedByWaiver
        );
        assert_eq!(p.tranches[0].state, SourceTrancheState::EligibleUnapproved)
    }
    #[test]
    fn waiver_is_tranche_scoped() {
        let mut i = input();
        i.program.tranches.push(SourceGateTranche {
            id: "full".into(),
            label: "Full".into(),
            requirement_ids: vec!["landfire.replacement".into()],
            historical_only: false,
        });
        i.authorities.push(SourceGateAuthority {
            contract: SOURCE_GATE_AUTHORITY_CONTRACT.into(),
            id: "op".into(),
            campaign_id: "atr".into(),
            actor: "primary".into(),
            decision_kinds: vec![SourceGateDecisionKind::Waiver],
            requirement_ids: vec![],
            tranche_ids: vec![],
            active: true,
        });
        i.decisions.push(SourceGateDecision {
            contract: SOURCE_GATE_DECISION_CONTRACT.into(),
            id: "w".into(),
            campaign_id: "atr".into(),
            kind: SourceGateDecisionKind::Waiver,
            requirement_id: "landfire.replacement".into(),
            source_id: "landfire".into(),
            scope_id: "lf2024".into(),
            tranche_ids: vec!["diagnostic".into()],
            authority_id: "op".into(),
            rationale: "diagnostic only".into(),
        });
        let p = compile_source_gate(i).unwrap();
        assert_eq!(p.tranches[0].state, SourceTrancheState::EligibleUnapproved);
        assert_eq!(p.tranches[1].state, SourceTrancheState::Ineligible);
    }
    #[test]
    fn deferral_is_tranche_scoped() {
        let mut i = input();
        i.program.tranches.push(SourceGateTranche {
            id: "full".into(),
            label: "Full".into(),
            requirement_ids: vec!["landfire.replacement".into()],
            historical_only: false,
        });
        i.authorities.push(SourceGateAuthority {
            contract: SOURCE_GATE_AUTHORITY_CONTRACT.into(),
            id: "op".into(),
            campaign_id: "atr".into(),
            actor: "primary".into(),
            decision_kinds: vec![SourceGateDecisionKind::Deferral],
            requirement_ids: vec![],
            tranche_ids: vec![],
            active: true,
        });
        i.decisions.push(SourceGateDecision {
            contract: SOURCE_GATE_DECISION_CONTRACT.into(),
            id: "d".into(),
            campaign_id: "atr".into(),
            kind: SourceGateDecisionKind::Deferral,
            requirement_id: "landfire.replacement".into(),
            source_id: "landfire".into(),
            scope_id: "lf2024".into(),
            tranche_ids: vec!["diagnostic".into()],
            authority_id: "op".into(),
            rationale: "later".into(),
        });
        let p = compile_source_gate(i).unwrap();
        assert_eq!(
            p.tranches
                .iter()
                .find(|t| t.tranche_id == "diagnostic")
                .unwrap()
                .state,
            SourceTrancheState::EligibleUnapproved
        );
        assert_eq!(
            p.tranches
                .iter()
                .find(|t| t.tranche_id == "full")
                .unwrap()
                .state,
            SourceTrancheState::Ineligible
        )
    }

    #[test]
    fn normalization_property_holds_for_permutations_and_duplicates() {
        let mut expected_input = input();
        expected_input.assertions.push(assertion(
            "new",
            SourceEvidenceState::Verified,
            2,
            Some("base"),
        ));
        expected_input.program.sources.push("landfire".into());
        expected_input.program.requirements[0]
            .accepted_evidence_classes
            .push("official_document".into());
        let expected = compile_source_gate(expected_input.clone())
            .unwrap()
            .projection_sha256;
        for iteration in 0..64 {
            let mut candidate = expected_input.clone();
            if iteration % 2 == 0 {
                candidate.assertions.reverse();
                candidate.program.sources.reverse();
                candidate.program.requirements.reverse();
            }
            candidate
                .assertions
                .rotate_left(iteration % expected_input.assertions.len());
            assert_eq!(
                compile_source_gate(candidate).unwrap().projection_sha256,
                expected
            );
        }
    }

    #[test]
    fn mutation_suite_fails_closed_on_identity_authority_and_lineage_drift() {
        let mutations: Vec<Box<dyn Fn(&mut SourceGateInput)>> = vec![
            Box::new(|i| i.contract = "unknown".into()),
            Box::new(|i| i.campaign_snapshot_sha256 = "not-a-hash".into()),
            Box::new(|i| i.program.campaign_id = "other".into()),
            Box::new(|i| i.program.requirements[0].scope_id = "missing".into()),
            Box::new(|i| i.assertions[0].source_id = "other".into()),
            Box::new(|i| i.assertions[0].parent_assertion_id = Some("missing".into())),
            Box::new(|i| i.assertions[0].amendment_kind = Some(SourceAmendmentKind::Supersedes)),
        ];
        for mutate in mutations {
            let mut candidate = input();
            mutate(&mut candidate);
            assert!(compile_source_gate(candidate).is_err());
        }

        let mut invalid_authority = input();
        invalid_authority.authorities.push(SourceGateAuthority {
            contract: SOURCE_GATE_AUTHORITY_CONTRACT.into(),
            id: "invalid".into(),
            campaign_id: "atr".into(),
            actor: "primary".into(),
            decision_kinds: vec![SourceGateDecisionKind::Waiver],
            requirement_ids: vec!["missing".into()],
            tranche_ids: vec![],
            active: true,
        });
        assert!(compile_source_gate(invalid_authority).is_err());
    }

    #[test]
    fn malformed_input_fuzz_never_panics_or_succeeds_with_drifted_contracts() {
        let seed = serde_json::to_value(input()).unwrap();
        let fields = [
            "/contract",
            "/campaignId",
            "/campaignSnapshotSha256",
            "/program/contract",
            "/program/campaignId",
            "/program/requirements/0/sourceId",
            "/program/requirements/0/scopeId",
            "/assertions/0/contract",
            "/assertions/0/requirementId",
            "/assertions/0/scopeId",
        ];
        for iteration in 0..512 {
            let mut candidate = seed.clone();
            let pointer = fields[iteration % fields.len()];
            if let Some(value) = candidate.pointer_mut(pointer) {
                *value = if iteration % 3 == 0 {
                    Value::Null
                } else if iteration % 3 == 1 {
                    json!(format!("mutated-{iteration}"))
                } else {
                    json!({"unexpected": iteration})
                };
            }
            let result = std::panic::catch_unwind(|| {
                serde_json::from_value::<SourceGateInput>(candidate)
                    .map_err(anyhow::Error::from)
                    .and_then(compile_source_gate)
            });
            assert!(result.is_ok(), "mutation {iteration} panicked");
            assert!(
                result.unwrap().is_err(),
                "mutation {iteration} was accepted"
            );
        }
    }

    #[test]
    fn long_amendment_lineage_replays_without_state_degradation() {
        let mut i = input();
        let mut parent = "base".to_owned();
        for sequence in 2..=258 {
            let id = format!("amendment-{sequence:03}");
            i.assertions.push(assertion(
                &id,
                if sequence == 258 {
                    SourceEvidenceState::Verified
                } else {
                    SourceEvidenceState::PartiallyVerified
                },
                sequence,
                Some(&parent),
            ));
            parent = id;
        }
        let first = compile_source_gate(i.clone()).unwrap();
        assert_eq!(first.assertions[0].state, SourceEvidenceState::Verified);
        assert_eq!(first.assertions[0].superseded_assertion_ids.len(), 257);
        verify_source_gate_projection(i, &first).unwrap();
    }

    #[test]
    fn program_migration_produces_an_attributable_cross_program_diff() {
        let previous = compile_source_gate(input()).unwrap();
        let mut migrated = input();
        migrated.program.id = "expanded-sources".into();
        migrated.program.version = "2".into();
        migrated.assertions.push(assertion(
            "new",
            SourceEvidenceState::Verified,
            2,
            Some("base"),
        ));
        migrated.previous_projection = Some(Box::new(previous.clone()));
        let projection = compile_source_gate(migrated).unwrap();
        assert_eq!(
            projection.previous_projection_sha256.as_deref(),
            Some(previous.projection_sha256.as_str())
        );
        assert_eq!(projection.changes.len(), 1);
        assert_eq!(
            projection.changes[0].previous_state,
            Some(SourceEvidenceState::Unresolved)
        );
        assert_eq!(
            projection.changes[0].current_state,
            Some(SourceEvidenceState::Verified)
        );
    }

    #[test]
    fn epact_lowering_preserves_tranche_scoped_waiver_semantics() {
        let mut source = input();
        source.program.tranches.push(SourceGateTranche {
            id: "full".into(),
            label: "Full".into(),
            requirement_ids: vec!["landfire.replacement".into()],
            historical_only: false,
        });
        source.authorities.push(SourceGateAuthority {
            contract: SOURCE_GATE_AUTHORITY_CONTRACT.into(),
            id: "operator-waiver".into(),
            campaign_id: "atr".into(),
            actor: "operator".into(),
            decision_kinds: vec![SourceGateDecisionKind::Waiver],
            requirement_ids: vec!["landfire.replacement".into()],
            tranche_ids: vec!["diagnostic".into()],
            active: true,
        });
        source.decisions.push(SourceGateDecision {
            contract: SOURCE_GATE_DECISION_CONTRACT.into(),
            id: "waive-diagnostic".into(),
            campaign_id: "atr".into(),
            kind: SourceGateDecisionKind::Waiver,
            requirement_id: "landfire.replacement".into(),
            source_id: "landfire".into(),
            scope_id: "lf2024".into(),
            tranche_ids: vec!["diagnostic".into()],
            authority_id: "operator-waiver".into(),
            rationale: "The diagnostic tranche can proceed without this field.".into(),
        });
        let compiled = compile_source_gate_epact(source).unwrap();
        assert!(compiled.image.activatable);
        assert_eq!(compiled.binding.requirements.len(), 1);
        assert_eq!(compiled.binding.tranches.len(), 2);
        assert_eq!(
            compiled
                .projection
                .tranches
                .iter()
                .find(|tranche| tranche.tranche_id == "diagnostic")
                .unwrap()
                .state,
            SourceTrancheState::EligibleUnapproved
        );
        assert_eq!(
            compiled
                .projection
                .tranches
                .iter()
                .find(|tranche| tranche.tranche_id == "full")
                .unwrap()
                .state,
            SourceTrancheState::Ineligible
        );
        let requirement = &compiled.binding.requirements[0];
        let diagnostic = requirement
            .tranche_bindings
            .iter()
            .find(|binding| binding.tranche_id == "diagnostic")
            .unwrap();
        let full = requirement
            .tranche_bindings
            .iter()
            .find(|binding| binding.tranche_id == "full")
            .unwrap();
        assert!(compiled
            .binding
            .fact_plan
            .satisfy_obligation_ids
            .contains(&diagnostic.obligation_id));
        assert!(!compiled
            .binding
            .fact_plan
            .satisfy_obligation_ids
            .contains(&full.obligation_id));
        assert!(compiled
            .binding
            .fact_plan
            .record_object_ids
            .contains(&diagnostic.waiver_object_id));
        assert!(!compiled
            .binding
            .fact_plan
            .record_object_ids
            .contains(&full.waiver_object_id));
    }
}
