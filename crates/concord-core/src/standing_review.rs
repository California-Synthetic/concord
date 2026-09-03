use crate::{
    AgentEvent, ResearchPlanDecision, ScienceArtifactAnnotation, ScienceArtifactDisposition,
    ScienceArtifactDispositionKind, ScienceArtifactReview, ScienceArtifactVersion,
    ScienceBatchReceipt, ScienceDecisionMemo, ScienceRankedTable, SemanticObject,
};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub const STANDING_REVIEW_RECEIPT_CONTRACT: &str = "concord.standing-review-receipt/1";
pub const STANDING_REVIEWER_ID: &str = "concord.standing-reviewer/1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScientificClaimClass {
    Observation,
    Calculation,
    Literature,
    ModelInference,
    Uncertainty,
}

impl ScientificClaimClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::Observation => "observation",
            Self::Calculation => "calculation",
            Self::Literature => "literature",
            Self::ModelInference => "model_inference",
            Self::Uncertainty => "uncertainty",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimReviewDisposition {
    RecordConsistent,
    MissingEvidence,
    MissingExecution,
    DisclosureOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewFindingSeverity {
    Notice,
    Attention,
    Blocking,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StandingReviewStatus {
    Clean,
    Attention,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimEvidenceBinding {
    pub claim_id: String,
    pub source_ref: String,
    pub class: ScientificClaimClass,
    pub statement: String,
    pub statement_sha256: String,
    pub evidence_refs: Vec<String>,
    pub execution_refs: Vec<String>,
    pub disposition: ClaimReviewDisposition,
    pub rationale: String,
    pub independent_validation_required: bool,
    pub binding_sha256: String,
}

impl ClaimEvidenceBinding {
    fn build(
        claim_id: String,
        source_ref: String,
        class: ScientificClaimClass,
        statement: String,
        evidence_refs: Vec<String>,
        execution_refs: Vec<String>,
    ) -> Result<Self> {
        let disposition = match class {
            ScientificClaimClass::Observation | ScientificClaimClass::Literature
                if evidence_refs.is_empty() =>
            {
                ClaimReviewDisposition::MissingEvidence
            }
            ScientificClaimClass::Calculation if execution_refs.is_empty() => {
                ClaimReviewDisposition::MissingExecution
            }
            ScientificClaimClass::ModelInference | ScientificClaimClass::Uncertainty => {
                ClaimReviewDisposition::DisclosureOnly
            }
            _ => ClaimReviewDisposition::RecordConsistent,
        };
        let rationale = match disposition {
            ClaimReviewDisposition::RecordConsistent => {
                "The typed claim points to the declared same-campaign record. This checks lineage, not scientific truth.".to_owned()
            }
            ClaimReviewDisposition::MissingEvidence => {
                "The claim class requires an exact evidence reference before decision use.".to_owned()
            }
            ClaimReviewDisposition::MissingExecution => {
                "The calculation requires an exact execution or denominator receipt.".to_owned()
            }
            ClaimReviewDisposition::DisclosureOnly => {
                "The statement is explicitly separated from observed or calculated evidence.".to_owned()
            }
        };
        let mut binding = Self {
            claim_id,
            source_ref,
            class,
            statement: statement.trim().to_owned(),
            statement_sha256: sha256(statement.trim().as_bytes()),
            evidence_refs,
            execution_refs,
            disposition,
            rationale,
            independent_validation_required: class != ScientificClaimClass::Uncertainty,
            binding_sha256: String::new(),
        };
        binding.validate_content()?;
        binding.binding_sha256 = hash_without_field(&binding, "bindingSha256")?;
        Ok(binding)
    }

    fn validate(&self) -> Result<()> {
        self.validate_content()?;
        if self.binding_sha256 != hash_without_field(self, "bindingSha256")? {
            bail!("claim evidence binding hash mismatch");
        }
        Ok(())
    }

    fn validate_content(&self) -> Result<()> {
        required(&self.claim_id, "claim id")?;
        required(&self.source_ref, "claim source")?;
        required(&self.statement, "claim statement")?;
        required(&self.rationale, "claim review rationale")?;
        validate_sha256(&self.statement_sha256, "statement hash")?;
        unique(&self.evidence_refs, "claim evidence references")?;
        unique(&self.execution_refs, "claim execution references")?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StandingReviewFinding {
    pub code: String,
    pub severity: ReviewFindingSeverity,
    pub subject_ref: String,
    pub message: String,
    pub required_action: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StandingReviewCoverage {
    pub assistant_messages: u32,
    pub agent_messages: u32,
    pub plan_decisions: u32,
    pub artifact_versions: u32,
    pub reviewed_artifact_versions: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub artifact_dispositions: u32,
    pub decision_memos: u32,
    pub typed_claims: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StandingReviewReceipt {
    pub contract: String,
    pub id: String,
    pub campaign_id: String,
    pub reviewer_id: String,
    pub scope: Vec<String>,
    pub input_sha256: String,
    pub previous_review_sha256: Option<String>,
    pub inspected_refs: Vec<String>,
    pub claim_bindings: Vec<ClaimEvidenceBinding>,
    pub findings: Vec<StandingReviewFinding>,
    pub coverage: StandingReviewCoverage,
    pub status: StandingReviewStatus,
    pub record_consistency_only: bool,
    pub created_at: String,
    pub review_sha256: String,
}

impl StandingReviewReceipt {
    pub fn validate(&self) -> Result<()> {
        if self.contract != STANDING_REVIEW_RECEIPT_CONTRACT
            || self.reviewer_id != STANDING_REVIEWER_ID
            || !self.record_consistency_only
        {
            bail!("standing review identity or authority boundary is invalid");
        }
        for (value, name) in [
            (&self.id, "standing review id"),
            (&self.campaign_id, "standing review campaign"),
            (&self.created_at, "standing review creation time"),
        ] {
            required(value, name)?;
        }
        validate_sha256(&self.input_sha256, "standing review input hash")?;
        if let Some(previous) = &self.previous_review_sha256 {
            validate_sha256(previous, "previous standing review hash")?;
        }
        unique_nonempty(&self.scope, "standing review scope")?;
        unique(&self.inspected_refs, "standing review inspected references")?;
        for binding in &self.claim_bindings {
            binding.validate()?;
        }
        let claim_ids = self
            .claim_bindings
            .iter()
            .map(|binding| binding.claim_id.as_str())
            .collect::<HashSet<_>>();
        if claim_ids.len() != self.claim_bindings.len() {
            bail!("standing review claim identities must be unique");
        }
        for finding in &self.findings {
            for (value, name) in [
                (&finding.code, "finding code"),
                (&finding.subject_ref, "finding subject"),
                (&finding.message, "finding message"),
                (&finding.required_action, "finding required action"),
            ] {
                required(value, name)?;
            }
        }
        let expected_status = status_for_findings(&self.findings);
        if self.status != expected_status {
            bail!("standing review status does not match its findings");
        }
        if self.review_sha256 != hash_without_field(self, "reviewSha256")? {
            bail!("standing review receipt hash mismatch");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StandingReviewWorkspace {
    pub latest: Option<StandingReviewReceipt>,
    pub history: Vec<StandingReviewReceipt>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StandingReviewInput<'a> {
    pub campaign_id: &'a str,
    pub assistant_messages: Vec<&'a SemanticObject>,
    pub agent_messages: Vec<&'a AgentEvent>,
    pub plan_decisions: Vec<&'a ResearchPlanDecision>,
    pub artifact_versions: &'a [ScienceArtifactVersion],
    pub annotations: &'a [ScienceArtifactAnnotation],
    pub artifact_reviews: &'a [ScienceArtifactReview],
    pub artifact_dispositions: &'a [ScienceArtifactDisposition],
    pub batches: &'a [ScienceBatchReceipt],
    pub ranked_tables: &'a [ScienceRankedTable],
    pub decision_memos: &'a [ScienceDecisionMemo],
}

pub fn compile_standing_review(
    input: &StandingReviewInput<'_>,
    previous_review_sha256: Option<String>,
    created_at: String,
) -> Result<StandingReviewReceipt> {
    let input_sha256 = sha256(&serde_json::to_vec(input)?);
    let mut inspected_refs = Vec::new();
    inspected_refs.extend(
        input
            .assistant_messages
            .iter()
            .map(|message| {
                Ok(format!(
                    "research-message:{}@sha256:{}",
                    message.id,
                    sha256(&serde_json::to_vec(message)?),
                ))
            })
            .collect::<Result<Vec<_>>>()?,
    );
    inspected_refs.extend(input.agent_messages.iter().map(|event| {
        format!(
            "agent-event:{}:{}@sha256:{}",
            event.agent_run_id, event.sequence, event.event_sha256
        )
    }));
    inspected_refs.extend(input.plan_decisions.iter().map(|decision| {
        format!(
            "plan-decision:{}@sha256:{}",
            decision.id, decision.decision_sha256
        )
    }));
    inspected_refs.extend(input.artifact_versions.iter().map(artifact_version_ref));
    inspected_refs.extend(input.annotations.iter().map(|annotation| {
        format!(
            "artifact-annotation:{}@sha256:{}",
            annotation.id, annotation.annotation_sha256
        )
    }));
    inspected_refs.extend(input.artifact_reviews.iter().map(|review| {
        format!(
            "artifact-review:{}@sha256:{}",
            review.id, review.review_sha256
        )
    }));
    inspected_refs.extend(input.artifact_dispositions.iter().map(|disposition| {
        format!(
            "artifact-disposition:{}@sha256:{}",
            disposition.id, disposition.disposition_sha256
        )
    }));
    inspected_refs.extend(
        input
            .batches
            .iter()
            .map(|batch| format!("batch-receipt:{}@sha256:{}", batch.id, batch.receipt_sha256)),
    );
    inspected_refs.extend(
        input
            .ranked_tables
            .iter()
            .map(|table| format!("ranked-table:{}@sha256:{}", table.id, table.table_sha256)),
    );
    inspected_refs.extend(input.decision_memos.iter().map(decision_memo_ref));
    inspected_refs.sort();
    inspected_refs.dedup();

    let mut reviewed_versions = input
        .artifact_reviews
        .iter()
        .map(|review| review.artifact_version_id.as_str())
        .collect::<HashSet<_>>();
    reviewed_versions.extend(
        input
            .artifact_dispositions
            .iter()
            .filter(|record| record.disposition == ScienceArtifactDispositionKind::Accepted)
            .map(|record| record.artifact_version_id.as_str()),
    );
    let mut findings = Vec::new();
    for version in input.artifact_versions {
        if !reviewed_versions.contains(version.id.as_str()) {
            findings.push(StandingReviewFinding {
                code: "artifact_review_missing".to_owned(),
                severity: ReviewFindingSeverity::Attention,
                subject_ref: artifact_version_ref(version),
                message: "No independent review targets this exact immutable artifact version."
                    .to_owned(),
                required_action:
                    "Assign a reviewer run distinct from the producer and record its exact checks."
                        .to_owned(),
            });
        }
    }
    for review in input.artifact_reviews {
        let has_material_finding = !matches!(
            review.status.as_str(),
            "clean" | "passed" | "accepted" | "complete"
        ) || !review.findings.is_empty();
        let corrected = input.artifact_versions.iter().any(|version| {
            version.parent_version_id.as_deref() == Some(&review.artifact_version_id)
        });
        if has_material_finding && !corrected {
            findings.push(StandingReviewFinding {
                code: "review_finding_unresolved".to_owned(),
                severity: ReviewFindingSeverity::Attention,
                subject_ref: format!(
                    "artifact-review:{}@sha256:{}",
                    review.id, review.review_sha256
                ),
                message: "The independent review has findings but no immutable corrected child version."
                    .to_owned(),
                required_action: "Create a corrected child or record an explicit decision that preserves the dissent."
                    .to_owned(),
            });
        }
    }
    let disposed_versions = input
        .artifact_dispositions
        .iter()
        .map(|record| record.artifact_version_id.as_str())
        .collect::<HashSet<_>>();
    for version in input.artifact_versions {
        let is_leaf = !input
            .artifact_versions
            .iter()
            .any(|candidate| candidate.parent_version_id.as_deref() == Some(version.id.as_str()));
        if is_leaf
            && reviewed_versions.contains(version.id.as_str())
            && !disposed_versions.contains(version.id.as_str())
        {
            findings.push(StandingReviewFinding {
                code: "artifact_disposition_missing".to_owned(),
                severity: ReviewFindingSeverity::Attention,
                subject_ref: artifact_version_ref(version),
                message: "The current reviewed artifact has no operator acceptance or revision request.".to_owned(),
                required_action: "Inspect the exact version and record an operator disposition bound to its annotations and review lineage.".to_owned(),
            });
        }
    }

    let version_refs = input
        .artifact_versions
        .iter()
        .map(|version| (version.id.as_str(), artifact_version_ref(version)))
        .collect::<std::collections::HashMap<_, _>>();
    let batch_refs = input
        .batches
        .iter()
        .map(|batch| {
            (
                batch.id.as_str(),
                format!("batch-receipt:{}@sha256:{}", batch.id, batch.receipt_sha256),
            )
        })
        .collect::<std::collections::HashMap<_, _>>();
    let table_refs = input
        .ranked_tables
        .iter()
        .map(|table| {
            (
                table.id.as_str(),
                format!("ranked-table:{}@sha256:{}", table.id, table.table_sha256),
            )
        })
        .collect::<std::collections::HashMap<_, _>>();
    let mut claim_bindings = Vec::new();
    for memo in input.decision_memos {
        let source_ref = decision_memo_ref(memo);
        let evidence_refs = memo
            .source_artifact_version_ids
            .iter()
            .filter_map(|id| version_refs.get(id.as_str()).cloned())
            .collect::<Vec<_>>();
        let execution_refs = [
            batch_refs.get(memo.batch_receipt_id.as_str()),
            table_refs.get(memo.ranked_table_id.as_str()),
        ]
        .into_iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>();
        for (class, statements) in [
            (ScientificClaimClass::Observation, &memo.observations),
            (ScientificClaimClass::Calculation, &memo.calculations),
            (ScientificClaimClass::Literature, &memo.literature),
            (ScientificClaimClass::ModelInference, &memo.model_inference),
            (ScientificClaimClass::Uncertainty, &memo.uncertainty),
        ] {
            for (index, statement) in statements.iter().enumerate() {
                let claim_id = format!("{}:{}:{}", memo.id, class.as_str(), index + 1);
                let claim_execution_refs = if class == ScientificClaimClass::Calculation {
                    execution_refs.clone()
                } else {
                    Vec::new()
                };
                let claim_evidence_refs = if matches!(
                    class,
                    ScientificClaimClass::ModelInference | ScientificClaimClass::Uncertainty
                ) {
                    Vec::new()
                } else {
                    evidence_refs.clone()
                };
                claim_bindings.push(ClaimEvidenceBinding::build(
                    claim_id,
                    source_ref.clone(),
                    class,
                    statement.clone(),
                    claim_evidence_refs,
                    claim_execution_refs,
                )?);
            }
        }
    }
    for binding in &claim_bindings {
        match binding.disposition {
            ClaimReviewDisposition::MissingEvidence | ClaimReviewDisposition::MissingExecution => {
                findings.push(StandingReviewFinding {
                    code: "claim_binding_incomplete".to_owned(),
                    severity: ReviewFindingSeverity::Blocking,
                    subject_ref: binding.claim_id.clone(),
                    message: binding.rationale.clone(),
                    required_action:
                        "Bind the claim to the exact canonical evidence or execution record."
                            .to_owned(),
                });
            }
            _ => {}
        }
    }
    let coverage = StandingReviewCoverage {
        assistant_messages: input.assistant_messages.len().try_into()?,
        agent_messages: input.agent_messages.len().try_into()?,
        plan_decisions: input.plan_decisions.len().try_into()?,
        artifact_versions: input.artifact_versions.len().try_into()?,
        reviewed_artifact_versions: reviewed_versions.len().try_into()?,
        artifact_dispositions: input.artifact_dispositions.len().try_into()?,
        decision_memos: input.decision_memos.len().try_into()?,
        typed_claims: claim_bindings.len().try_into()?,
    };
    let status = status_for_findings(&findings);
    let mut receipt = StandingReviewReceipt {
        contract: STANDING_REVIEW_RECEIPT_CONTRACT.to_owned(),
        id: format!("standing_review_{input_sha256}"),
        campaign_id: input.campaign_id.to_owned(),
        reviewer_id: STANDING_REVIEWER_ID.to_owned(),
        scope: vec![
            "record_consistency".to_owned(),
            "claim_evidence_binding".to_owned(),
            "artifact_correction_lineage".to_owned(),
        ],
        input_sha256,
        previous_review_sha256,
        inspected_refs,
        claim_bindings,
        findings,
        coverage,
        status,
        record_consistency_only: true,
        created_at,
        review_sha256: String::new(),
    };
    receipt.review_sha256 = hash_without_field(&receipt, "reviewSha256")?;
    receipt.validate()?;
    Ok(receipt)
}

fn artifact_version_ref(version: &ScienceArtifactVersion) -> String {
    format!(
        "artifact-version:{}@sha256:{}",
        version.id, version.version_sha256
    )
}

fn decision_memo_ref(memo: &ScienceDecisionMemo) -> String {
    format!("decision-memo:{}@sha256:{}", memo.id, memo.memo_sha256)
}

fn status_for_findings(findings: &[StandingReviewFinding]) -> StandingReviewStatus {
    if findings
        .iter()
        .any(|finding| finding.severity == ReviewFindingSeverity::Blocking)
    {
        StandingReviewStatus::Blocked
    } else if findings
        .iter()
        .any(|finding| finding.severity == ReviewFindingSeverity::Attention)
    {
        StandingReviewStatus::Attention
    } else {
        StandingReviewStatus::Clean
    }
}

fn hash_without_field<T: Serialize>(value: &T, field: &str) -> Result<String> {
    let mut value = serde_json::to_value(value)?;
    value.as_object_mut().map(|object| object.remove(field));
    Ok(sha256(&serde_json::to_vec(&value)?))
}

fn sha256(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn is_zero(value: &u32) -> bool {
    *value == 0
}

fn validate_sha256(value: &str, name: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{name} is invalid");
    }
    Ok(())
}

fn required(value: &str, name: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{name} is required");
    }
    Ok(())
}

fn unique(values: &[String], name: &str) -> Result<()> {
    if values.iter().any(|value| value.trim().is_empty())
        || values.iter().collect::<HashSet<_>>().len() != values.len()
    {
        bail!("{name} must be unique and nonempty when present");
    }
    Ok(())
}

fn unique_nonempty(values: &[String], name: &str) -> Result<()> {
    if values.is_empty() {
        bail!("{name} must not be empty");
    }
    unique(values, name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_artifact_disposition_coverage_preserves_legacy_receipt_shape() {
        let coverage = StandingReviewCoverage::default();
        let serialized = serde_json::to_value(&coverage).unwrap();
        assert!(serialized.get("artifactDispositions").is_none());

        let restored: StandingReviewCoverage = serde_json::from_value(serialized).unwrap();
        assert_eq!(restored.artifact_dispositions, 0);

        let current = StandingReviewCoverage {
            artifact_dispositions: 1,
            ..StandingReviewCoverage::default()
        };
        assert_eq!(
            serde_json::to_value(current).unwrap()["artifactDispositions"],
            1
        );
    }

    #[test]
    fn review_receipt_does_not_confuse_record_consistency_with_validation() {
        let input = StandingReviewInput {
            campaign_id: "campaign-1",
            assistant_messages: vec![],
            agent_messages: vec![],
            plan_decisions: vec![],
            artifact_versions: &[],
            annotations: &[],
            artifact_reviews: &[],
            artifact_dispositions: &[],
            batches: &[],
            ranked_tables: &[],
            decision_memos: &[],
        };
        let receipt = compile_standing_review(&input, None, "2026-08-23T00:00:00Z".into()).unwrap();
        assert_eq!(receipt.status, StandingReviewStatus::Clean);
        assert!(receipt.record_consistency_only);
        receipt.validate().unwrap();

        let mut tampered = receipt;
        tampered.record_consistency_only = false;
        assert!(tampered.validate().is_err());
    }

    #[test]
    fn typed_decision_claims_bind_to_evidence_and_execution_by_class() {
        let version = ScienceArtifactVersion {
            contract: "concord.science-artifact-version/1".into(),
            id: "version-1".into(),
            campaign_id: "campaign-1".into(),
            version: 1,
            title: "Result".into(),
            kind: "figure".into(),
            producing_agent_run_id: "producer".into(),
            parent_version_id: None,
            artifact_ids: vec!["artifact-1".into()],
            source_version_ids: vec![],
            plan_id: "plan-1".into(),
            phase_id: "phase-1".into(),
            status: "review_required".into(),
            metadata: serde_json::json!({}),
            version_sha256: "a".repeat(64),
            created_at: "2026-08-23T00:00:00Z".into(),
        };
        let batch = ScienceBatchReceipt {
            contract: "concord.science-batch-receipt/1".into(),
            id: "batch-1".into(),
            campaign_id: "campaign-1".into(),
            label: "Batch".into(),
            producing_agent_run_id: "producer".into(),
            expected_job_ids: vec![],
            jobs: vec![],
            expected: 0,
            completed: 0,
            failed: 0,
            missing: 0,
            denominator_locked: true,
            receipt_sha256: "b".repeat(64),
            created_at: "2026-08-23T00:00:00Z".into(),
        };
        let table = ScienceRankedTable {
            contract: "concord.science-ranked-table/1".into(),
            id: "table-1".into(),
            campaign_id: "campaign-1".into(),
            title: "Ranking".into(),
            rows: vec![],
            table_sha256: "c".repeat(64),
            created_at: "2026-08-23T00:00:00Z".into(),
        };
        let memo = ScienceDecisionMemo {
            contract: "concord.science-decision-memo/1".into(),
            id: "memo-1".into(),
            campaign_id: "campaign-1".into(),
            title: "Decision".into(),
            decision: "conditional_go".into(),
            observations: vec!["The saved result contains the declared row.".into()],
            calculations: vec!["The denominator retains every declared job.".into()],
            literature: vec!["The cited source states the declared method.".into()],
            model_inference: vec!["A follow-up may be worthwhile.".into()],
            uncertainty: vec!["External validity remains unknown.".into()],
            first_decisive_experiment: "Run the prospective test.".into(),
            kill_criteria: vec!["Stop on denominator drift.".into()],
            source_artifact_version_ids: vec![version.id.clone()],
            batch_receipt_id: batch.id.clone(),
            ranked_table_id: table.id.clone(),
            memo_sha256: "d".repeat(64),
            created_at: "2026-08-23T00:00:00Z".into(),
        };
        let receipt = compile_standing_review(
            &StandingReviewInput {
                campaign_id: "campaign-1",
                assistant_messages: vec![],
                agent_messages: vec![],
                plan_decisions: vec![],
                artifact_versions: &[version],
                annotations: &[],
                artifact_reviews: &[],
                artifact_dispositions: &[],
                batches: &[batch],
                ranked_tables: &[table],
                decision_memos: &[memo],
            },
            None,
            "2026-08-23T00:01:00Z".into(),
        )
        .unwrap();
        assert_eq!(receipt.claim_bindings.len(), 5);
        let calculation = receipt
            .claim_bindings
            .iter()
            .find(|binding| binding.class == ScientificClaimClass::Calculation)
            .unwrap();
        assert_eq!(
            calculation.disposition,
            ClaimReviewDisposition::RecordConsistent
        );
        assert_eq!(calculation.evidence_refs.len(), 1);
        assert_eq!(calculation.execution_refs.len(), 2);
        let inference = receipt
            .claim_bindings
            .iter()
            .find(|binding| binding.class == ScientificClaimClass::ModelInference)
            .unwrap();
        assert_eq!(
            inference.disposition,
            ClaimReviewDisposition::DisclosureOnly
        );
        assert!(receipt
            .findings
            .iter()
            .any(|finding| finding.code == "artifact_review_missing"));
        receipt.validate().unwrap();
    }
}
