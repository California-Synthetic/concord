use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub const SCIENCE_ARTIFACT_VERSION_CONTRACT: &str = "concord.science-artifact-version/1";
pub const SCIENCE_ARTIFACT_ANNOTATION_CONTRACT: &str = "concord.science-artifact-annotation/1";
pub const SCIENCE_ARTIFACT_REVIEW_CONTRACT: &str = "concord.science-artifact-review/1";
pub const SCIENCE_ARTIFACT_DISPOSITION_CONTRACT: &str = "concord.science-artifact-disposition/1";
pub const SCIENCE_BATCH_RECEIPT_CONTRACT: &str = "concord.science-batch-receipt/1";
pub const SCIENCE_RANKED_TABLE_CONTRACT: &str = "concord.science-ranked-table/1";
pub const SCIENCE_DECISION_MEMO_CONTRACT: &str = "concord.science-decision-memo/1";

fn hash_without_field<T: Serialize>(value: &T, field: &str) -> Result<String> {
    let mut value = serde_json::to_value(value)?;
    value.as_object_mut().map(|object| object.remove(field));
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(&value)?)))
}

fn required(value: &str, name: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{name} is required");
    }
    Ok(())
}

fn unique_nonempty(values: &[String], name: &str) -> Result<()> {
    let mut seen = HashSet::new();
    if values.is_empty()
        || values
            .iter()
            .any(|value| value.trim().is_empty() || !seen.insert(value))
    {
        bail!("{name} must be nonempty and unique");
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateScienceArtifactVersionRequest {
    pub title: String,
    pub kind: String,
    pub producing_agent_run_id: String,
    #[serde(default)]
    pub parent_version_id: Option<String>,
    pub artifact_ids: Vec<String>,
    #[serde(default)]
    pub source_version_ids: Vec<String>,
    pub plan_id: String,
    pub phase_id: String,
    pub status: String,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScienceArtifactVersion {
    pub contract: String,
    pub id: String,
    pub campaign_id: String,
    pub version: u32,
    pub title: String,
    pub kind: String,
    pub producing_agent_run_id: String,
    pub parent_version_id: Option<String>,
    pub artifact_ids: Vec<String>,
    pub source_version_ids: Vec<String>,
    pub plan_id: String,
    pub phase_id: String,
    pub status: String,
    pub metadata: Value,
    pub version_sha256: String,
    pub created_at: String,
}

impl ScienceArtifactVersion {
    pub fn build(
        id: String,
        campaign_id: String,
        version: u32,
        request: CreateScienceArtifactVersionRequest,
        created_at: String,
    ) -> Result<Self> {
        let mut record = Self {
            contract: SCIENCE_ARTIFACT_VERSION_CONTRACT.into(),
            id,
            campaign_id,
            version,
            title: request.title.trim().into(),
            kind: request.kind.trim().into(),
            producing_agent_run_id: request.producing_agent_run_id,
            parent_version_id: request.parent_version_id,
            artifact_ids: request.artifact_ids,
            source_version_ids: request.source_version_ids,
            plan_id: request.plan_id,
            phase_id: request.phase_id,
            status: request.status.trim().into(),
            metadata: request.metadata,
            version_sha256: String::new(),
            created_at,
        };
        record.validate_content()?;
        record.version_sha256 = hash_without_field(&record, "versionSha256")?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_content()?;
        if self.version_sha256 != hash_without_field(self, "versionSha256")? {
            bail!("science artifact version hash mismatch");
        }
        Ok(())
    }

    fn validate_content(&self) -> Result<()> {
        if self.contract != SCIENCE_ARTIFACT_VERSION_CONTRACT || self.version == 0 {
            bail!("science artifact version identity is invalid");
        }
        for (value, name) in [
            (&self.id, "artifact version id"),
            (&self.campaign_id, "campaign id"),
            (&self.title, "title"),
            (&self.kind, "kind"),
            (&self.producing_agent_run_id, "producer run"),
            (&self.plan_id, "plan id"),
            (&self.phase_id, "phase id"),
            (&self.status, "status"),
        ] {
            required(value, name)?;
        }
        unique_nonempty(&self.artifact_ids, "artifact ids")?;
        if self
            .source_version_ids
            .iter()
            .any(|value| value.trim().is_empty())
        {
            bail!("source version ids are invalid");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateScienceArtifactAnnotationRequest {
    pub artifact_version_id: String,
    pub actor: String,
    pub category: String,
    pub body: String,
    #[serde(default)]
    pub anchor: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScienceArtifactAnnotation {
    pub contract: String,
    pub id: String,
    pub campaign_id: String,
    pub artifact_version_id: String,
    pub actor: String,
    pub category: String,
    pub body: String,
    pub anchor: Value,
    pub previous_annotation_sha256: Option<String>,
    pub annotation_sha256: String,
    pub created_at: String,
}

impl ScienceArtifactAnnotation {
    pub fn build(
        id: String,
        campaign_id: String,
        request: CreateScienceArtifactAnnotationRequest,
        previous_annotation_sha256: Option<String>,
        created_at: String,
    ) -> Result<Self> {
        let mut record = Self {
            contract: SCIENCE_ARTIFACT_ANNOTATION_CONTRACT.into(),
            id,
            campaign_id,
            artifact_version_id: request.artifact_version_id,
            actor: request.actor.trim().into(),
            category: request.category.trim().into(),
            body: request.body.trim().into(),
            anchor: request.anchor,
            previous_annotation_sha256,
            annotation_sha256: String::new(),
            created_at,
        };
        for (value, name) in [
            (&record.id, "annotation id"),
            (&record.campaign_id, "campaign id"),
            (&record.artifact_version_id, "artifact version id"),
            (&record.actor, "actor"),
            (&record.category, "category"),
            (&record.body, "body"),
        ] {
            required(value, name)?;
        }
        record.annotation_sha256 = hash_without_field(&record, "annotationSha256")?;
        Ok(record)
    }
    pub fn validate(&self) -> Result<()> {
        if self.contract != SCIENCE_ARTIFACT_ANNOTATION_CONTRACT
            || self.annotation_sha256 != hash_without_field(self, "annotationSha256")?
        {
            bail!("science artifact annotation is invalid");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateScienceArtifactReviewRequest {
    pub artifact_version_id: String,
    pub reviewer_agent_run_id: String,
    pub status: String,
    pub findings: Vec<Value>,
    pub checked: Vec<String>,
    pub review_artifact_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScienceArtifactReview {
    pub contract: String,
    pub id: String,
    pub campaign_id: String,
    pub artifact_version_id: String,
    pub reviewer_agent_run_id: String,
    pub status: String,
    pub findings: Vec<Value>,
    pub checked: Vec<String>,
    pub review_artifact_ids: Vec<String>,
    pub review_sha256: String,
    pub created_at: String,
}

impl ScienceArtifactReview {
    pub fn build(
        id: String,
        campaign_id: String,
        request: CreateScienceArtifactReviewRequest,
        created_at: String,
    ) -> Result<Self> {
        let mut record = Self {
            contract: SCIENCE_ARTIFACT_REVIEW_CONTRACT.into(),
            id,
            campaign_id,
            artifact_version_id: request.artifact_version_id,
            reviewer_agent_run_id: request.reviewer_agent_run_id,
            status: request.status,
            findings: request.findings,
            checked: request.checked,
            review_artifact_ids: request.review_artifact_ids,
            review_sha256: String::new(),
            created_at,
        };
        for (value, name) in [
            (&record.id, "review id"),
            (&record.campaign_id, "campaign id"),
            (&record.artifact_version_id, "artifact version id"),
            (&record.reviewer_agent_run_id, "reviewer run"),
            (&record.status, "review status"),
        ] {
            required(value, name)?;
        }
        unique_nonempty(&record.checked, "review checks")?;
        unique_nonempty(&record.review_artifact_ids, "review artifacts")?;
        record.review_sha256 = hash_without_field(&record, "reviewSha256")?;
        Ok(record)
    }
    pub fn validate(&self) -> Result<()> {
        if self.contract != SCIENCE_ARTIFACT_REVIEW_CONTRACT
            || self.review_sha256 != hash_without_field(self, "reviewSha256")?
        {
            bail!("science artifact review is invalid");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScienceArtifactDispositionKind {
    RevisionRequested,
    Accepted,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateScienceArtifactDispositionRequest {
    pub artifact_version_id: String,
    pub actor: String,
    pub disposition: ScienceArtifactDispositionKind,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScienceArtifactDisposition {
    pub contract: String,
    pub id: String,
    pub campaign_id: String,
    pub artifact_version_id: String,
    pub actor: String,
    pub disposition: ScienceArtifactDispositionKind,
    pub rationale: String,
    pub annotation_ids: Vec<String>,
    pub review_ids: Vec<String>,
    pub previous_disposition_sha256: Option<String>,
    pub disposition_sha256: String,
    pub created_at: String,
}

impl ScienceArtifactDisposition {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        id: String,
        campaign_id: String,
        request: CreateScienceArtifactDispositionRequest,
        annotation_ids: Vec<String>,
        review_ids: Vec<String>,
        previous_disposition_sha256: Option<String>,
        created_at: String,
    ) -> Result<Self> {
        let mut record = Self {
            contract: SCIENCE_ARTIFACT_DISPOSITION_CONTRACT.into(),
            id,
            campaign_id,
            artifact_version_id: request.artifact_version_id,
            actor: request.actor.trim().into(),
            disposition: request.disposition,
            rationale: request.rationale.trim().into(),
            annotation_ids,
            review_ids,
            previous_disposition_sha256,
            disposition_sha256: String::new(),
            created_at,
        };
        record.validate_content()?;
        record.disposition_sha256 = hash_without_field(&record, "dispositionSha256")?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_content()?;
        if self.disposition_sha256 != hash_without_field(self, "dispositionSha256")? {
            bail!("science artifact disposition hash mismatch");
        }
        Ok(())
    }

    fn validate_content(&self) -> Result<()> {
        if self.contract != SCIENCE_ARTIFACT_DISPOSITION_CONTRACT {
            bail!("science artifact disposition identity is invalid");
        }
        for (value, name) in [
            (&self.id, "disposition id"),
            (&self.campaign_id, "campaign id"),
            (&self.artifact_version_id, "artifact version id"),
            (&self.actor, "disposition actor"),
            (&self.rationale, "disposition rationale"),
            (&self.created_at, "disposition creation time"),
        ] {
            required(value, name)?;
        }
        unique_nonempty(&self.annotation_ids, "disposition annotation ids")?;
        if self.disposition == ScienceArtifactDispositionKind::Accepted {
            unique_nonempty(&self.review_ids, "accepted disposition review ids")?;
        } else if self.review_ids.iter().any(|value| value.trim().is_empty()) {
            bail!("disposition review ids are invalid");
        }
        if let Some(previous) = &self.previous_disposition_sha256 {
            required(previous, "previous disposition hash")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScienceBatchJob {
    pub id: String,
    pub status: String,
    pub artifact_id: Option<String>,
    pub failure: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateScienceBatchReceiptRequest {
    pub label: String,
    pub producing_agent_run_id: String,
    pub expected_job_ids: Vec<String>,
    pub jobs: Vec<ScienceBatchJob>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScienceBatchReceipt {
    pub contract: String,
    pub id: String,
    pub campaign_id: String,
    pub label: String,
    pub producing_agent_run_id: String,
    pub expected_job_ids: Vec<String>,
    pub jobs: Vec<ScienceBatchJob>,
    pub expected: u32,
    pub completed: u32,
    pub failed: u32,
    pub missing: u32,
    pub denominator_locked: bool,
    pub receipt_sha256: String,
    pub created_at: String,
}

impl ScienceBatchReceipt {
    pub fn build(
        id: String,
        campaign_id: String,
        request: CreateScienceBatchReceiptRequest,
        created_at: String,
    ) -> Result<Self> {
        unique_nonempty(&request.expected_job_ids, "expected job ids")?;
        let expected_set = request.expected_job_ids.iter().collect::<HashSet<_>>();
        let mut observed = HashSet::new();
        for job in &request.jobs {
            required(&job.id, "batch job id")?;
            if !expected_set.contains(&job.id) || !observed.insert(&job.id) {
                bail!("batch jobs must map one-to-one into the frozen denominator");
            }
            if !matches!(job.status.as_str(), "completed" | "failed") {
                bail!("batch job status must be completed or failed");
            }
            if job.status == "completed" && job.artifact_id.is_none() {
                bail!("completed batch jobs require an artifact");
            }
            if job.status == "failed" && job.failure.as_deref().unwrap_or("").trim().is_empty() {
                bail!("failed batch jobs require a reason");
            }
        }
        let expected = expected_set.len() as u32;
        let completed = request
            .jobs
            .iter()
            .filter(|job| job.status == "completed")
            .count() as u32;
        let failed = request
            .jobs
            .iter()
            .filter(|job| job.status == "failed")
            .count() as u32;
        let missing = request.expected_job_ids.len() as u32 - request.jobs.len() as u32;
        let mut record = Self {
            contract: SCIENCE_BATCH_RECEIPT_CONTRACT.into(),
            id,
            campaign_id,
            label: request.label,
            producing_agent_run_id: request.producing_agent_run_id,
            expected_job_ids: request.expected_job_ids,
            jobs: request.jobs,
            expected,
            completed,
            failed,
            missing,
            denominator_locked: true,
            receipt_sha256: String::new(),
            created_at,
        };
        record.receipt_sha256 = hash_without_field(&record, "receiptSha256")?;
        Ok(record)
    }
    pub fn validate(&self) -> Result<()> {
        if self.contract != SCIENCE_BATCH_RECEIPT_CONTRACT
            || !self.denominator_locked
            || self.receipt_sha256 != hash_without_field(self, "receiptSha256")?
            || self.completed + self.failed + self.missing != self.expected
        {
            bail!("science batch receipt is invalid");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScienceRankedRow {
    pub rank: u32,
    pub candidate_id: String,
    pub label: String,
    pub score: f64,
    pub source_artifact_version_ids: Vec<String>,
    pub method: String,
    pub filters: Vec<String>,
    pub independent_review_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateScienceRankedTableRequest {
    pub title: String,
    pub rows: Vec<ScienceRankedRow>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScienceRankedTable {
    pub contract: String,
    pub id: String,
    pub campaign_id: String,
    pub title: String,
    pub rows: Vec<ScienceRankedRow>,
    pub table_sha256: String,
    pub created_at: String,
}

impl ScienceRankedTable {
    pub fn build(
        id: String,
        campaign_id: String,
        title: String,
        rows: Vec<ScienceRankedRow>,
        created_at: String,
    ) -> Result<Self> {
        if rows.is_empty() {
            bail!("ranked table requires rows");
        }
        for (index, row) in rows.iter().enumerate() {
            if row.rank != index as u32 + 1 || !row.score.is_finite() {
                bail!("ranked rows must have contiguous ranks and finite scores");
            }
            required(&row.candidate_id, "candidate id")?;
            required(&row.method, "ranking method")?;
            required(&row.independent_review_id, "independent review")?;
            unique_nonempty(&row.source_artifact_version_ids, "ranked row sources")?;
        }
        let mut record = Self {
            contract: SCIENCE_RANKED_TABLE_CONTRACT.into(),
            id,
            campaign_id,
            title,
            rows,
            table_sha256: String::new(),
            created_at,
        };
        record.table_sha256 = hash_without_field(&record, "tableSha256")?;
        Ok(record)
    }
    pub fn validate(&self) -> Result<()> {
        if self.contract != SCIENCE_RANKED_TABLE_CONTRACT
            || self.table_sha256 != hash_without_field(self, "tableSha256")?
        {
            bail!("science ranked table is invalid");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateScienceDecisionMemoRequest {
    pub title: String,
    pub decision: String,
    pub observations: Vec<String>,
    pub calculations: Vec<String>,
    pub literature: Vec<String>,
    pub model_inference: Vec<String>,
    pub uncertainty: Vec<String>,
    pub first_decisive_experiment: String,
    pub kill_criteria: Vec<String>,
    pub source_artifact_version_ids: Vec<String>,
    pub batch_receipt_id: String,
    pub ranked_table_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScienceDecisionMemo {
    pub contract: String,
    pub id: String,
    pub campaign_id: String,
    pub title: String,
    pub decision: String,
    pub observations: Vec<String>,
    pub calculations: Vec<String>,
    pub literature: Vec<String>,
    pub model_inference: Vec<String>,
    pub uncertainty: Vec<String>,
    pub first_decisive_experiment: String,
    pub kill_criteria: Vec<String>,
    pub source_artifact_version_ids: Vec<String>,
    pub batch_receipt_id: String,
    pub ranked_table_id: String,
    pub memo_sha256: String,
    pub created_at: String,
}

impl ScienceDecisionMemo {
    pub fn build(
        id: String,
        campaign_id: String,
        request: CreateScienceDecisionMemoRequest,
        created_at: String,
    ) -> Result<Self> {
        if request.decision != "conditional_go" && request.decision != "no_go" {
            bail!("decision memo must be conditional_go or no_go");
        }
        for values in [
            &request.observations,
            &request.calculations,
            &request.literature,
            &request.model_inference,
            &request.uncertainty,
            &request.kill_criteria,
        ] {
            unique_nonempty(values, "decision memo section")?;
        }
        unique_nonempty(
            &request.source_artifact_version_ids,
            "decision memo sources",
        )?;
        let mut record = Self {
            contract: SCIENCE_DECISION_MEMO_CONTRACT.into(),
            id,
            campaign_id,
            title: request.title,
            decision: request.decision,
            observations: request.observations,
            calculations: request.calculations,
            literature: request.literature,
            model_inference: request.model_inference,
            uncertainty: request.uncertainty,
            first_decisive_experiment: request.first_decisive_experiment,
            kill_criteria: request.kill_criteria,
            source_artifact_version_ids: request.source_artifact_version_ids,
            batch_receipt_id: request.batch_receipt_id,
            ranked_table_id: request.ranked_table_id,
            memo_sha256: String::new(),
            created_at,
        };
        required(
            &record.first_decisive_experiment,
            "first decisive experiment",
        )?;
        record.memo_sha256 = hash_without_field(&record, "memoSha256")?;
        Ok(record)
    }
    pub fn validate(&self) -> Result<()> {
        if self.contract != SCIENCE_DECISION_MEMO_CONTRACT
            || self.memo_sha256 != hash_without_field(self, "memoSha256")?
        {
            bail!("science decision memo is invalid");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScienceArtifactWorkspace {
    pub versions: Vec<ScienceArtifactVersion>,
    pub annotations: Vec<ScienceArtifactAnnotation>,
    pub reviews: Vec<ScienceArtifactReview>,
    #[serde(default)]
    pub dispositions: Vec<ScienceArtifactDisposition>,
    pub batches: Vec<ScienceBatchReceipt>,
    pub ranked_tables: Vec<ScienceRankedTable>,
    pub decision_memos: Vec<ScienceDecisionMemo>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_workspace_serializes_every_collection() {
        let serialized = serde_json::to_value(ScienceArtifactWorkspace::default()).unwrap();
        for field in [
            "versions",
            "annotations",
            "reviews",
            "dispositions",
            "batches",
            "rankedTables",
            "decisionMemos",
        ] {
            assert_eq!(serialized[field], json!([]), "missing {field}");
        }
    }

    #[test]
    fn artifact_versions_are_hash_bound_and_corrections_are_explicit() {
        let record = ScienceArtifactVersion::build(
            "version-1".into(),
            "campaign".into(),
            1,
            CreateScienceArtifactVersionRequest {
                title: "Decision figure".into(),
                kind: "figure_bundle".into(),
                producing_agent_run_id: "producer".into(),
                parent_version_id: None,
                artifact_ids: vec!["sha256:one".into()],
                source_version_ids: vec![],
                plan_id: "plan".into(),
                phase_id: "artifact".into(),
                status: "review_required".into(),
                metadata: json!({"fixture":true}),
            },
            "2026-08-13T00:00:00Z".into(),
        )
        .unwrap();
        record.validate().unwrap();
        let mut altered = record;
        altered.status = "corrected".into();
        assert!(altered.validate().is_err());
    }

    #[test]
    fn artifact_acceptance_binds_inspection_and_review_lineage() {
        let record = ScienceArtifactDisposition::build(
            "disposition-1".into(),
            "campaign".into(),
            CreateScienceArtifactDispositionRequest {
                artifact_version_id: "version-2".into(),
                actor: "primary".into(),
                disposition: ScienceArtifactDispositionKind::Accepted,
                rationale: "The correction resolves the recorded finding.".into(),
            },
            vec!["annotation-2".into()],
            vec!["review-1".into()],
            None,
            "2026-08-13T00:00:00Z".into(),
        )
        .unwrap();
        record.validate().unwrap();
        let mut altered = record;
        altered.review_ids.clear();
        assert!(altered.validate().is_err());
    }

    #[test]
    fn batch_receipt_preserves_declared_failures_in_the_denominator() {
        let receipt = ScienceBatchReceipt::build(
            "batch".into(),
            "campaign".into(),
            CreateScienceBatchReceiptRequest {
                label: "fixture".into(),
                producing_agent_run_id: "agent".into(),
                expected_job_ids: vec!["one".into(), "two".into(), "three".into()],
                jobs: vec![
                    ScienceBatchJob {
                        id: "one".into(),
                        status: "completed".into(),
                        artifact_id: Some("sha256:one".into()),
                        failure: None,
                    },
                    ScienceBatchJob {
                        id: "two".into(),
                        status: "failed".into(),
                        artifact_id: None,
                        failure: Some("retained failure".into()),
                    },
                ],
            },
            "2026-08-13T00:00:00Z".into(),
        )
        .unwrap();
        assert_eq!(
            (
                receipt.expected,
                receipt.completed,
                receipt.failed,
                receipt.missing
            ),
            (3, 1, 1, 1)
        );
        receipt.validate().unwrap();
    }
}
