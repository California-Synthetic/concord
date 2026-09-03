use anyhow::{bail, ensure, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const EXECUTION_PLAN_CONTRACT: &str = "concord.execution-plan/1";
pub const EXECUTION_RECEIPT_CONTRACT: &str = "concord.execution-receipt/1";
pub const SANDBOX_POLICY_CONTRACT: &str = "concord.process-sandbox-policy/1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlacementKind {
    Local,
    Ssh,
    Hpc,
    Managed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacementTarget {
    pub id: String,
    pub kind: PlacementKind,
    pub adapter: String,
    pub locality: String,
    pub disconnect_safe: bool,
    pub max_parallel: u32,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionJobSpec {
    pub id: String,
    pub task_class: String,
    pub input_sha256: String,
    #[serde(default)]
    pub required_capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionPlan {
    pub contract: String,
    pub id: String,
    pub campaign_id: String,
    pub label: String,
    pub jobs: Vec<ExecutionJobSpec>,
    pub targets: Vec<PlacementTarget>,
    pub max_parallel: u32,
    pub max_cost_usd: f64,
    pub deterministic_fixture: bool,
    pub plan_sha256: String,
    pub created_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecutionPlanHash<'a> {
    contract: &'a str,
    id: &'a str,
    campaign_id: &'a str,
    label: &'a str,
    jobs: &'a [ExecutionJobSpec],
    targets: &'a [PlacementTarget],
    max_parallel: u32,
    max_cost_usd: f64,
    deterministic_fixture: bool,
    created_at: &'a str,
}

impl ExecutionPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        id: String,
        campaign_id: String,
        label: String,
        mut jobs: Vec<ExecutionJobSpec>,
        mut targets: Vec<PlacementTarget>,
        max_parallel: u32,
        max_cost_usd: f64,
        deterministic_fixture: bool,
        created_at: String,
    ) -> Result<Self> {
        jobs.sort_by(|left, right| left.id.cmp(&right.id));
        targets.sort_by(|left, right| left.id.cmp(&right.id));
        let mut plan = Self {
            contract: EXECUTION_PLAN_CONTRACT.into(),
            id,
            campaign_id,
            label,
            jobs,
            targets,
            max_parallel,
            max_cost_usd,
            deterministic_fixture,
            plan_sha256: String::new(),
            created_at,
        };
        plan.plan_sha256 = plan.expected_sha256()?;
        plan.validate()?;
        Ok(plan)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.contract == EXECUTION_PLAN_CONTRACT,
            "unsupported execution plan"
        );
        ensure!(
            !self.id.trim().is_empty() && !self.campaign_id.trim().is_empty(),
            "execution plan identity is required"
        );
        ensure!(
            !self.label.trim().is_empty(),
            "execution plan label is required"
        );
        ensure!(
            !self.jobs.is_empty() && self.jobs.len() <= 10_000,
            "execution plan requires 1-10000 jobs"
        );
        ensure!(
            !self.targets.is_empty(),
            "execution plan requires a placement target"
        );
        ensure!(
            self.max_parallel > 0 && self.max_parallel as usize <= self.jobs.len(),
            "execution maxParallel is invalid"
        );
        ensure!(
            self.max_cost_usd.is_finite() && self.max_cost_usd >= 0.0,
            "execution cost ceiling is invalid"
        );
        if self.deterministic_fixture {
            ensure!(
                self.max_cost_usd == 0.0,
                "deterministic execution fixture must be zero-spend"
            );
        }
        let mut job_ids = BTreeSet::new();
        let mut previous_job: Option<&str> = None;
        for job in &self.jobs {
            ensure!(
                job_ids.insert(job.id.as_str()),
                "duplicate execution job {}",
                job.id
            );
            ensure!(
                previous_job.is_none_or(|value| value < job.id.as_str()),
                "execution jobs must be sorted"
            );
            previous_job = Some(&job.id);
            validate_sha256(&job.input_sha256)?;
            ensure!(
                !job.task_class.trim().is_empty(),
                "execution task class is required"
            );
        }
        let mut target_ids = BTreeSet::new();
        let mut previous_target: Option<&str> = None;
        for target in &self.targets {
            ensure!(
                target_ids.insert(target.id.as_str()),
                "duplicate placement target {}",
                target.id
            );
            ensure!(
                previous_target.is_none_or(|value| value < target.id.as_str()),
                "placement targets must be sorted"
            );
            previous_target = Some(&target.id);
            ensure!(
                !target.adapter.trim().is_empty() && !target.locality.trim().is_empty(),
                "placement adapter and locality are required"
            );
            ensure!(
                target.max_parallel > 0,
                "placement target maxParallel must be positive"
            );
        }
        ensure!(
            self.plan_sha256 == self.expected_sha256()?,
            "execution plan digest mismatch"
        );
        Ok(())
    }

    fn expected_sha256(&self) -> Result<String> {
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&ExecutionPlanHash {
                contract: &self.contract,
                id: &self.id,
                campaign_id: &self.campaign_id,
                label: &self.label,
                jobs: &self.jobs,
                targets: &self.targets,
                max_parallel: self.max_parallel,
                max_cost_usd: self.max_cost_usd,
                deterministic_fixture: self.deterministic_fixture,
                created_at: &self.created_at,
            })?)
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacementAssignment {
    pub job_id: String,
    pub target_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionJobResult {
    pub job_id: String,
    pub status: String,
    #[serde(default)]
    pub artifact_id: Option<String>,
    #[serde(default)]
    pub failure: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionReceipt {
    pub contract: String,
    pub id: String,
    pub campaign_id: String,
    pub plan_id: String,
    pub plan_sha256: String,
    pub assignments: Vec<PlacementAssignment>,
    pub results: Vec<ExecutionJobResult>,
    pub expected: u32,
    pub completed: u32,
    pub failed: u32,
    pub missing: u32,
    pub actual_cost_usd: f64,
    pub denominator_locked: bool,
    pub receipt_sha256: String,
    pub created_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecutionReceiptHash<'a> {
    contract: &'a str,
    id: &'a str,
    campaign_id: &'a str,
    plan_id: &'a str,
    plan_sha256: &'a str,
    assignments: &'a [PlacementAssignment],
    results: &'a [ExecutionJobResult],
    expected: u32,
    completed: u32,
    failed: u32,
    missing: u32,
    actual_cost_usd: f64,
    denominator_locked: bool,
    created_at: &'a str,
}

impl ExecutionReceipt {
    pub fn build(
        id: String,
        plan: &ExecutionPlan,
        mut assignments: Vec<PlacementAssignment>,
        mut results: Vec<ExecutionJobResult>,
        actual_cost_usd: f64,
        created_at: String,
    ) -> Result<Self> {
        assignments.sort_by(|left, right| left.job_id.cmp(&right.job_id));
        results.sort_by(|left, right| left.job_id.cmp(&right.job_id));
        let expected_ids = plan
            .jobs
            .iter()
            .map(|job| job.id.as_str())
            .collect::<BTreeSet<_>>();
        let result_ids = results
            .iter()
            .map(|job| job.job_id.as_str())
            .collect::<BTreeSet<_>>();
        let completed = results
            .iter()
            .filter(|job| job.status == "completed")
            .count() as u32;
        let failed = results.iter().filter(|job| job.status == "failed").count() as u32;
        let missing = expected_ids.difference(&result_ids).count() as u32;
        let mut receipt = Self {
            contract: EXECUTION_RECEIPT_CONTRACT.into(),
            id,
            campaign_id: plan.campaign_id.clone(),
            plan_id: plan.id.clone(),
            plan_sha256: plan.plan_sha256.clone(),
            assignments,
            results,
            expected: plan.jobs.len() as u32,
            completed,
            failed,
            missing,
            actual_cost_usd,
            denominator_locked: true,
            receipt_sha256: String::new(),
            created_at,
        };
        receipt.receipt_sha256 = receipt.expected_sha256()?;
        receipt.validate(plan)?;
        Ok(receipt)
    }

    pub fn validate(&self, plan: &ExecutionPlan) -> Result<()> {
        plan.validate()?;
        ensure!(
            self.contract == EXECUTION_RECEIPT_CONTRACT,
            "unsupported execution receipt"
        );
        ensure!(
            self.plan_id == plan.id
                && self.plan_sha256 == plan.plan_sha256
                && self.campaign_id == plan.campaign_id,
            "execution receipt is not bound to the plan"
        );
        ensure!(
            self.denominator_locked,
            "execution receipt denominator must be locked"
        );
        ensure!(
            self.actual_cost_usd.is_finite()
                && self.actual_cost_usd >= 0.0
                && self.actual_cost_usd <= plan.max_cost_usd,
            "execution receipt exceeds the cost ceiling"
        );
        let expected_ids = plan
            .jobs
            .iter()
            .map(|job| job.id.as_str())
            .collect::<BTreeSet<_>>();
        let targets = plan
            .targets
            .iter()
            .map(|target| target.id.as_str())
            .collect::<BTreeSet<_>>();
        let mut assignments = BTreeMap::new();
        for assignment in &self.assignments {
            ensure!(
                expected_ids.contains(assignment.job_id.as_str()),
                "assignment names an undeclared job"
            );
            ensure!(
                targets.contains(assignment.target_id.as_str()),
                "assignment names an undeclared target"
            );
            ensure!(
                !assignment.reason.trim().is_empty(),
                "placement reason is required"
            );
            ensure!(
                assignments
                    .insert(assignment.job_id.as_str(), assignment.target_id.as_str())
                    .is_none(),
                "job has multiple placement assignments"
            );
        }
        ensure!(
            assignments.len() == expected_ids.len(),
            "every job requires exactly one placement assignment"
        );
        let mut result_ids = BTreeSet::new();
        for result in &self.results {
            ensure!(
                expected_ids.contains(result.job_id.as_str()),
                "result names an undeclared job"
            );
            ensure!(
                result_ids.insert(result.job_id.as_str()),
                "duplicate execution result"
            );
            match result.status.as_str() {
                "completed" => ensure!(
                    result.failure.is_none(),
                    "completed result cannot carry a failure"
                ),
                "failed" => ensure!(
                    result
                        .failure
                        .as_deref()
                        .is_some_and(|value| !value.trim().is_empty()),
                    "failed result requires a reason"
                ),
                other => bail!("unsupported execution result state {other}"),
            }
        }
        let completed = self
            .results
            .iter()
            .filter(|job| job.status == "completed")
            .count() as u32;
        let failed = self
            .results
            .iter()
            .filter(|job| job.status == "failed")
            .count() as u32;
        ensure!(
            self.expected == plan.jobs.len() as u32
                && self.completed == completed
                && self.failed == failed
                && self.missing == self.expected - completed - failed,
            "execution receipt counts do not match its rows"
        );
        ensure!(
            self.receipt_sha256 == self.expected_sha256()?,
            "execution receipt digest mismatch"
        );
        Ok(())
    }

    fn expected_sha256(&self) -> Result<String> {
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&ExecutionReceiptHash {
                contract: &self.contract,
                id: &self.id,
                campaign_id: &self.campaign_id,
                plan_id: &self.plan_id,
                plan_sha256: &self.plan_sha256,
                assignments: &self.assignments,
                results: &self.results,
                expected: self.expected,
                completed: self.completed,
                failed: self.failed,
                missing: self.missing,
                actual_cost_usd: self.actual_cost_usd,
                denominator_locked: self.denominator_locked,
                created_at: &self.created_at,
            })?)
        ))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionWorkspace {
    pub plans: Vec<ExecutionPlan>,
    pub receipts: Vec<ExecutionReceipt>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessSandboxPolicy {
    pub contract: String,
    pub package_content_sha256: String,
    pub entrypoint: String,
    pub network_allowed: bool,
    pub host_writes_allowed: bool,
    #[serde(default)]
    pub environment_keys: Vec<String>,
    pub max_elapsed_seconds: u64,
    pub max_output_bytes: u64,
}

impl ProcessSandboxPolicy {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.contract == SANDBOX_POLICY_CONTRACT,
            "unsupported sandbox policy"
        );
        validate_sha256(&self.package_content_sha256)?;
        ensure!(
            !self.entrypoint.is_empty()
                && !self.entrypoint.starts_with('/')
                && !self.entrypoint.split('/').any(|part| part == ".."),
            "sandbox entrypoint must be package-relative"
        );
        ensure!(
            !self.network_allowed,
            "v0.1 executable packages cannot use network access"
        );
        ensure!(
            !self.host_writes_allowed,
            "v0.1 executable packages cannot write to the host"
        );
        ensure!(
            (1..=3_600).contains(&self.max_elapsed_seconds),
            "sandbox deadline is invalid"
        );
        ensure!(
            (1..=16_777_216).contains(&self.max_output_bytes),
            "sandbox output ceiling is invalid"
        );
        let mut keys = BTreeSet::new();
        for key in &self.environment_keys {
            ensure!(
                !key.is_empty()
                    && key.chars().all(|character| character.is_ascii_uppercase()
                        || character.is_ascii_digit()
                        || character == '_'),
                "sandbox environment key is invalid"
            );
            ensure!(keys.insert(key), "duplicate sandbox environment key");
        }
        Ok(())
    }

    pub fn macos_profile(&self) -> Result<String> {
        self.validate()?;
        Ok("(version 1)\n(deny default)\n(allow process*)\n(allow file-read*)\n(allow sysctl-read)\n(allow mach-lookup)\n(deny network*)\n".into())
    }
}

fn validate_sha256(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid SHA-256 digest"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> ExecutionPlan {
        ExecutionPlan::build(
            "plan".into(),
            "campaign".into(),
            "bounded scale-out".into(),
            (0..100)
                .map(|index| ExecutionJobSpec {
                    id: format!("job-{index:03}"),
                    task_class: "assessment".into(),
                    input_sha256: format!("{:064x}", index + 1),
                    required_capabilities: vec!["cpu".into()],
                })
                .collect(),
            vec![PlacementTarget {
                id: "local".into(),
                kind: PlacementKind::Local,
                adapter: "sandboxed_process".into(),
                locality: "workstation".into(),
                disconnect_safe: true,
                max_parallel: 8,
                capabilities: vec!["cpu".into()],
            }],
            8,
            0.0,
            true,
            "2026-08-13T00:00:00Z".into(),
        )
        .unwrap()
    }

    #[test]
    fn scaleout_receipt_keeps_declared_failures_and_exact_denominator() {
        let plan = plan();
        let receipt = ExecutionReceipt::build(
            "receipt".into(),
            &plan,
            plan.jobs
                .iter()
                .map(|job| PlacementAssignment {
                    job_id: job.id.clone(),
                    target_id: "local".into(),
                    reason: "zero-spend fixture".into(),
                })
                .collect(),
            plan.jobs
                .iter()
                .map(|job| ExecutionJobResult {
                    job_id: job.id.clone(),
                    status: if job.id.ends_with("099") {
                        "failed".into()
                    } else {
                        "completed".into()
                    },
                    artifact_id: None,
                    failure: job
                        .id
                        .ends_with("099")
                        .then(|| "declared fixture failure".into()),
                })
                .collect(),
            0.0,
            "2026-08-13T00:01:00Z".into(),
        )
        .unwrap();
        assert_eq!(
            (
                receipt.expected,
                receipt.completed,
                receipt.failed,
                receipt.missing
            ),
            (100, 99, 1, 0)
        );
    }

    #[test]
    fn sandbox_policy_rejects_network_writes_and_path_escape() {
        let valid = ProcessSandboxPolicy {
            contract: SANDBOX_POLICY_CONTRACT.into(),
            package_content_sha256: "a".repeat(64),
            entrypoint: "scripts/run.py".into(),
            network_allowed: false,
            host_writes_allowed: false,
            environment_keys: vec![],
            max_elapsed_seconds: 30,
            max_output_bytes: 1024,
        };
        valid.validate().unwrap();
        assert!(ProcessSandboxPolicy {
            entrypoint: "../escape.py".into(),
            ..valid.clone()
        }
        .validate()
        .is_err());
        assert!(ProcessSandboxPolicy {
            network_allowed: true,
            ..valid
        }
        .validate()
        .is_err());
    }
}
