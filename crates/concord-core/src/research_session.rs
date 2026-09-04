use anyhow::{bail, Result};
use concord_protocol::EpactAgentBinding;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub const RESEARCH_PLAN_CONTRACT: &str = "concord.research-plan/1";
pub const RESEARCH_PLAN_DECISION_CONTRACT: &str = "concord.research-plan-decision/1";
pub const RESEARCH_PHASE_DISPATCH_CONTRACT: &str = "concord.research-phase-dispatch/1";

/// Provider and exact input choices frozen into the plan before its independent approval.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResearchTaskExecution {
    pub provider_id: String,
    pub model: String,
    pub budget_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epact: Option<EpactAgentBinding>,
    pub input_versions: Vec<ResearchInputBinding>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResearchInputBinding {
    pub input_id: String,
    pub record_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResearchPlanTask {
    pub id: String,
    pub title: String,
    pub specialist_role: String,
    pub objective: String,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub input_scope: Vec<String>,
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    pub steps: Vec<String>,
    pub output_schema: Value,
    pub deliverables: Vec<String>,
    pub max_model_calls: u32,
    pub max_tool_calls: u32,
    pub max_elapsed_seconds: u64,
    pub max_cost_usd: f64,
    #[serde(default)]
    pub deterministic_fixture: bool,
    // Omission preserves the hashes of historical fixture plans.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<ResearchTaskExecution>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResearchPlanPhase {
    pub id: String,
    pub title: String,
    pub objective: String,
    pub max_parallel: u32,
    pub tasks: Vec<ResearchPlanTask>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateResearchPlanRequest {
    pub objective: String,
    pub confidence: f64,
    pub confidence_basis: String,
    pub feasibility_limits: Vec<String>,
    pub max_parallel: u32,
    pub max_cost_usd: f64,
    pub phases: Vec<ResearchPlanPhase>,
    pub created_by: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResearchPlanVersion {
    pub contract: String,
    pub id: String,
    pub campaign_id: String,
    pub version: u32,
    pub objective: String,
    pub confidence: f64,
    pub confidence_basis: String,
    pub feasibility_limits: Vec<String>,
    pub max_parallel: u32,
    pub max_cost_usd: f64,
    pub phases: Vec<ResearchPlanPhase>,
    #[serde(default)]
    pub previous_plan_sha256: Option<String>,
    pub plan_sha256: String,
    pub created_by: String,
    pub created_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResearchPlanHashInput<'a> {
    contract: &'a str,
    id: &'a str,
    campaign_id: &'a str,
    version: u32,
    objective: &'a str,
    confidence: f64,
    confidence_basis: &'a str,
    feasibility_limits: &'a [String],
    max_parallel: u32,
    max_cost_usd: f64,
    phases: &'a [ResearchPlanPhase],
    previous_plan_sha256: &'a Option<String>,
    created_by: &'a str,
    created_at: &'a str,
}

impl ResearchPlanVersion {
    pub fn build(
        id: String,
        campaign_id: String,
        version: u32,
        request: CreateResearchPlanRequest,
        previous_plan_sha256: Option<String>,
        created_at: String,
    ) -> Result<Self> {
        let mut plan = Self {
            contract: RESEARCH_PLAN_CONTRACT.to_owned(),
            id,
            campaign_id,
            version,
            objective: request.objective.trim().to_owned(),
            confidence: request.confidence,
            confidence_basis: request.confidence_basis.trim().to_owned(),
            feasibility_limits: request.feasibility_limits,
            max_parallel: request.max_parallel,
            max_cost_usd: request.max_cost_usd,
            phases: request.phases,
            previous_plan_sha256,
            plan_sha256: String::new(),
            created_by: request.created_by.trim().to_owned(),
            created_at,
        };
        plan.validate_content()?;
        plan.plan_sha256 = plan.recompute_sha256()?;
        Ok(plan)
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_content()?;
        if self.plan_sha256 != self.recompute_sha256()? {
            bail!("research plan hash mismatch");
        }
        Ok(())
    }

    fn recompute_sha256(&self) -> Result<String> {
        let input = ResearchPlanHashInput {
            contract: &self.contract,
            id: &self.id,
            campaign_id: &self.campaign_id,
            version: self.version,
            objective: &self.objective,
            confidence: self.confidence,
            confidence_basis: &self.confidence_basis,
            feasibility_limits: &self.feasibility_limits,
            max_parallel: self.max_parallel,
            max_cost_usd: self.max_cost_usd,
            phases: &self.phases,
            previous_plan_sha256: &self.previous_plan_sha256,
            created_by: &self.created_by,
            created_at: &self.created_at,
        };
        Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(&input)?)))
    }

    fn validate_content(&self) -> Result<()> {
        if self.contract != RESEARCH_PLAN_CONTRACT
            || self.id.trim().is_empty()
            || self.campaign_id.trim().is_empty()
            || self.version == 0
        {
            bail!("research plan identity is invalid");
        }
        if self.objective.is_empty()
            || self.objective.chars().count() > 16_000
            || self.confidence_basis.is_empty()
            || self.created_by.is_empty()
        {
            bail!("research plan objective, confidence basis, and author are required");
        }
        if !self.confidence.is_finite() || !(0.0..=1.0).contains(&self.confidence) {
            bail!("research plan confidence must be between zero and one");
        }
        if self.max_parallel == 0 || self.max_parallel > 1_000 {
            bail!("research plan parallel ceiling must be between one and 1000");
        }
        if !self.max_cost_usd.is_finite() || self.max_cost_usd < 0.0 {
            bail!("research plan cost ceiling must be finite and non-negative");
        }
        if self.phases.is_empty() || self.phases.len() > 64 {
            bail!("research plan must contain between one and 64 phases");
        }
        validate_nonempty_unique(&self.feasibility_limits, "feasibility limits")?;
        let mut phase_ids = HashSet::new();
        let mut prior_task_ids = HashSet::new();
        let mut worst_case_cost = 0.0;
        for phase in &self.phases {
            if phase.id.trim().is_empty()
                || phase.title.trim().is_empty()
                || phase.objective.trim().is_empty()
                || !phase_ids.insert(phase.id.as_str())
            {
                bail!("research plan phases require unique ids, titles, and objectives");
            }
            if phase.tasks.is_empty()
                || phase.max_parallel == 0
                || phase.max_parallel > self.max_parallel
                || phase.max_parallel as usize > phase.tasks.len()
            {
                bail!("research plan phase parallel ceiling is invalid");
            }
            let mut phase_task_ids = HashSet::new();
            for task in &phase.tasks {
                if task.id.trim().is_empty()
                    || task.title.trim().is_empty()
                    || task.specialist_role.trim().is_empty()
                    || task.objective.trim().is_empty()
                    || !phase_task_ids.insert(task.id.as_str())
                    || prior_task_ids.contains(task.id.as_str())
                {
                    bail!("research plan tasks require unique ids, titles, roles, and objectives");
                }
                if task.steps.is_empty()
                    || task.deliverables.is_empty()
                    || task.max_model_calls == 0
                    || task.max_elapsed_seconds == 0
                    || !task.output_schema.is_object()
                {
                    bail!("research plan task execution contract is incomplete");
                }
                if !task.max_cost_usd.is_finite() || task.max_cost_usd < 0.0 {
                    bail!("research plan task cost ceiling is invalid");
                }
                for dependency in &task.depends_on {
                    if !prior_task_ids.contains(dependency.as_str()) {
                        bail!("task dependencies must refer to a task in an earlier phase");
                    }
                }
                if let Some(execution) = &task.execution {
                    if task.deterministic_fixture
                        || execution.provider_id.trim().is_empty()
                        || execution.model.trim().is_empty()
                        || execution
                            .budget_id
                            .as_deref()
                            .is_some_and(|id| id.trim().is_empty())
                        || (task.max_cost_usd > 0.0 && execution.budget_id.is_none())
                    {
                        bail!("ordinary research execution requires a provider, model and explicit paid budget; fixtures cannot carry an ordinary execution binding");
                    }
                    let mut ids = HashSet::new();
                    for input in &execution.input_versions {
                        if input.input_id.trim().is_empty()
                            || !ids.insert(&input.input_id)
                            || input.record_sha256.len() != 64
                            || !input
                                .record_sha256
                                .bytes()
                                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                        {
                            bail!("research input bindings require unique identities and lowercase SHA-256 hashes");
                        }
                    }
                }
                validate_nonempty_unique(&task.input_scope, "task input scope")?;
                validate_nonempty_unique(&task.allowed_tools, "task allowed tools")?;
                validate_nonempty_unique(&task.steps, "task steps")?;
                validate_nonempty_unique(&task.deliverables, "task deliverables")?;
                worst_case_cost += task.max_cost_usd;
            }
            prior_task_ids.extend(phase_task_ids);
        }
        if worst_case_cost > self.max_cost_usd + 1e-9 {
            bail!("task cost ceilings exceed the plan ceiling");
        }
        Ok(())
    }
}

fn validate_nonempty_unique(values: &[String], label: &str) -> Result<()> {
    let mut seen = HashSet::new();
    for value in values {
        let value = value.trim();
        if value.is_empty() || !seen.insert(value) {
            bail!("{label} must be non-empty and unique");
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchPlanDecisionKind {
    Approved,
    Rejected,
    Withdrawn,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResearchPlanDecision {
    pub contract: String,
    pub id: String,
    pub plan_id: String,
    pub plan_sha256: String,
    pub decision: ResearchPlanDecisionKind,
    pub actor: String,
    pub rationale: String,
    #[serde(default)]
    pub previous_decision_sha256: Option<String>,
    pub decision_sha256: String,
    pub created_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResearchPlanDecisionHashInput<'a> {
    contract: &'a str,
    id: &'a str,
    plan_id: &'a str,
    plan_sha256: &'a str,
    decision: ResearchPlanDecisionKind,
    actor: &'a str,
    rationale: &'a str,
    previous_decision_sha256: &'a Option<String>,
    created_at: &'a str,
}

impl ResearchPlanDecision {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        id: String,
        plan_id: String,
        plan_sha256: String,
        decision: ResearchPlanDecisionKind,
        actor: String,
        rationale: String,
        previous_decision_sha256: Option<String>,
        created_at: String,
    ) -> Result<Self> {
        let mut record = Self {
            contract: RESEARCH_PLAN_DECISION_CONTRACT.to_owned(),
            id,
            plan_id,
            plan_sha256,
            decision,
            actor: actor.trim().to_owned(),
            rationale: rationale.trim().to_owned(),
            previous_decision_sha256,
            decision_sha256: String::new(),
            created_at,
        };
        record.validate_content()?;
        record.decision_sha256 = record.recompute_sha256()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_content()?;
        if self.decision_sha256 != self.recompute_sha256()? {
            bail!("research plan decision hash mismatch");
        }
        Ok(())
    }

    fn validate_content(&self) -> Result<()> {
        if self.contract != RESEARCH_PLAN_DECISION_CONTRACT
            || self.id.trim().is_empty()
            || self.plan_id.trim().is_empty()
            || self.plan_sha256.len() != 64
            || self.actor.is_empty()
            || self.rationale.is_empty()
        {
            bail!("research plan decision is incomplete");
        }
        Ok(())
    }

    fn recompute_sha256(&self) -> Result<String> {
        let input = ResearchPlanDecisionHashInput {
            contract: &self.contract,
            id: &self.id,
            plan_id: &self.plan_id,
            plan_sha256: &self.plan_sha256,
            decision: self.decision,
            actor: &self.actor,
            rationale: &self.rationale,
            previous_decision_sha256: &self.previous_decision_sha256,
            created_at: &self.created_at,
        };
        Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(&input)?)))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResearchPlanEnvelope {
    pub plan: ResearchPlanVersion,
    pub decisions: Vec<ResearchPlanDecision>,
    #[serde(default)]
    pub dispatches: Vec<ResearchPhaseDispatch>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResearchPhaseDispatchChild {
    pub task_id: String,
    pub agent_run_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResearchPhaseDispatch {
    pub contract: String,
    pub id: String,
    pub campaign_id: String,
    pub plan_id: String,
    pub plan_sha256: String,
    pub approval_decision_sha256: String,
    pub phase_id: String,
    pub coordinator_run_id: String,
    pub children: Vec<ResearchPhaseDispatchChild>,
    pub max_parallel: u32,
    pub actor: String,
    pub dispatch_sha256: String,
    pub created_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResearchPhaseDispatchHashInput<'a> {
    contract: &'a str,
    id: &'a str,
    campaign_id: &'a str,
    plan_id: &'a str,
    plan_sha256: &'a str,
    approval_decision_sha256: &'a str,
    phase_id: &'a str,
    coordinator_run_id: &'a str,
    children: &'a [ResearchPhaseDispatchChild],
    max_parallel: u32,
    actor: &'a str,
    created_at: &'a str,
}

impl ResearchPhaseDispatch {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        id: String,
        campaign_id: String,
        plan_id: String,
        plan_sha256: String,
        approval_decision_sha256: String,
        phase_id: String,
        coordinator_run_id: String,
        children: Vec<ResearchPhaseDispatchChild>,
        max_parallel: u32,
        actor: String,
        created_at: String,
    ) -> Result<Self> {
        let mut record = Self {
            contract: RESEARCH_PHASE_DISPATCH_CONTRACT.to_owned(),
            id,
            campaign_id,
            plan_id,
            plan_sha256,
            approval_decision_sha256,
            phase_id,
            coordinator_run_id,
            children,
            max_parallel,
            actor: actor.trim().to_owned(),
            dispatch_sha256: String::new(),
            created_at,
        };
        record.validate_content()?;
        record.dispatch_sha256 = record.recompute_sha256()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_content()?;
        if self.dispatch_sha256 != self.recompute_sha256()? {
            bail!("research phase dispatch hash mismatch");
        }
        Ok(())
    }

    fn validate_content(&self) -> Result<()> {
        if self.contract != RESEARCH_PHASE_DISPATCH_CONTRACT
            || self.id.trim().is_empty()
            || self.campaign_id.trim().is_empty()
            || self.plan_id.trim().is_empty()
            || self.plan_sha256.len() != 64
            || self.approval_decision_sha256.len() != 64
            || self.phase_id.trim().is_empty()
            || self.coordinator_run_id.trim().is_empty()
            || self.actor.is_empty()
            || self.max_parallel == 0
            || self.children.is_empty()
            || self.max_parallel as usize > self.children.len()
        {
            bail!("research phase dispatch is incomplete");
        }
        let mut task_ids = HashSet::new();
        let mut run_ids = HashSet::new();
        for child in &self.children {
            if child.task_id.trim().is_empty()
                || child.agent_run_id.trim().is_empty()
                || !task_ids.insert(child.task_id.as_str())
                || !run_ids.insert(child.agent_run_id.as_str())
            {
                bail!("research phase dispatch children must be unique");
            }
        }
        Ok(())
    }

    fn recompute_sha256(&self) -> Result<String> {
        let input = ResearchPhaseDispatchHashInput {
            contract: &self.contract,
            id: &self.id,
            campaign_id: &self.campaign_id,
            plan_id: &self.plan_id,
            plan_sha256: &self.plan_sha256,
            approval_decision_sha256: &self.approval_decision_sha256,
            phase_id: &self.phase_id,
            coordinator_run_id: &self.coordinator_run_id,
            children: &self.children,
            max_parallel: self.max_parallel,
            actor: &self.actor,
            created_at: &self.created_at,
        };
        Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(&input)?)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request() -> CreateResearchPlanRequest {
        CreateResearchPlanRequest {
            objective: "Rehearse the complete scientific workflow without producing evidence"
                .into(),
            confidence: 0.82,
            confidence_basis: "All effects are deterministic fixtures".into(),
            feasibility_limits: vec!["No external compute".into()],
            max_parallel: 3,
            max_cost_usd: 0.0,
            phases: vec![ResearchPlanPhase {
                id: "landscape".into(),
                title: "Landscape".into(),
                objective: "Produce three independent scoped assessments".into(),
                max_parallel: 1,
                tasks: vec![ResearchPlanTask {
                    id: "evidence".into(),
                    title: "Evidence audit".into(),
                    specialist_role: "evidence reviewer".into(),
                    objective: "Inventory retained evidence".into(),
                    depends_on: vec![],
                    input_scope: vec!["campaign archive".into()],
                    allowed_tools: vec!["read_campaign_object".into()],
                    steps: vec!["Read the frozen archive".into()],
                    output_schema: json!({"type": "object"}),
                    deliverables: vec!["evidence inventory".into()],
                    max_model_calls: 2,
                    max_tool_calls: 1,
                    max_elapsed_seconds: 300,
                    max_cost_usd: 0.0,
                    deterministic_fixture: true,
                    execution: None,
                }],
            }],
            created_by: "primary".into(),
        }
    }

    #[test]
    fn plan_hash_binds_briefs_and_decisions_are_separate() {
        let plan = ResearchPlanVersion::build(
            "plan-1".into(),
            "campaign-1".into(),
            1,
            request(),
            None,
            "2026-08-13T00:00:00Z".into(),
        )
        .unwrap();
        plan.validate().unwrap();
        let mut tampered = plan.clone();
        tampered.phases[0].tasks[0].objective = "Different work".into();
        assert!(tampered.validate().is_err());
        let decision = ResearchPlanDecision::build(
            "decision-1".into(),
            plan.id.clone(),
            plan.plan_sha256.clone(),
            ResearchPlanDecisionKind::Approved,
            "primary".into(),
            "Exact zero-spend rehearsal approved".into(),
            None,
            "2026-08-13T00:01:00Z".into(),
        )
        .unwrap();
        decision.validate().unwrap();
    }
}
