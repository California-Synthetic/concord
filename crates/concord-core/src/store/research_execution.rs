use super::*;
use crate::project_inputs::ProjectInputVersion;

/// Validate accepted identities at the transaction that records or authorizes the plan.
/// Byte disclosure remains a separately approved tool operation.
pub(super) fn validate_execution_bindings(
    connection: &Connection,
    plan: &ResearchPlanVersion,
) -> Result<()> {
    let closed: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM campaign_closeouts WHERE campaign_id=?1)",
        [&plan.campaign_id],
        |row| row.get(0),
    )?;
    anyhow::ensure!(
        !closed,
        "closed campaign cannot authorize new research work"
    );
    for task in plan.phases.iter().flat_map(|phase| &phase.tasks) {
        let Some(execution) = &task.execution else {
            anyhow::ensure!(task.deterministic_fixture, "ordinary research task {} requires an explicit execution binding; historical unbound plans must be amended", task.id);
            continue;
        };
        let (kind, status, metadata): (String, String, String) = connection
            .query_row(
                "SELECT kind,status,metadata_json FROM provider_profiles WHERE id=?1",
                [&execution.provider_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .context("research task provider does not exist")?;
        let metadata: Value = serde_json::from_str(&metadata)?;
        anyhow::ensure!(
            kind == "model_api" && status == "ready",
            "research task provider is not a ready model provider"
        );
        anyhow::ensure!(
            metadata.get("fixture") != Some(&Value::Bool(true))
                && metadata.get("transport").and_then(Value::as_str) != Some("deterministic"),
            "ordinary research execution cannot use a deterministic fixture provider"
        );
        if let Some(budget_id) = &execution.budget_id {
            let exists: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM budgets WHERE id=?1)",
                [budget_id],
                |row| row.get(0),
            )?;
            anyhow::ensure!(exists, "research budget account does not exist");
        }
        for binding in &execution.input_versions {
            let raw: String = connection
                .query_row(
                    "SELECT record_json FROM project_inputs WHERE id=?1 AND campaign_id=?2",
                    params![binding.input_id, plan.campaign_id],
                    |row| row.get(0),
                )
                .context("research input does not belong to the plan's campaign")?;
            let input: ProjectInputVersion = serde_json::from_str(&raw)?;
            input.validate()?;
            anyhow::ensure!(
                input.id == binding.input_id
                    && input.campaign_id == plan.campaign_id
                    && input.record_sha256 == binding.record_sha256,
                "research input binding does not match the exact recorded version"
            );
        }
    }
    Ok(())
}

impl Database {
    /// Resolve an exact input while retaining any plan scope through agent forks.
    pub fn project_input_for_agent(
        &self,
        agent_run_id: &str,
        input_id: &str,
    ) -> Result<ProjectInputVersion> {
        let mut envelope = self
            .agent_run_envelope(agent_run_id)?
            .context("agent run does not exist")?;
        let input = self
            .project_input(&envelope.run.campaign_id, input_id)?
            .context("input does not belong to this project")?;
        let mut visited = std::collections::HashSet::new();
        loop {
            anyhow::ensure!(
                visited.len() < 256 && visited.insert(envelope.run.id.clone()),
                "agent ancestry is cyclic or exceeds the input-scope traversal limit"
            );
            let brief = &envelope
                .events
                .first()
                .context("agent creation record is missing")?
                .payload["researchBrief"];
            if brief["role"] == "bounded_specialist" {
                let execution: ResearchTaskExecution =
                    serde_json::from_value(brief["brief"]["execution"].clone())
                        .context("plan task has no exact input execution binding")?;
                anyhow::ensure!(
                    execution
                        .input_versions
                        .iter()
                        .any(|binding| binding.input_id == input.id
                            && binding.record_sha256 == input.record_sha256),
                    "input version is outside this task's approved plan scope"
                );
                return Ok(input);
            }
            let Some(parent) = &envelope.run.parent_run_id else {
                return Ok(input);
            };
            let parent = self
                .agent_run_envelope(parent)?
                .context("agent parent is missing")?;
            anyhow::ensure!(
                parent.run.campaign_id == envelope.run.campaign_id,
                "agent parent belongs to a different project"
            );
            envelope = parent;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project_inputs::AttachProjectInputRequest;
    use sha2::{Digest, Sha256};

    #[test]
    fn ordinary_plans_bind_inputs_and_reserve_all_children_atomically() {
        let (database, path) = super::super::tests::note_test_database();
        let connection = database.connect().unwrap();
        connection
            .execute("DELETE FROM provider_profiles", [])
            .unwrap();
        connection.execute("INSERT INTO provider_profiles(id,name,kind,status,metadata_json,updated_at) VALUES ('research-model','Research model','model_api','ready','{}','2026-09-04')", []).unwrap();
        connection.execute("INSERT INTO budgets(id,name,source,currency,total,spent,exposure,remaining_floor,updated_at) VALUES ('research-budget','Research budget','test','USD',5,0,0,5,'2026-09-04')", []).unwrap();
        let bytes = b"sample,value\na,1\n";
        let input_path = path.with_extension("csv");
        std::fs::write(&input_path, bytes).unwrap();
        let input = database
            .attach_project_input(
                "campaign:a",
                &AttachProjectInputRequest {
                    logical_path: "samples.csv".into(),
                    content_sha256: format!("{:x}", Sha256::digest(bytes)),
                    previous_version_id: None,
                    actor: "primary".into(),
                    idempotency_key: "input-one".into(),
                },
                &Artifact {
                    id: "input-file".into(),
                    run_id: None,
                    kind: "project_input".into(),
                    media_type: "text/csv".into(),
                    byte_size: bytes.len() as u64,
                    path: input_path.to_string_lossy().into(),
                    source_path: Some("samples.csv".into()),
                    created_at: Utc::now().to_rfc3339(),
                },
            )
            .unwrap();
        let mut request = super::super::tests::research_plan_request("Inspect my samples");
        request.max_cost_usd = 6.0;
        let task = &mut request.phases[0].tasks[0];
        task.deterministic_fixture = false;
        task.max_cost_usd = 3.0;
        task.execution = Some(ResearchTaskExecution {
            provider_id: "research-model".into(),
            model: "research-model-v1".into(),
            budget_id: Some("research-budget".into()),
            epact: None,
            input_versions: vec![ResearchInputBinding {
                input_id: input.id.clone(),
                record_sha256: input.record_sha256.clone(),
            }],
        });
        let mut second = task.clone();
        second.id = "second-task".into();
        request.phases[0].tasks.push(second);
        let mut missing = request.clone();
        missing.phases[0].tasks[0].execution = None;
        assert!(database
            .record_research_plan("campaign:a", missing)
            .unwrap_err()
            .to_string()
            .contains("explicit execution binding"));
        let mut wrong_hash = request.clone();
        wrong_hash.phases[0].tasks[0]
            .execution
            .as_mut()
            .unwrap()
            .input_versions[0]
            .record_sha256 = "a".repeat(64);
        assert!(database
            .record_research_plan("campaign:a", wrong_hash)
            .unwrap_err()
            .to_string()
            .contains("exact recorded version"));
        assert!(database
            .record_research_plan("campaign:b", request.clone())
            .unwrap_err()
            .to_string()
            .contains("does not belong"));
        let plan = database
            .record_research_plan("campaign:a", request)
            .unwrap();
        assert!(database
            .dispatch_research_plan_phase("campaign:a", &plan.plan.id, "phase-one", "primary")
            .is_err());
        let mut tampered = plan.plan.clone();
        tampered.phases[0].tasks[0]
            .execution
            .as_mut()
            .unwrap()
            .model = "different-model".into();
        assert!(tampered.validate().is_err());
        database
            .record_research_plan_decision(
                "campaign:a",
                &plan.plan.id,
                ResearchPlanDecisionKind::Approved,
                "primary",
                "Approved exact files, model, methods and limits.",
            )
            .unwrap();
        assert!(database
            .dispatch_research_plan_phase("campaign:a", &plan.plan.id, "phase-one", "primary")
            .is_err());
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM agent_runs", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT remaining_floor FROM budgets WHERE id='research-budget'",
                    [],
                    |row| row.get::<_, f64>(0)
                )
                .unwrap(),
            5.0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM agent_budget_reservations",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        connection
            .execute(
                "UPDATE budgets SET total=10,remaining_floor=10 WHERE id='research-budget'",
                [],
            )
            .unwrap();
        let dispatch = database
            .dispatch_research_plan_phase("campaign:a", &plan.plan.id, "phase-one", "primary")
            .unwrap();
        assert_eq!(dispatch.children.len(), 2);
        let retry = database
            .dispatch_research_plan_phase("campaign:a", &plan.plan.id, "phase-one", "primary")
            .unwrap();
        assert_eq!(dispatch, retry);
        assert_eq!(
            connection
                .query_row(
                    "SELECT remaining_floor FROM budgets WHERE id='research-budget'",
                    [],
                    |row| row.get::<_, f64>(0)
                )
                .unwrap(),
            4.0
        );
        for child in &dispatch.children {
            let run = database
                .agent_run_envelope(&child.agent_run_id)
                .unwrap()
                .unwrap();
            assert_eq!(run.run.provider_id, "research-model");
            assert_eq!(run.run.model, "research-model-v1");
            assert_eq!(run.run.budget.budget_id.as_deref(), Some("research-budget"));
            assert_eq!(
                run.events[0].payload["researchBrief"]["brief"]["execution"]["inputVersions"][0]
                    ["recordSha256"],
                input.record_sha256
            );
            assert_eq!(run.run.status, AgentRunStatus::Ready);
        }
        let child_id = &dispatch.children[0].agent_run_id;
        assert_eq!(
            database
                .project_input_for_agent(child_id, &input.id)
                .unwrap()
                .id,
            input.id
        );
        let next = database
            .attach_project_input(
                "campaign:a",
                &AttachProjectInputRequest {
                    logical_path: "samples.csv".into(),
                    content_sha256: input.content_sha256.clone(),
                    previous_version_id: Some(input.id.clone()),
                    actor: "primary".into(),
                    idempotency_key: "input-two".into(),
                },
                &Artifact {
                    id: "input-file-two".into(),
                    run_id: None,
                    kind: "project_input".into(),
                    media_type: "text/csv".into(),
                    byte_size: bytes.len() as u64,
                    path: input_path.to_string_lossy().into(),
                    source_path: Some("samples.csv".into()),
                    created_at: Utc::now().to_rfc3339(),
                },
            )
            .unwrap();
        assert!(database
            .project_input_for_agent(child_id, &next.id)
            .unwrap_err()
            .to_string()
            .contains("outside"));
        let child = database.agent_run_envelope(child_id).unwrap().unwrap();
        connection
            .execute(
                "UPDATE budgets SET total=30,remaining_floor=24 WHERE id='research-budget'",
                [],
            )
            .unwrap();
        let fork = database
            .fork_agent_run(
                child_id,
                child.run.revision,
                "fork-input-scope",
                Some("Inspect the same approved inputs"),
                None,
                None,
                None,
            )
            .unwrap();
        assert_eq!(
            database
                .project_input_for_agent(&fork.run.id, &input.id)
                .unwrap()
                .id,
            input.id
        );
        assert!(database
            .project_input_for_agent(&fork.run.id, &next.id)
            .is_err());
        connection
            .execute("UPDATE provider_profiles SET status='offline'", [])
            .unwrap();
        database
            .record_research_plan_decision(
                "campaign:a",
                &plan.plan.id,
                ResearchPlanDecisionKind::Withdrawn,
                "primary",
                "Pause while the provider is unavailable.",
            )
            .unwrap();
        assert_eq!(
            database
                .research_plans_for_campaign("campaign:a")
                .unwrap()
                .len(),
            1
        );
        drop(connection);
        std::fs::remove_file(input_path).unwrap();
        std::fs::remove_file(path).unwrap();
    }
}
