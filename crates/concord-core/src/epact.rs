use anyhow::{bail, ensure, Context, Result};
use chrono::{SecondsFormat, Utc};
use concord_harness::{
    compile_epact_program, evaluate_epact_operation, initial_epact_state, replay_epact_events,
    require_epact_activatable, verify_epact_event_authority, verify_epact_program_image,
    verify_epact_program_successor,
};
use concord_protocol::{
    AgentBudget, AgentRun, AuthorizeCampaignDispatchRequest, EpactAgentBinding, EpactAmendment,
    EpactDispatchBinding, EpactOperationRequest, EpactPlacementClaim, EpactProgram,
    EpactProgramImage, EpactResourceEnvelope, EpactRuntimeEvent, EpactRuntimeEventKind,
    EpactRuntimeState, KernelOperation,
};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::Database;

pub const EPACT_ACTIVATION_CONTRACT: &str = "concord.epact-activation/1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpactActivation {
    pub contract: String,
    pub id: String,
    pub campaign_id: String,
    pub image_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor_image_sha256: Option<String>,
    pub effective_event_head_sha256: String,
    pub actor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amendment: Option<EpactAmendment>,
    pub activated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveEpactProgram {
    pub activation: EpactActivation,
    pub image: EpactProgramImage,
    pub state: EpactRuntimeState,
    pub events: Vec<EpactRuntimeEvent>,
}

impl Database {
    pub fn activate_epact_program(
        &self,
        campaign_id: &str,
        program: EpactProgram,
        actor: &str,
        rationale: Option<&str>,
    ) -> Result<ActiveEpactProgram> {
        let image = compile_epact_program(program)?;
        require_epact_activatable(&image)?;
        let actor = actor.trim();
        ensure!(!actor.is_empty(), "Epact activation actor is required");
        let now = canonical_now();

        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let campaign_exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM campaigns WHERE id=?1)",
            params![campaign_id],
            |row| row.get(0),
        )?;
        ensure!(campaign_exists, "unknown campaign {campaign_id}");

        let current = active_epact_program_tx(&transaction, campaign_id)?;
        let (predecessor_image_sha256, effective_event_head_sha256, amendment, rationale) =
            if let Some(current) = current {
                let rationale = rationale
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .context("Epact successor activation requires a rationale")?;
                ensure_program_authority(&current.image, actor, KernelOperation::Amend, &now)?;
                let effective_head = current
                    .state
                    .event_head_sha256
                    .clone()
                    .unwrap_or_else(|| current.image.image_sha256.clone());
                let amendment = verify_epact_program_successor(
                    &current.image,
                    &image,
                    actor,
                    rationale,
                    &effective_head,
                )?;
                (
                    Some(current.image.image_sha256),
                    effective_head,
                    Some(amendment),
                    Some(rationale.to_owned()),
                )
            } else {
                ensure!(
                    image.program.predecessor.is_none(),
                    "first Epact activation cannot declare a predecessor"
                );
                ensure_program_authority(&image, actor, KernelOperation::Freeze, &now)?;
                ensure_program_authority(&image, actor, KernelOperation::Authorize, &now)?;
                (None, image.image_sha256.clone(), None, None)
            };

        transaction.execute(
            "INSERT OR IGNORE INTO epact_program_images(image_sha256,program_id,program_version,program_sha256,image_json,recorded_at) VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                image.image_sha256,
                image.program.id,
                image.program.version,
                image.program_sha256,
                serde_json::to_string(&image)?,
                now,
            ],
        )?;
        transaction.execute(
            "UPDATE epact_campaign_activations SET active=0 WHERE campaign_id=?1 AND active=1",
            params![campaign_id],
        )?;
        let activation = EpactActivation {
            contract: EPACT_ACTIVATION_CONTRACT.to_owned(),
            id: format!("epact_activation_{}", Uuid::new_v4().simple()),
            campaign_id: campaign_id.to_owned(),
            image_sha256: image.image_sha256.clone(),
            predecessor_image_sha256,
            effective_event_head_sha256,
            actor: actor.to_owned(),
            rationale,
            amendment,
            activated_at: now.clone(),
        };
        transaction.execute(
            "INSERT INTO epact_campaign_activations(id,campaign_id,image_sha256,predecessor_image_sha256,effective_event_head_sha256,actor,rationale,amendment_json,active,activated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,1,?9)",
            params![
                activation.id,
                activation.campaign_id,
                activation.image_sha256,
                activation.predecessor_image_sha256,
                activation.effective_event_head_sha256,
                activation.actor,
                activation.rationale,
                activation
                    .amendment
                    .as_ref()
                    .map(serde_json::to_string)
                    .transpose()?,
                activation.activated_at,
            ],
        )?;
        transaction.commit()?;
        Ok(ActiveEpactProgram {
            activation,
            state: initial_epact_state(&image)?,
            image,
            events: Vec::new(),
        })
    }

    pub fn active_epact_program(&self, campaign_id: &str) -> Result<Option<ActiveEpactProgram>> {
        let connection = self.connect()?;
        let transaction = connection.unchecked_transaction()?;
        let active = active_epact_program_tx(&transaction, campaign_id)?;
        transaction.commit()?;
        Ok(active)
    }

    /// Derive a dispatch binding from durable agent authority and the currently active image.
    /// The caller still submits the result through the atomic dispatch-permit path, which repeats
    /// eligibility under the same transaction that reserves any budget.
    pub fn epact_binding_for_agent_operation(
        &self,
        run: &AgentRun,
        operation: KernelOperation,
        actual_effects: Option<Vec<concord_protocol::EffectClass>>,
        placement: Option<EpactPlacementClaim>,
        resources: EpactResourceEnvelope,
    ) -> Result<Option<(String, EpactDispatchBinding)>> {
        let connection = self.connect()?;
        let transaction = connection.unchecked_transaction()?;
        let active = active_epact_program_tx(&transaction, &run.campaign_id)?;
        let Some(active) = active else {
            ensure!(
                run.epact.is_none(),
                "agent binding references Epact but the campaign has no active program"
            );
            transaction.commit()?;
            return Ok(None);
        };
        let agent_binding = run
            .epact
            .as_ref()
            .context("campaign has an active Epact program; agent run requires an Epact binding")?;
        ensure!(
            agent_binding.program_image_sha256 == active.image.image_sha256,
            "agent run references a stale or unrelated Epact program image"
        );
        let obligation = active
            .image
            .program
            .obligations
            .iter()
            .find(|obligation| obligation.id == agent_binding.obligation_id)
            .context("agent run references an unknown Epact obligation")?;
        ensure!(
            actual_effects.is_some() || operation == KernelOperation::Propose,
            "effect-bearing agent operations require trusted observed effects"
        );
        let mut effects = actual_effects.unwrap_or_else(|| obligation.effects.clone());
        effects.sort();
        effects.dedup();
        let binding = EpactDispatchBinding {
            program_image_sha256: active.image.image_sha256,
            obligation_id: agent_binding.obligation_id.clone(),
            operation,
            capability_id: agent_binding.capability_id.clone(),
            effects,
            resources,
            placement,
        };
        binding.validate()?;
        let actor = agent_binding.principal_id.clone();
        transaction.commit()?;
        Ok(Some((actor, binding)))
    }

    pub fn append_epact_event(
        &self,
        campaign_id: &str,
        actor: &str,
        idempotency_key: &str,
        kind: EpactRuntimeEventKind,
        receipt_sha256: Option<String>,
    ) -> Result<EpactRuntimeEvent> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let active = active_epact_program_tx(&transaction, campaign_id)?
            .context("campaign has no active Epact program")?;

        let existing: Option<String> = transaction
            .query_row(
                "SELECT event_json FROM epact_runtime_events WHERE campaign_id=?1 AND image_sha256=?2 AND idempotency_key=?3",
                params![campaign_id, active.image.image_sha256, idempotency_key],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            let event: EpactRuntimeEvent = serde_json::from_str(&existing)?;
            ensure!(
                event.actor == actor.trim()
                    && event.kind == kind
                    && event.receipt_sha256 == receipt_sha256,
                "Epact idempotency key was reused for a different event"
            );
            transaction.commit()?;
            return Ok(event);
        }

        let event = EpactRuntimeEvent::build(
            format!("epact_event_{}", Uuid::new_v4().simple()),
            active.image.image_sha256.clone(),
            active.state.next_sequence,
            actor.trim().to_owned(),
            idempotency_key.trim().to_owned(),
            kind,
            receipt_sha256,
            active.state.event_head_sha256.clone(),
            canonical_now(),
        )?;
        verify_epact_event_authority(&active.image, &active.state, &event)?;
        let mut candidate = active.events;
        candidate.push(event.clone());
        replay_epact_events(&active.image, &candidate)?;
        transaction.execute(
            "INSERT INTO epact_runtime_events(event_sha256,event_id,campaign_id,image_sha256,sequence,idempotency_key,event_json,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                event.event_sha256,
                event.id,
                campaign_id,
                event.program_image_sha256,
                i64::try_from(event.sequence)?,
                event.idempotency_key,
                serde_json::to_string(&event)?,
                event.created_at,
            ],
        )?;
        transaction.commit()?;
        Ok(event)
    }
}
pub(crate) fn enforce_epact_dispatch_tx(
    transaction: &Transaction<'_>,
    campaign_id: &str,
    request: &AuthorizeCampaignDispatchRequest,
    requested_at: &str,
) -> Result<()> {
    let Some(active) = active_epact_program_tx(transaction, campaign_id)? else {
        return Ok(());
    };
    let binding = request
        .epact
        .as_ref()
        .context("campaign has an active Epact program; dispatch requires an Epact binding")?;
    ensure!(
        binding.program_image_sha256 == active.image.image_sha256,
        "dispatch references a stale or unrelated Epact program image"
    );
    let eligibility = evaluate_epact_operation(
        &active.image,
        &active.state,
        &EpactOperationRequest {
            principal_id: request.actor.trim().to_owned(),
            operation: binding.operation,
            requested_at: requested_at.to_owned(),
            obligation_id: Some(binding.obligation_id.clone()),
            capability_id: binding.capability_id.clone(),
            effects: binding.effects.clone(),
            resources: binding.resources.clone(),
            placement: binding.placement.clone(),
        },
    )?;
    if !eligibility.allowed {
        let reasons = eligibility
            .blockers
            .iter()
            .map(|blocker| format!("{}:{}", blocker.code, blocker.subject_id))
            .collect::<Vec<_>>()
            .join(", ");
        bail!("Epact denied dispatch: {reasons}");
    }
    Ok(())
}

pub(crate) fn enforce_epact_agent_binding_tx(
    transaction: &Transaction<'_>,
    campaign_id: &str,
    binding: Option<&EpactAgentBinding>,
    budget: &AgentBudget,
) -> Result<()> {
    let Some(active) = active_epact_program_tx(transaction, campaign_id)? else {
        ensure!(
            binding.is_none(),
            "agent binding references Epact but the campaign has no active program"
        );
        return Ok(());
    };
    let binding = binding
        .context("campaign has an active Epact program; agent run requires an Epact binding")?;
    ensure!(
        binding.program_image_sha256 == active.image.image_sha256,
        "agent run references a stale or unrelated Epact program image"
    );
    let obligation = active
        .image
        .program
        .obligations
        .iter()
        .find(|obligation| obligation.id == binding.obligation_id)
        .context("agent run references an unknown Epact obligation")?;
    let resources = EpactResourceEnvelope {
        maximum_cost_usd: budget.max_cost_usd.unwrap_or(0.0),
        maximum_elapsed_seconds: budget.max_elapsed_seconds,
        ..EpactResourceEnvelope::default()
    };
    let eligibility = evaluate_epact_operation(
        &active.image,
        &active.state,
        &EpactOperationRequest {
            principal_id: binding.principal_id.clone(),
            operation: KernelOperation::Propose,
            requested_at: canonical_now(),
            obligation_id: Some(binding.obligation_id.clone()),
            capability_id: binding.capability_id.clone(),
            effects: obligation.effects.clone(),
            resources,
            placement: None,
        },
    )?;
    if !eligibility.allowed {
        let reasons = eligibility
            .blockers
            .iter()
            .map(|blocker| format!("{}:{}", blocker.code, blocker.subject_id))
            .collect::<Vec<_>>()
            .join(", ");
        bail!("Epact denied agent proposal authority: {reasons}");
    }
    Ok(())
}

fn active_epact_program_tx(
    transaction: &Transaction<'_>,
    campaign_id: &str,
) -> Result<Option<ActiveEpactProgram>> {
    let record: Option<(String, String)> = transaction
        .query_row(
            "SELECT a.id,a.image_sha256 FROM epact_campaign_activations a WHERE a.campaign_id=?1 AND a.active=1",
            params![campaign_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((activation_id, image_sha256)) = record else {
        return Ok(None);
    };
    let image_json: String = transaction.query_row(
        "SELECT image_json FROM epact_program_images WHERE image_sha256=?1",
        params![image_sha256],
        |row| row.get(0),
    )?;
    let image: EpactProgramImage = serde_json::from_str(&image_json)?;
    verify_epact_program_image(&image)?;
    let activation = transaction.query_row(
        "SELECT id,campaign_id,image_sha256,predecessor_image_sha256,effective_event_head_sha256,actor,rationale,amendment_json,activated_at FROM epact_campaign_activations WHERE id=?1",
        params![activation_id],
        |row| {
            let amendment_json: Option<String> = row.get(7)?;
            let amendment = amendment_json
                .map(|value| serde_json::from_str(&value))
                .transpose()
                .map_err(|error| rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(error)))?;
            Ok(EpactActivation {
                contract: EPACT_ACTIVATION_CONTRACT.to_owned(),
                id: row.get(0)?,
                campaign_id: row.get(1)?,
                image_sha256: row.get(2)?,
                predecessor_image_sha256: row.get(3)?,
                effective_event_head_sha256: row.get(4)?,
                actor: row.get(5)?,
                rationale: row.get(6)?,
                amendment,
                activated_at: row.get(8)?,
            })
        },
    )?;
    let mut statement = transaction.prepare(
        "SELECT event_json FROM epact_runtime_events WHERE campaign_id=?1 AND image_sha256=?2 ORDER BY sequence",
    )?;
    let events = statement
        .query_map(params![campaign_id, image.image_sha256], |row| {
            row.get::<_, String>(0)
        })?
        .map(|raw| Ok(serde_json::from_str::<EpactRuntimeEvent>(&raw?)?))
        .collect::<Result<Vec<_>>>()?;
    let state = replay_epact_events(&image, &events)?;
    Ok(Some(ActiveEpactProgram {
        activation,
        image,
        state,
        events,
    }))
}

fn ensure_program_authority(
    image: &EpactProgramImage,
    actor: &str,
    operation: KernelOperation,
    at: &str,
) -> Result<()> {
    ensure!(
        image.authorities.iter().any(|authority| {
            authority.principal_id == actor
                && authority.operation == operation
                && authority.whole_program
                && authority
                    .valid_after
                    .as_ref()
                    .is_none_or(|after| at >= after)
                && authority
                    .valid_before
                    .as_ref()
                    .is_none_or(|before| at < before)
        }),
        "principal {actor} lacks active whole-program {operation:?} authority"
    );
    Ok(())
}

fn canonical_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use concord_protocol::{
        AgentEventKind, CreateAgentRunRequest, DispatchOperation, EffectClass,
        EpactAmendmentPolicy, EpactAuthorityGrant, EpactAuthorityScope, EpactCapabilityRequirement,
        EpactDispatchBinding, EpactObjectDeclaration, EpactObligation, EpactPrincipal,
        EpactProgramRef, EpactTerminalRule, PrincipalKind, ProgramLifecycle, ReversibilityClass,
        ReversibilityPolicy, EPACT_PROGRAM_CONTRACT,
    };

    const RECEIPT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn kernel_activation_replay_dispatch_and_amendment_are_durable() {
        let (database, path) = database_with_campaign();
        let mut initial_program = program("1", None);
        initial_program.principals.push(EpactPrincipal {
            id: "principal:observer".to_owned(),
            kind: PrincipalKind::Human,
            display_name: "Observer without event authority".to_owned(),
        });
        let first = database
            .activate_epact_program(
                "campaign:epact",
                initial_program,
                "principal:operator",
                None,
            )
            .unwrap();
        assert_eq!(first.state.next_sequence, 0);

        database
            .upsert_provider(&crate::ProviderProfile {
                id: "provider:fixture".to_owned(),
                name: "Fixture model".to_owned(),
                kind: "model_api".to_owned(),
                base_url: None,
                secret_ref: None,
                secret_available: true,
                status: "ready".to_owned(),
                metadata: serde_json::json!({"model": "fixture-v1"}),
                updated_at: canonical_now(),
            })
            .unwrap();
        let agent_budget = AgentBudget {
            max_model_calls: 2,
            max_tool_calls: 1,
            max_elapsed_seconds: 60,
            budget_id: None,
            max_cost_usd: Some(0.0),
        };
        let unbound_agent = CreateAgentRunRequest {
            campaign_id: "campaign:epact".to_owned(),
            provider_id: "provider:fixture".to_owned(),
            model: Some("fixture-v1".to_owned()),
            task: "Propose the analysis.".to_owned(),
            allowed_tools: vec![],
            budget: agent_budget.clone(),
            epact: None,
            parent_run_id: None,
            parent_event_hash: None,
        };
        assert!(database
            .create_agent_run(&unbound_agent, "fixture-v1")
            .is_err());
        let bound_agent = database
            .create_agent_run(
                &CreateAgentRunRequest {
                    epact: Some(EpactAgentBinding {
                        program_image_sha256: first.image.image_sha256.clone(),
                        principal_id: "principal:operator".to_owned(),
                        obligation_id: "obligation:analyze".to_owned(),
                        capability_id: Some("capability:analyze".to_owned()),
                    }),
                    ..unbound_agent
                },
                "fixture-v1",
            )
            .unwrap();
        assert_eq!(
            bound_agent.run.epact.as_ref().unwrap().program_image_sha256,
            first.image.image_sha256
        );
        let tool_resources = EpactResourceEnvelope {
            maximum_elapsed_seconds: 60,
            ..EpactResourceEnvelope::default()
        };
        let (tool_actor, tool_binding) = database
            .epact_binding_for_agent_operation(
                &bound_agent.run,
                KernelOperation::Dispatch,
                Some(vec![EffectClass::ReadOnly]),
                None,
                tool_resources.clone(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(tool_actor, "principal:operator");
        assert_eq!(tool_binding.effects, [EffectClass::ReadOnly]);
        let mut tool_request = dispatch_request(&first.image.image_sha256);
        tool_request.operation = DispatchOperation::AgentToolCall;
        tool_request.epact = Some(tool_binding);
        let connection = database.connect().unwrap();
        let transaction = connection.unchecked_transaction().unwrap();
        enforce_epact_dispatch_tx(
            &transaction,
            "campaign:epact",
            &tool_request,
            "2026-09-03T00:00:00Z",
        )
        .unwrap();
        transaction.commit().unwrap();

        let (_, wrong_effect_binding) = database
            .epact_binding_for_agent_operation(
                &bound_agent.run,
                KernelOperation::Dispatch,
                Some(vec![EffectClass::ExternalWrite]),
                None,
                tool_resources,
            )
            .unwrap()
            .unwrap();
        tool_request.epact = Some(wrong_effect_binding);
        let connection = database.connect().unwrap();
        let transaction = connection.unchecked_transaction().unwrap();
        assert!(enforce_epact_dispatch_tx(
            &transaction,
            "campaign:epact",
            &tool_request,
            "2026-09-03T00:00:00Z",
        )
        .is_err());
        transaction.commit().unwrap();

        assert!(database
            .append_epact_event(
                "campaign:epact",
                "principal:observer",
                "object:unauthorized",
                EpactRuntimeEventKind::ObjectRecorded {
                    object_id: "object:result".to_owned(),
                },
                Some(RECEIPT.to_owned()),
            )
            .is_err());
        assert_eq!(
            database
                .active_epact_program("campaign:epact")
                .unwrap()
                .unwrap()
                .state
                .next_sequence,
            0
        );

        let request = dispatch_request(&first.image.image_sha256);
        let connection = database.connect().unwrap();
        let transaction = connection.unchecked_transaction().unwrap();
        enforce_epact_dispatch_tx(
            &transaction,
            "campaign:epact",
            &request,
            "2026-09-03T00:00:00Z",
        )
        .unwrap();
        transaction.commit().unwrap();

        let mut unbound = request.clone();
        unbound.epact = None;
        let connection = database.connect().unwrap();
        let transaction = connection.unchecked_transaction().unwrap();
        assert!(enforce_epact_dispatch_tx(
            &transaction,
            "campaign:epact",
            &unbound,
            "2026-09-03T00:00:00Z",
        )
        .is_err());

        database
            .append_epact_event(
                "campaign:epact",
                "principal:operator",
                "object:result",
                EpactRuntimeEventKind::ObjectRecorded {
                    object_id: "object:result".to_owned(),
                },
                Some(RECEIPT.to_owned()),
            )
            .unwrap();
        database
            .append_epact_event(
                "campaign:epact",
                "principal:operator",
                "obligation:analyze:satisfied",
                EpactRuntimeEventKind::ObligationSatisfied {
                    obligation_id: "obligation:analyze".to_owned(),
                    receipt_contract: "example.analysis-receipt/1".to_owned(),
                },
                Some(RECEIPT.to_owned()),
            )
            .unwrap();

        let reopened = Database::new(&path).unwrap();
        let restored = reopened
            .active_epact_program("campaign:epact")
            .unwrap()
            .unwrap();
        assert_eq!(restored.state.next_sequence, 2);
        assert_eq!(restored.events.len(), 2);
        assert_eq!(
            restored.state.obligations[0].state,
            concord_protocol::EpactObligationState::Satisfied
        );

        let successor = program(
            "2",
            Some(EpactProgramRef {
                id: restored.image.program.id.clone(),
                version: restored.image.program.version.clone(),
                program_sha256: restored.image.program_sha256.clone(),
            }),
        );
        let amended = reopened
            .activate_epact_program(
                "campaign:epact",
                successor,
                "principal:operator",
                Some("Tighten the next prospective execution without rewriting run one."),
            )
            .unwrap();
        assert_eq!(
            amended.activation.predecessor_image_sha256,
            Some(restored.image.image_sha256.clone())
        );
        assert_eq!(
            amended.activation.effective_event_head_sha256,
            restored.state.event_head_sha256.unwrap()
        );
        assert!(amended.activation.amendment.is_some());
        assert!(amended.events.is_empty());
        assert_eq!(amended.state.next_sequence, 0);
        assert!(reopened
            .append_agent_event(
                &bound_agent.run.id,
                bound_agent.run.revision,
                "model:stale-image",
                AgentEventKind::ModelRequested,
                serde_json::json!({"requestId": "stale"}),
            )
            .is_err());

        let connection = reopened.connect().unwrap();
        let historical_events: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM epact_runtime_events WHERE campaign_id='campaign:epact'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let activations: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM epact_campaign_activations WHERE campaign_id='campaign:epact'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(historical_events, 2);
        assert_eq!(activations, 2);
        std::fs::remove_file(path).unwrap();
    }

    fn database_with_campaign() -> (Database, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "concord-epact-kernel-test-{}.sqlite3",
            Uuid::new_v4().simple()
        ));
        let database = Database::new(&path).unwrap();
        let connection = database.connect().unwrap();
        connection
            .execute(
                "INSERT INTO programs(id,name,language,language_version,source) VALUES ('program:legacy','Legacy reference','Epact','0.1','{}')",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO campaigns(id,name,domain,objective,status,created_at,program_id) VALUES ('campaign:epact','Epact test','testing','Exercise Epact','active','2026-09-03T00:00:00Z','program:legacy')",
                [],
            )
            .unwrap();
        drop(connection);
        (database, path)
    }

    fn dispatch_request(image_sha256: &str) -> AuthorizeCampaignDispatchRequest {
        AuthorizeCampaignDispatchRequest {
            generation: 1,
            idempotency_key: "dispatch:analyze".to_owned(),
            actor: "principal:operator".to_owned(),
            operation: DispatchOperation::ExecutionRun,
            target_id: "run:analysis".to_owned(),
            budget_id: None,
            maximum_cost_usd: 0.0,
            reserve_budget: false,
            budget_pre_reserved: false,
            maximum_elapsed_seconds: 60,
            epact: Some(EpactDispatchBinding {
                program_image_sha256: image_sha256.to_owned(),
                obligation_id: "obligation:analyze".to_owned(),
                operation: KernelOperation::Dispatch,
                capability_id: Some("capability:analyze".to_owned()),
                effects: vec![EffectClass::ReadOnly],
                resources: EpactResourceEnvelope {
                    maximum_elapsed_seconds: 60,
                    maximum_cpu_cores: 1.0,
                    maximum_ram_gb: 1.0,
                    ..EpactResourceEnvelope::default()
                },
                placement: None,
            }),
        }
    }

    fn program(version: &str, predecessor: Option<EpactProgramRef>) -> EpactProgram {
        EpactProgram {
            contract: EPACT_PROGRAM_CONTRACT.to_owned(),
            id: "epact:kernel-test".to_owned(),
            version: version.to_owned(),
            title: format!("Kernel test program {version}"),
            lifecycle: ProgramLifecycle::Frozen,
            created_by: "principal:operator".to_owned(),
            predecessor,
            imports: vec![],
            principals: vec![EpactPrincipal {
                id: "principal:operator".to_owned(),
                kind: PrincipalKind::Human,
                display_name: "Operator".to_owned(),
            }],
            objects: vec![EpactObjectDeclaration {
                id: "object:result".to_owned(),
                type_name: "example.result/1".to_owned(),
                schema_sha256: None,
                data_classes: vec![],
            }],
            capabilities: vec![EpactCapabilityRequirement {
                id: "capability:analyze".to_owned(),
                capability_type: "deterministic_analysis".to_owned(),
                contract: "example.analysis/1".to_owned(),
                required_effects: vec![EffectClass::ReadOnly],
                required_data_classes: vec![],
                placement: None,
            }],
            authorities: vec![EpactAuthorityGrant {
                id: "authority:operator".to_owned(),
                principal_id: "principal:operator".to_owned(),
                operations: vec![
                    KernelOperation::Freeze,
                    KernelOperation::Authorize,
                    KernelOperation::Amend,
                    KernelOperation::Propose,
                    KernelOperation::Reserve,
                    KernelOperation::Dispatch,
                ],
                scope: EpactAuthorityScope {
                    whole_program: true,
                    obligation_ids: vec![],
                    capability_ids: vec![],
                },
                maximum_cost_usd: 0.0,
                valid_after: None,
                valid_before: None,
            }],
            resources: EpactResourceEnvelope {
                maximum_elapsed_seconds: 60,
                maximum_cpu_cores: 1.0,
                maximum_ram_gb: 1.0,
                ..EpactResourceEnvelope::default()
            },
            obligations: vec![EpactObligation {
                id: "obligation:analyze".to_owned(),
                label: "Analyze".to_owned(),
                description: "Produce one deterministic result.".to_owned(),
                dependency_ids: vec![],
                gate_ids: vec![],
                discharge: concord_protocol::EpactDischarge::Capability {
                    capability_id: "capability:analyze".to_owned(),
                },
                output_object_ids: vec!["object:result".to_owned()],
                effects: vec![EffectClass::ReadOnly],
                resources: EpactResourceEnvelope {
                    maximum_elapsed_seconds: 60,
                    maximum_cpu_cores: 1.0,
                    maximum_ram_gb: 1.0,
                    ..EpactResourceEnvelope::default()
                },
                reversibility: ReversibilityPolicy {
                    class: ReversibilityClass::ReadOnly,
                    reversal_action: None,
                    limitations: vec![],
                },
                retry_limit: 1,
                terminal_receipt_contract: "example.analysis-receipt/1".to_owned(),
            }],
            gates: vec![],
            evidence_rules: vec![],
            amendment_policy: EpactAmendmentPolicy {
                authorized_principal_ids: vec!["principal:operator".to_owned()],
                rationale_required: true,
                effective_causal_head_required: true,
                preserve_prior_interpretation: true,
            },
            terminal: EpactTerminalRule {
                required_obligation_ids: vec!["obligation:analyze".to_owned()],
                required_object_ids: vec!["object:result".to_owned()],
                required_receipt_contracts: vec!["example.analysis-receipt/1".to_owned()],
            },
        }
    }
}
