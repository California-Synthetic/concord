use super::*;
use crate::agent_progression::*;

fn read_records(
    connection: &Connection,
    agent_run_id: &str,
) -> Result<Vec<AgentProgressionRecord>> {
    let mut statement = connection.prepare("SELECT sequence,record_json FROM agent_progressions WHERE agent_run_id=?1 ORDER BY sequence")?;
    let rows = statement
        .query_map([agent_run_id], |row| {
            Ok((row.get::<_, u64>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut records: Vec<AgentProgressionRecord> = Vec::with_capacity(rows.len());
    for (sequence, raw) in rows {
        let record: AgentProgressionRecord = serde_json::from_str(&raw)?;
        record.validate()?;
        anyhow::ensure!(
            record.agent_run_id == agent_run_id
                && record.sequence == sequence
                && sequence == records.len() as u64,
            "progression sequence is incomplete"
        );
        anyhow::ensure!(
            record.previous_record_sha256.as_ref()
                == records.last().map(|record| &record.record_sha256),
            "progression chain is incomplete"
        );
        records.push(record);
    }
    Ok(records)
}

impl Database {
    pub fn agent_progressions(&self, agent_run_id: &str) -> Result<Vec<AgentProgressionRecord>> {
        read_records(&self.connect()?, agent_run_id)
    }

    /// This records scheduling intent only. It cannot approve a tool or repeat an ambiguous effect.
    pub fn set_agent_progression(
        &self,
        agent_run_id: &str,
        request: &SetAgentProgressionRequest,
    ) -> Result<AgentProgressionRecord> {
        for (name, value, maximum) in [
            ("actor", &request.actor, 256),
            ("reason", &request.reason, 2000),
            ("idempotency key", &request.idempotency_key, 256),
        ] {
            anyhow::ensure!(
                !value.trim().is_empty() && value.chars().count() <= maximum,
                "progression {name} is empty or too long"
            );
        }
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let records = read_records(&transaction, agent_run_id)?;
        if let Some(existing) = records
            .iter()
            .find(|record| record.request.idempotency_key == request.idempotency_key)
        {
            anyhow::ensure!(
                existing.request == *request,
                "progression idempotency key is bound to another request"
            );
            return Ok(existing.clone());
        }
        let previous = records.last();
        anyhow::ensure!(
            request.expected_record_sha256.as_ref() == previous.map(|record| &record.record_sha256),
            "progression control conflict; refresh the current request"
        );
        let (campaign_id, revision, status): (String, u64, String) = transaction
            .query_row(
                "SELECT campaign_id,revision,status FROM agent_runs WHERE id=?1",
                [agent_run_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .context("agent run does not exist")?;
        if request.action == AgentProgressionAction::Run {
            anyhow::ensure!(
                request.expected_agent_revision == Some(revision),
                "agent revision conflict before progression"
            );
            anyhow::ensure!(
                status == "ready" || status == "ready_for_tool",
                "agent cannot start progression from {status}; approval or recovery is required"
            );
            let closed: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM campaign_closeouts WHERE campaign_id=?1)",
                [&campaign_id],
                |row| row.get(0),
            )?;
            anyhow::ensure!(!closed, "closed campaign cannot start progression");
            let first: String = transaction.query_row(
                "SELECT payload_json FROM agent_events WHERE agent_run_id=?1 AND sequence=0",
                [agent_run_id],
                |row| row.get(0),
            )?;
            let first: Value = serde_json::from_str(&first)?;
            anyhow::ensure!(
                first["researchBrief"]["executionEnabled"] != false,
                "lineage-only coordinator cannot execute"
            );
        }
        let event_sha256 = transaction.query_row("SELECT event_sha256 FROM agent_events WHERE agent_run_id=?1 ORDER BY sequence DESC LIMIT 1", [agent_run_id], |row| row.get(0))?;
        let mut record = AgentProgressionRecord {
            contract: AGENT_PROGRESSION_CONTRACT.into(),
            agent_run_id: agent_run_id.into(),
            sequence: records.len() as u64,
            agent_revision: revision,
            agent_event_sha256: event_sha256,
            request: request.clone(),
            previous_record_sha256: previous.map(|record| record.record_sha256.clone()),
            created_at: Utc::now().to_rfc3339(),
            record_sha256: String::new(),
        };
        record.record_sha256 = record.recompute_sha256()?;
        record.validate()?;
        transaction.execute("INSERT INTO agent_progressions(agent_run_id,sequence,action,record_json) VALUES (?1,?2,?3,?4)", params![agent_run_id, record.sequence, if request.action == AgentProgressionAction::Run { "run" } else { "pause" }, serde_json::to_string(&record)?])?;
        transaction.commit()?;
        Ok(record)
    }

    pub fn active_agent_progressions(&self) -> Result<Vec<AgentProgressionRecord>> {
        let connection = self.connect()?;
        let mut statement = connection.prepare("SELECT p.agent_run_id FROM agent_progressions p WHERE p.action='run' AND p.sequence=(SELECT MAX(q.sequence) FROM agent_progressions q WHERE q.agent_run_id=p.agent_run_id)")?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut records = Vec::new();
        for id in ids {
            let record = read_records(&connection, &id)?
                .pop()
                .context("progression head missing")?;
            anyhow::ensure!(
                record.request.action == AgentProgressionAction::Run,
                "progression index does not match its record"
            );
            records.push(record);
        }
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progression_is_durable_idempotent_and_cannot_authorize_ambiguous_work() {
        let (database, path) = super::super::tests::note_test_database();
        let run = database
            .create_agent_run(
                &CreateAgentRunRequest {
                    campaign_id: "campaign:a".into(),
                    provider_id: "concord-deterministic".into(),
                    model: None,
                    task: "Inspect a bounded fixture".into(),
                    allowed_tools: vec![],
                    budget: AgentBudget::default(),
                    epact: None,
                    parent_run_id: None,
                    parent_event_hash: None,
                },
                "concord-deterministic-v1",
            )
            .unwrap();
        let request = SetAgentProgressionRequest {
            action: AgentProgressionAction::Run,
            expected_agent_revision: Some(run.run.revision),
            expected_record_sha256: None,
            actor: "primary".into(),
            reason: "Run within the frozen limits".into(),
            idempotency_key: "start".into(),
        };
        let first = database
            .set_agent_progression(&run.run.id, &request)
            .unwrap();
        assert_eq!(
            database
                .set_agent_progression(&run.run.id, &request)
                .unwrap(),
            first
        );
        assert_eq!(
            database.agent_run_envelope(&run.run.id).unwrap().unwrap(),
            run
        );
        let reopened = Database::new(&path).unwrap();
        assert_eq!(
            reopened.active_agent_progressions().unwrap(),
            vec![first.clone()]
        );
        let mut conflict = request.clone();
        conflict.reason = "Different request".into();
        assert!(database
            .set_agent_progression(&run.run.id, &conflict)
            .is_err());
        let in_flight = database
            .append_agent_event(
                &run.run.id,
                run.run.revision,
                "model-started",
                AgentEventKind::ModelRequested,
                json!({"request": {}}),
            )
            .unwrap();
        let paused = database
            .set_agent_progression(
                &run.run.id,
                &SetAgentProgressionRequest {
                    action: AgentProgressionAction::Pause,
                    expected_agent_revision: None,
                    expected_record_sha256: Some(first.record_sha256.clone()),
                    idempotency_key: "pause".into(),
                    actor: "primary".into(),
                    reason: "Pause after the current effect".into(),
                },
            )
            .unwrap();
        assert_eq!(paused.agent_revision, in_flight.run.revision);
        assert!(database.active_agent_progressions().unwrap().is_empty());
        let mut resume = request.clone();
        resume.idempotency_key = "resume".into();
        resume.expected_record_sha256 = Some(paused.record_sha256.clone());
        resume.expected_agent_revision = Some(in_flight.run.revision);
        assert!(database
            .set_agent_progression(&run.run.id, &resume)
            .unwrap_err()
            .to_string()
            .contains("approval or recovery"));
        assert_eq!(
            database
                .set_agent_progression(&run.run.id, &request)
                .unwrap(),
            first
        );
        assert!(database.active_agent_progressions().unwrap().is_empty());
        let returned = database
            .append_agent_event(
                &run.run.id,
                in_flight.run.revision,
                "model-returned",
                AgentEventKind::ModelResponded,
                json!({"response": {}}),
            )
            .unwrap();
        resume.expected_agent_revision = Some(returned.run.revision);
        let next = database
            .set_agent_progression(&run.run.id, &resume)
            .unwrap();
        assert_eq!(next.previous_record_sha256, Some(paused.record_sha256));
        // Recording scheduling intent must not mask the last semantic checkpoint.
        assert_eq!(
            database
                .agent_run_envelope(&run.run.id)
                .unwrap()
                .unwrap()
                .events
                .last()
                .unwrap()
                .kind,
            AgentEventKind::ModelResponded
        );
        assert_eq!(
            database
                .campaign_archive("campaign:a")
                .unwrap()
                .agent_progressions
                .len(),
            3
        );
        let connection = database.connect().unwrap();
        connection.execute("UPDATE agent_progressions SET record_json=replace(record_json,'Run within the frozen limits','unbound authority') WHERE agent_run_id=?1 AND sequence=0", [&run.run.id]).unwrap();
        assert!(database.active_agent_progressions().is_err());
        drop(connection);
        drop(reopened);
        drop(database);
        std::fs::remove_file(path).unwrap();
    }
}
