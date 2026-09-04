//! Durable requests to progress within an agent's existing authority and budget.
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const AGENT_PROGRESSION_CONTRACT: &str = "concord.agent-progression/1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentProgressionAction {
    Run,
    Pause,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SetAgentProgressionRequest {
    pub action: AgentProgressionAction,
    pub expected_agent_revision: Option<u64>,
    pub expected_record_sha256: Option<String>,
    pub idempotency_key: String,
    pub actor: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentProgressionRecord {
    pub contract: String,
    pub agent_run_id: String,
    pub sequence: u64,
    pub agent_revision: u64,
    pub agent_event_sha256: String,
    pub request: SetAgentProgressionRequest,
    pub previous_record_sha256: Option<String>,
    pub created_at: String,
    pub record_sha256: String,
}

impl AgentProgressionRecord {
    pub fn recompute_sha256(&self) -> Result<String> {
        let mut value = serde_json::to_value(self)?;
        value.as_object_mut().unwrap().remove("recordSha256");
        Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(&value)?)))
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.contract == AGENT_PROGRESSION_CONTRACT && !self.agent_run_id.is_empty(),
            "invalid progression record identity"
        );
        ensure!(
            self.request.expected_record_sha256 == self.previous_record_sha256,
            "progression request does not bind its predecessor"
        );
        ensure!(
            self.agent_event_sha256.len() == 64 && self.record_sha256 == self.recompute_sha256()?,
            "progression record hash mismatch"
        );
        Ok(())
    }
}
