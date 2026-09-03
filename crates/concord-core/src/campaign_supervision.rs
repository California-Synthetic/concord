use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub use concord_protocol::{
    AuthorizeCampaignDispatchRequest, CampaignDispatchPermit, DispatchAccountingSummary,
    DispatchOperation, DispatchPermitStatus, DispatchReapSummary, InterruptedDispatchResolution,
    ResolveInterruptedDispatchRequest, CAMPAIGN_DISPATCH_PERMIT_CONTRACT,
};

pub const CAMPAIGN_SUPERVISION_CONTRACT: &str = "concord.campaign-supervision/1";
pub const CAMPAIGN_RECONCILIATION_CONTRACT: &str = "concord.campaign-reconciliation/1";
pub const CAMPAIGN_CLOSEOUT_CONTRACT: &str = "concord.campaign-closeout/1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupervisorRole {
    Clock,
    Budget,
    Watchdog,
    Scribe,
    Deliverables,
    Reviewer,
    Reconciler,
}

impl SupervisorRole {
    pub const REQUIRED: [Self; 7] = [
        Self::Clock,
        Self::Budget,
        Self::Watchdog,
        Self::Scribe,
        Self::Deliverables,
        Self::Reviewer,
        Self::Reconciler,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clock => "clock",
            Self::Budget => "budget",
            Self::Watchdog => "watchdog",
            Self::Scribe => "scribe",
            Self::Deliverables => "deliverables",
            Self::Reviewer => "reviewer",
            Self::Reconciler => "reconciler",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "clock" => Self::Clock,
            "budget" => Self::Budget,
            "watchdog" => Self::Watchdog,
            "scribe" => Self::Scribe,
            "deliverables" => Self::Deliverables,
            "reviewer" => Self::Reviewer,
            "reconciler" => Self::Reconciler,
            other => bail!("unknown supervisor role {other}"),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernorStatus {
    Closed,
    Reconciling,
    Open,
    Blocked,
}

impl GovernorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Reconciling => "reconciling",
            Self::Open => "open",
            Self::Blocked => "blocked",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "closed" => Self::Closed,
            "reconciling" => Self::Reconciling,
            "open" => Self::Open,
            "blocked" => Self::Blocked,
            other => bail!("unknown campaign governor status {other}"),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceLeaseStatus {
    Healthy,
    Stale,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceLease {
    pub campaign_id: String,
    pub role: SupervisorRole,
    pub owner_id: String,
    pub generation: u64,
    pub status: ServiceLeaseStatus,
    pub last_heartbeat_at: String,
    pub lease_expires_at: String,
    #[serde(default)]
    pub details: Value,
}

impl ServiceLease {
    pub fn is_live_at(&self, now: DateTime<Utc>) -> Result<bool> {
        let expires = DateTime::parse_from_rfc3339(&self.lease_expires_at)
            .map_err(|error| anyhow::anyhow!("invalid lease expiry: {error}"))?
            .with_timezone(&Utc);
        Ok(expires > now)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CampaignGovernor {
    pub contract: String,
    pub campaign_id: String,
    pub generation: u64,
    pub status: GovernorStatus,
    #[serde(default)]
    pub last_reconciliation_sha256: Option<String>,
    #[serde(default)]
    pub blocked_reason: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStep {
    RestoreHeartbeatAndGovernor,
    RestartSingletons,
    ReloadDurableLedgers,
    ReconcileProviderStateAndSpend,
    ReviewReconciliationBeforeDispatch,
}

impl RecoveryStep {
    pub const ORDERED: [Self; 5] = [
        Self::RestoreHeartbeatAndGovernor,
        Self::RestartSingletons,
        Self::ReloadDurableLedgers,
        Self::ReconcileProviderStateAndSpend,
        Self::ReviewReconciliationBeforeDispatch,
    ];
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CampaignSupervisionSnapshot {
    pub governor: CampaignGovernor,
    pub services: Vec<ServiceLease>,
    pub missing_or_stale_roles: Vec<SupervisorRole>,
    pub recovery_plan: Vec<RecoveryStep>,
    pub dispatch_allowed: bool,
    pub dispatch_accounting: DispatchAccountingSummary,
    pub observed_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BeginCampaignRecoveryRequest {
    pub owner_id: String,
    pub reason: String,
}

impl BeginCampaignRecoveryRequest {
    pub fn validate(&self) -> Result<()> {
        validate_text("ownerId", &self.owner_id, 160)?;
        validate_text("reason", &self.reason, 2_000)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceHeartbeatRequest {
    pub role: SupervisorRole,
    pub owner_id: String,
    pub generation: u64,
    pub lease_seconds: u64,
    #[serde(default)]
    pub details: Value,
}

impl ServiceHeartbeatRequest {
    pub fn validate(&self) -> Result<()> {
        validate_text("ownerId", &self.owner_id, 160)?;
        if !(5..=3_600).contains(&self.lease_seconds) {
            bail!("leaseSeconds must be between 5 and 3600");
        }
        let encoded = serde_json::to_vec(&self.details)?;
        if encoded.len() > 32_768 {
            bail!("heartbeat details exceed 32768 bytes");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationDisposition {
    Clean,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReconcileCampaignRequest {
    pub generation: u64,
    pub reconciler_owner_id: String,
    pub provider_snapshot_sha256: String,
    pub budget_snapshot_sha256: String,
    pub ledger_heads: BTreeMap<String, String>,
    pub disposition: ReconciliationDisposition,
    #[serde(default)]
    pub findings: Vec<String>,
}

impl ReconcileCampaignRequest {
    pub fn validate(&self) -> Result<()> {
        validate_text("reconcilerOwnerId", &self.reconciler_owner_id, 160)?;
        validate_sha256("providerSnapshotSha256", &self.provider_snapshot_sha256)?;
        validate_sha256("budgetSnapshotSha256", &self.budget_snapshot_sha256)?;
        if self.ledger_heads.is_empty() {
            bail!("at least one durable ledger head is required");
        }
        if self.ledger_heads.len() > 64 {
            bail!("at most 64 durable ledger heads are supported");
        }
        for (name, digest) in &self.ledger_heads {
            validate_text("ledger name", name, 160)?;
            validate_sha256("ledger head", digest)?;
        }
        if self.findings.len() > 64 {
            bail!("at most 64 reconciliation findings are supported");
        }
        for finding in &self.findings {
            validate_text("finding", finding, 2_000)?;
        }
        match self.disposition {
            ReconciliationDisposition::Clean if !self.findings.is_empty() => {
                bail!("a clean reconciliation cannot contain findings")
            }
            ReconciliationDisposition::Blocked if self.findings.is_empty() => {
                bail!("a blocked reconciliation requires at least one finding")
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CampaignReconciliation {
    pub contract: String,
    pub id: String,
    pub campaign_id: String,
    pub generation: u64,
    pub reconciler_owner_id: String,
    pub provider_snapshot_sha256: String,
    pub budget_snapshot_sha256: String,
    pub ledger_heads: BTreeMap<String, String>,
    pub disposition: ReconciliationDisposition,
    pub findings: Vec<String>,
    pub reconciliation_sha256: String,
    pub created_at: String,
}

impl CampaignReconciliation {
    pub fn build(
        campaign_id: &str,
        request: &ReconcileCampaignRequest,
        created_at: &str,
    ) -> Result<Self> {
        request.validate()?;
        let mut record = Self {
            contract: CAMPAIGN_RECONCILIATION_CONTRACT.to_owned(),
            id: String::new(),
            campaign_id: campaign_id.to_owned(),
            generation: request.generation,
            reconciler_owner_id: request.reconciler_owner_id.trim().to_owned(),
            provider_snapshot_sha256: request.provider_snapshot_sha256.clone(),
            budget_snapshot_sha256: request.budget_snapshot_sha256.clone(),
            ledger_heads: request.ledger_heads.clone(),
            disposition: request.disposition,
            findings: request
                .findings
                .iter()
                .map(|value| value.trim().to_owned())
                .collect(),
            reconciliation_sha256: String::new(),
            created_at: created_at.to_owned(),
        };
        let digest = hash_without_fields(&record, &["id", "reconciliationSha256", "createdAt"])?;
        record.id = format!("campaign_reconciliation_{}", &digest[..24]);
        record.reconciliation_sha256 = digest;
        Ok(record)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloseoutCampaignRequest {
    pub generation: u64,
    pub actor: String,
    pub decision_sha256: String,
    pub evidence_sha256: Vec<String>,
    pub ledger_heads: BTreeMap<String, String>,
}

impl CloseoutCampaignRequest {
    pub fn validate(&self) -> Result<()> {
        validate_text("actor", &self.actor, 160)?;
        validate_sha256("decisionSha256", &self.decision_sha256)?;
        if self.evidence_sha256.is_empty() {
            bail!("closeout requires at least one evidence digest");
        }
        let unique = self.evidence_sha256.iter().collect::<BTreeSet<_>>();
        if unique.len() != self.evidence_sha256.len() {
            bail!("closeout evidence digests must be unique");
        }
        for digest in &self.evidence_sha256 {
            validate_sha256("evidence digest", digest)?;
        }
        if self.ledger_heads.is_empty() {
            bail!("closeout requires durable ledger heads");
        }
        for (name, digest) in &self.ledger_heads {
            validate_text("ledger name", name, 160)?;
            validate_sha256("ledger head", digest)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CampaignCloseout {
    pub contract: String,
    pub id: String,
    pub campaign_id: String,
    pub generation: u64,
    pub actor: String,
    pub decision_sha256: String,
    pub evidence_sha256: Vec<String>,
    pub ledger_heads: BTreeMap<String, String>,
    pub closeout_sha256: String,
    pub created_at: String,
}

impl CampaignCloseout {
    pub fn build(
        campaign_id: &str,
        request: &CloseoutCampaignRequest,
        created_at: &str,
    ) -> Result<Self> {
        request.validate()?;
        let mut evidence = request.evidence_sha256.clone();
        evidence.sort();
        let mut record = Self {
            contract: CAMPAIGN_CLOSEOUT_CONTRACT.to_owned(),
            id: String::new(),
            campaign_id: campaign_id.to_owned(),
            generation: request.generation,
            actor: request.actor.trim().to_owned(),
            decision_sha256: request.decision_sha256.clone(),
            evidence_sha256: evidence,
            ledger_heads: request.ledger_heads.clone(),
            closeout_sha256: String::new(),
            created_at: created_at.to_owned(),
        };
        let digest = hash_without_fields(&record, &["id", "closeoutSha256", "createdAt"])?;
        record.id = format!("campaign_closeout_{}", &digest[..24]);
        record.closeout_sha256 = digest;
        Ok(record)
    }
}

fn validate_text(name: &str, value: &str, max_chars: usize) -> Result<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().count() > max_chars {
        bail!("{name} must contain between 1 and {max_chars} characters");
    }
    Ok(())
}

pub fn validate_sha256(name: &str, value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("{name} must be a lowercase SHA-256 digest");
    }
    Ok(())
}

fn hash_without_fields<T: Serialize>(value: &T, fields: &[&str]) -> Result<String> {
    let mut json = serde_json::to_value(value)?;
    let object = json
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("hash input must be an object"))?;
    for field in fields {
        object.remove(*field);
    }
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(&json)?)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha(character: char) -> String {
        std::iter::repeat_n(character, 64).collect()
    }

    #[test]
    fn clean_reconciliation_rejects_findings() {
        let request = ReconcileCampaignRequest {
            generation: 1,
            reconciler_owner_id: "reconciler-1".into(),
            provider_snapshot_sha256: sha('a'),
            budget_snapshot_sha256: sha('b'),
            ledger_heads: BTreeMap::from([("events".into(), sha('c'))]),
            disposition: ReconciliationDisposition::Clean,
            findings: vec!["unowned job".into()],
        };
        assert!(request.validate().is_err());
    }

    #[test]
    fn closeout_hash_is_order_independent_for_evidence() {
        let first = CloseoutCampaignRequest {
            generation: 3,
            actor: "operator".into(),
            decision_sha256: sha('a'),
            evidence_sha256: vec![sha('b'), sha('c')],
            ledger_heads: BTreeMap::from([("events".into(), sha('d'))]),
        };
        let mut second = first.clone();
        second.evidence_sha256.reverse();
        let left = CampaignCloseout::build("campaign", &first, "2026-08-19T00:00:00Z").unwrap();
        let right = CampaignCloseout::build("campaign", &second, "2026-08-19T00:00:00Z").unwrap();
        assert_eq!(left.closeout_sha256, right.closeout_sha256);
    }
}
