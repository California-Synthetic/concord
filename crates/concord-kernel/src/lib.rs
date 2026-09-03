//! Public, durable reference kernel for Concord scientific campaigns.
//!
//! The kernel is intentionally smaller than a product control plane. It owns the portable
//! authority path: campaign identity, one active Epact image, accepted Epact events, budget
//! reservations, dispatch permits, and hash-chained kernel receipts. Interfaces, credentials,
//! provider clients, effect execution, collaboration, and managed operations belong above it.

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use chrono::{DateTime, SecondsFormat, Utc};
use concord_harness::DispatchKernel;
use concord_protocol::{
    AuthorizeCampaignDispatchRequest, CampaignDispatchPermit, DispatchPermitStatus,
    InterruptedDispatchResolution, ResolveInterruptedDispatchRequest,
    CAMPAIGN_DISPATCH_PERMIT_CONTRACT,
};
use epact_compiler::{require_activatable, verify_program_image};
use epact_protocol::{
    canonical_epact_json_bytes, EpactOperationRequest, EpactProgramImage, EpactRuntimeEvent,
    EpactRuntimeState,
};
use epact_runtime::{evaluate_epact_operation, replay_epact_events};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub const KERNEL_EVENT_CONTRACT: &str = "concord.kernel-event/1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignStatus {
    Open,
    Blocked,
}

impl CampaignStatus {
    fn parse(value: &str) -> Result<Self, KernelError> {
        match value {
            "open" => Ok(Self::Open),
            "blocked" => Ok(Self::Blocked),
            other => Err(KernelError::Integrity(format!(
                "unknown campaign status {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateCampaignRequest {
    pub id: String,
    pub name: String,
    pub objective: String,
    pub image: EpactProgramImage,
}

impl CreateCampaignRequest {
    fn validate(&self) -> Result<(), KernelError> {
        validate_text("campaign id", &self.id, 240)?;
        validate_text("campaign name", &self.name, 240)?;
        validate_text("campaign objective", &self.objective, 8_000)?;
        verify_program_image(&self.image)
            .map_err(|error| KernelError::Contract(error.to_string()))?;
        require_activatable(&self.image).map_err(|error| KernelError::Contract(error.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CampaignRecord {
    pub id: String,
    pub name: String,
    pub objective: String,
    pub generation: u64,
    pub status: CampaignStatus,
    pub blocked_reason: Option<String>,
    pub program_image_sha256: String,
    pub reconciliation_sha256: String,
    pub event_head_sha256: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateBudgetRequest {
    pub id: String,
    pub total_usd: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BudgetRecord {
    pub id: String,
    pub campaign_id: String,
    pub total_usd: f64,
    pub spent_usd: f64,
    pub exposure_usd: f64,
    pub available_usd: f64,
    pub updated_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelEventKind {
    CampaignCreated,
    BudgetCreated,
    EpactEventAccepted,
    DispatchAuthorized,
    DispatchConsumed,
    DispatchSettled,
    DispatchInterrupted,
    DispatchReleased,
    DispatchResolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KernelEvent {
    pub contract: String,
    pub campaign_id: String,
    pub sequence: u64,
    pub kind: KernelEventKind,
    pub actor: String,
    pub subject_id: String,
    pub payload_sha256: String,
    pub previous_event_sha256: Option<String>,
    pub created_at: String,
    pub event_sha256: String,
}

impl KernelEvent {
    fn build(
        campaign_id: String,
        sequence: u64,
        kind: KernelEventKind,
        actor: String,
        subject_id: String,
        payload: &impl Serialize,
        previous_event_sha256: Option<String>,
        created_at: String,
    ) -> Result<Self, KernelError> {
        let payload_sha256 = sha256(&canonical_epact_json_bytes(payload)?);
        let mut event = Self {
            contract: KERNEL_EVENT_CONTRACT.to_owned(),
            campaign_id,
            sequence,
            kind,
            actor,
            subject_id,
            payload_sha256,
            previous_event_sha256,
            created_at,
            event_sha256: String::new(),
        };
        event.event_sha256 = event.recompute_sha256()?;
        Ok(event)
    }

    fn recompute_sha256(&self) -> Result<String, KernelError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct HashInput<'a> {
            contract: &'a str,
            campaign_id: &'a str,
            sequence: u64,
            kind: KernelEventKind,
            actor: &'a str,
            subject_id: &'a str,
            payload_sha256: &'a str,
            previous_event_sha256: &'a Option<String>,
            created_at: &'a str,
        }
        Ok(sha256(&canonical_epact_json_bytes(&HashInput {
            contract: &self.contract,
            campaign_id: &self.campaign_id,
            sequence: self.sequence,
            kind: self.kind,
            actor: &self.actor,
            subject_id: &self.subject_id,
            payload_sha256: &self.payload_sha256,
            previous_event_sha256: &self.previous_event_sha256,
            created_at: &self.created_at,
        })?))
    }

    fn verify(
        &self,
        expected_sequence: u64,
        expected_previous: Option<&str>,
    ) -> Result<(), KernelError> {
        if self.contract != KERNEL_EVENT_CONTRACT
            || self.sequence != expected_sequence
            || self.previous_event_sha256.as_deref() != expected_previous
            || self.event_sha256 != self.recompute_sha256()?
        {
            return Err(KernelError::Integrity(format!(
                "kernel event {} failed chain verification",
                self.sequence
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CampaignSnapshot {
    pub campaign: CampaignRecord,
    pub image: EpactProgramImage,
    pub epact_state: EpactRuntimeState,
    pub epact_events: Vec<EpactRuntimeEvent>,
    pub budgets: Vec<BudgetRecord>,
    pub dispatch_permits: Vec<CampaignDispatchPermit>,
    pub kernel_events: Vec<KernelEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub campaign_id: String,
    pub program_image_sha256: String,
    pub epact_event_count: usize,
    pub kernel_event_count: usize,
    pub dispatch_permit_count: usize,
    pub budget_count: usize,
    pub terminal: bool,
}

#[derive(Debug, Error)]
pub enum KernelError {
    #[error("storage error: {0}")]
    Storage(#[from] rusqlite::Error),
    #[error("record encoding error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("contract rejected: {0}")]
    Contract(String),
    #[error("unknown {0}")]
    NotFound(String),
    #[error("state conflict: {0}")]
    Conflict(String),
    #[error("authority denied: {0}")]
    AuthorityDenied(String),
    #[error("integrity failure: {0}")]
    Integrity(String),
}

#[derive(Debug, Clone)]
pub struct ReferenceKernel {
    path: PathBuf,
}

impl ReferenceKernel {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, KernelError> {
        let kernel = Self { path: path.into() };
        kernel.migrate()?;
        Ok(kernel)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn connect(&self) -> Result<Connection, KernelError> {
        let connection = Connection::open(&self.path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        Ok(connection)
    }

    fn migrate(&self) -> Result<(), KernelError> {
        let connection = self.connect()?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS campaigns (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                objective TEXT NOT NULL,
                generation INTEGER NOT NULL,
                status TEXT NOT NULL,
                blocked_reason TEXT,
                image_json TEXT NOT NULL,
                program_image_sha256 TEXT NOT NULL,
                reconciliation_sha256 TEXT NOT NULL,
                event_head_sha256 TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS epact_events (
                event_sha256 TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
                sequence INTEGER NOT NULL,
                idempotency_key TEXT NOT NULL,
                event_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(campaign_id, sequence),
                UNIQUE(campaign_id, idempotency_key)
            );

            CREATE TABLE IF NOT EXISTS budgets (
                campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
                id TEXT NOT NULL,
                total_usd REAL NOT NULL,
                spent_usd REAL NOT NULL,
                exposure_usd REAL NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(campaign_id, id)
            );

            CREATE TABLE IF NOT EXISTS dispatch_permits (
                token TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
                generation INTEGER NOT NULL,
                idempotency_key TEXT NOT NULL,
                status TEXT NOT NULL,
                record_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(campaign_id, generation, idempotency_key)
            );

            CREATE TABLE IF NOT EXISTS kernel_events (
                event_sha256 TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
                sequence INTEGER NOT NULL,
                kind TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                event_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(campaign_id, sequence)
            );

            CREATE INDEX IF NOT EXISTS idx_dispatch_campaign_status
                ON dispatch_permits(campaign_id, status, updated_at);
            CREATE INDEX IF NOT EXISTS idx_kernel_events_campaign_sequence
                ON kernel_events(campaign_id, sequence);
            "#,
        )?;
        Ok(())
    }

    pub fn create_campaign(
        &self,
        request: &CreateCampaignRequest,
    ) -> Result<CampaignRecord, KernelError> {
        request.validate()?;
        let now = canonical_now();
        let reconciliation_sha256 = campaign_reconciliation_sha256(request, 1)?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = campaign_tx(&transaction, &request.id)? {
            if existing.name == request.name
                && existing.objective == request.objective
                && existing.program_image_sha256 == request.image.image_sha256
            {
                transaction.commit()?;
                return Ok(existing);
            }
            return Err(KernelError::Conflict(format!(
                "campaign {} already exists with different content",
                request.id
            )));
        }
        transaction.execute(
            "INSERT INTO campaigns(id,name,objective,generation,status,blocked_reason,image_json,program_image_sha256,reconciliation_sha256,event_head_sha256,created_at,updated_at) VALUES (?1,?2,?3,1,'open',NULL,?4,?5,?6,NULL,?7,?7)",
            params![
                request.id,
                request.name,
                request.objective,
                serde_json::to_string(&request.image)?,
                request.image.image_sha256,
                reconciliation_sha256,
                now,
            ],
        )?;
        append_kernel_event_tx(
            &transaction,
            &request.id,
            KernelEventKind::CampaignCreated,
            &request.image.program.created_by,
            &request.image.image_sha256,
            request,
            &now,
        )?;
        let campaign = campaign_tx(&transaction, &request.id)?
            .ok_or_else(|| KernelError::NotFound(format!("campaign {}", request.id)))?;
        transaction.commit()?;
        Ok(campaign)
    }

    pub fn campaign(&self, campaign_id: &str) -> Result<CampaignRecord, KernelError> {
        campaign_connection(&self.connect()?, campaign_id)
    }

    pub fn create_budget(
        &self,
        campaign_id: &str,
        request: &CreateBudgetRequest,
    ) -> Result<BudgetRecord, KernelError> {
        validate_text("budget id", &request.id, 160)?;
        if !request.total_usd.is_finite() || request.total_usd < 0.0 {
            return Err(KernelError::Contract(
                "budget total must be finite and non-negative".to_owned(),
            ));
        }
        let now = canonical_now();
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_campaign_tx(&transaction, campaign_id)?;
        let existing = budget_tx(&transaction, campaign_id, &request.id)?;
        if let Some(existing) = existing {
            if (existing.total_usd - request.total_usd).abs() <= 1e-9 {
                transaction.commit()?;
                return Ok(existing);
            }
            return Err(KernelError::Conflict(format!(
                "budget {} already exists with a different total",
                request.id
            )));
        }
        transaction.execute(
            "INSERT INTO budgets(campaign_id,id,total_usd,spent_usd,exposure_usd,updated_at) VALUES (?1,?2,?3,0,0,?4)",
            params![campaign_id, request.id, request.total_usd, now],
        )?;
        append_kernel_event_tx(
            &transaction,
            campaign_id,
            KernelEventKind::BudgetCreated,
            "operator",
            &request.id,
            request,
            &now,
        )?;
        let budget = budget_tx(&transaction, campaign_id, &request.id)?
            .ok_or_else(|| KernelError::NotFound(format!("budget {}", request.id)))?;
        transaction.commit()?;
        Ok(budget)
    }

    pub fn accept_epact_event(
        &self,
        campaign_id: &str,
        event: &EpactRuntimeEvent,
    ) -> Result<EpactRuntimeState, KernelError> {
        event
            .validate()
            .map_err(|error| KernelError::Contract(error.to_string()))?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (campaign, image) = campaign_and_image_tx(&transaction, campaign_id)?;
        if event.program_image_sha256 != campaign.program_image_sha256 {
            return Err(KernelError::Conflict(
                "Epact event targets a different active image".to_owned(),
            ));
        }
        let mut events = epact_events_tx(&transaction, campaign_id)?;
        if let Some(existing) = events
            .iter()
            .find(|existing| existing.idempotency_key == event.idempotency_key)
        {
            if existing.event_sha256 != event.event_sha256 {
                return Err(KernelError::Conflict(
                    "Epact idempotency key was reused for a different event".to_owned(),
                ));
            }
            return replay_epact_events(&image, &events)
                .map_err(|error| KernelError::Contract(error.to_string()));
        }
        events.push(event.clone());
        let state = replay_epact_events(&image, &events)
            .map_err(|error| KernelError::AuthorityDenied(error.to_string()))?;
        transaction.execute(
            "INSERT INTO epact_events(event_sha256,campaign_id,sequence,idempotency_key,event_json,created_at) VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                event.event_sha256,
                campaign_id,
                i64::try_from(event.sequence).map_err(|_| KernelError::Contract("Epact sequence exceeds SQLite range".to_owned()))?,
                event.idempotency_key,
                serde_json::to_string(event)?,
                event.created_at,
            ],
        )?;
        append_kernel_event_tx(
            &transaction,
            campaign_id,
            KernelEventKind::EpactEventAccepted,
            &event.actor,
            &event.id,
            event,
            &canonical_now(),
        )?;
        transaction.commit()?;
        Ok(state)
    }

    pub fn snapshot(&self, campaign_id: &str) -> Result<CampaignSnapshot, KernelError> {
        let connection = self.connect()?;
        let (campaign, image) = campaign_and_image_connection(&connection, campaign_id)?;
        let epact_events = epact_events_connection(&connection, campaign_id)?;
        let epact_state = replay_epact_events(&image, &epact_events)
            .map_err(|error| KernelError::Integrity(error.to_string()))?;
        Ok(CampaignSnapshot {
            campaign,
            image,
            epact_state,
            epact_events,
            budgets: budgets_connection(&connection, campaign_id)?,
            dispatch_permits: permits_connection(&connection, campaign_id)?,
            kernel_events: kernel_events_connection(&connection, campaign_id)?,
        })
    }

    pub fn verify_campaign(&self, campaign_id: &str) -> Result<VerificationReport, KernelError> {
        let snapshot = self.snapshot(campaign_id)?;
        verify_program_image(&snapshot.image)
            .map_err(|error| KernelError::Integrity(error.to_string()))?;
        require_activatable(&snapshot.image)
            .map_err(|error| KernelError::Integrity(error.to_string()))?;
        let expected_reconciliation = campaign_reconciliation_sha256(
            &CreateCampaignRequest {
                id: snapshot.campaign.id.clone(),
                name: snapshot.campaign.name.clone(),
                objective: snapshot.campaign.objective.clone(),
                image: snapshot.image.clone(),
            },
            snapshot.campaign.generation,
        )?;
        if snapshot.campaign.reconciliation_sha256 != expected_reconciliation {
            return Err(KernelError::Integrity(
                "campaign reconciliation digest does not match its canonical identity".to_owned(),
            ));
        }
        let mut previous: Option<String> = None;
        for (index, event) in snapshot.kernel_events.iter().enumerate() {
            event.verify(index as u64, previous.as_deref())?;
            previous = Some(event.event_sha256.clone());
        }
        if snapshot.campaign.event_head_sha256 != previous {
            return Err(KernelError::Integrity(
                "campaign event head does not match the verified kernel chain".to_owned(),
            ));
        }
        for permit in &snapshot.dispatch_permits {
            permit
                .validate()
                .map_err(|error| KernelError::Integrity(error.to_string()))?;
            if permit.campaign_id != campaign_id
                || permit.generation != snapshot.campaign.generation
                || permit.reconciliation_sha256 != snapshot.campaign.reconciliation_sha256
            {
                return Err(KernelError::Integrity(format!(
                    "dispatch permit {} is not bound to this campaign generation",
                    permit.token
                )));
            }
        }
        for budget in &snapshot.budgets {
            if ![budget.total_usd, budget.spent_usd, budget.exposure_usd]
                .into_iter()
                .all(|value| value.is_finite() && value >= 0.0)
            {
                return Err(KernelError::Integrity(format!(
                    "budget {} contains invalid accounting",
                    budget.id
                )));
            }
        }
        let terminal = epact_runtime::epact_program_is_terminal(
            &snapshot.image,
            &snapshot.epact_state,
            &snapshot.epact_events,
        )
        .map_err(|error| KernelError::Integrity(error.to_string()))?;
        Ok(VerificationReport {
            campaign_id: campaign_id.to_owned(),
            program_image_sha256: snapshot.image.image_sha256,
            epact_event_count: snapshot.epact_events.len(),
            kernel_event_count: snapshot.kernel_events.len(),
            dispatch_permit_count: snapshot.dispatch_permits.len(),
            budget_count: snapshot.budgets.len(),
            terminal,
        })
    }

    pub fn permit(&self, token: &str) -> Result<CampaignDispatchPermit, KernelError> {
        let connection = self.connect()?;
        permit_connection(&connection, token)?
            .ok_or_else(|| KernelError::NotFound(format!("dispatch permit {token}")))
    }

    pub fn authorize_campaign_dispatch(
        &self,
        campaign_id: &str,
        request: &AuthorizeCampaignDispatchRequest,
    ) -> Result<CampaignDispatchPermit, KernelError> {
        request
            .validate()
            .map_err(|error| KernelError::Contract(error.to_string()))?;
        if request.budget_pre_reserved {
            return Err(KernelError::Contract(
                "the reference kernel does not accept opaque pre-reservations".to_owned(),
            ));
        }
        let now = Utc::now();
        let now_text = canonical_time(now);
        let deadline_at = canonical_time(
            now + chrono::Duration::seconds(
                i64::try_from(request.maximum_elapsed_seconds)
                    .map_err(|_| KernelError::Contract("elapsed limit is too large".to_owned()))?,
            ),
        );
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (campaign, image) = campaign_and_image_tx(&transaction, campaign_id)?;
        if campaign.status != CampaignStatus::Open {
            return Err(KernelError::AuthorityDenied(
                campaign
                    .blocked_reason
                    .unwrap_or_else(|| "campaign is blocked".to_owned()),
            ));
        }
        if campaign.generation != request.generation {
            return Err(KernelError::Conflict(format!(
                "campaign generation is {}, request uses {}",
                campaign.generation, request.generation
            )));
        }
        if let Some(existing) = permit_by_idempotency_tx(
            &transaction,
            campaign_id,
            request.generation,
            &request.idempotency_key,
        )? {
            if permit_matches_request(&existing, campaign_id, request) {
                transaction.commit()?;
                return Ok(existing);
            }
            return Err(KernelError::Conflict(
                "dispatch idempotency key was reused for different authority".to_owned(),
            ));
        }
        let binding = request.epact.as_ref().ok_or_else(|| {
            KernelError::AuthorityDenied(
                "the public kernel requires every dispatch to bind an Epact obligation".to_owned(),
            )
        })?;
        if binding.program_image_sha256 != campaign.program_image_sha256 {
            return Err(KernelError::Conflict(
                "dispatch binding targets a different active Epact image".to_owned(),
            ));
        }
        let events = epact_events_tx(&transaction, campaign_id)?;
        let state = replay_epact_events(&image, &events)
            .map_err(|error| KernelError::Integrity(error.to_string()))?;
        let eligibility = evaluate_epact_operation(
            &image,
            &state,
            &EpactOperationRequest {
                principal_id: request.actor.trim().to_owned(),
                operation: binding.operation,
                requested_at: now_text.clone(),
                obligation_id: Some(binding.obligation_id.clone()),
                capability_id: binding.capability_id.clone(),
                effects: binding.effects.clone(),
                resources: binding.resources.clone(),
                placement: binding.placement.clone(),
            },
        )
        .map_err(|error| KernelError::Contract(error.to_string()))?;
        if !eligibility.allowed {
            let message = eligibility
                .blockers
                .iter()
                .map(|blocker| format!("{}:{}", blocker.code, blocker.subject_id))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(KernelError::AuthorityDenied(message));
        }
        if let Some(budget_id) = &request.budget_id {
            let budget = budget_tx(&transaction, campaign_id, budget_id)?
                .ok_or_else(|| KernelError::NotFound(format!("budget {budget_id}")))?;
            if request.maximum_cost_usd > budget.available_usd + 1e-9 {
                return Err(KernelError::AuthorityDenied(format!(
                    "dispatch ceiling ${:.6} exceeds budget availability ${:.6}",
                    request.maximum_cost_usd, budget.available_usd
                )));
            }
            if request.reserve_budget {
                transaction.execute(
                    "UPDATE budgets SET exposure_usd=exposure_usd+?3,updated_at=?4 WHERE campaign_id=?1 AND id=?2",
                    params![campaign_id, budget_id, request.maximum_cost_usd, now_text],
                )?;
            }
        }
        let permit = CampaignDispatchPermit {
            contract: CAMPAIGN_DISPATCH_PERMIT_CONTRACT.to_owned(),
            token: format!("dispatch_{}", Uuid::new_v4().simple()),
            campaign_id: campaign_id.to_owned(),
            generation: request.generation,
            idempotency_key: request.idempotency_key.clone(),
            actor: request.actor.trim().to_owned(),
            operation: request.operation,
            target_id: request.target_id.trim().to_owned(),
            budget_id: request.budget_id.clone(),
            maximum_cost_usd: request.maximum_cost_usd,
            reserve_budget: request.reserve_budget,
            budget_pre_reserved: false,
            epact: request.epact.clone(),
            reconciliation_sha256: campaign.reconciliation_sha256,
            status: DispatchPermitStatus::Authorized,
            issued_at: now_text.clone(),
            deadline_at,
            consumed_at: None,
            settled_at: None,
            actual_cost_usd: None,
            settlement_basis: None,
            interruption: None,
            released_at: None,
            resolution_evidence_sha256: None,
            resolved_by: None,
        };
        permit
            .validate()
            .map_err(|error| KernelError::Integrity(error.to_string()))?;
        store_permit_tx(&transaction, &permit, &now_text)?;
        append_kernel_event_tx(
            &transaction,
            campaign_id,
            KernelEventKind::DispatchAuthorized,
            &permit.actor,
            &permit.token,
            &permit,
            &now_text,
        )?;
        transaction.commit()?;
        Ok(permit)
    }

    pub fn consume_campaign_dispatch(
        &self,
        token: &str,
    ) -> Result<CampaignDispatchPermit, KernelError> {
        let now = Utc::now();
        let now_text = canonical_time(now);
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut permit = require_permit_tx(&transaction, token)?;
        if permit.status != DispatchPermitStatus::Authorized {
            return Err(KernelError::Conflict(
                "dispatch permit is not awaiting consumption".to_owned(),
            ));
        }
        let deadline = DateTime::parse_from_rfc3339(&permit.deadline_at)
            .map_err(|error| KernelError::Integrity(error.to_string()))?
            .with_timezone(&Utc);
        if deadline <= now {
            return Err(KernelError::AuthorityDenied(
                "dispatch permit expired before consumption".to_owned(),
            ));
        }
        let campaign = require_campaign_tx(&transaction, &permit.campaign_id)?;
        if campaign.status != CampaignStatus::Open
            || campaign.generation != permit.generation
            || campaign.reconciliation_sha256 != permit.reconciliation_sha256
        {
            return Err(KernelError::AuthorityDenied(
                "dispatch permit is no longer bound to an open campaign generation".to_owned(),
            ));
        }
        permit.status = DispatchPermitStatus::Consumed;
        permit.consumed_at = Some(now_text.clone());
        update_permit_tx(
            &transaction,
            &permit,
            DispatchPermitStatus::Authorized,
            &now_text,
        )?;
        append_kernel_event_tx(
            &transaction,
            &permit.campaign_id,
            KernelEventKind::DispatchConsumed,
            &permit.actor,
            token,
            &permit,
            &now_text,
        )?;
        transaction.commit()?;
        Ok(permit)
    }

    pub fn settle_campaign_dispatch(
        &self,
        token: &str,
        actual_cost_usd: f64,
        settlement_basis: &str,
    ) -> Result<CampaignDispatchPermit, KernelError> {
        if !actual_cost_usd.is_finite() || actual_cost_usd < 0.0 {
            return Err(KernelError::Contract(
                "settlement cost must be finite and non-negative".to_owned(),
            ));
        }
        validate_text("settlement basis", settlement_basis, 240)?;
        let now = canonical_now();
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut permit = require_permit_tx(&transaction, token)?;
        if permit.status == DispatchPermitStatus::Settled {
            if permit.actual_cost_usd == Some(actual_cost_usd)
                && permit.settlement_basis.as_deref() == Some(settlement_basis.trim())
            {
                transaction.commit()?;
                return Ok(permit);
            }
            return Err(KernelError::Conflict(
                "settlement was repeated with different accounting".to_owned(),
            ));
        }
        let previous = permit.status;
        if !matches!(
            previous,
            DispatchPermitStatus::Consumed | DispatchPermitStatus::Interrupted
        ) {
            return Err(KernelError::Conflict(
                "dispatch permit is not in a settleable state".to_owned(),
            ));
        }
        settle_budget_tx(&transaction, &permit, actual_cost_usd, &now)?;
        permit.status = DispatchPermitStatus::Settled;
        permit.settled_at = Some(now.clone());
        permit.actual_cost_usd = Some(actual_cost_usd);
        permit.settlement_basis = Some(settlement_basis.trim().to_owned());
        permit.interruption = None;
        update_permit_tx(&transaction, &permit, previous, &now)?;
        if actual_cost_usd > permit.maximum_cost_usd + 1e-9 {
            block_campaign_tx(
                &transaction,
                &permit.campaign_id,
                &format!(
                    "dispatch settled at ${actual_cost_usd:.6} against ${:.6} authority",
                    permit.maximum_cost_usd
                ),
                &now,
            )?;
        } else if previous == DispatchPermitStatus::Interrupted {
            reopen_if_reconciled_tx(&transaction, &permit.campaign_id, &now)?;
        }
        append_kernel_event_tx(
            &transaction,
            &permit.campaign_id,
            KernelEventKind::DispatchSettled,
            &permit.actor,
            token,
            &permit,
            &now,
        )?;
        transaction.commit()?;
        Ok(permit)
    }

    pub fn interrupt_campaign_dispatch(
        &self,
        token: &str,
        reason: &str,
    ) -> Result<CampaignDispatchPermit, KernelError> {
        validate_text("interruption reason", reason, 2_000)?;
        let now = canonical_now();
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut permit = require_permit_tx(&transaction, token)?;
        if permit.status == DispatchPermitStatus::Interrupted {
            transaction.commit()?;
            return Ok(permit);
        }
        if permit.status != DispatchPermitStatus::Consumed {
            return Err(KernelError::Conflict(
                "only a consumed dispatch can become interrupted".to_owned(),
            ));
        }
        permit.status = DispatchPermitStatus::Interrupted;
        permit.interruption = Some(reason.trim().to_owned());
        update_permit_tx(&transaction, &permit, DispatchPermitStatus::Consumed, &now)?;
        block_campaign_tx(
            &transaction,
            &permit.campaign_id,
            &format!("interrupted dispatch {token} requires reconciliation"),
            &now,
        )?;
        append_kernel_event_tx(
            &transaction,
            &permit.campaign_id,
            KernelEventKind::DispatchInterrupted,
            &permit.actor,
            token,
            &permit,
            &now,
        )?;
        transaction.commit()?;
        Ok(permit)
    }

    pub fn release_campaign_dispatch(
        &self,
        token: &str,
    ) -> Result<CampaignDispatchPermit, KernelError> {
        let now = canonical_now();
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut permit = require_permit_tx(&transaction, token)?;
        if permit.status == DispatchPermitStatus::Released {
            transaction.commit()?;
            return Ok(permit);
        }
        if permit.status != DispatchPermitStatus::Authorized {
            return Err(KernelError::Conflict(
                "only an unconsumed dispatch can be released".to_owned(),
            ));
        }
        release_budget_tx(&transaction, &permit, &now)?;
        permit.status = DispatchPermitStatus::Released;
        permit.released_at = Some(now.clone());
        update_permit_tx(
            &transaction,
            &permit,
            DispatchPermitStatus::Authorized,
            &now,
        )?;
        append_kernel_event_tx(
            &transaction,
            &permit.campaign_id,
            KernelEventKind::DispatchReleased,
            &permit.actor,
            token,
            &permit,
            &now,
        )?;
        transaction.commit()?;
        Ok(permit)
    }

    pub fn resolve_interrupted_dispatch(
        &self,
        campaign_id: &str,
        token: &str,
        request: &ResolveInterruptedDispatchRequest,
    ) -> Result<CampaignDispatchPermit, KernelError> {
        request
            .validate()
            .map_err(|error| KernelError::Contract(error.to_string()))?;
        let now = canonical_now();
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut permit = require_permit_tx(&transaction, token)?;
        if permit.campaign_id != campaign_id || permit.status != DispatchPermitStatus::Interrupted {
            return Err(KernelError::Conflict(
                "dispatch is not an interrupted permit for this campaign".to_owned(),
            ));
        }
        permit.resolution_evidence_sha256 = Some(request.evidence_sha256.clone());
        permit.resolved_by = Some(request.actor.trim().to_owned());
        match request.resolution {
            InterruptedDispatchResolution::NoProviderStart => {
                release_budget_tx(&transaction, &permit, &now)?;
                permit.status = DispatchPermitStatus::Released;
                permit.released_at = Some(now.clone());
                permit.settlement_basis = Some("verified_no_provider_start".to_owned());
            }
            InterruptedDispatchResolution::ProviderSettled => {
                let actual_cost = request.actual_cost_usd.ok_or_else(|| {
                    KernelError::Contract("provider settlement lost its cost".to_owned())
                })?;
                settle_budget_tx(&transaction, &permit, actual_cost, &now)?;
                permit.status = DispatchPermitStatus::Settled;
                permit.settled_at = Some(now.clone());
                permit.actual_cost_usd = Some(actual_cost);
                permit.settlement_basis = request.settlement_basis.clone();
                permit.interruption = None;
                if actual_cost > permit.maximum_cost_usd + 1e-9 {
                    block_campaign_tx(
                        &transaction,
                        campaign_id,
                        "resolved dispatch exceeded its authorized ceiling",
                        &now,
                    )?;
                }
            }
        }
        update_permit_tx(
            &transaction,
            &permit,
            DispatchPermitStatus::Interrupted,
            &now,
        )?;
        reopen_if_reconciled_tx(&transaction, campaign_id, &now)?;
        append_kernel_event_tx(
            &transaction,
            campaign_id,
            KernelEventKind::DispatchResolved,
            &request.actor,
            token,
            &permit,
            &now,
        )?;
        transaction.commit()?;
        Ok(permit)
    }
}

impl DispatchKernel for ReferenceKernel {
    type Error = KernelError;

    fn authorize_dispatch(
        &self,
        campaign_id: &str,
        request: &AuthorizeCampaignDispatchRequest,
    ) -> Result<CampaignDispatchPermit, Self::Error> {
        self.authorize_campaign_dispatch(campaign_id, request)
    }

    fn consume_dispatch(&self, token: &str) -> Result<CampaignDispatchPermit, Self::Error> {
        self.consume_campaign_dispatch(token)
    }

    fn settle_dispatch(
        &self,
        token: &str,
        actual_cost_usd: f64,
        settlement_basis: &str,
    ) -> Result<CampaignDispatchPermit, Self::Error> {
        self.settle_campaign_dispatch(token, actual_cost_usd, settlement_basis)
    }

    fn interrupt_dispatch(
        &self,
        token: &str,
        reason: &str,
    ) -> Result<CampaignDispatchPermit, Self::Error> {
        self.interrupt_campaign_dispatch(token, reason)
    }

    fn release_dispatch(&self, token: &str) -> Result<CampaignDispatchPermit, Self::Error> {
        self.release_campaign_dispatch(token)
    }
}

fn canonical_now() -> String {
    canonical_time(Utc::now())
}

fn canonical_time(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn validate_text(label: &str, value: &str, maximum: usize) -> Result<(), KernelError> {
    let length = value.chars().count();
    if value.trim().is_empty() || length > maximum {
        return Err(KernelError::Contract(format!(
            "{label} must contain 1-{maximum} characters"
        )));
    }
    Ok(())
}

fn campaign_reconciliation_sha256(
    request: &CreateCampaignRequest,
    generation: u64,
) -> Result<String, KernelError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Input<'a> {
        campaign_id: &'a str,
        name: &'a str,
        objective: &'a str,
        generation: u64,
        program_image_sha256: &'a str,
    }
    Ok(sha256(&canonical_epact_json_bytes(&Input {
        campaign_id: &request.id,
        name: &request.name,
        objective: &request.objective,
        generation,
        program_image_sha256: &request.image.image_sha256,
    })?))
}

fn campaign_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CampaignRecord> {
    let generation: i64 = row.get(3)?;
    let status: String = row.get(4)?;
    Ok(CampaignRecord {
        id: row.get(0)?,
        name: row.get(1)?,
        objective: row.get(2)?,
        generation: u64::try_from(generation).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                3,
                rusqlite::types::Type::Integer,
                Box::new(error),
            )
        })?,
        status: CampaignStatus::parse(&status).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                4,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        blocked_reason: row.get(5)?,
        program_image_sha256: row.get(6)?,
        reconciliation_sha256: row.get(7)?,
        event_head_sha256: row.get(8)?,
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
    })
}

const CAMPAIGN_SELECT: &str = "SELECT id,name,objective,generation,status,blocked_reason,program_image_sha256,reconciliation_sha256,event_head_sha256,created_at,updated_at FROM campaigns WHERE id=?1";

fn campaign_tx(
    transaction: &Transaction<'_>,
    campaign_id: &str,
) -> Result<Option<CampaignRecord>, KernelError> {
    Ok(transaction
        .query_row(CAMPAIGN_SELECT, params![campaign_id], campaign_from_row)
        .optional()?)
}

fn campaign_connection(
    connection: &Connection,
    campaign_id: &str,
) -> Result<CampaignRecord, KernelError> {
    connection
        .query_row(CAMPAIGN_SELECT, params![campaign_id], campaign_from_row)
        .optional()?
        .ok_or_else(|| KernelError::NotFound(format!("campaign {campaign_id}")))
}

fn require_campaign_tx(
    transaction: &Transaction<'_>,
    campaign_id: &str,
) -> Result<CampaignRecord, KernelError> {
    campaign_tx(transaction, campaign_id)?
        .ok_or_else(|| KernelError::NotFound(format!("campaign {campaign_id}")))
}

fn campaign_and_image_tx(
    transaction: &Transaction<'_>,
    campaign_id: &str,
) -> Result<(CampaignRecord, EpactProgramImage), KernelError> {
    let campaign = require_campaign_tx(transaction, campaign_id)?;
    let raw: String = transaction.query_row(
        "SELECT image_json FROM campaigns WHERE id=?1",
        params![campaign_id],
        |row| row.get(0),
    )?;
    Ok((campaign, serde_json::from_str(&raw)?))
}

fn campaign_and_image_connection(
    connection: &Connection,
    campaign_id: &str,
) -> Result<(CampaignRecord, EpactProgramImage), KernelError> {
    let campaign = campaign_connection(connection, campaign_id)?;
    let raw: String = connection.query_row(
        "SELECT image_json FROM campaigns WHERE id=?1",
        params![campaign_id],
        |row| row.get(0),
    )?;
    Ok((campaign, serde_json::from_str(&raw)?))
}

fn append_kernel_event_tx(
    transaction: &Transaction<'_>,
    campaign_id: &str,
    kind: KernelEventKind,
    actor: &str,
    subject_id: &str,
    payload: &impl Serialize,
    created_at: &str,
) -> Result<KernelEvent, KernelError> {
    let campaign = require_campaign_tx(transaction, campaign_id)?;
    let sequence: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM kernel_events WHERE campaign_id=?1",
        params![campaign_id],
        |row| row.get(0),
    )?;
    let event = KernelEvent::build(
        campaign_id.to_owned(),
        u64::try_from(sequence)
            .map_err(|_| KernelError::Integrity("negative kernel event count".to_owned()))?,
        kind,
        actor.trim().to_owned(),
        subject_id.to_owned(),
        payload,
        campaign.event_head_sha256,
        created_at.to_owned(),
    )?;
    transaction.execute(
        "INSERT INTO kernel_events(event_sha256,campaign_id,sequence,kind,subject_id,payload_json,event_json,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            event.event_sha256,
            campaign_id,
            sequence,
            format!("{:?}", kind).to_ascii_lowercase(),
            subject_id,
            serde_json::to_string(payload)?,
            serde_json::to_string(&event)?,
            created_at,
        ],
    )?;
    transaction.execute(
        "UPDATE campaigns SET event_head_sha256=?2,updated_at=?3 WHERE id=?1",
        params![campaign_id, event.event_sha256, created_at],
    )?;
    Ok(event)
}

fn epact_events_tx(
    transaction: &Transaction<'_>,
    campaign_id: &str,
) -> Result<Vec<EpactRuntimeEvent>, KernelError> {
    read_json_list(
        transaction,
        "SELECT event_json FROM epact_events WHERE campaign_id=?1 ORDER BY sequence",
        campaign_id,
    )
}

fn epact_events_connection(
    connection: &Connection,
    campaign_id: &str,
) -> Result<Vec<EpactRuntimeEvent>, KernelError> {
    read_json_list(
        connection,
        "SELECT event_json FROM epact_events WHERE campaign_id=?1 ORDER BY sequence",
        campaign_id,
    )
}

trait QueryConnection {
    fn prepare_query(&self, sql: &str) -> rusqlite::Result<rusqlite::Statement<'_>>;
}

impl QueryConnection for Connection {
    fn prepare_query(&self, sql: &str) -> rusqlite::Result<rusqlite::Statement<'_>> {
        self.prepare(sql)
    }
}

impl QueryConnection for Transaction<'_> {
    fn prepare_query(&self, sql: &str) -> rusqlite::Result<rusqlite::Statement<'_>> {
        self.prepare(sql)
    }
}

fn read_json_list<T: serde::de::DeserializeOwned>(
    connection: &impl QueryConnection,
    sql: &str,
    campaign_id: &str,
) -> Result<Vec<T>, KernelError> {
    let mut statement = connection.prepare_query(sql)?;
    let rows = statement.query_map(params![campaign_id], |row| row.get::<_, String>(0))?;
    let mut records = Vec::new();
    for row in rows {
        records.push(serde_json::from_str(&row?)?);
    }
    Ok(records)
}

fn budget_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<BudgetRecord> {
    let total_usd: f64 = row.get(2)?;
    let spent_usd: f64 = row.get(3)?;
    let exposure_usd: f64 = row.get(4)?;
    Ok(BudgetRecord {
        campaign_id: row.get(0)?,
        id: row.get(1)?,
        total_usd,
        spent_usd,
        exposure_usd,
        available_usd: total_usd - spent_usd - exposure_usd,
        updated_at: row.get(5)?,
    })
}

fn budget_tx(
    transaction: &Transaction<'_>,
    campaign_id: &str,
    budget_id: &str,
) -> Result<Option<BudgetRecord>, KernelError> {
    Ok(transaction
        .query_row(
            "SELECT campaign_id,id,total_usd,spent_usd,exposure_usd,updated_at FROM budgets WHERE campaign_id=?1 AND id=?2",
            params![campaign_id, budget_id],
            budget_from_row,
        )
        .optional()?)
}

fn budgets_connection(
    connection: &Connection,
    campaign_id: &str,
) -> Result<Vec<BudgetRecord>, KernelError> {
    let mut statement = connection.prepare(
        "SELECT campaign_id,id,total_usd,spent_usd,exposure_usd,updated_at FROM budgets WHERE campaign_id=?1 ORDER BY id",
    )?;
    let rows = statement.query_map(params![campaign_id], budget_from_row)?;
    let mut records = Vec::new();
    for row in rows {
        records.push(row?);
    }
    Ok(records)
}

fn permit_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CampaignDispatchPermit> {
    let raw: String = row.get(0)?;
    let status: String = row.get(1)?;
    let mut permit: CampaignDispatchPermit = serde_json::from_str(&raw).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })?;
    permit.status = DispatchPermitStatus::parse(&status).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(permit)
}

fn permit_connection(
    connection: &Connection,
    token: &str,
) -> Result<Option<CampaignDispatchPermit>, KernelError> {
    Ok(connection
        .query_row(
            "SELECT record_json,status FROM dispatch_permits WHERE token=?1",
            params![token],
            permit_from_row,
        )
        .optional()?)
}

fn require_permit_tx(
    transaction: &Transaction<'_>,
    token: &str,
) -> Result<CampaignDispatchPermit, KernelError> {
    transaction
        .query_row(
            "SELECT record_json,status FROM dispatch_permits WHERE token=?1",
            params![token],
            permit_from_row,
        )
        .optional()?
        .ok_or_else(|| KernelError::NotFound(format!("dispatch permit {token}")))
}

fn permit_by_idempotency_tx(
    transaction: &Transaction<'_>,
    campaign_id: &str,
    generation: u64,
    idempotency_key: &str,
) -> Result<Option<CampaignDispatchPermit>, KernelError> {
    let generation = i64::try_from(generation)
        .map_err(|_| KernelError::Contract("generation exceeds SQLite range".to_owned()))?;
    Ok(transaction
        .query_row(
            "SELECT record_json,status FROM dispatch_permits WHERE campaign_id=?1 AND generation=?2 AND idempotency_key=?3",
            params![campaign_id, generation, idempotency_key],
            permit_from_row,
        )
        .optional()?)
}

fn permits_connection(
    connection: &Connection,
    campaign_id: &str,
) -> Result<Vec<CampaignDispatchPermit>, KernelError> {
    let mut statement = connection.prepare(
        "SELECT record_json,status FROM dispatch_permits WHERE campaign_id=?1 ORDER BY updated_at,token",
    )?;
    let rows = statement.query_map(params![campaign_id], permit_from_row)?;
    let mut records = Vec::new();
    for row in rows {
        records.push(row?);
    }
    Ok(records)
}

fn kernel_events_connection(
    connection: &Connection,
    campaign_id: &str,
) -> Result<Vec<KernelEvent>, KernelError> {
    read_json_list(
        connection,
        "SELECT event_json FROM kernel_events WHERE campaign_id=?1 ORDER BY sequence",
        campaign_id,
    )
}

fn store_permit_tx(
    transaction: &Transaction<'_>,
    permit: &CampaignDispatchPermit,
    updated_at: &str,
) -> Result<(), KernelError> {
    transaction.execute(
        "INSERT INTO dispatch_permits(token,campaign_id,generation,idempotency_key,status,record_json,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7)",
        params![
            permit.token,
            permit.campaign_id,
            i64::try_from(permit.generation).map_err(|_| KernelError::Contract("generation exceeds SQLite range".to_owned()))?,
            permit.idempotency_key,
            permit.status.as_str(),
            serde_json::to_string(permit)?,
            updated_at,
        ],
    )?;
    Ok(())
}

fn update_permit_tx(
    transaction: &Transaction<'_>,
    permit: &CampaignDispatchPermit,
    expected: DispatchPermitStatus,
    updated_at: &str,
) -> Result<(), KernelError> {
    permit
        .validate()
        .map_err(|error| KernelError::Integrity(error.to_string()))?;
    let changed = transaction.execute(
        "UPDATE dispatch_permits SET status=?2,record_json=?3,updated_at=?4 WHERE token=?1 AND status=?5",
        params![
            permit.token,
            permit.status.as_str(),
            serde_json::to_string(permit)?,
            updated_at,
            expected.as_str(),
        ],
    )?;
    if changed != 1 {
        return Err(KernelError::Conflict(
            "dispatch transition lost its single-writer race".to_owned(),
        ));
    }
    Ok(())
}

fn permit_matches_request(
    permit: &CampaignDispatchPermit,
    campaign_id: &str,
    request: &AuthorizeCampaignDispatchRequest,
) -> bool {
    permit.campaign_id == campaign_id
        && permit.generation == request.generation
        && permit.idempotency_key == request.idempotency_key
        && permit.actor == request.actor.trim()
        && permit.operation == request.operation
        && permit.target_id == request.target_id.trim()
        && permit.budget_id == request.budget_id
        && (permit.maximum_cost_usd - request.maximum_cost_usd).abs() <= 1e-9
        && permit.reserve_budget == request.reserve_budget
        && permit.budget_pre_reserved == request.budget_pre_reserved
        && permit.epact == request.epact
}

fn settle_budget_tx(
    transaction: &Transaction<'_>,
    permit: &CampaignDispatchPermit,
    actual_cost_usd: f64,
    updated_at: &str,
) -> Result<(), KernelError> {
    if permit.reserve_budget {
        let budget_id = permit.budget_id.as_deref().ok_or_else(|| {
            KernelError::Integrity("reserved permit lost its budget id".to_owned())
        })?;
        let changed = transaction.execute(
            "UPDATE budgets SET spent_usd=spent_usd+?3,exposure_usd=MAX(0,exposure_usd-?4),updated_at=?5 WHERE campaign_id=?1 AND id=?2",
            params![
                permit.campaign_id,
                budget_id,
                actual_cost_usd,
                permit.maximum_cost_usd,
                updated_at,
            ],
        )?;
        if changed != 1 {
            return Err(KernelError::Integrity(
                "reserved permit references a missing budget".to_owned(),
            ));
        }
    }
    Ok(())
}

fn release_budget_tx(
    transaction: &Transaction<'_>,
    permit: &CampaignDispatchPermit,
    updated_at: &str,
) -> Result<(), KernelError> {
    if permit.reserve_budget {
        let budget_id = permit.budget_id.as_deref().ok_or_else(|| {
            KernelError::Integrity("reserved permit lost its budget id".to_owned())
        })?;
        let changed = transaction.execute(
            "UPDATE budgets SET exposure_usd=MAX(0,exposure_usd-?3),updated_at=?4 WHERE campaign_id=?1 AND id=?2",
            params![campaign_id(permit), budget_id, permit.maximum_cost_usd, updated_at],
        )?;
        if changed != 1 {
            return Err(KernelError::Integrity(
                "reserved permit references a missing budget".to_owned(),
            ));
        }
    }
    Ok(())
}

fn campaign_id(permit: &CampaignDispatchPermit) -> &str {
    &permit.campaign_id
}

fn block_campaign_tx(
    transaction: &Transaction<'_>,
    campaign_id: &str,
    reason: &str,
    updated_at: &str,
) -> Result<(), KernelError> {
    transaction.execute(
        "UPDATE campaigns SET status='blocked',blocked_reason=?2,updated_at=?3 WHERE id=?1",
        params![campaign_id, reason, updated_at],
    )?;
    Ok(())
}

fn reopen_if_reconciled_tx(
    transaction: &Transaction<'_>,
    campaign_id: &str,
    updated_at: &str,
) -> Result<(), KernelError> {
    let interrupted: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM dispatch_permits WHERE campaign_id=?1 AND status='interrupted'",
        params![campaign_id],
        |row| row.get(0),
    )?;
    if interrupted == 0 {
        let reason: Option<String> = transaction.query_row(
            "SELECT blocked_reason FROM campaigns WHERE id=?1",
            params![campaign_id],
            |row| row.get(0),
        )?;
        if reason
            .as_deref()
            .is_some_and(|reason| reason.starts_with("interrupted dispatch"))
        {
            transaction.execute(
                "UPDATE campaigns SET status='open',blocked_reason=NULL,updated_at=?2 WHERE id=?1",
                params![campaign_id, updated_at],
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
