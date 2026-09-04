use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const EPACT_LANGUAGE: &str = "Epact";
pub const EPACT_LANGUAGE_VERSION: &str = "0.1";
pub const EPACT_PROGRAM_CONTRACT: &str = "epact.program/0.1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesignProgram {
    pub id: String,
    pub name: String,
    pub language: String,
    pub language_version: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Campaign {
    pub id: String,
    pub name: String,
    pub domain: String,
    pub objective: String,
    pub status: String,
    pub created_at: String,
    pub program: DesignProgram,
    #[serde(default)]
    pub capability_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceRequest {
    #[serde(default = "default_cpu")]
    pub cpu_cores: f64,
    #[serde(default)]
    pub ram_gb: f64,
    #[serde(default)]
    pub gpu_count: u32,
    #[serde(default)]
    pub vram_gb: f64,
    #[serde(default = "default_locality")]
    pub locality: String,
}

fn default_cpu() -> f64 {
    1.0
}

fn default_locality() -> String {
    "local".to_owned()
}

impl Default for ResourceRequest {
    fn default() -> Self {
        Self {
            cpu_cores: default_cpu(),
            ram_gb: 0.5,
            gpu_count: 0,
            vram_gb: 0.0,
            locality: default_locality(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Capability {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub version: String,
    pub provider: String,
    pub description: String,
    pub trust_status: String,
    pub lifecycle: Vec<String>,
    pub command: Vec<String>,
    pub resources: ResourceRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Run {
    pub id: String,
    pub campaign_id: String,
    pub capability_id: String,
    pub name: String,
    pub status: String,
    pub phase: String,
    pub progress: f64,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub external_url: Option<String>,
    pub pid: Option<u32>,
    pub budget_ceiling_usd: Option<f64>,
    pub cost_usd: Option<f64>,
    pub parameters: Value,
    pub resources: ResourceRequest,
}

/// Canonical lifecycle vocabulary shared by local workers and imported providers.
///
/// External systems use several spellings for the same operational state.  Concord
/// normalizes them at the storage boundary so summaries, filters, budgets, and stage
/// gates do not silently disagree.
pub fn canonical_execution_status(value: &str) -> String {
    match value.trim().to_ascii_lowercase().replace('-', "_").as_str() {
        "complete" | "completed" | "succeeded" | "qualified" | "success" => "completed".to_owned(),
        "in_progress" | "running" | "external" => "running".to_owned(),
        "submitted" | "requested" | "waiting" | "pending" | "building" | "provisioning"
        | "queued" => "queued".to_owned(),
        "canceled" | "cancelled" | "skipped" => "cancelled".to_owned(),
        "terminal_unvalidated" => "terminal_unvalidated".to_owned(),
        "checkpointed" => "checkpointed".to_owned(),
        "planned" => "planned".to_owned(),
        "recovering" => "recovering".to_owned(),
        "failed" | "failure" | "error" => "failed".to_owned(),
        "blocked" => "blocked".to_owned(),
        "idle" => "idle".to_owned(),
        other => other.to_owned(),
    }
}

#[cfg(test)]
mod status_tests {
    use super::canonical_execution_status;

    #[test]
    fn canonicalizes_provider_lifecycle_aliases() {
        assert_eq!(canonical_execution_status("succeeded"), "completed");
        assert_eq!(canonical_execution_status("in-progress"), "running");
        assert_eq!(canonical_execution_status("building"), "queued");
        assert_eq!(canonical_execution_status("canceled"), "cancelled");
        assert_eq!(
            canonical_execution_status("terminal_unvalidated"),
            "terminal_unvalidated"
        );
    }
}

#[derive(Debug, Clone)]
pub struct RunSupervision {
    pub run_id: String,
    pub event_path: String,
    pub stderr_path: String,
    pub event_offset: u64,
    pub stderr_offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricPoint {
    pub run_id: String,
    pub name: String,
    pub step: i64,
    pub value: f64,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LedgerEvent {
    pub id: String,
    pub campaign_id: Option<String>,
    pub run_id: Option<String>,
    pub object_type: String,
    pub object_id: String,
    pub verb: String,
    pub timestamp: String,
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Artifact {
    pub id: String,
    pub run_id: Option<String>,
    pub kind: String,
    pub media_type: String,
    pub byte_size: u64,
    pub path: String,
    pub source_path: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BudgetAccount {
    pub id: String,
    pub name: String,
    pub source: String,
    pub currency: String,
    pub total: f64,
    pub spent: f64,
    pub exposure: f64,
    pub remaining_floor: f64,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidatePoint {
    pub id: String,
    pub campaign_id: String,
    pub basin_id: i64,
    pub x: f64,
    pub y: f64,
    pub z: Option<f64>,
    pub conflict: f64,
    pub geometry: Option<f64>,
    pub motif: Option<f64>,
    pub selected: bool,
    pub failure: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BasinSummary {
    pub campaign_id: String,
    pub id: i64,
    pub size: i64,
    pub suspicion: f64,
    pub dominant_failure: Option<String>,
    pub core_pass_rate: f64,
    pub geometry_pass_rate: f64,
    pub esm_pass_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticObject {
    pub id: String,
    pub campaign_id: Option<String>,
    pub run_id: Option<String>,
    pub kind: String,
    pub type_name: String,
    pub state: String,
    pub label: Option<String>,
    pub payload: Value,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticRelation {
    pub id: String,
    pub campaign_id: Option<String>,
    pub run_id: Option<String>,
    pub subject_id: String,
    pub predicate: String,
    pub object_id: String,
    pub payload: Value,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionRecord {
    pub id: String,
    pub campaign_id: Option<String>,
    pub run_id: Option<String>,
    pub action_type: String,
    pub actor: String,
    pub target_id: Option<String>,
    pub status: String,
    pub payload: Value,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalJob {
    pub id: String,
    pub campaign_id: Option<String>,
    pub run_id: Option<String>,
    pub provider: String,
    pub external_id: String,
    pub label: String,
    pub status: String,
    pub chip: Option<String>,
    pub submitted_at: Option<String>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub rate_per_min_usd: Option<f64>,
    pub max_cost_usd: Option<f64>,
    pub cost_usd: Option<f64>,
    pub queue_position: Option<i64>,
    pub estimated_wait_seconds: Option<i64>,
    pub payload: Value,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderProfile {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub base_url: Option<String>,
    pub secret_ref: Option<String>,
    pub secret_available: bool,
    pub status: String,
    pub metadata: Value,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectProjection {
    pub id: String,
    pub campaign_id: String,
    pub run_id: Option<String>,
    pub object_id: String,
    pub space: String,
    pub x: f64,
    pub y: f64,
    pub z: Option<f64>,
    pub group_id: Option<String>,
    pub signals: Value,
    pub selected: bool,
    pub label: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceSnapshot {
    pub runtime: RuntimeStatus,
    pub campaigns: Vec<Campaign>,
    pub capabilities: Vec<Capability>,
    pub runs: Vec<Run>,
    pub metrics: Vec<MetricPoint>,
    pub events: Vec<LedgerEvent>,
    pub artifacts: Vec<Artifact>,
    pub budgets: Vec<BudgetAccount>,
    pub candidates: Vec<CandidatePoint>,
    pub basins: Vec<BasinSummary>,
    pub objects: Vec<SemanticObject>,
    pub relations: Vec<SemanticRelation>,
    pub actions: Vec<ActionRecord>,
    pub external_jobs: Vec<ExternalJob>,
    pub providers: Vec<ProviderProfile>,
    pub projections: Vec<ObjectProjection>,
    pub operational_imports: Vec<OperationalImportRecord>,
    pub operational_sources: Vec<OperationalSourceStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeStatus {
    pub version: String,
    pub status: String,
    pub state_path: String,
    pub artifact_path: String,
    pub started_at: String,
    pub host: HostResources,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostResources {
    pub logical_cpu_count: usize,
    pub memory_gb: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SeedBundle {
    pub campaigns: Vec<Campaign>,
    pub capabilities: Vec<Capability>,
    pub runs: Vec<Run>,
    #[serde(default)]
    pub metrics: Vec<MetricPoint>,
    #[serde(default)]
    pub events: Vec<LedgerEvent>,
    #[serde(default)]
    pub artifacts: Vec<Artifact>,
    #[serde(default)]
    pub budgets: Vec<BudgetAccount>,
    #[serde(default)]
    pub candidates: Vec<CandidatePoint>,
    #[serde(default)]
    pub basins: Vec<BasinSummary>,
    #[serde(default)]
    pub objects: Vec<SemanticObject>,
    #[serde(default)]
    pub relations: Vec<SemanticRelation>,
    #[serde(default)]
    pub actions: Vec<ActionRecord>,
    #[serde(default)]
    pub external_jobs: Vec<ExternalJob>,
    #[serde(default)]
    pub providers: Vec<ProviderProfile>,
    #[serde(default)]
    pub projections: Vec<ObjectProjection>,
}

/// A provenance-bound, scientifically inert snapshot from an external system of record.
///
/// Operational imports deliberately exclude candidate data, endpoint metrics, and executable
/// capability commands. Domain adapters translate their native state into this contract; the
/// Concord kernel remains unaware of proteins, crystals, or any other scientific representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationalImportSource {
    pub system: String,
    pub stream: String,
    pub repository: String,
    pub revision: String,
    #[serde(default)]
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationalImportEnvelope {
    pub contract: String,
    pub import_id: String,
    pub generated_at: String,
    pub classification: String,
    pub contains_scientific_endpoints: bool,
    pub source: OperationalImportSource,
    pub bundle: SeedBundle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationalImportRecord {
    pub import_id: String,
    pub contract: String,
    pub source_system: String,
    pub source_stream: String,
    pub source_repository: String,
    pub source_revision: String,
    pub source_url: Option<String>,
    pub generated_at: String,
    pub content_sha256: String,
    pub imported_at: String,
    pub record_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationalSourceStatus {
    pub source_system: String,
    pub source_stream: String,
    pub source_repository: String,
    pub source_revision: String,
    pub source_url: Option<String>,
    pub last_generated_at: String,
    pub last_checked_at: String,
    pub last_changed_at: String,
    pub latest_import_id: String,
    pub content_sha256: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationalImportResponse {
    pub imported: bool,
    pub record: OperationalImportRecord,
    pub source: OperationalSourceStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkerEvent {
    Status {
        status: String,
        #[serde(default)]
        phase: String,
        #[serde(default)]
        progress: f64,
        #[serde(default)]
        message: String,
    },
    Metric {
        name: String,
        step: i64,
        value: f64,
        #[serde(default)]
        timestamp: Option<String>,
    },
    Artifact {
        path: String,
        kind: String,
        #[serde(default = "default_media_type")]
        media_type: String,
    },
    Log {
        level: String,
        message: String,
    },
    Result {
        status: String,
        #[serde(default)]
        summary: Value,
    },
    Object {
        id: String,
        kind: String,
        type_name: String,
        state: String,
        #[serde(default)]
        label: Option<String>,
        #[serde(default)]
        payload: Value,
    },
    Relation {
        id: String,
        subject_id: String,
        predicate: String,
        object_id: String,
        #[serde(default)]
        payload: Value,
    },
    Action {
        id: String,
        action_type: String,
        actor: String,
        #[serde(default)]
        target_id: Option<String>,
        status: String,
        #[serde(default)]
        payload: Value,
    },
    ExternalJob {
        provider: String,
        external_id: String,
        label: String,
        status: String,
        #[serde(default)]
        chip: Option<String>,
        #[serde(default)]
        submitted_at: Option<String>,
        #[serde(default)]
        started_at: Option<String>,
        #[serde(default)]
        finished_at: Option<String>,
        #[serde(default)]
        rate_per_min_usd: Option<f64>,
        #[serde(default)]
        max_cost_usd: Option<f64>,
        #[serde(default)]
        cost_usd: Option<f64>,
        #[serde(default)]
        queue_position: Option<i64>,
        #[serde(default)]
        estimated_wait_seconds: Option<i64>,
        #[serde(default)]
        payload: Value,
    },
    Projection {
        object_id: String,
        #[serde(default = "default_projection_space")]
        space: String,
        x: f64,
        y: f64,
        #[serde(default)]
        z: Option<f64>,
        #[serde(default)]
        group_id: Option<String>,
        #[serde(default)]
        signals: Value,
        #[serde(default)]
        selected: bool,
        #[serde(default)]
        label: Option<String>,
    },
    Cost {
        cost_usd: f64,
        source: String,
        #[serde(default)]
        observed_at: Option<String>,
    },
}

fn default_media_type() -> String {
    "application/octet-stream".to_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LaunchRequest {
    pub campaign_id: String,
    pub capability_id: String,
    pub name: String,
    #[serde(default)]
    pub parameters: Value,
    #[serde(default)]
    pub budget_ceiling_usd: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalJobUpdate {
    pub campaign_id: Option<String>,
    pub run_id: Option<String>,
    pub provider: String,
    pub external_id: String,
    pub label: String,
    pub status: String,
    #[serde(default)]
    pub chip: Option<String>,
    #[serde(default)]
    pub submitted_at: Option<String>,
    #[serde(default)]
    pub started_at: Option<String>,
    #[serde(default)]
    pub finished_at: Option<String>,
    #[serde(default)]
    pub rate_per_min_usd: Option<f64>,
    #[serde(default)]
    pub max_cost_usd: Option<f64>,
    #[serde(default)]
    pub cost_usd: Option<f64>,
    #[serde(default)]
    pub queue_position: Option<i64>,
    #[serde(default)]
    pub estimated_wait_seconds: Option<i64>,
    #[serde(default)]
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCampaignRequest {
    pub name: String,
    pub domain: String,
    pub objective: String,
    #[serde(default)]
    pub program_source: Option<String>,
    #[serde(default)]
    pub capability_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CampaignCapabilityUpdate {
    pub capability_id: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpsertProviderRequest {
    pub id: String,
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub base_url: Option<String>,
    #[serde(default)]
    pub secret_ref: Option<String>,
    #[serde(default = "default_json_object")]
    pub metadata: Value,
}

fn default_json_object() -> Value {
    Value::Object(Default::default())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResearchPromptRequest {
    pub campaign_id: String,
    pub provider_id: String,
    pub prompt: String,
    #[serde(default)]
    pub model: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResearchPromptResponse {
    pub user_message: SemanticObject,
    pub assistant_message: SemanticObject,
    pub action: ActionRecord,
    pub usage: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateNoteRequest {
    pub campaign_id: String,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub target_id: Option<String>,
    pub category: String,
    #[serde(default = "default_note_severity")]
    pub severity: String,
    pub title: String,
    pub body: String,
    #[serde(default = "default_note_actor")]
    pub actor: String,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default = "default_json_object")]
    pub provenance: Value,
}

fn default_note_severity() -> String {
    "normal".to_owned()
}

fn default_note_actor() -> String {
    "operator".to_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NoteResponse {
    pub note: SemanticObject,
    pub action: ActionRecord,
    pub relation: SemanticRelation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectionUpdate {
    pub campaign_id: String,
    #[serde(default)]
    pub run_id: Option<String>,
    pub object_id: String,
    #[serde(default = "default_projection_space")]
    pub space: String,
    pub x: f64,
    pub y: f64,
    #[serde(default)]
    pub z: Option<f64>,
    #[serde(default)]
    pub group_id: Option<String>,
    #[serde(default)]
    pub signals: Value,
    #[serde(default)]
    pub selected: bool,
    #[serde(default)]
    pub label: Option<String>,
}

fn default_projection_space() -> String {
    "pca".to_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayCampaignRequest {
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CampaignArchive {
    #[serde(default)]
    pub project_inputs: Vec<crate::project_inputs::ProjectInputVersion>,
    pub schema_version: String,
    pub exported_at: String,
    pub campaign: Campaign,
    pub capabilities: Vec<Capability>,
    pub runs: Vec<Run>,
    pub metrics: Vec<MetricPoint>,
    pub events: Vec<LedgerEvent>,
    pub artifacts: Vec<Artifact>,
    pub candidates: Vec<CandidatePoint>,
    pub basins: Vec<BasinSummary>,
    pub objects: Vec<SemanticObject>,
    pub relations: Vec<SemanticRelation>,
    pub actions: Vec<ActionRecord>,
    pub external_jobs: Vec<ExternalJob>,
    pub projections: Vec<ObjectProjection>,
    pub research_plans: Vec<crate::research_session::ResearchPlanEnvelope>,
    pub agent_runs: Vec<crate::agent_runtime::AgentRunEnvelope>,
    #[serde(default)]
    pub science_artifacts: crate::science_artifacts::ScienceArtifactWorkspace,
    #[serde(default)]
    pub execution: crate::execution_control::ExecutionWorkspace,
    #[serde(default)]
    pub standing_review: crate::standing_review::StandingReviewWorkspace,
}
