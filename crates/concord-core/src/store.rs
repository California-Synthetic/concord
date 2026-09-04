mod agent_progression;
mod project_inputs;
mod research_execution;

use crate::agent_runtime::*;
use crate::campaign_supervision::*;
use crate::capability_packages::*;
use crate::epact::enforce_epact_dispatch_tx;
use crate::execution_control::*;
use crate::model_harness::{ContextCompilationReceipt, CONTEXT_COMPILATION_RECEIPT_CONTRACT};
use crate::models::*;
use crate::research_session::*;
use crate::science_artifacts::*;
use crate::source_gate::*;
use crate::standing_review::*;
use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use uuid::Uuid;

const SNAPSHOT_METRIC_POINTS_PER_SERIES: i64 = 600;
const SNAPSHOT_CANDIDATE_LIMIT: i64 = 10_000;

#[derive(Debug, Clone)]
pub struct Database {
    path: PathBuf,
}

impl Database {
    pub fn new(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let database = Self { path };
        database.migrate()?;
        Ok(database)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn connect(&self) -> Result<Connection> {
        let connection = Connection::open(&self.path)
            .with_context(|| format!("open Concord database {}", self.path.display()))?;
        // Every connection waits for short write contention. Journal mode is initialized once in
        // `migrate`; reissuing that database-wide pragma here made parallel request setup contend
        // before the requests reached their own transactions.
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        Ok(connection)
    }

    fn migrate(&self) -> Result<()> {
        let mut connection = self.connect()?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS programs (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                language TEXT NOT NULL,
                language_version TEXT NOT NULL,
                source TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS campaigns (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                domain TEXT NOT NULL,
                objective TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                program_id TEXT NOT NULL REFERENCES programs(id)
            );

            CREATE TABLE IF NOT EXISTS epact_program_images (
                image_sha256 TEXT PRIMARY KEY,
                program_id TEXT NOT NULL,
                program_version TEXT NOT NULL,
                program_sha256 TEXT NOT NULL,
                image_json TEXT NOT NULL,
                recorded_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS epact_campaign_activations (
                id TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL REFERENCES campaigns(id),
                image_sha256 TEXT NOT NULL REFERENCES epact_program_images(image_sha256),
                predecessor_image_sha256 TEXT REFERENCES epact_program_images(image_sha256),
                effective_event_head_sha256 TEXT NOT NULL,
                actor TEXT NOT NULL,
                rationale TEXT,
                amendment_json TEXT,
                active INTEGER NOT NULL,
                activated_at TEXT NOT NULL,
                UNIQUE(campaign_id,image_sha256)
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_epact_campaign_active
                ON epact_campaign_activations(campaign_id) WHERE active=1;

            CREATE TABLE IF NOT EXISTS epact_runtime_events (
                event_sha256 TEXT PRIMARY KEY,
                event_id TEXT NOT NULL UNIQUE,
                campaign_id TEXT NOT NULL REFERENCES campaigns(id),
                image_sha256 TEXT NOT NULL REFERENCES epact_program_images(image_sha256),
                sequence INTEGER NOT NULL,
                idempotency_key TEXT NOT NULL,
                event_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(campaign_id,image_sha256,sequence),
                UNIQUE(campaign_id,image_sha256,idempotency_key)
            );

            CREATE INDEX IF NOT EXISTS idx_epact_events_replay
                ON epact_runtime_events(campaign_id,image_sha256,sequence);

            CREATE TABLE IF NOT EXISTS capabilities (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                kind TEXT NOT NULL,
                version TEXT NOT NULL,
                provider TEXT NOT NULL,
                description TEXT NOT NULL,
                trust_status TEXT NOT NULL,
                lifecycle_json TEXT NOT NULL,
                command_json TEXT NOT NULL,
                resources_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS campaign_capabilities (
                campaign_id TEXT NOT NULL REFERENCES campaigns(id),
                capability_id TEXT NOT NULL REFERENCES capabilities(id),
                PRIMARY KEY (campaign_id, capability_id)
            );

            CREATE TABLE IF NOT EXISTS capability_package_records (
                record_id TEXT PRIMARY KEY,
                package_id TEXT NOT NULL,
                package_version TEXT NOT NULL,
                content_sha256 TEXT NOT NULL,
                trust_status TEXT NOT NULL,
                manifest_json TEXT NOT NULL,
                registered_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(package_id,package_version,content_sha256)
            );

            CREATE INDEX IF NOT EXISTS idx_capability_package_identity
                ON capability_package_records(package_id,package_version,updated_at DESC);

            CREATE TABLE IF NOT EXISTS mcp_discovery_records (
                record_id TEXT PRIMARY KEY,
                package_record_id TEXT NOT NULL REFERENCES capability_package_records(record_id),
                package_content_sha256 TEXT NOT NULL,
                discovery_sha256 TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                UNIQUE(package_record_id,discovery_sha256)
            );

            CREATE INDEX IF NOT EXISTS idx_mcp_discovery_package_time
                ON mcp_discovery_records(package_record_id,recorded_at DESC);

            CREATE TABLE IF NOT EXISTS capability_qualification_records (
                record_id TEXT PRIMARY KEY,
                package_record_id TEXT NOT NULL REFERENCES capability_package_records(record_id),
                package_content_sha256 TEXT NOT NULL,
                discovery_record_id TEXT REFERENCES mcp_discovery_records(record_id),
                disposition TEXT NOT NULL,
                qualification_sha256 TEXT NOT NULL UNIQUE,
                qualification_json TEXT NOT NULL,
                recorded_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_capability_qualification_package_time
                ON capability_qualification_records(package_record_id,recorded_at DESC,record_id DESC);

            CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL REFERENCES campaigns(id),
                capability_id TEXT NOT NULL,
                name TEXT NOT NULL,
                status TEXT NOT NULL,
                phase TEXT NOT NULL,
                progress REAL NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                external_url TEXT,
                pid INTEGER,
                budget_ceiling_usd REAL,
                cost_usd REAL,
                parameters_json TEXT NOT NULL,
                resources_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS run_supervision (
                run_id TEXT PRIMARY KEY REFERENCES runs(id) ON DELETE CASCADE,
                event_path TEXT NOT NULL,
                stderr_path TEXT NOT NULL,
                event_offset INTEGER NOT NULL DEFAULT 0,
                stderr_offset INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS metrics (
                run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                step INTEGER NOT NULL,
                value REAL NOT NULL,
                timestamp TEXT NOT NULL,
                PRIMARY KEY (run_id, name, step)
            );

            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                campaign_id TEXT,
                run_id TEXT,
                object_type TEXT NOT NULL,
                object_id TEXT NOT NULL,
                verb TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_events_campaign_time ON events(campaign_id, timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_events_run_time ON events(run_id, timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_metrics_run_name ON metrics(run_id, name, step);
            CREATE INDEX IF NOT EXISTS idx_runs_started_at ON runs(started_at DESC);

            CREATE TABLE IF NOT EXISTS artifacts (
                id TEXT PRIMARY KEY,
                run_id TEXT,
                kind TEXT NOT NULL,
                media_type TEXT NOT NULL,
                byte_size INTEGER NOT NULL,
                path TEXT NOT NULL,
                source_path TEXT,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_artifacts_created_at
                ON artifacts(created_at DESC);

            CREATE TABLE IF NOT EXISTS project_inputs (
                id TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL REFERENCES campaigns(id),
                logical_path TEXT NOT NULL,
                version INTEGER NOT NULL,
                artifact_id TEXT NOT NULL REFERENCES artifacts(id),
                idempotency_key TEXT NOT NULL,
                record_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(campaign_id,logical_path,version),
                UNIQUE(campaign_id,idempotency_key)
            );

            CREATE TABLE IF NOT EXISTS budgets (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                source TEXT NOT NULL,
                currency TEXT NOT NULL,
                total REAL NOT NULL,
                spent REAL NOT NULL,
                exposure REAL NOT NULL,
                remaining_floor REAL NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS budget_reservations (
                run_id TEXT PRIMARY KEY REFERENCES runs(id) ON DELETE CASCADE,
                budget_id TEXT NOT NULL REFERENCES budgets(id),
                reserved_usd REAL NOT NULL,
                baseline_spent_usd REAL NOT NULL DEFAULT 0,
                settled_usd REAL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_budget_reservations_budget_status
                ON budget_reservations(budget_id,status,updated_at DESC);

            CREATE TABLE IF NOT EXISTS candidates (
                id TEXT NOT NULL,
                campaign_id TEXT NOT NULL REFERENCES campaigns(id),
                basin_id INTEGER NOT NULL,
                x REAL NOT NULL,
                y REAL NOT NULL,
                z REAL,
                conflict REAL NOT NULL,
                geometry REAL,
                motif REAL,
                selected INTEGER NOT NULL,
                failure TEXT,
                PRIMARY KEY (campaign_id, id)
            );

            CREATE INDEX IF NOT EXISTS idx_candidates_campaign_basin ON candidates(campaign_id, basin_id);
            CREATE INDEX IF NOT EXISTS idx_candidates_snapshot
                ON candidates(selected DESC,campaign_id,id);

            CREATE TABLE IF NOT EXISTS basins (
                campaign_id TEXT NOT NULL REFERENCES campaigns(id),
                id INTEGER NOT NULL,
                size INTEGER NOT NULL,
                suspicion REAL NOT NULL,
                dominant_failure TEXT,
                core_pass_rate REAL NOT NULL,
                geometry_pass_rate REAL NOT NULL,
                esm_pass_rate REAL NOT NULL,
                PRIMARY KEY (campaign_id, id)
            );

            CREATE TABLE IF NOT EXISTS semantic_objects (
                id TEXT PRIMARY KEY,
                campaign_id TEXT,
                run_id TEXT,
                kind TEXT NOT NULL,
                type_name TEXT NOT NULL,
                state TEXT NOT NULL,
                label TEXT,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_semantic_objects_campaign_kind
                ON semantic_objects(campaign_id,kind,updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_semantic_objects_run
                ON semantic_objects(run_id,updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_semantic_objects_updated
                ON semantic_objects(updated_at DESC);

            CREATE TABLE IF NOT EXISTS semantic_relations (
                id TEXT PRIMARY KEY,
                campaign_id TEXT,
                run_id TEXT,
                subject_id TEXT NOT NULL,
                predicate TEXT NOT NULL,
                object_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_semantic_relations_subject
                ON semantic_relations(subject_id,predicate,timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_semantic_relations_object
                ON semantic_relations(object_id,predicate,timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_semantic_relations_time
                ON semantic_relations(timestamp DESC);

            CREATE TABLE IF NOT EXISTS source_gate_compilations (
                projection_sha256 TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL REFERENCES campaigns(id),
                input_sha256 TEXT NOT NULL,
                snapshot_sha256 TEXT NOT NULL,
                input_json TEXT NOT NULL,
                projection_json TEXT NOT NULL,
                compiled_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_source_gate_campaign_time
                ON source_gate_compilations(campaign_id,compiled_at DESC,projection_sha256 DESC);

            CREATE TABLE IF NOT EXISTS source_gate_epact_bindings (
                projection_sha256 TEXT PRIMARY KEY REFERENCES source_gate_compilations(projection_sha256) ON DELETE CASCADE,
                image_sha256 TEXT NOT NULL REFERENCES epact_program_images(image_sha256),
                binding_json TEXT NOT NULL,
                recorded_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_source_gate_epact_image
                ON source_gate_epact_bindings(image_sha256,recorded_at DESC);

            CREATE TABLE IF NOT EXISTS actions (
                id TEXT PRIMARY KEY,
                campaign_id TEXT,
                run_id TEXT,
                action_type TEXT NOT NULL,
                actor TEXT NOT NULL,
                target_id TEXT,
                status TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_actions_campaign_time
                ON actions(campaign_id,timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_actions_run_time
                ON actions(run_id,timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_actions_time ON actions(timestamp DESC);

            CREATE TABLE IF NOT EXISTS agent_runs (
                id TEXT PRIMARY KEY,
                contract TEXT NOT NULL,
                campaign_id TEXT NOT NULL REFERENCES campaigns(id),
                provider_id TEXT NOT NULL REFERENCES provider_profiles(id),
                model TEXT NOT NULL,
                task TEXT NOT NULL,
                allowed_tools_json TEXT NOT NULL,
                budget_json TEXT NOT NULL,
                status TEXT NOT NULL,
                revision INTEGER NOT NULL,
                model_calls INTEGER NOT NULL,
                tool_calls INTEGER NOT NULL,
                parent_run_id TEXT REFERENCES agent_runs(id),
                parent_event_hash TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                epact_json TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_agent_runs_campaign_time
                ON agent_runs(campaign_id,updated_at DESC);

            CREATE TABLE IF NOT EXISTS agent_events (
                id TEXT PRIMARY KEY,
                contract TEXT NOT NULL,
                agent_run_id TEXT NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
                sequence INTEGER NOT NULL,
                idempotency_key TEXT NOT NULL,
                kind TEXT NOT NULL,
                from_status TEXT NOT NULL,
                to_status TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                previous_event_sha256 TEXT,
                event_sha256 TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                UNIQUE(agent_run_id,sequence),
                UNIQUE(agent_run_id,idempotency_key)
            );

            CREATE INDEX IF NOT EXISTS idx_agent_events_run_sequence
                ON agent_events(agent_run_id,sequence);

            CREATE TABLE IF NOT EXISTS campaign_governors (
                campaign_id TEXT PRIMARY KEY REFERENCES campaigns(id) ON DELETE CASCADE,
                contract TEXT NOT NULL,
                generation INTEGER NOT NULL,
                status TEXT NOT NULL,
                last_reconciliation_sha256 TEXT,
                blocked_reason TEXT,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS campaign_service_leases (
                campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
                role TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                generation INTEGER NOT NULL,
                last_heartbeat_at TEXT NOT NULL,
                lease_expires_at TEXT NOT NULL,
                details_json TEXT NOT NULL,
                PRIMARY KEY (campaign_id,role)
            );

            CREATE INDEX IF NOT EXISTS idx_campaign_service_generation
                ON campaign_service_leases(campaign_id,generation,lease_expires_at);

            CREATE TABLE IF NOT EXISTS campaign_reconciliations (
                id TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
                generation INTEGER NOT NULL,
                reconciliation_sha256 TEXT NOT NULL UNIQUE,
                record_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_campaign_reconciliation_generation
                ON campaign_reconciliations(campaign_id,generation,created_at);

            CREATE TABLE IF NOT EXISTS campaign_closeouts (
                id TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL UNIQUE REFERENCES campaigns(id) ON DELETE CASCADE,
                closeout_sha256 TEXT NOT NULL UNIQUE,
                record_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS campaign_dispatch_permits (
                token TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
                generation INTEGER NOT NULL,
                idempotency_key TEXT NOT NULL,
                operation TEXT NOT NULL,
                target_id TEXT NOT NULL,
                record_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'authorized',
                consumed_at TEXT,
                settled_cost_usd REAL,
                updated_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(campaign_id,generation,idempotency_key)
            );

            CREATE INDEX IF NOT EXISTS idx_campaign_dispatch_target
                ON campaign_dispatch_permits(campaign_id,generation,operation,target_id);
            CREATE TABLE IF NOT EXISTS research_plan_versions (
                id TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL REFERENCES campaigns(id),
                version INTEGER NOT NULL,
                plan_sha256 TEXT NOT NULL UNIQUE,
                previous_plan_sha256 TEXT,
                plan_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(campaign_id,version)
            );

            CREATE INDEX IF NOT EXISTS idx_research_plan_campaign_version
                ON research_plan_versions(campaign_id,version DESC);

            CREATE TABLE IF NOT EXISTS research_plan_decisions (
                id TEXT PRIMARY KEY,
                plan_id TEXT NOT NULL REFERENCES research_plan_versions(id),
                plan_sha256 TEXT NOT NULL,
                decision TEXT NOT NULL,
                decision_sha256 TEXT NOT NULL UNIQUE,
                previous_decision_sha256 TEXT,
                decision_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_research_plan_decision_plan_time
                ON research_plan_decisions(plan_id,created_at,id);

            CREATE TABLE IF NOT EXISTS research_phase_dispatches (
                id TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL REFERENCES campaigns(id),
                plan_id TEXT NOT NULL REFERENCES research_plan_versions(id),
                phase_id TEXT NOT NULL,
                dispatch_sha256 TEXT NOT NULL UNIQUE,
                dispatch_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(plan_id,phase_id)
            );

            CREATE INDEX IF NOT EXISTS idx_research_phase_dispatch_campaign_time
                ON research_phase_dispatches(campaign_id,created_at,id);

            CREATE TABLE IF NOT EXISTS science_artifact_versions (
                id TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL REFERENCES campaigns(id),
                version INTEGER NOT NULL,
                parent_version_id TEXT REFERENCES science_artifact_versions(id),
                producing_agent_run_id TEXT NOT NULL REFERENCES agent_runs(id),
                version_sha256 TEXT NOT NULL UNIQUE,
                record_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_science_artifact_campaign_time
                ON science_artifact_versions(campaign_id,created_at,id);

            CREATE TABLE IF NOT EXISTS science_artifact_annotations (
                id TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL REFERENCES campaigns(id),
                artifact_version_id TEXT NOT NULL REFERENCES science_artifact_versions(id),
                annotation_sha256 TEXT NOT NULL UNIQUE,
                previous_annotation_sha256 TEXT,
                record_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_science_annotation_version_time
                ON science_artifact_annotations(artifact_version_id,created_at,id);

            CREATE TABLE IF NOT EXISTS science_artifact_reviews (
                id TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL REFERENCES campaigns(id),
                artifact_version_id TEXT NOT NULL REFERENCES science_artifact_versions(id),
                reviewer_agent_run_id TEXT NOT NULL REFERENCES agent_runs(id),
                review_sha256 TEXT NOT NULL UNIQUE,
                record_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_science_review_version_time
                ON science_artifact_reviews(artifact_version_id,created_at,id);

            CREATE TABLE IF NOT EXISTS science_artifact_dispositions (
                id TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL REFERENCES campaigns(id),
                artifact_version_id TEXT NOT NULL REFERENCES science_artifact_versions(id),
                disposition TEXT NOT NULL,
                disposition_sha256 TEXT NOT NULL UNIQUE,
                previous_disposition_sha256 TEXT,
                record_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(artifact_version_id)
            );
            CREATE INDEX IF NOT EXISTS idx_science_disposition_campaign_time
                ON science_artifact_dispositions(campaign_id,created_at,id);

            CREATE TABLE IF NOT EXISTS standing_review_receipts (
                id TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
                input_sha256 TEXT NOT NULL,
                previous_review_sha256 TEXT,
                review_sha256 TEXT NOT NULL UNIQUE,
                record_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(campaign_id,input_sha256)
            );
            CREATE INDEX IF NOT EXISTS idx_standing_review_campaign_time
                ON standing_review_receipts(campaign_id,created_at,id);

            CREATE TABLE IF NOT EXISTS science_batch_receipts (
                id TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL REFERENCES campaigns(id),
                producing_agent_run_id TEXT NOT NULL REFERENCES agent_runs(id),
                receipt_sha256 TEXT NOT NULL UNIQUE,
                record_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS science_ranked_tables (
                id TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL REFERENCES campaigns(id),
                table_sha256 TEXT NOT NULL UNIQUE,
                record_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS science_decision_memos (
                id TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL REFERENCES campaigns(id),
                memo_sha256 TEXT NOT NULL UNIQUE,
                record_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS execution_plans (
                id TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL REFERENCES campaigns(id),
                plan_sha256 TEXT NOT NULL UNIQUE,
                record_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS execution_receipts (
                id TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL REFERENCES campaigns(id),
                plan_id TEXT NOT NULL REFERENCES execution_plans(id),
                receipt_sha256 TEXT NOT NULL UNIQUE,
                record_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_execution_campaign_time
                ON execution_plans(campaign_id,created_at,id);

            CREATE TABLE IF NOT EXISTS agent_budget_reservations (
                agent_run_id TEXT PRIMARY KEY REFERENCES agent_runs(id) ON DELETE CASCADE,
                budget_id TEXT NOT NULL REFERENCES budgets(id),
                reserved_usd REAL NOT NULL,
                estimated_spent_usd REAL NOT NULL DEFAULT 0,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_agent_budget_reservations_budget_status
                ON agent_budget_reservations(budget_id,status,updated_at DESC);

            CREATE TABLE IF NOT EXISTS external_jobs (
                id TEXT PRIMARY KEY,
                campaign_id TEXT,
                run_id TEXT,
                provider TEXT NOT NULL,
                external_id TEXT NOT NULL,
                label TEXT NOT NULL,
                status TEXT NOT NULL,
                chip TEXT,
                submitted_at TEXT,
                started_at TEXT,
                finished_at TEXT,
                rate_per_min_usd REAL,
                max_cost_usd REAL,
                cost_usd REAL,
                queue_position INTEGER,
                estimated_wait_seconds INTEGER,
                payload_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(provider,external_id)
            );

            CREATE INDEX IF NOT EXISTS idx_external_jobs_run_time
                ON external_jobs(run_id,updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_external_jobs_campaign_time
                ON external_jobs(campaign_id,updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_external_jobs_updated
                ON external_jobs(updated_at DESC);

            CREATE TABLE IF NOT EXISTS agent_progressions (
                agent_run_id TEXT NOT NULL REFERENCES agent_runs(id),
                sequence INTEGER NOT NULL,
                action TEXT NOT NULL,
                record_json TEXT NOT NULL,
                PRIMARY KEY(agent_run_id,sequence)
            );

            CREATE TABLE IF NOT EXISTS provider_profiles (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                kind TEXT NOT NULL,
                base_url TEXT,
                secret_ref TEXT,
                status TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS object_projections (
                id TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL REFERENCES campaigns(id),
                run_id TEXT,
                object_id TEXT NOT NULL,
                space TEXT NOT NULL,
                x REAL NOT NULL,
                y REAL NOT NULL,
                z REAL,
                group_id TEXT,
                signals_json TEXT NOT NULL,
                selected INTEGER NOT NULL,
                label TEXT,
                updated_at TEXT NOT NULL,
                UNIQUE(campaign_id,object_id,space)
            );

            CREATE INDEX IF NOT EXISTS idx_object_projections_campaign_space
                ON object_projections(campaign_id,space,updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_object_projections_run
                ON object_projections(run_id,updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_object_projections_updated
                ON object_projections(updated_at DESC);

            CREATE TABLE IF NOT EXISTS operational_imports (
                import_id TEXT PRIMARY KEY,
                contract TEXT NOT NULL,
                source_system TEXT NOT NULL,
                source_stream TEXT NOT NULL,
                source_repository TEXT NOT NULL,
                source_revision TEXT NOT NULL,
                source_url TEXT,
                generated_at TEXT NOT NULL,
                content_sha256 TEXT NOT NULL,
                imported_at TEXT NOT NULL,
                record_count INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_operational_imports_stream_time
                ON operational_imports(source_system,source_stream,generated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_operational_imports_imported
                ON operational_imports(imported_at DESC);

            CREATE TABLE IF NOT EXISTS operational_sources (
                source_system TEXT NOT NULL,
                source_stream TEXT NOT NULL,
                source_repository TEXT NOT NULL,
                source_revision TEXT NOT NULL,
                source_url TEXT,
                last_generated_at TEXT NOT NULL,
                last_checked_at TEXT NOT NULL,
                last_changed_at TEXT NOT NULL,
                latest_import_id TEXT NOT NULL,
                content_sha256 TEXT NOT NULL,
                status TEXT NOT NULL,
                PRIMARY KEY (source_system,source_stream)
            );
            "#,
        )?;

        // Normalize legacy provider spellings once, then keep all future writes canonical at the
        // storage boundary.  This prevents different screens from disagreeing about active and
        // terminal counts.
        connection.execute_batch(
            r#"
            UPDATE runs SET status='completed' WHERE status IN ('complete','succeeded','qualified','success');
            UPDATE runs SET status='running' WHERE status IN ('in_progress','external');
            UPDATE runs SET status='queued' WHERE status IN ('submitted','requested','waiting','pending','building','provisioning');
            UPDATE runs SET status='cancelled' WHERE status IN ('canceled','skipped');
            UPDATE external_jobs SET status='completed' WHERE status IN ('complete','succeeded','qualified','success');
            UPDATE external_jobs SET status='running' WHERE status IN ('in_progress','external');
            UPDATE external_jobs SET status='queued' WHERE status IN ('submitted','requested','waiting','pending','building','provisioning');
            UPDATE external_jobs SET status='cancelled' WHERE status IN ('canceled','skipped');
            UPDATE actions SET status='completed' WHERE status IN ('complete','succeeded','qualified','success');
            UPDATE actions SET status='running' WHERE status IN ('in_progress','external');
            UPDATE actions SET status='queued' WHERE status IN ('submitted','requested','waiting','pending','building','provisioning');
            UPDATE actions SET status='cancelled' WHERE status IN ('canceled','skipped');

            INSERT OR IGNORE INTO operational_sources
            (source_system,source_stream,source_repository,source_revision,source_url,
             last_generated_at,last_checked_at,last_changed_at,latest_import_id,content_sha256,status)
            SELECT i.source_system,i.source_stream,i.source_repository,i.source_revision,i.source_url,
                   i.generated_at,i.imported_at,i.imported_at,i.import_id,i.content_sha256,'unchecked'
            FROM operational_imports i
            WHERE i.imported_at=(
                SELECT MAX(candidate.imported_at) FROM operational_imports candidate
                WHERE candidate.source_system=i.source_system AND candidate.source_stream=i.source_stream
            );
            "#,
        )?;
        let has_z = {
            let mut statement = connection.prepare("PRAGMA table_info(candidates)")?;
            let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
            columns
                .collect::<rusqlite::Result<Vec<_>>>()?
                .iter()
                .any(|name| name == "z")
        };
        if !has_z {
            connection.execute("ALTER TABLE candidates ADD COLUMN z REAL", [])?;
        }
        let has_budget_baseline = {
            let mut statement = connection.prepare("PRAGMA table_info(budget_reservations)")?;
            let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
            columns
                .collect::<rusqlite::Result<Vec<_>>>()?
                .iter()
                .any(|name| name == "baseline_spent_usd")
        };
        if !has_budget_baseline {
            connection.execute(
                "ALTER TABLE budget_reservations ADD COLUMN baseline_spent_usd REAL NOT NULL DEFAULT 0",
                [],
            )?;
        }
        let dispatch_permit_columns = {
            let mut statement =
                connection.prepare("PRAGMA table_info(campaign_dispatch_permits)")?;
            let columns = statement
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<rusqlite::Result<std::collections::BTreeSet<_>>>()?;
            columns
        };
        if !dispatch_permit_columns.contains("status") {
            connection.execute(
                "ALTER TABLE campaign_dispatch_permits ADD COLUMN status TEXT NOT NULL DEFAULT 'authorized'",
                [],
            )?;
        }
        if !dispatch_permit_columns.contains("settled_cost_usd") {
            connection.execute(
                "ALTER TABLE campaign_dispatch_permits ADD COLUMN settled_cost_usd REAL",
                [],
            )?;
        }
        if !dispatch_permit_columns.contains("updated_at") {
            connection.execute(
                "ALTER TABLE campaign_dispatch_permits ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''",
                [],
            )?;
            connection.execute(
                "UPDATE campaign_dispatch_permits SET updated_at=created_at WHERE updated_at=''",
                [],
            )?;
        }
        let agent_run_columns = {
            let mut statement = connection.prepare("PRAGMA table_info(agent_runs)")?;
            let columns = statement
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<rusqlite::Result<std::collections::BTreeSet<_>>>()?;
            columns
        };
        if !agent_run_columns.contains("epact_json") {
            connection.execute("ALTER TABLE agent_runs ADD COLUMN epact_json TEXT", [])?;
        }
        connection.execute(
            "UPDATE campaign_dispatch_permits SET status=CASE WHEN consumed_at IS NULL THEN 'authorized' ELSE 'consumed' END WHERE status NOT IN ('authorized','consumed','settled','interrupted','released') OR status IS NULL",
            [],
        )?;
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_campaign_dispatch_status ON campaign_dispatch_permits(status,updated_at)",
            [],
        )?;
        let terminal_reservations = {
            let mut statement = connection.prepare(
                r#"SELECT br.run_id
                FROM budget_reservations br JOIN runs r ON r.id=br.run_id
                WHERE r.status IN ('completed','failed','cancelled')
                AND r.cost_usd IS NULL
                AND br.status IN ('reserved','pending_reconciliation')"#,
            )?;
            let run_ids = statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            run_ids
        };
        if !terminal_reservations.is_empty() {
            let transaction = connection.transaction()?;
            for run_id in terminal_reservations {
                settle_run_budget_tx(&transaction, &run_id)?;
            }
            transaction.commit()?;
        }
        Ok(())
    }

    pub fn is_empty(&self) -> Result<bool> {
        let connection = self.connect()?;
        let count: i64 =
            connection.query_row("SELECT COUNT(*) FROM campaigns", [], |row| row.get(0))?;
        Ok(count == 0)
    }

    pub fn seed(&self, seed: &SeedBundle) -> Result<()> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;

        for capability in &seed.capabilities {
            upsert_capability(&transaction, capability)?;
        }
        for campaign in &seed.campaigns {
            transaction.execute(
                "INSERT OR REPLACE INTO programs(id,name,language,language_version,source) VALUES (?1,?2,?3,?4,?5)",
                params![campaign.program.id, campaign.program.name, campaign.program.language, campaign.program.language_version, campaign.program.source],
            )?;
            transaction.execute(
                "INSERT OR REPLACE INTO campaigns(id,name,domain,objective,status,created_at,program_id) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![campaign.id, campaign.name, campaign.domain, campaign.objective, campaign.status, campaign.created_at, campaign.program.id],
            )?;
            for capability in &seed.capabilities {
                transaction.execute(
                    "INSERT OR IGNORE INTO campaign_capabilities(campaign_id, capability_id) VALUES (?1,?2)",
                    params![campaign.id, capability.id],
                )?;
            }
        }
        for run in &seed.runs {
            upsert_run(&transaction, run)?;
        }
        for metric in &seed.metrics {
            insert_metric_tx(&transaction, metric)?;
        }
        for event in &seed.events {
            insert_event_tx(&transaction, event)?;
        }
        for artifact in &seed.artifacts {
            insert_artifact_tx(&transaction, artifact)?;
        }
        for budget in &seed.budgets {
            transaction.execute(
                r#"INSERT OR REPLACE INTO budgets
                (id,name,source,currency,total,spent,exposure,remaining_floor,updated_at)
                VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)"#,
                params![
                    budget.id,
                    budget.name,
                    budget.source,
                    budget.currency,
                    budget.total,
                    budget.spent,
                    budget.exposure,
                    budget.remaining_floor,
                    budget.updated_at
                ],
            )?;
        }
        for candidate in &seed.candidates {
            transaction.execute(
                r#"INSERT OR REPLACE INTO candidates
                (id,campaign_id,basin_id,x,y,z,conflict,geometry,motif,selected,failure)
                VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)"#,
                params![
                    candidate.id,
                    candidate.campaign_id,
                    candidate.basin_id,
                    candidate.x,
                    candidate.y,
                    candidate.z,
                    candidate.conflict,
                    candidate.geometry,
                    candidate.motif,
                    candidate.selected as i64,
                    candidate.failure
                ],
            )?;
        }
        for basin in &seed.basins {
            transaction.execute(
                r#"INSERT OR REPLACE INTO basins
                (campaign_id,id,size,suspicion,dominant_failure,core_pass_rate,geometry_pass_rate,esm_pass_rate)
                VALUES (?1,?2,?3,?4,?5,?6,?7,?8)"#,
                params![basin.campaign_id, basin.id, basin.size, basin.suspicion, basin.dominant_failure,
                    basin.core_pass_rate, basin.geometry_pass_rate, basin.esm_pass_rate],
            )?;
        }
        for object in &seed.objects {
            upsert_semantic_object_tx(&transaction, object)?;
        }
        for relation in &seed.relations {
            upsert_semantic_relation_tx(&transaction, relation)?;
        }
        for action in &seed.actions {
            upsert_action_tx(&transaction, action)?;
        }
        for job in &seed.external_jobs {
            upsert_external_job_tx(&transaction, job)?;
        }
        for provider in &seed.providers {
            upsert_provider_tx(&transaction, provider)?;
        }
        for projection in &seed.projections {
            upsert_projection_tx(&transaction, projection)?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn import_operational(
        &self,
        envelope: &OperationalImportEnvelope,
    ) -> Result<OperationalImportResponse> {
        anyhow::ensure!(
            envelope.contract == "concord.operational-import/1",
            "unsupported operational import contract"
        );
        anyhow::ensure!(
            envelope.classification == "operational_metadata",
            "operational import has the wrong information classification"
        );
        anyhow::ensure!(
            !envelope.contains_scientific_endpoints,
            "scientific endpoint material cannot enter the operational import boundary"
        );
        for (label, value) in [
            ("import id", envelope.import_id.as_str()),
            ("generated at", envelope.generated_at.as_str()),
            ("source system", envelope.source.system.as_str()),
            ("source stream", envelope.source.stream.as_str()),
            ("source repository", envelope.source.repository.as_str()),
            ("source revision", envelope.source.revision.as_str()),
        ] {
            anyhow::ensure!(!value.trim().is_empty(), "{label} must not be empty");
        }
        anyhow::ensure!(
            envelope.bundle.metrics.is_empty()
                && envelope.bundle.candidates.is_empty()
                && envelope.bundle.basins.is_empty()
                && envelope.bundle.projections.is_empty(),
            "operational imports cannot contain scientific metrics, candidates, basins, or projections"
        );
        anyhow::ensure!(
            envelope
                .bundle
                .capabilities
                .iter()
                .all(|capability| capability.command.is_empty()),
            "imported capabilities must be descriptive and non-executable"
        );
        anyhow::ensure!(
            envelope
                .bundle
                .providers
                .iter()
                .all(|provider| provider.secret_ref.is_none()),
            "operational imports cannot contain secret references"
        );

        let content_sha256 = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&envelope.bundle)?)
        );
        let record_count = operational_record_count(&envelope.bundle);
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        let existing: Option<OperationalImportRecord> = transaction
            .query_row(
                r#"SELECT import_id,contract,source_system,source_stream,source_repository,
                source_revision,source_url,generated_at,content_sha256,imported_at,record_count
                FROM operational_imports WHERE import_id=?1"#,
                params![envelope.import_id],
                operational_import_from_row,
            )
            .optional()?;
        if let Some(record) = existing {
            anyhow::ensure!(
                record.content_sha256 == content_sha256,
                "operational import id was reused with different content"
            );
            let source = upsert_operational_source_tx(
                &transaction,
                envelope,
                &record,
                &Utc::now().to_rfc3339(),
                false,
            )?;
            transaction.commit()?;
            return Ok(OperationalImportResponse {
                imported: false,
                record,
                source,
            });
        }
        let latest_generated_at: Option<String> = transaction
            .query_row(
                r#"SELECT generated_at FROM operational_imports
                WHERE source_system=?1 AND source_stream=?2
                ORDER BY generated_at DESC LIMIT 1"#,
                params![envelope.source.system, envelope.source.stream],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(latest_generated_at) = latest_generated_at {
            let incoming = chrono::DateTime::parse_from_rfc3339(&envelope.generated_at)
                .context("operational import generated_at is not RFC3339")?;
            let latest = chrono::DateTime::parse_from_rfc3339(&latest_generated_at)
                .context("stored operational import generated_at is not RFC3339")?;
            anyhow::ensure!(
                incoming > latest,
                "operational import is stale or reuses a source-stream timestamp"
            );
        } else {
            chrono::DateTime::parse_from_rfc3339(&envelope.generated_at)
                .context("operational import generated_at is not RFC3339")?;
        }

        for capability in &envelope.bundle.capabilities {
            upsert_capability(&transaction, capability)?;
        }
        for campaign in &envelope.bundle.campaigns {
            transaction.execute(
                r#"INSERT INTO programs(id,name,language,language_version,source)
                VALUES (?1,?2,?3,?4,?5)
                ON CONFLICT(id) DO UPDATE SET name=excluded.name,language=excluded.language,
                language_version=excluded.language_version,source=excluded.source"#,
                params![
                    campaign.program.id,
                    campaign.program.name,
                    campaign.program.language,
                    campaign.program.language_version,
                    campaign.program.source
                ],
            )?;
            transaction.execute(
                r#"INSERT INTO campaigns(id,name,domain,objective,status,created_at,program_id)
                VALUES (?1,?2,?3,?4,?5,?6,?7)
                ON CONFLICT(id) DO UPDATE SET name=excluded.name,domain=excluded.domain,
                objective=excluded.objective,status=excluded.status,program_id=excluded.program_id"#,
                params![campaign.id, campaign.name, campaign.domain, campaign.objective,
                    campaign.status, campaign.created_at, campaign.program.id],
            )?;
            for capability_id in &campaign.capability_ids {
                transaction.execute(
                    "INSERT OR IGNORE INTO campaign_capabilities(campaign_id,capability_id) VALUES (?1,?2)",
                    params![campaign.id, capability_id],
                )?;
            }
        }
        for run in &envelope.bundle.runs {
            upsert_run(&transaction, run)?;
        }
        for event in &envelope.bundle.events {
            insert_event_tx(&transaction, event)?;
        }
        for artifact in &envelope.bundle.artifacts {
            insert_artifact_tx(&transaction, artifact)?;
        }
        for budget in &envelope.bundle.budgets {
            transaction.execute(
                r#"INSERT INTO budgets
                (id,name,source,currency,total,spent,exposure,remaining_floor,updated_at)
                VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
                ON CONFLICT(id) DO UPDATE SET name=excluded.name,source=excluded.source,
                currency=excluded.currency,total=excluded.total,spent=excluded.spent,
                exposure=excluded.exposure,remaining_floor=excluded.remaining_floor,
                updated_at=excluded.updated_at"#,
                params![
                    budget.id,
                    budget.name,
                    budget.source,
                    budget.currency,
                    budget.total,
                    budget.spent,
                    budget.exposure,
                    budget.remaining_floor,
                    budget.updated_at
                ],
            )?;
        }
        for object in &envelope.bundle.objects {
            upsert_semantic_object_tx(&transaction, object)?;
        }
        for relation in &envelope.bundle.relations {
            upsert_semantic_relation_tx(&transaction, relation)?;
        }
        for action in &envelope.bundle.actions {
            upsert_action_tx(&transaction, action)?;
        }
        for job in &envelope.bundle.external_jobs {
            upsert_external_job_tx(&transaction, job)?;
        }
        for provider in &envelope.bundle.providers {
            upsert_provider_tx(&transaction, provider)?;
        }

        let imported_at = Utc::now().to_rfc3339();
        transaction.execute(
            r#"INSERT INTO operational_imports
            (import_id,contract,source_system,source_stream,source_repository,source_revision,
             source_url,generated_at,content_sha256,imported_at,record_count)
            VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)"#,
            params![
                envelope.import_id,
                envelope.contract,
                envelope.source.system,
                envelope.source.stream,
                envelope.source.repository,
                envelope.source.revision,
                envelope.source.url,
                envelope.generated_at,
                content_sha256,
                imported_at,
                record_count as i64
            ],
        )?;
        let record = OperationalImportRecord {
            import_id: envelope.import_id.clone(),
            contract: envelope.contract.clone(),
            source_system: envelope.source.system.clone(),
            source_stream: envelope.source.stream.clone(),
            source_repository: envelope.source.repository.clone(),
            source_revision: envelope.source.revision.clone(),
            source_url: envelope.source.url.clone(),
            generated_at: envelope.generated_at.clone(),
            content_sha256,
            imported_at,
            record_count,
        };
        let source = upsert_operational_source_tx(
            &transaction,
            envelope,
            &record,
            &record.imported_at,
            true,
        )?;
        transaction.commit()?;
        Ok(OperationalImportResponse {
            imported: true,
            record,
            source,
        })
    }

    pub fn refresh_candidate_projections(&self, candidates: &[CandidatePoint]) -> Result<()> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        for candidate in candidates {
            transaction.execute(
                "UPDATE candidates SET x=?3,y=?4,z=?5 WHERE campaign_id=?1 AND id=?2",
                params![
                    candidate.campaign_id,
                    candidate.id,
                    candidate.x,
                    candidate.y,
                    candidate.z
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn refresh_seed_reference_data(&self, seed: &SeedBundle) -> Result<()> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        for run in &seed.runs {
            let status = canonical_execution_status(&run.status);
            transaction.execute(
                r#"UPDATE runs SET
                status=?2,phase=?3,progress=?4,started_at=?5,finished_at=?6,external_url=?7,
                budget_ceiling_usd=?8,cost_usd=?9,parameters_json=?10,resources_json=?11
                WHERE id=?1 AND status IN ('external','running')
                AND json_extract(resources_json,'$.locality')='external'"#,
                params![
                    run.id,
                    status,
                    run.phase,
                    run.progress,
                    run.started_at,
                    run.finished_at,
                    run.external_url,
                    run.budget_ceiling_usd,
                    run.cost_usd,
                    serde_json::to_string(&run.parameters)?,
                    serde_json::to_string(&run.resources)?,
                ],
            )?;
        }
        for metric in &seed.metrics {
            insert_metric_tx(&transaction, metric)?;
        }
        for event in &seed.events {
            insert_event_tx(&transaction, event)?;
        }
        for artifact in &seed.artifacts {
            insert_artifact_tx(&transaction, artifact)?;
        }
        for budget in &seed.budgets {
            transaction.execute(
                r#"INSERT INTO budgets
                (id,name,source,currency,total,spent,exposure,remaining_floor,updated_at)
                VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
                ON CONFLICT(id) DO UPDATE SET
                name=excluded.name,source=excluded.source,currency=excluded.currency,
                total=excluded.total,spent=excluded.spent,exposure=excluded.exposure,
                remaining_floor=excluded.remaining_floor,updated_at=excluded.updated_at
                WHERE budgets.updated_at < excluded.updated_at
                AND NOT EXISTS (
                    SELECT 1 FROM runs
                    WHERE status IN ('queued','running') AND COALESCE(budget_ceiling_usd,0) > 0
                )"#,
                params![
                    budget.id,
                    budget.name,
                    budget.source,
                    budget.currency,
                    budget.total,
                    budget.spent,
                    budget.exposure,
                    budget.remaining_floor,
                    budget.updated_at,
                ],
            )?;
        }
        for provider in &seed.providers {
            upsert_provider_tx(&transaction, provider)?;
        }
        for projection in &seed.projections {
            upsert_projection_tx(&transaction, projection)?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn upsert_capability(&self, capability: &Capability) -> Result<()> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        upsert_capability(&transaction, capability)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn create_campaign(&self, request: &CreateCampaignRequest) -> Result<Campaign> {
        let name = request.name.trim();
        let domain = request.domain.trim();
        let objective = request.objective.trim();
        anyhow::ensure!(!name.is_empty(), "campaign name is required");
        anyhow::ensure!(!domain.is_empty(), "campaign domain is required");
        anyhow::ensure!(!objective.is_empty(), "campaign objective is required");

        let now = Utc::now().to_rfc3339();
        let campaign_id = format!("campaign_{}", Uuid::new_v4().simple());
        let program_id = format!("program_{}", Uuid::new_v4().simple());
        let mut capability_ids = request.capability_ids.clone();
        capability_ids.sort();
        capability_ids.dedup();
        let program = DesignProgram {
            id: program_id,
            name: format!("{name} program"),
            language: EPACT_LANGUAGE.to_owned(),
            language_version: EPACT_LANGUAGE_VERSION.to_owned(),
            source: request.program_source.clone().unwrap_or_else(|| {
                format!(
                    "contract {EPACT_PROGRAM_CONTRACT}\ncampaign {}:\n  objective {}",
                    campaign_id, objective
                )
            }),
        };
        let campaign = Campaign {
            id: campaign_id,
            name: name.to_owned(),
            domain: domain.to_owned(),
            objective: objective.to_owned(),
            status: "active".to_owned(),
            created_at: now.clone(),
            program,
            capability_ids,
        };

        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        transaction.execute(
            "INSERT INTO programs(id,name,language,language_version,source) VALUES (?1,?2,?3,?4,?5)",
            params![campaign.program.id, campaign.program.name, campaign.program.language, campaign.program.language_version, campaign.program.source],
        )?;
        transaction.execute(
            "INSERT INTO campaigns(id,name,domain,objective,status,created_at,program_id) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![campaign.id, campaign.name, campaign.domain, campaign.objective, campaign.status, campaign.created_at, campaign.program.id],
        )?;
        for capability_id in &campaign.capability_ids {
            let exists: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM capabilities WHERE id=?1)",
                params![capability_id],
                |row| row.get(0),
            )?;
            anyhow::ensure!(exists, "unknown capability {capability_id}");
            transaction.execute(
                "INSERT INTO campaign_capabilities(campaign_id,capability_id) VALUES (?1,?2)",
                params![campaign.id, capability_id],
            )?;
        }
        insert_event_tx(
            &transaction,
            &LedgerEvent {
                id: format!("evt_{}", Uuid::new_v4().simple()),
                campaign_id: Some(campaign.id.clone()),
                run_id: None,
                object_type: "campaign".to_owned(),
                object_id: campaign.id.clone(),
                verb: "created".to_owned(),
                timestamp: now,
                payload: json!({"domain": campaign.domain, "capabilityIds": campaign.capability_ids}),
            },
        )?;
        transaction.commit()?;
        Ok(campaign)
    }

    pub fn set_campaign_capability(
        &self,
        campaign_id: &str,
        update: &CampaignCapabilityUpdate,
    ) -> Result<()> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        let campaign_exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM campaigns WHERE id=?1)",
            params![campaign_id],
            |row| row.get(0),
        )?;
        anyhow::ensure!(campaign_exists, "unknown campaign {campaign_id}");
        let capability_exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM capabilities WHERE id=?1)",
            params![update.capability_id],
            |row| row.get(0),
        )?;
        anyhow::ensure!(
            capability_exists,
            "unknown capability {}",
            update.capability_id
        );
        if update.enabled {
            transaction.execute(
                "INSERT OR IGNORE INTO campaign_capabilities(campaign_id,capability_id) VALUES (?1,?2)",
                params![campaign_id, update.capability_id],
            )?;
        } else {
            transaction.execute(
                "DELETE FROM campaign_capabilities WHERE campaign_id=?1 AND capability_id=?2",
                params![campaign_id, update.capability_id],
            )?;
        }
        insert_event_tx(
            &transaction,
            &LedgerEvent {
                id: format!("evt_{}", Uuid::new_v4().simple()),
                campaign_id: Some(campaign_id.to_owned()),
                run_id: None,
                object_type: "capability_binding".to_owned(),
                object_id: update.capability_id.clone(),
                verb: if update.enabled { "bound" } else { "unbound" }.to_owned(),
                timestamp: Utc::now().to_rfc3339(),
                payload: json!({}),
            },
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn replay_campaign(&self, campaign_id: &str, name: Option<&str>) -> Result<Campaign> {
        let source = self
            .campaign(campaign_id)?
            .with_context(|| format!("unknown campaign {campaign_id}"))?;
        let replay = self.create_campaign(&CreateCampaignRequest {
            name: name
                .map(str::to_owned)
                .unwrap_or_else(|| format!("{} replay", source.name)),
            domain: source.domain.clone(),
            objective: source.objective.clone(),
            program_source: Some(source.program.source.clone()),
            capability_ids: source.capability_ids.clone(),
        })?;
        self.record_event(
            Some(replay.id.clone()),
            None,
            "campaign",
            &replay.id,
            "replayed",
            json!({"sourceCampaignId": campaign_id}),
        )?;
        Ok(replay)
    }

    pub fn campaign(&self, campaign_id: &str) -> Result<Option<Campaign>> {
        Ok(read_campaigns(&self.connect()?)?
            .into_iter()
            .find(|campaign| campaign.id == campaign_id))
    }

    pub fn campaign_ids(&self) -> Result<Vec<String>> {
        let connection = self.connect()?;
        read_all(&connection, "SELECT id FROM campaigns ORDER BY id", |row| {
            row.get(0)
        })
    }

    pub fn capability(&self, id: &str) -> Result<Option<Capability>> {
        let connection = self.connect()?;
        connection
            .query_row(
                "SELECT id,name,kind,version,provider,description,trust_status,lifecycle_json,command_json,resources_json FROM capabilities WHERE id=?1",
                params![id],
                capability_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn create_run(&self, request: &LaunchRequest, capability: &Capability) -> Result<Run> {
        self.create_run_with_id(
            request,
            capability,
            &format!("run_{}", Uuid::new_v4().simple()),
        )
    }

    pub fn create_run_with_id(
        &self,
        request: &LaunchRequest,
        capability: &Capability,
        run_id: &str,
    ) -> Result<Run> {
        anyhow::ensure!(
            run_id.starts_with("run_")
                && run_id.len() <= 96
                && run_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'),
            "invalid preallocated run id"
        );
        let now = Utc::now().to_rfc3339();
        let run = Run {
            id: run_id.to_owned(),
            campaign_id: request.campaign_id.clone(),
            capability_id: request.capability_id.clone(),
            name: request.name.clone(),
            status: "queued".to_owned(),
            phase: "prepare".to_owned(),
            progress: 0.0,
            started_at: Some(now.clone()),
            finished_at: None,
            external_url: None,
            pid: None,
            budget_ceiling_usd: request.budget_ceiling_usd,
            cost_usd: None,
            parameters: request.parameters.clone(),
            resources: capability.resources.clone(),
        };
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        let mut reservation = None;
        if let Some(ceiling) = request.budget_ceiling_usd.filter(|value| *value > 0.0) {
            anyhow::ensure!(ceiling.is_finite(), "run budget ceiling must be finite");
            let budget: Option<(String, f64, f64)> = transaction
                .query_row(
                    "SELECT id,remaining_floor,spent FROM budgets ORDER BY remaining_floor DESC LIMIT 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let (budget_id, remaining_floor, baseline_spent_usd) =
                budget.context("paid execution requires a configured Concord budget account")?;
            anyhow::ensure!(
                ceiling <= remaining_floor,
                "run budget ceiling ${ceiling:.2} exceeds remaining floor ${remaining_floor:.2}"
            );
            transaction.execute(
                "UPDATE budgets SET exposure=exposure+?2,remaining_floor=remaining_floor-?2,updated_at=?3 WHERE id=?1",
                params![budget_id, ceiling, now],
            )?;
            reservation = Some((budget_id, ceiling, baseline_spent_usd));
        }
        upsert_run(&transaction, &run)?;
        if let Some((budget_id, ceiling, baseline_spent_usd)) = reservation {
            transaction.execute(
                r#"INSERT INTO budget_reservations
                (run_id,budget_id,reserved_usd,baseline_spent_usd,settled_usd,status,created_at,updated_at)
                VALUES (?1,?2,?3,?4,NULL,'reserved',?5,?5)"#,
                params![run.id, budget_id, ceiling, baseline_spent_usd, now],
            )?;
        }
        insert_event_tx(
            &transaction,
            &LedgerEvent {
                id: format!("evt_{}", Uuid::new_v4().simple()),
                campaign_id: Some(run.campaign_id.clone()),
                run_id: Some(run.id.clone()),
                object_type: "run".to_owned(),
                object_id: run.id.clone(),
                verb: "queued".to_owned(),
                timestamp: now,
                payload: json!({
                    "capabilityId": run.capability_id,
                    "name": run.name,
                    "budgetCeilingUsd": run.budget_ceiling_usd,
                    "budgetReserved": run.budget_ceiling_usd.unwrap_or(0.0) > 0.0,
                }),
            },
        )?;
        transaction.commit()?;
        Ok(run)
    }

    pub fn preferred_dispatch_budget(&self, maximum_cost_usd: f64) -> Result<Option<String>> {
        anyhow::ensure!(
            maximum_cost_usd.is_finite() && maximum_cost_usd >= 0.0,
            "dispatch maximum cost must be finite and non-negative"
        );
        if maximum_cost_usd == 0.0 {
            return Ok(None);
        }
        self.connect()?
            .query_row(
                "SELECT id FROM budgets WHERE remaining_floor >= ?1 ORDER BY remaining_floor DESC,id LIMIT 1",
                params![maximum_cost_usd],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn set_run_pid(&self, run_id: &str, pid: u32) -> Result<()> {
        let connection = self.connect()?;
        connection.execute(
            "UPDATE runs SET pid=?2,status='running' WHERE id=?1",
            params![run_id, pid],
        )?;
        Ok(())
    }

    pub fn initialize_run_supervision(
        &self,
        run_id: &str,
        event_path: &Path,
        stderr_path: &Path,
    ) -> Result<RunSupervision> {
        let now = Utc::now().to_rfc3339();
        let connection = self.connect()?;
        connection.execute(
            r#"INSERT INTO run_supervision
            (run_id,event_path,stderr_path,event_offset,stderr_offset,updated_at)
            VALUES (?1,?2,?3,0,0,?4)
            ON CONFLICT(run_id) DO UPDATE SET
                event_path=excluded.event_path,stderr_path=excluded.stderr_path,updated_at=excluded.updated_at"#,
            params![run_id, event_path.display().to_string(), stderr_path.display().to_string(), now],
        )?;
        self.run_supervision(run_id)?
            .context("run supervision was not persisted")
    }

    pub fn run_supervision(&self, run_id: &str) -> Result<Option<RunSupervision>> {
        let connection = self.connect()?;
        connection
            .query_row(
                "SELECT run_id,event_path,stderr_path,event_offset,stderr_offset FROM run_supervision WHERE run_id=?1",
                params![run_id],
                |row| {
                    Ok(RunSupervision {
                        run_id: row.get(0)?,
                        event_path: row.get(1)?,
                        stderr_path: row.get(2)?,
                        event_offset: row.get::<_, i64>(3)?.max(0) as u64,
                        stderr_offset: row.get::<_, i64>(4)?.max(0) as u64,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn update_supervision_offset(&self, run_id: &str, stream: &str, offset: u64) -> Result<()> {
        let column = match stream {
            "events" => "event_offset",
            "stderr" => "stderr_offset",
            _ => anyhow::bail!("unknown supervision stream {stream}"),
        };
        let connection = self.connect()?;
        connection.execute(
            &format!("UPDATE run_supervision SET {column}=?2,updated_at=?3 WHERE run_id=?1"),
            params![run_id, i64::try_from(offset)?, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn terminal_announcement(&self, run_id: &str) -> Result<Option<String>> {
        let connection = self.connect()?;
        connection
            .query_row(
                r#"SELECT verb FROM events
                WHERE run_id=?1 AND object_type='worker_status'
                    AND verb IN ('completed_announced','failed_announced','cancelled_announced')
                ORDER BY timestamp DESC LIMIT 1"#,
                params![run_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map(|value| value.map(|verb| verb.trim_end_matches("_announced").to_owned()))
            .map_err(Into::into)
    }

    pub fn update_run_status(
        &self,
        run_id: &str,
        status: &str,
        phase: &str,
        progress: f64,
        message: Option<&str>,
    ) -> Result<LedgerEvent> {
        let status = canonical_execution_status(status);
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        let finished = matches!(status.as_str(), "completed" | "failed" | "cancelled");
        let (current_status, campaign_id): (String, String) = transaction.query_row(
            "SELECT status,campaign_id FROM runs WHERE id=?1",
            params![run_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let current_finished = matches!(
            current_status.as_str(),
            "completed" | "failed" | "cancelled"
        );
        if current_finished && !finished {
            let event = LedgerEvent {
                id: format!("evt_{}", Uuid::new_v4().simple()),
                campaign_id: Some(campaign_id),
                run_id: Some(run_id.to_owned()),
                object_type: "run_transition".to_owned(),
                object_id: run_id.to_owned(),
                verb: "ignored_after_terminal".to_owned(),
                timestamp: Utc::now().to_rfc3339(),
                payload: json!({
                    "currentStatus": current_status,
                    "requestedStatus": status,
                    "phase": phase,
                    "progress": progress,
                    "message": message,
                }),
            };
            insert_event_tx(&transaction, &event)?;
            transaction.commit()?;
            return Ok(event);
        }
        let finished_at = finished.then(|| Utc::now().to_rfc3339());
        transaction.execute(
            "UPDATE runs SET status=?2,phase=?3,progress=?4,finished_at=COALESCE(?5,finished_at) WHERE id=?1",
            params![run_id, status, phase, progress.clamp(0.0, 1.0), finished_at],
        )?;
        if finished {
            settle_run_budget_tx(&transaction, run_id)?;
        }
        let event = LedgerEvent {
            id: format!("evt_{}", Uuid::new_v4().simple()),
            campaign_id: Some(campaign_id),
            run_id: Some(run_id.to_owned()),
            object_type: "run".to_owned(),
            object_id: run_id.to_owned(),
            verb: status,
            timestamp: Utc::now().to_rfc3339(),
            payload: json!({"phase": phase, "progress": progress, "message": message}),
        };
        insert_event_tx(&transaction, &event)?;
        transaction.commit()?;
        Ok(event)
    }

    pub fn insert_metric(&self, metric: &MetricPoint) -> Result<()> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        insert_metric_tx(&transaction, metric)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn insert_metric_bounded(&self, metric: &MetricPoint, retention_points: i64) -> Result<()> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        insert_metric_tx(&transaction, metric)?;
        if retention_points > 0 {
            transaction.execute(
                r#"DELETE FROM metrics
                WHERE run_id=?1 AND name=?2 AND step <= (
                    SELECT COALESCE(MAX(step),0)-?3 FROM metrics WHERE run_id=?1 AND name=?2
                )"#,
                params![metric.run_id, metric.name, retention_points],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn next_metric_step(&self, run_id: &str, name: &str) -> Result<i64> {
        let connection = self.connect()?;
        connection
            .query_row(
                "SELECT COALESCE(MAX(step)+1,0) FROM metrics WHERE run_id=?1 AND name=?2",
                params![run_id, name],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }

    pub fn metrics_for_run(
        &self,
        run_id: &str,
        after_step: Option<i64>,
        limit: i64,
    ) -> Result<Vec<MetricPoint>> {
        let connection = self.connect()?;
        let mut statement = connection.prepare(
            r#"SELECT run_id,name,step,value,timestamp FROM metrics
            WHERE run_id=?1 AND (?2 IS NULL OR step>?2)
            ORDER BY step,name LIMIT ?3"#,
        )?;
        let rows =
            statement.query_map(params![run_id, after_step, limit.clamp(1, 20_000)], |row| {
                Ok(MetricPoint {
                    run_id: row.get(0)?,
                    name: row.get(1)?,
                    step: row.get(2)?,
                    value: row.get(3)?,
                    timestamp: row.get(4)?,
                })
            })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn run(&self, run_id: &str) -> Result<Option<Run>> {
        let connection = self.connect()?;
        connection
            .query_row(
                "SELECT id,campaign_id,capability_id,name,status,phase,progress,started_at,finished_at,external_url,pid,budget_ceiling_usd,cost_usd,parameters_json,resources_json FROM runs WHERE id=?1",
                params![run_id],
                run_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn update_run_cost(&self, run_id: &str, cost_usd: f64, source: &str) -> Result<()> {
        anyhow::ensure!(
            cost_usd.is_finite() && cost_usd >= 0.0,
            "run cost must be finite and non-negative"
        );
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        transaction.execute(
            "UPDATE runs SET cost_usd=?2 WHERE id=?1",
            params![run_id, cost_usd],
        )?;
        settle_run_budget_tx(&transaction, run_id)?;
        let campaign_id: String = transaction.query_row(
            "SELECT campaign_id FROM runs WHERE id=?1",
            params![run_id],
            |row| row.get(0),
        )?;
        insert_event_tx(
            &transaction,
            &LedgerEvent {
                id: format!("evt_{}", Uuid::new_v4().simple()),
                campaign_id: Some(campaign_id),
                run_id: Some(run_id.to_owned()),
                object_type: "cost_observation".to_owned(),
                object_id: run_id.to_owned(),
                verb: "recorded".to_owned(),
                timestamp: Utc::now().to_rfc3339(),
                payload: json!({"costUsd": cost_usd, "source": source}),
            },
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn upsert_semantic_object(&self, object: &SemanticObject) -> Result<()> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        upsert_semantic_object_tx(&transaction, object)?;
        transaction.commit()?;
        Ok(())
    }

    /// Persist the exact model-facing context projection before provider execution.
    ///
    /// An optional request object is committed in the same transaction so an interrupted provider
    /// call cannot leave Concord with a receipt that points at an unrecorded user request.
    pub fn record_context_compilation(
        &self,
        receipt: &ContextCompilationReceipt,
        request_object: Option<&SemanticObject>,
    ) -> Result<SemanticObject> {
        receipt.validate()?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let campaign_exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM campaigns WHERE id=?1)",
            params![receipt.campaign_id],
            |row| row.get(0),
        )?;
        anyhow::ensure!(campaign_exists, "unknown campaign {}", receipt.campaign_id);
        if let Some(object) = request_object {
            anyhow::ensure!(
                object.campaign_id.as_deref() == Some(receipt.campaign_id.as_str()),
                "context request object belongs to another campaign"
            );
            insert_immutable_semantic_object_tx(&transaction, object)?;
        }
        let object = SemanticObject {
            id: receipt.id.clone(),
            campaign_id: Some(receipt.campaign_id.clone()),
            run_id: None,
            kind: "projection".to_owned(),
            type_name: CONTEXT_COMPILATION_RECEIPT_CONTRACT.to_owned(),
            state: "compiled".to_owned(),
            label: Some(format!("Context for {}", receipt.request_id)),
            payload: serde_json::to_value(receipt)?,
            created_at: receipt.created_at.clone(),
            updated_at: receipt.created_at.clone(),
        };
        insert_immutable_semantic_object_tx(&transaction, &object)?;
        if let Some(request) = request_object {
            upsert_semantic_relation_tx(
                &transaction,
                &SemanticRelation {
                    id: format!("relation:{}:compiled-for:{}", object.id, request.id),
                    campaign_id: Some(receipt.campaign_id.clone()),
                    run_id: None,
                    subject_id: object.id.clone(),
                    predicate: "compiled_for".to_owned(),
                    object_id: request.id.clone(),
                    payload: json!({"requestId": receipt.request_id}),
                    timestamp: receipt.created_at.clone(),
                },
            )?;
        }
        insert_event_tx(
            &transaction,
            &LedgerEvent {
                id: format!("evt_{}", Uuid::new_v4().simple()),
                campaign_id: Some(receipt.campaign_id.clone()),
                run_id: None,
                object_type: "context_compilation_receipt".to_owned(),
                object_id: object.id.clone(),
                verb: "compiled".to_owned(),
                timestamp: receipt.created_at.clone(),
                payload: json!({
                    "requestId": receipt.request_id,
                    "receiptSha256": receipt.receipt_sha256,
                    "included": receipt.included_context_refs.len(),
                    "omitted": receipt.omissions.len(),
                    "truncated": receipt.truncations.len(),
                }),
            },
        )?;
        transaction.commit()?;
        Ok(object)
    }

    pub fn context_compilation_receipts(
        &self,
        campaign_id: &str,
    ) -> Result<Vec<ContextCompilationReceipt>> {
        let connection = self.connect()?;
        let objects = read_all_for_campaign(
            &connection,
            "SELECT id,campaign_id,run_id,kind,type_name,state,label,payload_json,created_at,updated_at FROM semantic_objects WHERE campaign_id=?1 AND type_name='concord.context-compilation-receipt/1' ORDER BY created_at,id",
            campaign_id,
            semantic_object_from_row,
        )?;
        objects
            .into_iter()
            .map(|object| {
                let receipt: ContextCompilationReceipt = serde_json::from_value(object.payload)?;
                receipt.validate()?;
                Ok(receipt)
            })
            .collect()
    }

    pub fn standing_review_workspace(&self, campaign_id: &str) -> Result<StandingReviewWorkspace> {
        let connection = self.connect()?;
        let history: Vec<StandingReviewReceipt> = science_records(
            &connection,
            "SELECT record_json FROM standing_review_receipts WHERE campaign_id=?1 ORDER BY created_at,id",
            campaign_id,
        )?;
        for receipt in &history {
            receipt.validate()?;
        }
        Ok(StandingReviewWorkspace {
            latest: history.last().cloned(),
            history,
        })
    }

    /// Run the model-independent record-consistency reviewer over the current campaign surface.
    ///
    /// Unchanged inputs reuse the existing immutable receipt. New inputs append one hash-chained
    /// receipt; the reviewer never upgrades record consistency into scientific validation.
    pub fn run_standing_review(&self, campaign_id: &str) -> Result<StandingReviewReceipt> {
        let science = self.science_artifact_workspace(campaign_id)?;
        let plans = self.research_plans_for_campaign(campaign_id)?;
        let agent_runs = self.agent_run_envelopes(Some(campaign_id))?;
        let connection = self.connect()?;
        let assistant_messages = read_all_for_campaign(
            &connection,
            "SELECT id,campaign_id,run_id,kind,type_name,state,label,payload_json,created_at,updated_at FROM semantic_objects WHERE campaign_id=?1 AND type_name='concord.research_message' AND json_extract(payload_json,'$.role')='assistant' ORDER BY created_at,id",
            campaign_id,
            semantic_object_from_row,
        )?;
        let plan_decisions = plans
            .iter()
            .flat_map(|envelope| envelope.decisions.iter())
            .collect::<Vec<_>>();
        let agent_messages = agent_runs
            .iter()
            .flat_map(|envelope| envelope.events.iter())
            .filter(|event| event.kind == AgentEventKind::ModelResponded)
            .collect::<Vec<_>>();
        let workspace = self.standing_review_workspace(campaign_id)?;
        let previous = workspace
            .latest
            .as_ref()
            .map(|receipt| receipt.review_sha256.clone());
        let input = StandingReviewInput {
            campaign_id,
            assistant_messages: assistant_messages.iter().collect(),
            agent_messages,
            plan_decisions,
            artifact_versions: &science.versions,
            annotations: &science.annotations,
            artifact_reviews: &science.reviews,
            artifact_dispositions: &science.dispositions,
            batches: &science.batches,
            ranked_tables: &science.ranked_tables,
            decision_memos: &science.decision_memos,
        };
        let mut receipt = compile_standing_review(&input, previous, Utc::now().to_rfc3339())?;
        if let Some(latest) = workspace.latest {
            if latest.input_sha256 == receipt.input_sha256 {
                return Ok(latest);
            }
        }
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<String> = transaction
            .query_row(
                "SELECT record_json FROM standing_review_receipts WHERE campaign_id=?1 AND input_sha256=?2",
                params![campaign_id, receipt.input_sha256],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            let existing: StandingReviewReceipt = serde_json::from_str(&existing)?;
            existing.validate()?;
            return Ok(existing);
        }
        let current_previous: Option<String> = transaction
            .query_row(
                "SELECT review_sha256 FROM standing_review_receipts WHERE campaign_id=?1 ORDER BY created_at DESC,id DESC LIMIT 1",
                params![campaign_id],
                |row| row.get(0),
            )
            .optional()?;
        if receipt.previous_review_sha256 != current_previous {
            receipt = compile_standing_review(&input, current_previous, Utc::now().to_rfc3339())?;
        }
        transaction.execute(
            "INSERT INTO standing_review_receipts(id,campaign_id,input_sha256,previous_review_sha256,review_sha256,record_json,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                receipt.id,
                receipt.campaign_id,
                receipt.input_sha256,
                receipt.previous_review_sha256,
                receipt.review_sha256,
                serde_json::to_string(&receipt)?,
                receipt.created_at,
            ],
        )?;
        insert_event_tx(
            &transaction,
            &LedgerEvent {
                id: format!("evt_{}", Uuid::new_v4().simple()),
                campaign_id: Some(campaign_id.to_owned()),
                run_id: None,
                object_type: "standing_review_receipt".to_owned(),
                object_id: receipt.id.clone(),
                verb: "reviewed".to_owned(),
                timestamp: receipt.created_at.clone(),
                payload: json!({
                    "reviewSha256": receipt.review_sha256,
                    "status": receipt.status,
                    "claims": receipt.claim_bindings.len(),
                    "findings": receipt.findings.len(),
                    "recordConsistencyOnly": true,
                }),
            },
        )?;
        transaction.commit()?;
        Ok(receipt)
    }

    pub fn compile_source_gate(
        &self,
        campaign_id: &str,
        mut input: SourceGateInput,
    ) -> Result<SourceGateCompilation> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let campaign_exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM campaigns WHERE id=?1)",
            params![campaign_id],
            |row| row.get(0),
        )?;
        anyhow::ensure!(campaign_exists, "unknown campaign {campaign_id}");
        anyhow::ensure!(
            input.campaign_id == campaign_id && input.program.campaign_id == campaign_id,
            "source gate input campaign differs from runtime campaign"
        );

        let evidence_ids = input
            .assertions
            .iter()
            .flat_map(|assertion| assertion.evidence_object_ids.iter())
            .collect::<std::collections::BTreeSet<_>>();
        let mut evidence_objects = Vec::new();
        for object_id in evidence_ids {
            let object = transaction
                .query_row(
                    "SELECT id,campaign_id,run_id,kind,type_name,state,label,payload_json,created_at,updated_at FROM semantic_objects WHERE id=?1",
                    params![object_id],
                    semantic_object_from_row,
                )
                .optional()?
                .with_context(|| format!("source gate evidence object {object_id} does not exist"))?;
            anyhow::ensure!(
                object.campaign_id.as_deref() == Some(campaign_id),
                "source gate evidence object {object_id} belongs to another campaign"
            );
            evidence_objects.push(object);
        }
        evidence_objects.sort_by(|left, right| left.id.cmp(&right.id));
        let snapshot_material = json!({
            "campaignId": campaign_id,
            "program": input.program,
            "assertions": input.assertions,
            "decisions": input.decisions,
            "authorities": input.authorities,
            "authorizedTrancheIds": input.authorized_tranche_ids,
            "evidenceObjects": evidence_objects,
        });
        input.campaign_snapshot_sha256 = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&snapshot_material)?)
        );

        let accepted_at = Utc::now().to_rfc3339();
        let program_object = SemanticObject {
            id: format!(
                "source-gate-program:{}:{}",
                input.program.id, input.program.version
            ),
            campaign_id: Some(campaign_id.to_owned()),
            run_id: None,
            kind: "program".to_owned(),
            type_name: SOURCE_GATE_PROGRAM_CONTRACT.to_owned(),
            state: "accepted".to_owned(),
            label: Some(format!("Source gate program {}", input.program.id)),
            payload: serde_json::to_value(&input.program)?,
            created_at: accepted_at.clone(),
            updated_at: accepted_at.clone(),
        };
        insert_immutable_semantic_object_tx(&transaction, &program_object)?;
        for assertion in &input.assertions {
            let object = SemanticObject {
                id: format!("source-gate-assertion:{}", assertion.id),
                campaign_id: Some(campaign_id.to_owned()),
                run_id: None,
                kind: "evidence".to_owned(),
                type_name: SOURCE_GATE_ASSERTION_CONTRACT.to_owned(),
                state: "accepted".to_owned(),
                label: Some(assertion.requirement_id.clone()),
                payload: serde_json::to_value(assertion)?,
                created_at: accepted_at.clone(),
                updated_at: accepted_at.clone(),
            };
            insert_immutable_semantic_object_tx(&transaction, &object)?;
            for evidence_id in &assertion.evidence_object_ids {
                upsert_semantic_relation_tx(
                    &transaction,
                    &SemanticRelation {
                        id: format!("relation:{}:supported-by:{}", object.id, evidence_id),
                        campaign_id: Some(campaign_id.to_owned()),
                        run_id: None,
                        subject_id: object.id.clone(),
                        predicate: "supported_by".to_owned(),
                        object_id: evidence_id.clone(),
                        payload: json!({}),
                        timestamp: accepted_at.clone(),
                    },
                )?;
            }
        }
        for decision in &input.decisions {
            insert_immutable_semantic_object_tx(
                &transaction,
                &SemanticObject {
                    id: format!("source-gate-decision:{}", decision.id),
                    campaign_id: Some(campaign_id.to_owned()),
                    run_id: None,
                    kind: "decision".to_owned(),
                    type_name: SOURCE_GATE_DECISION_CONTRACT.to_owned(),
                    state: "accepted".to_owned(),
                    label: Some(decision.requirement_id.clone()),
                    payload: serde_json::to_value(decision)?,
                    created_at: accepted_at.clone(),
                    updated_at: accepted_at.clone(),
                },
            )?;
        }
        for authority in &input.authorities {
            insert_immutable_semantic_object_tx(
                &transaction,
                &SemanticObject {
                    id: format!("source-gate-authority:{}", authority.id),
                    campaign_id: Some(campaign_id.to_owned()),
                    run_id: None,
                    kind: "authority".to_owned(),
                    type_name: SOURCE_GATE_AUTHORITY_CONTRACT.to_owned(),
                    state: if authority.active {
                        "active"
                    } else {
                        "inactive"
                    }
                    .to_owned(),
                    label: Some(authority.actor.clone()),
                    payload: serde_json::to_value(authority)?,
                    created_at: accepted_at.clone(),
                    updated_at: accepted_at.clone(),
                },
            )?;
        }

        let latest: Option<SourceGateCompilation> = transaction
            .query_row(
                "SELECT s.input_json,s.projection_json,b.binding_json,s.compiled_at FROM source_gate_compilations s LEFT JOIN source_gate_epact_bindings b ON b.projection_sha256=s.projection_sha256 WHERE s.campaign_id=?1 ORDER BY s.compiled_at DESC,s.projection_sha256 DESC LIMIT 1",
                params![campaign_id],
                |row| {
                    Ok(SourceGateCompilation {
                        input: serde_json::from_str(&row.get::<_, String>(0)?).map_err(|error| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error)))?,
                        projection: serde_json::from_str(&row.get::<_, String>(1)?).map_err(|error| rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(error)))?,
                        epact: row.get::<_, Option<String>>(2)?.map(|value| serde_json::from_str(&value)).transpose().map_err(|error| rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(error)))?,
                        compiled_at: row.get(3)?,
                    })
                },
            )
            .optional()?;
        if let Some(mut latest) = latest {
            let same_snapshot = latest.input.campaign_snapshot_sha256
                == input.campaign_snapshot_sha256
                && latest.input.program == input.program
                && latest.input.assertions == input.assertions
                && latest.input.decisions == input.decisions
                && latest.input.authorities == input.authorities
                && latest.input.authorized_tranche_ids == input.authorized_tranche_ids;
            if same_snapshot {
                let input_object = SemanticObject {
                    id: format!(
                        "source-gate-input:{}",
                        &latest.projection.input_sha256[..16]
                    ),
                    campaign_id: Some(campaign_id.to_owned()),
                    run_id: None,
                    kind: "evidence".to_owned(),
                    type_name: SOURCE_GATE_INPUT_CONTRACT.to_owned(),
                    state: "accepted".to_owned(),
                    label: Some("Accepted source gate compiler input".to_owned()),
                    // The accepted input hash includes the previous projection identity. A caller
                    // replay omits that store-owned field, so retain the exact accepted payload.
                    payload: serde_json::to_value(&latest.input)?,
                    created_at: accepted_at.clone(),
                    updated_at: accepted_at.clone(),
                };
                insert_immutable_semantic_object_tx(&transaction, &input_object)?;
                upsert_semantic_relation_tx(
                    &transaction,
                    &SemanticRelation {
                        id: format!(
                            "relation:source-gate-projection:{}:compiled-from",
                            &latest.projection.projection_sha256[..16]
                        ),
                        campaign_id: Some(campaign_id.to_owned()),
                        run_id: None,
                        subject_id: format!(
                            "source-gate-projection:{}",
                            &latest.projection.projection_sha256[..16]
                        ),
                        predicate: "compiled_from".to_owned(),
                        object_id: input_object.id,
                        payload: json!({"inputSha256": latest.projection.input_sha256}),
                        timestamp: accepted_at.clone(),
                    },
                )?;
                if latest.epact.is_none() {
                    let lowered =
                        crate::source_gate::compile_source_gate_epact(latest.input.clone())?;
                    anyhow::ensure!(
                        lowered.projection == latest.projection,
                        "stored source-gate projection differs from Epact lowering replay"
                    );
                    persist_source_gate_epact_tx(
                        &transaction,
                        campaign_id,
                        &latest.compiled_at,
                        &latest.input,
                        &lowered,
                    )?;
                    latest.epact = Some(lowered.binding);
                }
                transaction.commit()?;
                return Ok(latest);
            }
            input.previous_projection = Some(Box::new(latest.projection.clone()));
        }
        let lowered = crate::source_gate::compile_source_gate_epact(input.clone())?;
        let projection = lowered.projection.clone();
        let compiled_at = Utc::now().to_rfc3339();
        transaction.execute(
            "INSERT INTO source_gate_compilations(projection_sha256,campaign_id,input_sha256,snapshot_sha256,input_json,projection_json,compiled_at) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![projection.projection_sha256, campaign_id, projection.input_sha256, projection.campaign_snapshot_sha256, serde_json::to_string(&input)?, serde_json::to_string(&projection)?, compiled_at],
        )?;
        persist_source_gate_epact_tx(&transaction, campaign_id, &compiled_at, &input, &lowered)?;
        let projection_object = SemanticObject {
            id: format!(
                "source-gate-projection:{}",
                &projection.projection_sha256[..16]
            ),
            campaign_id: Some(campaign_id.to_owned()),
            run_id: None,
            kind: "projection".to_owned(),
            type_name: SOURCE_GATE_PROJECTION_CONTRACT.to_owned(),
            state: "current".to_owned(),
            label: Some("Current source gate projection".to_owned()),
            payload: serde_json::to_value(&projection)?,
            created_at: compiled_at.clone(),
            updated_at: compiled_at.clone(),
        };
        let input_object = SemanticObject {
            id: format!("source-gate-input:{}", &projection.input_sha256[..16]),
            campaign_id: Some(campaign_id.to_owned()),
            run_id: None,
            kind: "evidence".to_owned(),
            type_name: SOURCE_GATE_INPUT_CONTRACT.to_owned(),
            state: "accepted".to_owned(),
            label: Some("Accepted source gate compiler input".to_owned()),
            payload: serde_json::to_value(&input)?,
            created_at: compiled_at.clone(),
            updated_at: compiled_at.clone(),
        };
        insert_immutable_semantic_object_tx(&transaction, &input_object)?;
        upsert_semantic_object_tx(&transaction, &projection_object)?;
        upsert_semantic_relation_tx(
            &transaction,
            &SemanticRelation {
                id: format!("relation:{}:compiled-from", projection_object.id),
                campaign_id: Some(campaign_id.to_owned()),
                run_id: None,
                subject_id: projection_object.id.clone(),
                predicate: "compiled_from".to_owned(),
                object_id: input_object.id,
                payload: json!({"inputSha256": projection.input_sha256}),
                timestamp: compiled_at.clone(),
            },
        )?;
        insert_event_tx(
            &transaction,
            &LedgerEvent {
                id: format!("evt_{}", Uuid::new_v4().simple()),
                campaign_id: Some(campaign_id.to_owned()),
                run_id: None,
                object_type: "source_gate_projection".to_owned(),
                object_id: projection_object.id,
                verb: "compiled".to_owned(),
                timestamp: compiled_at.clone(),
                payload: json!({"projectionSha256": projection.projection_sha256, "inputSha256": projection.input_sha256}),
            },
        )?;
        transaction.commit()?;
        Ok(SourceGateCompilation {
            input,
            projection,
            epact: Some(lowered.binding),
            compiled_at,
        })
    }

    pub fn latest_source_gate_compilation(
        &self,
        campaign_id: &str,
    ) -> Result<Option<SourceGateCompilation>> {
        let connection = self.connect()?;
        connection
            .query_row(
                "SELECT s.input_json,s.projection_json,b.binding_json,s.compiled_at FROM source_gate_compilations s LEFT JOIN source_gate_epact_bindings b ON b.projection_sha256=s.projection_sha256 WHERE s.campaign_id=?1 ORDER BY s.compiled_at DESC,s.projection_sha256 DESC LIMIT 1",
                params![campaign_id],
                |row| {
                    Ok(SourceGateCompilation {
                        input: serde_json::from_str(&row.get::<_, String>(0)?).map_err(|error| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error)))?,
                        projection: serde_json::from_str(&row.get::<_, String>(1)?).map_err(|error| rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(error)))?,
                        epact: row.get::<_, Option<String>>(2)?.map(|value| serde_json::from_str(&value)).transpose().map_err(|error| rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(error)))?,
                        compiled_at: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn upsert_semantic_relation(&self, relation: &SemanticRelation) -> Result<()> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        upsert_semantic_relation_tx(&transaction, relation)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn upsert_action(&self, action: &ActionRecord) -> Result<()> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        upsert_action_tx(&transaction, action)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn upsert_external_job(&self, job: &ExternalJob) -> Result<()> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        upsert_external_job_tx(&transaction, job)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn upsert_provider(&self, provider: &ProviderProfile) -> Result<()> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        upsert_provider_tx(&transaction, provider)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn provider(&self, provider_id: &str) -> Result<Option<ProviderProfile>> {
        let connection = self.connect()?;
        let mut statement = connection.prepare(
            "SELECT id,name,kind,base_url,secret_ref,status,metadata_json,updated_at FROM provider_profiles WHERE id=?1",
        )?;
        let mut rows = statement.query(params![provider_id])?;
        rows.next()?
            .map(provider_from_row)
            .transpose()
            .map_err(Into::into)
    }

    pub fn register_capability_package(
        &self,
        package: &CapabilityPackage,
    ) -> Result<RegisteredCapabilityPackage> {
        package.validate()?;
        let record_id = capability_package_record_id(package)?;
        let now = Utc::now().to_rfc3339();
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        transaction.execute(
            r#"INSERT OR IGNORE INTO capability_package_records
            (record_id,package_id,package_version,content_sha256,trust_status,manifest_json,registered_at,updated_at)
            VALUES (?1,?2,?3,?4,?5,?6,?7,?8)"#,
            params![
                record_id,
                package.package_id,
                package.version,
                package.content_sha256,
                package_trust_name(&package.trust_status),
                serde_json::to_string(package)?,
                now,
                now,
            ],
        )?;
        insert_event_tx(
            &transaction,
            &LedgerEvent {
                id: format!("event:{record_id}:registered"),
                campaign_id: None,
                run_id: None,
                object_type: "capability_package".to_owned(),
                object_id: record_id.clone(),
                verb: "package_registered".to_owned(),
                timestamp: now,
                payload: json!({
                    "packageId": package.package_id,
                    "version": package.version,
                    "contentSha256": package.content_sha256,
                    "trustStatus": package.trust_status,
                }),
            },
        )?;
        transaction.commit()?;
        self.capability_package(&record_id)?
            .context("registered capability package disappeared")
    }

    pub fn capability_package(
        &self,
        record_id: &str,
    ) -> Result<Option<RegisteredCapabilityPackage>> {
        let connection = self.connect()?;
        connection
            .query_row(
                "SELECT record_id,manifest_json,registered_at,updated_at FROM capability_package_records WHERE record_id=?1",
                params![record_id],
                capability_package_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn capability_packages(&self) -> Result<Vec<RegisteredCapabilityPackage>> {
        let connection = self.connect()?;
        read_all(
            &connection,
            "SELECT record_id,manifest_json,registered_at,updated_at FROM capability_package_records ORDER BY updated_at DESC,record_id",
            capability_package_from_row,
        )
    }

    pub fn record_mcp_discovery(
        &self,
        package_record_id: &str,
        snapshot: &McpDiscoverySnapshot,
    ) -> Result<McpDiscoveryRecord> {
        snapshot.validate()?;
        let package = self
            .capability_package(package_record_id)?
            .with_context(|| format!("unknown capability package {package_record_id}"))?;
        anyhow::ensure!(
            package.package.kind == CapabilityPackageKind::McpServer,
            "capability package is not an MCP server"
        );
        anyhow::ensure!(
            package.package.trust_status != PackageTrustStatus::Revoked,
            "revoked MCP package cannot be discovered"
        );
        anyhow::ensure!(
            snapshot.package_id == package.package.package_id,
            "MCP discovery package identity mismatch"
        );
        let record_id = format!("mcpdisc_{}", &snapshot.discovery_sha256[..24]);
        let now = Utc::now().to_rfc3339();
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        transaction.execute(
            r#"INSERT OR IGNORE INTO mcp_discovery_records
            (record_id,package_record_id,package_content_sha256,discovery_sha256,snapshot_json,recorded_at)
            VALUES (?1,?2,?3,?4,?5,?6)"#,
            params![
                record_id,
                package_record_id,
                package.package.content_sha256,
                snapshot.discovery_sha256,
                serde_json::to_string(snapshot)?,
                now,
            ],
        )?;
        insert_event_tx(
            &transaction,
            &LedgerEvent {
                id: format!("event:{record_id}:recorded"),
                campaign_id: None,
                run_id: None,
                object_type: "mcp_discovery".to_owned(),
                object_id: record_id.clone(),
                verb: "mcp_tools_discovered".to_owned(),
                timestamp: now,
                payload: json!({
                    "packageRecordId": package_record_id,
                    "packageContentSha256": package.package.content_sha256,
                    "discoverySha256": snapshot.discovery_sha256,
                    "toolCount": snapshot.tools.len(),
                }),
            },
        )?;
        transaction.commit()?;
        self.mcp_discovery(&record_id)?
            .context("recorded MCP discovery disappeared")
    }

    pub fn mcp_discovery(&self, record_id: &str) -> Result<Option<McpDiscoveryRecord>> {
        let connection = self.connect()?;
        connection
            .query_row(
                "SELECT record_id,package_record_id,package_content_sha256,snapshot_json,recorded_at FROM mcp_discovery_records WHERE record_id=?1",
                params![record_id],
                mcp_discovery_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn mcp_discoveries_for_package(
        &self,
        package_record_id: &str,
    ) -> Result<Vec<McpDiscoveryRecord>> {
        let connection = self.connect()?;
        read_all_for_campaign(
            &connection,
            "SELECT record_id,package_record_id,package_content_sha256,snapshot_json,recorded_at FROM mcp_discovery_records WHERE package_record_id=?1 ORDER BY recorded_at DESC",
            package_record_id,
            mcp_discovery_from_row,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_capability_qualification(
        &self,
        package_record_id: &str,
        discovery_record_id: Option<&str>,
        disposition: QualificationDisposition,
        tool_policies: Vec<CapabilityToolPolicy>,
        inspector: &str,
        rationale: &str,
    ) -> Result<CapabilityQualification> {
        let package = self
            .capability_package(package_record_id)?
            .with_context(|| format!("unknown capability package {package_record_id}"))?;
        let previous = self.latest_capability_qualification(package_record_id)?;
        if disposition == QualificationDisposition::Revoked {
            anyhow::ensure!(
                previous
                    .as_ref()
                    .is_some_and(|value| value.disposition == QualificationDisposition::Qualified),
                "only a currently qualified package may be revoked"
            );
        }
        let discovery = discovery_record_id
            .map(|record_id| {
                self.mcp_discovery(record_id)?
                    .with_context(|| format!("unknown MCP discovery {record_id}"))
            })
            .transpose()?;
        if let Some(discovery) = &discovery {
            anyhow::ensure!(
                discovery.package_record_id == package_record_id,
                "qualification discovery belongs to a different package"
            );
            anyhow::ensure!(
                discovery.package_content_sha256 == package.package.content_sha256,
                "qualification discovery package digest mismatch"
            );
        }
        match disposition {
            QualificationDisposition::Qualified => {
                anyhow::ensure!(
                    package.package.kind == CapabilityPackageKind::McpServer,
                    "Agent Skill and native execution remain blocked until a process sandbox exists"
                );
                let discovery = discovery
                    .as_ref()
                    .context("MCP qualification requires a frozen discovery record")?;
                let expected = discovery
                    .snapshot
                    .tools
                    .iter()
                    .map(|tool| tool.name.as_str())
                    .collect::<std::collections::BTreeSet<_>>();
                let actual = tool_policies
                    .iter()
                    .map(|policy| policy.tool_name.as_str())
                    .collect::<std::collections::BTreeSet<_>>();
                anyhow::ensure!(
                    actual == expected && actual.len() == tool_policies.len(),
                    "qualification must define exactly one policy for every discovered MCP tool"
                );
                anyhow::ensure!(
                    tool_policies
                        .iter()
                        .all(|policy| !policy.reversibility.is_unspecified()),
                    "qualification must define reversibility for every discovered MCP tool"
                );
            }
            QualificationDisposition::Inspected => {
                anyhow::ensure!(
                    tool_policies.is_empty(),
                    "inspection records cannot grant tool policies"
                );
                if package.package.kind == CapabilityPackageKind::McpServer {
                    anyhow::ensure!(
                        discovery.is_some(),
                        "MCP inspection requires a frozen discovery record"
                    );
                }
            }
            QualificationDisposition::Rejected | QualificationDisposition::Revoked => {
                anyhow::ensure!(
                    tool_policies.is_empty(),
                    "rejection and revocation records cannot grant tool policies"
                );
            }
        }
        let now = Utc::now().to_rfc3339();
        let qualification = CapabilityQualification::build(
            package_record_id.to_owned(),
            package.package.content_sha256.clone(),
            discovery.as_ref().map(|value| value.record_id.clone()),
            discovery
                .as_ref()
                .map(|value| value.snapshot.discovery_sha256.clone()),
            disposition,
            tool_policies,
            inspector.to_owned(),
            rationale.to_owned(),
            previous.map(|value| value.qualification_sha256),
            now.clone(),
        )?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        let current_head: Option<String> = transaction
            .query_row(
                "SELECT qualification_sha256 FROM capability_qualification_records WHERE package_record_id=?1 ORDER BY rowid DESC LIMIT 1",
                params![package_record_id],
                |row| row.get(0),
            )
            .optional()?;
        anyhow::ensure!(
            current_head == qualification.previous_qualification_sha256,
            "capability qualification head changed; reload before recording another decision"
        );
        transaction.execute(
            r#"INSERT OR IGNORE INTO capability_qualification_records
            (record_id,package_record_id,package_content_sha256,discovery_record_id,disposition,qualification_sha256,qualification_json,recorded_at)
            VALUES (?1,?2,?3,?4,?5,?6,?7,?8)"#,
            params![
                qualification.record_id,
                qualification.package_record_id,
                qualification.package_content_sha256,
                qualification.discovery_record_id,
                qualification_disposition_name(qualification.disposition),
                qualification.qualification_sha256,
                serde_json::to_string(&qualification)?,
                qualification.recorded_at,
            ],
        )?;
        insert_event_tx(
            &transaction,
            &LedgerEvent {
                id: format!("event:{}:recorded", qualification.record_id),
                campaign_id: None,
                run_id: None,
                object_type: "capability_qualification".to_owned(),
                object_id: qualification.record_id.clone(),
                verb: format!(
                    "package_{}",
                    qualification_disposition_name(qualification.disposition)
                ),
                timestamp: now,
                payload: json!({
                    "packageRecordId": qualification.package_record_id,
                    "packageContentSha256": qualification.package_content_sha256,
                    "discoveryRecordId": qualification.discovery_record_id,
                    "discoverySha256": qualification.discovery_sha256,
                    "disposition": qualification.disposition,
                    "toolPolicyCount": qualification.tool_policies.len(),
                    "inspector": qualification.inspector,
                    "qualificationSha256": qualification.qualification_sha256,
                    "previousQualificationSha256": qualification.previous_qualification_sha256,
                }),
            },
        )?;
        transaction.commit()?;
        self.capability_qualification(&qualification.record_id)?
            .context("recorded capability qualification disappeared")
    }

    pub fn capability_qualification(
        &self,
        record_id: &str,
    ) -> Result<Option<CapabilityQualification>> {
        let connection = self.connect()?;
        connection
            .query_row(
                "SELECT qualification_json FROM capability_qualification_records WHERE record_id=?1",
                params![record_id],
                capability_qualification_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn capability_qualifications_for_package(
        &self,
        package_record_id: &str,
    ) -> Result<Vec<CapabilityQualification>> {
        let connection = self.connect()?;
        let mut statement = connection.prepare(
            "SELECT qualification_json FROM capability_qualification_records WHERE package_record_id=?1 ORDER BY rowid DESC",
        )?;
        let records = statement
            .query_map(
                params![package_record_id],
                capability_qualification_from_row,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (index, record) in records.iter().enumerate() {
            anyhow::ensure!(
                record.package_record_id == package_record_id,
                "capability qualification package identity mismatch"
            );
            let expected_previous = records
                .get(index + 1)
                .map(|previous| previous.qualification_sha256.clone());
            anyhow::ensure!(
                record.previous_qualification_sha256 == expected_previous,
                "capability qualification history is not a complete hash chain"
            );
        }
        Ok(records)
    }

    pub fn latest_capability_qualification(
        &self,
        package_record_id: &str,
    ) -> Result<Option<CapabilityQualification>> {
        Ok(self
            .capability_qualifications_for_package(package_record_id)?
            .into_iter()
            .next())
    }

    pub fn qualified_mcp_tools(&self) -> Result<Vec<QualifiedMcpToolBinding>> {
        let mut bindings = Vec::new();
        for package in self.capability_packages()? {
            let Some(qualification) = self.latest_capability_qualification(&package.record_id)?
            else {
                continue;
            };
            if qualification.disposition != QualificationDisposition::Qualified {
                continue;
            }
            anyhow::ensure!(
                package.package.kind == CapabilityPackageKind::McpServer,
                "qualified executable package is not an MCP server"
            );
            let discovery_record_id = qualification
                .discovery_record_id
                .as_deref()
                .context("qualified MCP package has no discovery record")?;
            let discovery = self
                .mcp_discovery(discovery_record_id)?
                .context("qualified MCP discovery record disappeared")?;
            anyhow::ensure!(
                discovery.package_record_id == package.record_id
                    && discovery.package_content_sha256 == package.package.content_sha256
                    && qualification.discovery_sha256.as_deref()
                        == Some(discovery.snapshot.discovery_sha256.as_str()),
                "qualified MCP evidence no longer binds the package and discovery"
            );
            for policy in &qualification.tool_policies {
                let tool = discovery
                    .snapshot
                    .tools
                    .iter()
                    .find(|tool| tool.name == policy.tool_name)
                    .with_context(|| {
                        format!("qualified MCP tool {} disappeared", policy.tool_name)
                    })?;
                bindings.push(QualifiedMcpToolBinding {
                    alias: qualified_mcp_tool_alias(
                        &qualification.qualification_sha256,
                        &tool.name,
                    )?,
                    package_record_id: package.record_id.clone(),
                    package_id: package.package.package_id.clone(),
                    package_display_name: package.package.display_name.clone(),
                    package_content_sha256: package.package.content_sha256.clone(),
                    qualification_record_id: qualification.record_id.clone(),
                    qualification_sha256: qualification.qualification_sha256.clone(),
                    discovery_record_id: discovery.record_id.clone(),
                    discovery_sha256: discovery.snapshot.discovery_sha256.clone(),
                    source: package.package.source.clone(),
                    tool: tool.clone(),
                    policy: policy.clone(),
                });
            }
        }
        bindings.sort_by(|left, right| left.alias.cmp(&right.alias));
        Ok(bindings)
    }

    pub fn qualified_mcp_tool(&self, alias: &str) -> Result<Option<QualifiedMcpToolBinding>> {
        Ok(self
            .qualified_mcp_tools()?
            .into_iter()
            .find(|binding| binding.alias == alias))
    }

    pub fn research_plans_for_campaign(
        &self,
        campaign_id: &str,
    ) -> Result<Vec<ResearchPlanEnvelope>> {
        let connection = self.connect()?;
        let mut statement = connection.prepare(
            "SELECT plan_json FROM research_plan_versions WHERE campaign_id=?1 ORDER BY version",
        )?;
        let plans = statement
            .query_map(params![campaign_id], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut envelopes = Vec::with_capacity(plans.len());
        let mut previous_plan_sha256: Option<String> = None;
        for raw in plans {
            let plan: ResearchPlanVersion = serde_json::from_str(&raw)?;
            plan.validate()?;
            anyhow::ensure!(
                plan.previous_plan_sha256 == previous_plan_sha256,
                "research plan version chain is incomplete"
            );
            previous_plan_sha256 = Some(plan.plan_sha256.clone());
            let decisions = research_plan_decisions_for_plan(&connection, &plan)?;
            let dispatches = research_phase_dispatches_for_plan(&connection, &plan)?;
            envelopes.push(ResearchPlanEnvelope {
                plan,
                decisions,
                dispatches,
            });
        }
        Ok(envelopes)
    }

    pub fn record_research_plan(
        &self,
        campaign_id: &str,
        request: CreateResearchPlanRequest,
    ) -> Result<ResearchPlanEnvelope> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let campaign_exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM campaigns WHERE id=?1)",
            params![campaign_id],
            |row| row.get(0),
        )?;
        anyhow::ensure!(campaign_exists, "unknown campaign {campaign_id}");
        let latest: Option<(u32, String)> = transaction
            .query_row(
                "SELECT version,plan_sha256 FROM research_plan_versions WHERE campaign_id=?1 ORDER BY version DESC LIMIT 1",
                params![campaign_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let version = latest.as_ref().map_or(1, |(version, _)| version + 1);
        let previous_plan_sha256 = latest.map(|(_, sha)| sha);
        let now = Utc::now().to_rfc3339();
        let plan = ResearchPlanVersion::build(
            format!("research_plan_{}", Uuid::new_v4().simple()),
            campaign_id.to_owned(),
            version,
            request,
            previous_plan_sha256,
            now.clone(),
        )?;
        research_execution::validate_execution_bindings(&transaction, &plan)?;
        transaction.execute(
            r#"INSERT INTO research_plan_versions
            (id,campaign_id,version,plan_sha256,previous_plan_sha256,plan_json,created_at)
            VALUES (?1,?2,?3,?4,?5,?6,?7)"#,
            params![
                plan.id,
                plan.campaign_id,
                plan.version,
                plan.plan_sha256,
                plan.previous_plan_sha256,
                serde_json::to_string(&plan)?,
                plan.created_at,
            ],
        )?;
        transaction.commit()?;
        Ok(ResearchPlanEnvelope {
            plan,
            decisions: Vec::new(),
            dispatches: Vec::new(),
        })
    }

    pub fn record_research_plan_decision(
        &self,
        campaign_id: &str,
        plan_id: &str,
        decision: ResearchPlanDecisionKind,
        actor: &str,
        rationale: &str,
    ) -> Result<ResearchPlanEnvelope> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let raw: String = transaction
            .query_row(
                "SELECT plan_json FROM research_plan_versions WHERE id=?1 AND campaign_id=?2",
                params![plan_id, campaign_id],
                |row| row.get(0),
            )
            .context("research plan does not exist in this campaign")?;
        let plan: ResearchPlanVersion = serde_json::from_str(&raw)?;
        plan.validate()?;
        if decision == ResearchPlanDecisionKind::Approved {
            research_execution::validate_execution_bindings(&transaction, &plan)?;
        }
        let latest_plan_id: String = transaction.query_row(
            "SELECT id FROM research_plan_versions WHERE campaign_id=?1 ORDER BY version DESC LIMIT 1",
            params![campaign_id],
            |row| row.get(0),
        )?;
        anyhow::ensure!(
            latest_plan_id == plan.id,
            "only the latest research plan version can receive a decision"
        );
        let existing = research_plan_decisions_for_plan(&transaction, &plan)?;
        let previous = existing.last();
        if let Some(previous) = previous {
            anyhow::ensure!(
                previous.decision != decision,
                "an identical research plan decision is already current"
            );
        }
        if decision == ResearchPlanDecisionKind::Withdrawn {
            anyhow::ensure!(
                previous.is_some_and(|record| {
                    record.decision == ResearchPlanDecisionKind::Approved
                }),
                "only an approved research plan can be withdrawn"
            );
        }
        let record = ResearchPlanDecision::build(
            format!("research_plan_decision_{}", Uuid::new_v4().simple()),
            plan.id.clone(),
            plan.plan_sha256.clone(),
            decision,
            actor.to_owned(),
            rationale.to_owned(),
            previous.map(|record| record.decision_sha256.clone()),
            Utc::now().to_rfc3339(),
        )?;
        transaction.execute(
            r#"INSERT INTO research_plan_decisions
            (id,plan_id,plan_sha256,decision,decision_sha256,previous_decision_sha256,decision_json,created_at)
            VALUES (?1,?2,?3,?4,?5,?6,?7,?8)"#,
            params![
                record.id,
                record.plan_id,
                record.plan_sha256,
                research_plan_decision_name(record.decision),
                record.decision_sha256,
                record.previous_decision_sha256,
                serde_json::to_string(&record)?,
                record.created_at,
            ],
        )?;
        transaction.commit()?;
        let mut decisions = existing;
        decisions.push(record);
        let dispatches = research_phase_dispatches_for_plan(&connection, &plan)?;
        Ok(ResearchPlanEnvelope {
            plan,
            decisions,
            dispatches,
        })
    }

    pub fn dispatch_research_plan_phase(
        &self,
        campaign_id: &str,
        plan_id: &str,
        phase_id: &str,
        actor: &str,
    ) -> Result<ResearchPhaseDispatch> {
        anyhow::ensure!(!actor.trim().is_empty(), "dispatch actor is required");
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let raw: String = transaction
            .query_row(
                "SELECT plan_json FROM research_plan_versions WHERE id=?1 AND campaign_id=?2",
                params![plan_id, campaign_id],
                |row| row.get(0),
            )
            .context("research plan does not exist in this campaign")?;
        let plan: ResearchPlanVersion = serde_json::from_str(&raw)?;
        plan.validate()?;
        let latest_plan_id: String = transaction.query_row(
            "SELECT id FROM research_plan_versions WHERE campaign_id=?1 ORDER BY version DESC LIMIT 1",
            params![campaign_id],
            |row| row.get(0),
        )?;
        anyhow::ensure!(
            latest_plan_id == plan.id,
            "cannot dispatch a stale research plan"
        );
        let decisions = research_plan_decisions_for_plan(&transaction, &plan)?;
        let approval = decisions
            .last()
            .filter(|record| record.decision == ResearchPlanDecisionKind::Approved)
            .context("research plan is not currently approved")?;
        if let Some(existing) = transaction
            .query_row(
                "SELECT dispatch_json FROM research_phase_dispatches WHERE plan_id=?1 AND phase_id=?2",
                params![plan.id, phase_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            let existing: ResearchPhaseDispatch = serde_json::from_str(&existing)?;
            existing.validate()?;
            return Ok(existing);
        }
        research_execution::validate_execution_bindings(&transaction, &plan)?;
        let phase = plan
            .phases
            .iter()
            .find(|phase| phase.id == phase_id)
            .with_context(|| format!("research plan phase {phase_id} does not exist"))?;
        let prior_dispatches = research_phase_dispatches_for_plan(&transaction, &plan)?;
        for task in &phase.tasks {
            for dependency in &task.depends_on {
                let child = prior_dispatches
                    .iter()
                    .flat_map(|dispatch| &dispatch.children)
                    .find(|child| &child.task_id == dependency)
                    .with_context(|| format!("dependency {dependency} has not been dispatched"))?;
                let status: String = transaction.query_row(
                    "SELECT status FROM agent_runs WHERE id=?1",
                    params![child.agent_run_id],
                    |row| row.get(0),
                )?;
                anyhow::ensure!(
                    status == "completed",
                    "dependency {dependency} is not terminal-complete"
                );
            }
        }
        let now = Utc::now().to_rfc3339();
        let evidence = json!({
            "contract": "concord.approved-research-plan-evidence/1",
            "planId": plan.id,
            "planSha256": plan.plan_sha256,
            "approvalDecisionSha256": approval.decision_sha256,
            "phaseId": phase.id,
        });
        let (coordinator, coordinator_event) = insert_research_agent_tx(
            &transaction,
            campaign_id,
            format!("Coordinate approved phase: {}", phase.title),
            vec![],
            AgentBudget {
                max_model_calls: 1,
                max_tool_calls: 0,
                max_elapsed_seconds: 600,
                budget_id: None,
                max_cost_usd: Some(0.0),
            },
            None,
            None,
            json!({
                "role": "phase_coordinator",
                "planEvidence": evidence.clone(),
                "phase": phase,
                "executionEnabled": false,
                "message": "Coordinator identity records common parentage; children remain independently advanced and approval gated."
            }),
            phase.tasks.iter().find_map(|task| task.execution.as_ref()),
            &now,
        )?;
        let mut children = Vec::with_capacity(phase.tasks.len());
        for task in &phase.tasks {
            let (child, _) = insert_research_agent_tx(
                &transaction,
                campaign_id,
                format!("{}: {}", task.specialist_role, task.objective),
                task.allowed_tools.clone(),
                AgentBudget {
                    max_model_calls: task.max_model_calls,
                    max_tool_calls: task.max_tool_calls,
                    max_elapsed_seconds: task.max_elapsed_seconds,
                    budget_id: task
                        .execution
                        .as_ref()
                        .and_then(|execution| execution.budget_id.clone()),
                    max_cost_usd: Some(task.max_cost_usd),
                },
                Some(coordinator.id.clone()),
                Some(coordinator_event.event_sha256.clone()),
                json!({
                    "role": "bounded_specialist",
                    "planEvidence": evidence.clone(),
                    "brief": task,
                    "deterministicFixture": task.deterministic_fixture,
                    "executionEnabled": true
                }),
                task.execution.as_ref(),
                &now,
            )?;
            children.push(ResearchPhaseDispatchChild {
                task_id: task.id.clone(),
                agent_run_id: child.id,
            });
        }
        let dispatch = ResearchPhaseDispatch::build(
            format!("research_phase_dispatch_{}", Uuid::new_v4().simple()),
            campaign_id.to_owned(),
            plan.id.clone(),
            plan.plan_sha256.clone(),
            approval.decision_sha256.clone(),
            phase.id.clone(),
            coordinator.id,
            children,
            phase.max_parallel,
            actor.to_owned(),
            now.clone(),
        )?;
        transaction.execute(
            r#"INSERT INTO research_phase_dispatches
            (id,campaign_id,plan_id,phase_id,dispatch_sha256,dispatch_json,created_at)
            VALUES (?1,?2,?3,?4,?5,?6,?7)"#,
            params![
                dispatch.id,
                dispatch.campaign_id,
                dispatch.plan_id,
                dispatch.phase_id,
                dispatch.dispatch_sha256,
                serde_json::to_string(&dispatch)?,
                dispatch.created_at,
            ],
        )?;
        transaction.commit()?;
        Ok(dispatch)
    }

    pub fn science_artifact_workspace(
        &self,
        campaign_id: &str,
    ) -> Result<ScienceArtifactWorkspace> {
        let connection = self.connect()?;
        Ok(ScienceArtifactWorkspace {
            versions: science_records(&connection, "SELECT record_json FROM science_artifact_versions WHERE campaign_id=?1 ORDER BY created_at,id", campaign_id)?,
            annotations: science_records(&connection, "SELECT record_json FROM science_artifact_annotations WHERE campaign_id=?1 ORDER BY created_at,id", campaign_id)?,
            reviews: science_records(&connection, "SELECT record_json FROM science_artifact_reviews WHERE campaign_id=?1 ORDER BY created_at,id", campaign_id)?,
            dispositions: science_records(&connection, "SELECT record_json FROM science_artifact_dispositions WHERE campaign_id=?1 ORDER BY created_at,id", campaign_id)?,
            batches: science_records(&connection, "SELECT record_json FROM science_batch_receipts WHERE campaign_id=?1 ORDER BY created_at,id", campaign_id)?,
            ranked_tables: science_records(&connection, "SELECT record_json FROM science_ranked_tables WHERE campaign_id=?1 ORDER BY created_at,id", campaign_id)?,
            decision_memos: science_records(&connection, "SELECT record_json FROM science_decision_memos WHERE campaign_id=?1 ORDER BY created_at,id", campaign_id)?,
        })
    }

    pub fn execution_workspace(&self, campaign_id: &str) -> Result<ExecutionWorkspace> {
        let connection = self.connect()?;
        Ok(ExecutionWorkspace {
            plans: science_records(&connection, "SELECT record_json FROM execution_plans WHERE campaign_id=?1 ORDER BY created_at,id", campaign_id)?,
            receipts: science_records(&connection, "SELECT record_json FROM execution_receipts WHERE campaign_id=?1 ORDER BY created_at,id", campaign_id)?,
        })
    }

    pub fn record_execution_plan(&self, plan: &ExecutionPlan) -> Result<ExecutionPlan> {
        plan.validate()?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let campaign_exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM campaigns WHERE id=?1)",
            params![plan.campaign_id],
            |row| row.get(0),
        )?;
        anyhow::ensure!(campaign_exists, "execution campaign does not exist");
        let existing: Option<String> = transaction
            .query_row(
                "SELECT record_json FROM execution_plans WHERE id=?1",
                params![plan.id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            let existing: ExecutionPlan = serde_json::from_str(&existing)?;
            anyhow::ensure!(
                existing == *plan,
                "execution plan identity is already bound to different content"
            );
            return Ok(existing);
        }
        transaction.execute("INSERT INTO execution_plans(id,campaign_id,plan_sha256,record_json,created_at) VALUES (?1,?2,?3,?4,?5)", params![plan.id, plan.campaign_id, plan.plan_sha256, serde_json::to_string(plan)?, plan.created_at])?;
        transaction.commit()?;
        Ok(plan.clone())
    }

    pub fn record_execution_receipt(&self, receipt: &ExecutionReceipt) -> Result<ExecutionReceipt> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let plan_json: String = transaction
            .query_row(
                "SELECT record_json FROM execution_plans WHERE id=?1 AND campaign_id=?2",
                params![receipt.plan_id, receipt.campaign_id],
                |row| row.get(0),
            )
            .context("execution plan does not belong to the campaign")?;
        let plan: ExecutionPlan = serde_json::from_str(&plan_json)?;
        receipt.validate(&plan)?;
        let existing: Option<String> = transaction
            .query_row(
                "SELECT record_json FROM execution_receipts WHERE id=?1",
                params![receipt.id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            let existing: ExecutionReceipt = serde_json::from_str(&existing)?;
            anyhow::ensure!(
                existing == *receipt,
                "execution receipt identity is already bound to different content"
            );
            return Ok(existing);
        }
        transaction.execute("INSERT INTO execution_receipts(id,campaign_id,plan_id,receipt_sha256,record_json,created_at) VALUES (?1,?2,?3,?4,?5,?6)", params![receipt.id, receipt.campaign_id, receipt.plan_id, receipt.receipt_sha256, serde_json::to_string(receipt)?, receipt.created_at])?;
        transaction.commit()?;
        Ok(receipt.clone())
    }

    pub fn record_science_artifact_version(
        &self,
        campaign_id: &str,
        request: CreateScienceArtifactVersionRequest,
    ) -> Result<ScienceArtifactVersion> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_agent_campaign_tx(&transaction, &request.producing_agent_run_id, campaign_id)?;
        let plan_json: String = transaction
            .query_row(
                "SELECT plan_json FROM research_plan_versions WHERE id=?1 AND campaign_id=?2",
                params![request.plan_id, campaign_id],
                |row| row.get(0),
            )
            .context("science artifact plan does not belong to the campaign")?;
        let plan: ResearchPlanVersion = serde_json::from_str(&plan_json)?;
        anyhow::ensure!(
            plan.phases.iter().any(|phase| phase.id == request.phase_id),
            "science artifact phase does not exist in the plan"
        );
        let dispatch_json: String = transaction.query_row(
            "SELECT dispatch_json FROM research_phase_dispatches WHERE plan_id=?1 AND phase_id=?2",
            params![request.plan_id, request.phase_id], |row| row.get(0),
        ).context("science artifact phase was not dispatched")?;
        let dispatch: ResearchPhaseDispatch = serde_json::from_str(&dispatch_json)?;
        anyhow::ensure!(
            dispatch
                .children
                .iter()
                .any(|child| child.agent_run_id == request.producing_agent_run_id),
            "science artifact producer is not a child of the declared phase"
        );
        for artifact_id in &request.artifact_ids {
            let exists: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM artifacts WHERE id=?1)",
                params![artifact_id],
                |row| row.get(0),
            )?;
            anyhow::ensure!(
                exists,
                "science artifact file {artifact_id} is not in the content-addressed store"
            );
        }
        for source_id in &request.source_version_ids {
            ensure_science_version_campaign_tx(&transaction, source_id, campaign_id)?;
        }
        let version = if let Some(parent_id) = request.parent_version_id.as_deref() {
            let parent_json: String = transaction.query_row("SELECT record_json FROM science_artifact_versions WHERE id=?1 AND campaign_id=?2", params![parent_id, campaign_id], |row| row.get(0)).context("parent science artifact version does not exist")?;
            let parent: ScienceArtifactVersion = serde_json::from_str(&parent_json)?;
            anyhow::ensure!(
                parent.title == request.title && parent.kind == request.kind,
                "artifact correction must preserve lineage title and kind"
            );
            let existing_child: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM science_artifact_versions WHERE parent_version_id=?1)",
                params![parent_id],
                |row| row.get(0),
            )?;
            anyhow::ensure!(!existing_child, "artifact version already has a correction; branch through an explicit new contract instead");
            parent.version + 1
        } else {
            1
        };
        let record = ScienceArtifactVersion::build(
            format!("science_artifact_version_{}", Uuid::new_v4().simple()),
            campaign_id.to_owned(),
            version,
            request,
            Utc::now().to_rfc3339(),
        )?;
        transaction.execute("INSERT INTO science_artifact_versions(id,campaign_id,version,parent_version_id,producing_agent_run_id,version_sha256,record_json,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)", params![record.id, record.campaign_id, i64::from(record.version), record.parent_version_id, record.producing_agent_run_id, record.version_sha256, serde_json::to_string(&record)?, record.created_at])?;
        transaction.commit()?;
        Ok(record)
    }

    pub fn record_science_artifact_annotation(
        &self,
        campaign_id: &str,
        request: CreateScienceArtifactAnnotationRequest,
    ) -> Result<ScienceArtifactAnnotation> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_science_version_campaign_tx(
            &transaction,
            &request.artifact_version_id,
            campaign_id,
        )?;
        let previous = transaction.query_row("SELECT annotation_sha256 FROM science_artifact_annotations WHERE artifact_version_id=?1 ORDER BY created_at DESC,id DESC LIMIT 1", params![request.artifact_version_id], |row| row.get(0)).optional()?;
        let record = ScienceArtifactAnnotation::build(
            format!("science_annotation_{}", Uuid::new_v4().simple()),
            campaign_id.to_owned(),
            request,
            previous,
            Utc::now().to_rfc3339(),
        )?;
        transaction.execute("INSERT INTO science_artifact_annotations(id,campaign_id,artifact_version_id,annotation_sha256,previous_annotation_sha256,record_json,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7)", params![record.id, record.campaign_id, record.artifact_version_id, record.annotation_sha256, record.previous_annotation_sha256, serde_json::to_string(&record)?, record.created_at])?;
        transaction.commit()?;
        Ok(record)
    }

    pub fn record_science_artifact_review(
        &self,
        campaign_id: &str,
        request: CreateScienceArtifactReviewRequest,
    ) -> Result<ScienceArtifactReview> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_agent_campaign_tx(&transaction, &request.reviewer_agent_run_id, campaign_id)?;
        let producer: String = transaction.query_row("SELECT producing_agent_run_id FROM science_artifact_versions WHERE id=?1 AND campaign_id=?2", params![request.artifact_version_id, campaign_id], |row| row.get(0)).context("reviewed science artifact does not exist")?;
        anyhow::ensure!(
            producer != request.reviewer_agent_run_id,
            "independent reviewer must be a different agent run from the producer"
        );
        let annotated: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM science_artifact_annotations WHERE artifact_version_id=?1)",
            params![request.artifact_version_id],
            |row| row.get(0),
        )?;
        anyhow::ensure!(
            annotated,
            "independent review requires a primary annotation on the exact source version"
        );
        let duplicate: bool = transaction.query_row("SELECT EXISTS(SELECT 1 FROM science_artifact_reviews WHERE artifact_version_id=?1 AND reviewer_agent_run_id=?2)", params![request.artifact_version_id, request.reviewer_agent_run_id], |row| row.get(0))?;
        anyhow::ensure!(
            !duplicate,
            "this reviewer already recorded a review for the artifact version"
        );
        let record = ScienceArtifactReview::build(
            format!("science_review_{}", Uuid::new_v4().simple()),
            campaign_id.to_owned(),
            request,
            Utc::now().to_rfc3339(),
        )?;
        transaction.execute("INSERT INTO science_artifact_reviews(id,campaign_id,artifact_version_id,reviewer_agent_run_id,review_sha256,record_json,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7)", params![record.id, record.campaign_id, record.artifact_version_id, record.reviewer_agent_run_id, record.review_sha256, serde_json::to_string(&record)?, record.created_at])?;
        transaction.commit()?;
        Ok(record)
    }

    pub fn record_science_artifact_disposition(
        &self,
        campaign_id: &str,
        request: CreateScienceArtifactDispositionRequest,
    ) -> Result<ScienceArtifactDisposition> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let parent_version_id: Option<String> = transaction
            .query_row(
                "SELECT parent_version_id FROM science_artifact_versions WHERE id=?1 AND campaign_id=?2",
                params![request.artifact_version_id, campaign_id],
                |row| row.get(0),
            )
            .context("disposed science artifact does not exist")?;
        let existing: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM science_artifact_dispositions WHERE artifact_version_id=?1)",
            params![request.artifact_version_id],
            |row| row.get(0),
        )?;
        anyhow::ensure!(
            !existing,
            "artifact version already has an operator disposition"
        );
        let annotation_ids = transaction
            .prepare("SELECT id FROM science_artifact_annotations WHERE artifact_version_id=?1 ORDER BY created_at,id")?
            .query_map(params![request.artifact_version_id], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        anyhow::ensure!(
            !annotation_ids.is_empty(),
            "artifact disposition requires an operator annotation on the exact version"
        );
        let mut review_ids = transaction
            .prepare("SELECT id FROM science_artifact_reviews WHERE artifact_version_id=?1 ORDER BY created_at,id")?
            .query_map(params![request.artifact_version_id], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if let Some(parent_id) = &parent_version_id {
            review_ids.extend(
                transaction
                    .prepare("SELECT id FROM science_artifact_reviews WHERE artifact_version_id=?1 ORDER BY created_at,id")?
                    .query_map(params![parent_id], |row| row.get::<_, String>(0))?
                    .collect::<std::result::Result<Vec<_>, _>>()?,
            );
        }
        review_ids.sort();
        review_ids.dedup();
        if request.disposition == ScienceArtifactDispositionKind::Accepted {
            anyhow::ensure!(
                !review_ids.is_empty(),
                "artifact acceptance requires an independent review of this version or its corrected parent"
            );
            let has_child: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM science_artifact_versions WHERE parent_version_id=?1)",
                params![request.artifact_version_id],
                |row| row.get(0),
            )?;
            anyhow::ensure!(
                !has_child,
                "only the current leaf artifact version may be accepted"
            );
        }
        let previous_disposition_sha256 = if let Some(parent_id) = &parent_version_id {
            transaction
                .query_row(
                    "SELECT disposition_sha256 FROM science_artifact_dispositions WHERE artifact_version_id=?1",
                    params![parent_id],
                    |row| row.get(0),
                )
                .optional()?
        } else {
            None
        };
        let record = ScienceArtifactDisposition::build(
            format!("science_disposition_{}", Uuid::new_v4().simple()),
            campaign_id.to_owned(),
            request,
            annotation_ids,
            review_ids,
            previous_disposition_sha256,
            Utc::now().to_rfc3339(),
        )?;
        let disposition = match record.disposition {
            ScienceArtifactDispositionKind::RevisionRequested => "revision_requested",
            ScienceArtifactDispositionKind::Accepted => "accepted",
        };
        transaction.execute(
            "INSERT INTO science_artifact_dispositions(id,campaign_id,artifact_version_id,disposition,disposition_sha256,previous_disposition_sha256,record_json,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![record.id, record.campaign_id, record.artifact_version_id, disposition, record.disposition_sha256, record.previous_disposition_sha256, serde_json::to_string(&record)?, record.created_at],
        )?;
        transaction.commit()?;
        Ok(record)
    }

    pub fn record_science_batch_receipt(
        &self,
        campaign_id: &str,
        request: CreateScienceBatchReceiptRequest,
    ) -> Result<ScienceBatchReceipt> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_agent_campaign_tx(&transaction, &request.producing_agent_run_id, campaign_id)?;
        let record = ScienceBatchReceipt::build(
            format!("science_batch_{}", Uuid::new_v4().simple()),
            campaign_id.to_owned(),
            request,
            Utc::now().to_rfc3339(),
        )?;
        transaction.execute("INSERT INTO science_batch_receipts(id,campaign_id,producing_agent_run_id,receipt_sha256,record_json,created_at) VALUES (?1,?2,?3,?4,?5,?6)", params![record.id, record.campaign_id, record.producing_agent_run_id, record.receipt_sha256, serde_json::to_string(&record)?, record.created_at])?;
        transaction.commit()?;
        Ok(record)
    }

    pub fn record_science_ranked_table(
        &self,
        campaign_id: &str,
        request: CreateScienceRankedTableRequest,
    ) -> Result<ScienceRankedTable> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for row in &request.rows {
            for version_id in &row.source_artifact_version_ids {
                ensure_science_version_campaign_tx(&transaction, version_id, campaign_id)?;
            }
            let review_exists: bool = transaction.query_row("SELECT EXISTS(SELECT 1 FROM science_artifact_reviews WHERE id=?1 AND campaign_id=?2)", params![row.independent_review_id, campaign_id], |record| record.get(0))?;
            anyhow::ensure!(
                review_exists,
                "ranked row independent review does not exist"
            );
        }
        let record = ScienceRankedTable::build(
            format!("science_ranked_table_{}", Uuid::new_v4().simple()),
            campaign_id.to_owned(),
            request.title,
            request.rows,
            Utc::now().to_rfc3339(),
        )?;
        transaction.execute("INSERT INTO science_ranked_tables(id,campaign_id,table_sha256,record_json,created_at) VALUES (?1,?2,?3,?4,?5)", params![record.id, record.campaign_id, record.table_sha256, serde_json::to_string(&record)?, record.created_at])?;
        transaction.commit()?;
        Ok(record)
    }

    pub fn record_science_decision_memo(
        &self,
        campaign_id: &str,
        request: CreateScienceDecisionMemoRequest,
    ) -> Result<ScienceDecisionMemo> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for version_id in &request.source_artifact_version_ids {
            ensure_science_version_campaign_tx(&transaction, version_id, campaign_id)?;
        }
        let batch_exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM science_batch_receipts WHERE id=?1 AND campaign_id=?2)",
            params![request.batch_receipt_id, campaign_id],
            |row| row.get(0),
        )?;
        let table_exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM science_ranked_tables WHERE id=?1 AND campaign_id=?2)",
            params![request.ranked_table_id, campaign_id],
            |row| row.get(0),
        )?;
        anyhow::ensure!(
            batch_exists && table_exists,
            "decision memo requires a same-campaign batch receipt and ranked table"
        );
        let record = ScienceDecisionMemo::build(
            format!("science_decision_memo_{}", Uuid::new_v4().simple()),
            campaign_id.to_owned(),
            request,
            Utc::now().to_rfc3339(),
        )?;
        transaction.execute("INSERT INTO science_decision_memos(id,campaign_id,memo_sha256,record_json,created_at) VALUES (?1,?2,?3,?4,?5)", params![record.id, record.campaign_id, record.memo_sha256, serde_json::to_string(&record)?, record.created_at])?;
        transaction.commit()?;
        Ok(record)
    }

    pub fn create_agent_run(
        &self,
        request: &CreateAgentRunRequest,
        resolved_model: &str,
    ) -> Result<AgentRunEnvelope> {
        request.validate()?;
        anyhow::ensure!(!resolved_model.trim().is_empty(), "agent model is required");
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        let campaign_exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM campaigns WHERE id=?1)",
            params![request.campaign_id],
            |row| row.get(0),
        )?;
        anyhow::ensure!(campaign_exists, "unknown campaign {}", request.campaign_id);
        let provider_exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM provider_profiles WHERE id=?1)",
            params![request.provider_id],
            |row| row.get(0),
        )?;
        anyhow::ensure!(provider_exists, "unknown provider {}", request.provider_id);
        if let Some(parent_run_id) = request.parent_run_id.as_deref() {
            let parent: Option<String> = transaction
                .query_row(
                    "SELECT campaign_id FROM agent_runs WHERE id=?1",
                    params![parent_run_id],
                    |row| row.get(0),
                )
                .optional()?;
            anyhow::ensure!(
                parent.as_deref() == Some(request.campaign_id.as_str()),
                "agent fork parent must exist in the same campaign"
            );
            let parent_hash = request
                .parent_event_hash
                .as_deref()
                .context("agent fork requires a parent event hash")?;
            let hash_exists: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM agent_events WHERE agent_run_id=?1 AND event_sha256=?2)",
                params![parent_run_id, parent_hash],
                |row| row.get(0),
            )?;
            anyhow::ensure!(hash_exists, "agent fork parent event hash is unknown");
        } else {
            anyhow::ensure!(
                request.parent_event_hash.is_none(),
                "parent event hash requires a parent run"
            );
        }
        let now = Utc::now().to_rfc3339();
        crate::epact::enforce_epact_agent_binding_tx(
            &transaction,
            &request.campaign_id,
            request.epact.as_ref(),
            &request.budget,
        )?;
        let run = AgentRun {
            contract: AGENT_RUN_CONTRACT.to_owned(),
            id: format!("agent_{}", Uuid::new_v4().simple()),
            campaign_id: request.campaign_id.clone(),
            provider_id: request.provider_id.clone(),
            model: resolved_model.to_owned(),
            task: request.task.trim().to_owned(),
            allowed_tools: request.allowed_tools.clone(),
            budget: request.budget.clone(),
            epact: request.epact.clone(),
            status: AgentRunStatus::Ready,
            revision: 0,
            model_calls: 0,
            tool_calls: 0,
            parent_run_id: request.parent_run_id.clone(),
            parent_event_hash: request.parent_event_hash.clone(),
            created_at: now.clone(),
            updated_at: now.clone(),
        };
        insert_agent_run_tx(&transaction, &run)?;
        if let Some(ceiling) = run.budget.max_cost_usd.filter(|value| *value > 0.0) {
            let selected: Option<(String, f64)> = if let Some(budget_id) =
                run.budget.budget_id.as_deref()
            {
                transaction
                    .query_row(
                        "SELECT id,remaining_floor FROM budgets WHERE id=?1",
                        params![budget_id],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?
            } else {
                transaction
                    .query_row(
                        "SELECT id,remaining_floor FROM budgets ORDER BY remaining_floor DESC LIMIT 1",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?
            };
            let (budget_id, remaining_floor) = selected
                .context("paid agent execution requires a configured Concord budget account")?;
            anyhow::ensure!(
                ceiling <= remaining_floor,
                "agent cost ceiling ${ceiling:.2} exceeds remaining floor ${remaining_floor:.2}"
            );
            transaction.execute(
                "UPDATE budgets SET exposure=exposure+?2,remaining_floor=remaining_floor-?2,updated_at=?3 WHERE id=?1",
                params![budget_id, ceiling, now],
            )?;
            transaction.execute(
                r#"INSERT INTO agent_budget_reservations
                (agent_run_id,budget_id,reserved_usd,estimated_spent_usd,status,created_at,updated_at)
                VALUES (?1,?2,?3,0,'reserved',?4,?4)"#,
                params![run.id, budget_id, ceiling, now],
            )?;
        }
        let created = AgentEvent::build(
            format!("agent_event_{}", Uuid::new_v4().simple()),
            run.id.clone(),
            0,
            "run-created".to_owned(),
            AgentEventKind::RunCreated,
            AgentRunStatus::Ready,
            json!({
                "task": run.task,
                "providerId": run.provider_id,
                "model": run.model,
                "allowedTools": run.allowed_tools,
                "budget": run.budget,
                "epact": run.epact,
                "parentRunId": run.parent_run_id,
                "parentEventHash": run.parent_event_hash,
            }),
            request.parent_event_hash.clone(),
            now,
        )?;
        insert_agent_event_tx(&transaction, &created)?;
        transaction.commit()?;
        Ok(AgentRunEnvelope {
            run,
            events: vec![created],
        })
    }

    pub fn agent_budget_reservation(
        &self,
        agent_run_id: &str,
    ) -> Result<Option<(String, f64, f64)>> {
        let connection = self.connect()?;
        connection
            .query_row(
                "SELECT budget_id,reserved_usd,estimated_spent_usd FROM agent_budget_reservations WHERE agent_run_id=?1 AND status='reserved'",
                params![agent_run_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn record_agent_model_cost(&self, agent_run_id: &str, cost_usd: f64) -> Result<f64> {
        anyhow::ensure!(
            cost_usd.is_finite() && cost_usd >= 0.0,
            "agent model cost is invalid"
        );
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        let (budget_id, reserved_usd, estimated_spent_usd): (String, f64, f64) = transaction
            .query_row(
                "SELECT budget_id,reserved_usd,estimated_spent_usd FROM agent_budget_reservations WHERE agent_run_id=?1 AND status='reserved'",
                params![agent_run_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .context("remote agent has no active spend reservation")?;
        let next = estimated_spent_usd + cost_usd;
        anyhow::ensure!(
            next <= reserved_usd + 1e-9,
            "estimated agent spend ${next:.6} exceeds reservation ${reserved_usd:.6}"
        );
        let now = Utc::now().to_rfc3339();
        transaction.execute(
            "UPDATE agent_budget_reservations SET estimated_spent_usd=?2,updated_at=?3 WHERE agent_run_id=?1",
            params![agent_run_id, next, now],
        )?;
        transaction.execute(
            "UPDATE budgets SET spent=spent+?2,updated_at=?3 WHERE id=?1",
            params![budget_id, cost_usd, now],
        )?;
        transaction.commit()?;
        Ok(next)
    }

    pub fn settle_terminal_agent_budgets(&self) -> Result<usize> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        let rows = {
            let mut statement = transaction.prepare(
                r#"SELECT abr.agent_run_id,abr.budget_id,abr.reserved_usd,abr.estimated_spent_usd
                FROM agent_budget_reservations abr
                JOIN agent_runs ar ON ar.id=abr.agent_run_id
                WHERE abr.status='reserved' AND ar.status IN ('completed','failed','cancelled')"#,
            )?;
            let collected = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, f64>(2)?,
                        row.get::<_, f64>(3)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            collected
        };
        let now = Utc::now().to_rfc3339();
        for (agent_run_id, budget_id, reserved, estimated_spent) in &rows {
            transaction.execute(
                "UPDATE budgets SET exposure=MAX(0,exposure-?2),remaining_floor=remaining_floor+(?2-?3),updated_at=?4 WHERE id=?1",
                params![budget_id, reserved, estimated_spent, now],
            )?;
            transaction.execute(
                "UPDATE agent_budget_reservations SET status='settled_estimate',updated_at=?2 WHERE agent_run_id=?1",
                params![agent_run_id, now],
            )?;
        }
        transaction.commit()?;
        Ok(rows.len())
    }

    pub fn agent_run_envelope(&self, agent_run_id: &str) -> Result<Option<AgentRunEnvelope>> {
        let connection = self.connect()?;
        let run = connection
            .query_row(
                "SELECT contract,id,campaign_id,provider_id,model,task,allowed_tools_json,budget_json,status,revision,model_calls,tool_calls,parent_run_id,parent_event_hash,created_at,updated_at,epact_json FROM agent_runs WHERE id=?1",
                params![agent_run_id],
                agent_run_from_row,
            )
            .optional()?;
        let Some(run) = run else {
            return Ok(None);
        };
        let mut statement = connection.prepare(
            "SELECT contract,id,agent_run_id,sequence,idempotency_key,kind,from_status,to_status,payload_json,previous_event_sha256,event_sha256,created_at FROM agent_events WHERE agent_run_id=?1 ORDER BY sequence",
        )?;
        let events = statement
            .query_map(params![agent_run_id], agent_event_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Some(AgentRunEnvelope { run, events }))
    }

    pub fn agent_run_envelopes(&self, campaign_id: Option<&str>) -> Result<Vec<AgentRunEnvelope>> {
        let connection = self.connect()?;
        let mut statement = if campaign_id.is_some() {
            connection.prepare(
                "SELECT id FROM agent_runs WHERE campaign_id=?1 ORDER BY updated_at DESC,id",
            )?
        } else {
            connection.prepare("SELECT id FROM agent_runs ORDER BY updated_at DESC,id")?
        };
        let ids = if let Some(campaign_id) = campaign_id {
            statement
                .query_map(params![campaign_id], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        } else {
            statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        drop(statement);
        drop(connection);
        ids.into_iter()
            .map(|id| {
                self.agent_run_envelope(&id)?
                    .with_context(|| format!("agent run {id} disappeared during listing"))
            })
            .collect()
    }

    pub fn begin_campaign_recovery(
        &self,
        campaign_id: &str,
        request: &BeginCampaignRecoveryRequest,
    ) -> Result<CampaignSupervisionSnapshot> {
        request.validate()?;
        let now = Utc::now();
        let now_text = now.to_rfc3339();
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_campaign_exists_tx(&transaction, campaign_id)?;
        let frozen_closeout_exists = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM campaign_closeouts WHERE campaign_id=?1)",
            params![campaign_id],
            |row| row.get::<_, bool>(0),
        )?;
        anyhow::ensure!(
            !frozen_closeout_exists,
            "campaign has an immutable closeout and cannot enter a new recovery generation"
        );
        let existing: Option<(u64, GovernorStatus)> = transaction
            .query_row(
                "SELECT generation,status FROM campaign_governors WHERE campaign_id=?1",
                params![campaign_id],
                |row| {
                    let generation = u64::try_from(row.get::<_, i64>(0)?).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Integer,
                            Box::new(error),
                        )
                    })?;
                    let status =
                        GovernorStatus::parse(&row.get::<_, String>(1)?).map_err(|error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                1,
                                rusqlite::types::Type::Text,
                                error.into(),
                            )
                        })?;
                    Ok((generation, status))
                },
            )
            .optional()?;
        if existing.is_some_and(|(_, status)| status == GovernorStatus::Open) {
            anyhow::ensure!(
                campaign_supervision_is_stale_tx(&transaction, campaign_id, now)?,
                "an open healthy campaign must be closed before starting a new recovery generation"
            );
        }
        let generation = existing.map_or(1, |(value, _)| value.saturating_add(1));
        transaction.execute(
            r#"INSERT INTO campaign_governors
            (campaign_id,contract,generation,status,last_reconciliation_sha256,blocked_reason,updated_at)
            VALUES (?1,?2,?3,'reconciling',NULL,?4,?5)
            ON CONFLICT(campaign_id) DO UPDATE SET
                contract=excluded.contract,
                generation=excluded.generation,
                status='reconciling',
                last_reconciliation_sha256=NULL,
                blocked_reason=excluded.blocked_reason,
                updated_at=excluded.updated_at"#,
            params![
                campaign_id,
                CAMPAIGN_SUPERVISION_CONTRACT,
                i64::try_from(generation)?,
                format!(
                    "recovery initiated by {}: {}",
                    request.owner_id.trim(),
                    request.reason.trim()
                ),
                now_text,
            ],
        )?;
        transaction.commit()?;
        self.campaign_supervision_snapshot(campaign_id, now)
    }

    pub fn heartbeat_campaign_service(
        &self,
        campaign_id: &str,
        request: &ServiceHeartbeatRequest,
    ) -> Result<CampaignSupervisionSnapshot> {
        request.validate()?;
        let now = Utc::now();
        let now_text = now.to_rfc3339();
        let expires_at =
            (now + chrono::Duration::seconds(i64::try_from(request.lease_seconds)?)).to_rfc3339();
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (generation, status): (u64, GovernorStatus) = transaction
            .query_row(
                "SELECT generation,status FROM campaign_governors WHERE campaign_id=?1",
                params![campaign_id],
                |row| {
                    let generation = u64::try_from(row.get::<_, i64>(0)?).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Integer,
                            Box::new(error),
                        )
                    })?;
                    let status =
                        GovernorStatus::parse(&row.get::<_, String>(1)?).map_err(|error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                1,
                                rusqlite::types::Type::Text,
                                error.into(),
                            )
                        })?;
                    Ok((generation, status))
                },
            )
            .context("campaign recovery has not been initialized")?;
        anyhow::ensure!(
            status == GovernorStatus::Reconciling || status == GovernorStatus::Open,
            "campaign governor does not accept heartbeats while {}",
            status.as_str()
        );
        anyhow::ensure!(
            generation == request.generation,
            "campaign generation conflict: expected {generation}, received {}",
            request.generation
        );
        let prior: Option<(String, u64, String)> = transaction
            .query_row(
                "SELECT owner_id,generation,lease_expires_at FROM campaign_service_leases WHERE campaign_id=?1 AND role=?2",
                params![campaign_id, request.role.as_str()],
                |row| {
                    let generation = u64::try_from(row.get::<_, i64>(1)?).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            rusqlite::types::Type::Integer,
                            Box::new(error),
                        )
                    })?;
                    Ok((row.get(0)?, generation, row.get(2)?))
                },
            )
            .optional()?;
        if let Some((owner_id, prior_generation, prior_expiry)) = prior {
            if prior_generation == generation {
                anyhow::ensure!(
                    owner_id == request.owner_id.trim(),
                    "{} already has singleton owner {owner_id}",
                    request.role.as_str()
                );
                let expiry =
                    chrono::DateTime::parse_from_rfc3339(&prior_expiry)?.with_timezone(&Utc);
                anyhow::ensure!(
                    expiry > now,
                    "expired {} lease requires a new recovery generation",
                    request.role.as_str()
                );
            }
        }
        transaction.execute(
            r#"INSERT INTO campaign_service_leases
            (campaign_id,role,owner_id,generation,last_heartbeat_at,lease_expires_at,details_json)
            VALUES (?1,?2,?3,?4,?5,?6,?7)
            ON CONFLICT(campaign_id,role) DO UPDATE SET
                owner_id=excluded.owner_id,
                generation=excluded.generation,
                last_heartbeat_at=excluded.last_heartbeat_at,
                lease_expires_at=excluded.lease_expires_at,
                details_json=excluded.details_json"#,
            params![
                campaign_id,
                request.role.as_str(),
                request.owner_id.trim(),
                i64::try_from(generation)?,
                now_text,
                expires_at,
                serde_json::to_string(&request.details)?,
            ],
        )?;
        transaction.commit()?;
        self.campaign_supervision_snapshot(campaign_id, now)
    }

    pub fn campaign_supervision_snapshot(
        &self,
        campaign_id: &str,
        observed_at: chrono::DateTime<Utc>,
    ) -> Result<CampaignSupervisionSnapshot> {
        let connection = self.connect()?;
        let mut governor = connection
            .query_row(
                "SELECT contract,campaign_id,generation,status,last_reconciliation_sha256,blocked_reason,updated_at FROM campaign_governors WHERE campaign_id=?1",
                params![campaign_id],
                campaign_governor_from_row,
            )
            .optional()?
            .with_context(|| format!("campaign {campaign_id} has no supervision state"))?;
        let mut statement = connection.prepare(
            "SELECT campaign_id,role,owner_id,generation,last_heartbeat_at,lease_expires_at,details_json FROM campaign_service_leases WHERE campaign_id=?1 AND generation=?2 ORDER BY role",
        )?;
        let mut services = statement
            .query_map(
                params![campaign_id, i64::try_from(governor.generation)?],
                service_lease_from_row,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut live_roles = std::collections::BTreeSet::new();
        for service in &mut services {
            if service.is_live_at(observed_at)? {
                live_roles.insert(service.role);
            } else {
                service.status = ServiceLeaseStatus::Stale;
            }
        }
        let missing_or_stale_roles = SupervisorRole::REQUIRED
            .into_iter()
            .filter(|role| !live_roles.contains(role))
            .collect::<Vec<_>>();
        if governor.status == GovernorStatus::Open && !missing_or_stale_roles.is_empty() {
            governor.status = GovernorStatus::Closed;
            governor.blocked_reason = Some(format!(
                "dead-man switch: missing or stale singleton services: {}",
                missing_or_stale_roles
                    .iter()
                    .map(|role| role.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        let dispatch_allowed = governor.status == GovernorStatus::Open
            && governor.last_reconciliation_sha256.is_some()
            && missing_or_stale_roles.is_empty();
        let dispatch_accounting = dispatch_accounting_summary(&connection, campaign_id)?;
        Ok(CampaignSupervisionSnapshot {
            governor,
            services,
            missing_or_stale_roles,
            recovery_plan: RecoveryStep::ORDERED.to_vec(),
            dispatch_allowed,
            dispatch_accounting,
            observed_at: observed_at.to_rfc3339(),
        })
    }

    pub fn campaign_governor(&self, campaign_id: &str) -> Result<Option<CampaignGovernor>> {
        self.connect()?
            .query_row(
                "SELECT contract,campaign_id,generation,status,last_reconciliation_sha256,blocked_reason,updated_at FROM campaign_governors WHERE campaign_id=?1",
                params![campaign_id],
                campaign_governor_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    /// Build the exact provider, budget, and ledger digests used by the daemon reconciler.
    /// Volatile observation time is deliberately excluded so an unchanged durable state hashes
    /// identically across process restarts.
    pub fn campaign_reconciliation_evidence(
        &self,
        campaign_id: &str,
        generation: u64,
        reconciler_owner_id: &str,
    ) -> Result<ReconcileCampaignRequest> {
        let archive = self.campaign_archive(campaign_id)?;
        let connection = self.connect()?;
        let budgets = read_all(
            &connection,
            "SELECT id,name,source,currency,total,spent,exposure,remaining_floor,updated_at FROM budgets ORDER BY id",
            |row| {
                Ok(BudgetAccount {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    source: row.get(2)?,
                    currency: row.get(3)?,
                    total: row.get(4)?,
                    spent: row.get(5)?,
                    exposure: row.get(6)?,
                    remaining_floor: row.get(7)?,
                    updated_at: row.get(8)?,
                })
            },
        )?;
        let providers = read_all(
            &connection,
            "SELECT id,name,kind,base_url,secret_ref,status,metadata_json,updated_at FROM provider_profiles ORDER BY id",
            provider_from_row,
        )?;
        let run_reservations = read_all_for_campaign(
            &connection,
            "SELECT br.run_id,br.budget_id,br.reserved_usd,br.baseline_spent_usd,br.settled_usd,br.status,br.created_at,br.updated_at FROM budget_reservations br JOIN runs r ON r.id=br.run_id WHERE r.campaign_id=?1 ORDER BY br.run_id",
            campaign_id,
            |row| {
                Ok(json!({
                    "runId": row.get::<_, String>(0)?,
                    "budgetId": row.get::<_, String>(1)?,
                    "reservedUsd": row.get::<_, f64>(2)?,
                    "baselineSpentUsd": row.get::<_, f64>(3)?,
                    "settledUsd": row.get::<_, Option<f64>>(4)?,
                    "status": row.get::<_, String>(5)?,
                    "createdAt": row.get::<_, String>(6)?,
                    "updatedAt": row.get::<_, String>(7)?,
                }))
            },
        )?;
        let agent_reservations = read_all_for_campaign(
            &connection,
            "SELECT abr.agent_run_id,abr.budget_id,abr.reserved_usd,abr.estimated_spent_usd,abr.status,abr.created_at,abr.updated_at FROM agent_budget_reservations abr JOIN agent_runs ar ON ar.id=abr.agent_run_id WHERE ar.campaign_id=?1 ORDER BY abr.agent_run_id",
            campaign_id,
            |row| {
                Ok(json!({
                    "agentRunId": row.get::<_, String>(0)?,
                    "budgetId": row.get::<_, String>(1)?,
                    "reservedUsd": row.get::<_, f64>(2)?,
                    "estimatedSpentUsd": row.get::<_, f64>(3)?,
                    "status": row.get::<_, String>(4)?,
                    "createdAt": row.get::<_, String>(5)?,
                    "updatedAt": row.get::<_, String>(6)?,
                }))
            },
        )?;
        let dispatch_permits = read_all_for_campaign(
            &connection,
            "SELECT status,record_json FROM campaign_dispatch_permits WHERE campaign_id=?1 ORDER BY created_at,token",
            campaign_id,
            |row| {
                Ok(json!({
                    "status": row.get::<_, String>(0)?,
                    "permit": serde_json::from_str::<Value>(&row.get::<_, String>(1)?)
                        .map_err(|error| rusqlite::Error::FromSqlConversionFailure(
                            1,
                            rusqlite::types::Type::Text,
                            error.into(),
                        ))?,
                }))
            },
        )?;
        let provider_snapshot_sha256 = canonical_value_sha256(&json!({
            "providers": providers,
            "runs": archive.runs,
            "externalJobs": archive.external_jobs,
            "agentRuns": archive.agent_runs.iter().map(|entry| &entry.run).collect::<Vec<_>>(),
        }))?;
        let budget_snapshot_sha256 = canonical_value_sha256(&json!({
            "accounts": budgets,
            "runReservations": run_reservations,
            "agentReservations": agent_reservations,
            "dispatchPermits": dispatch_permits,
        }))?;
        let mut ledger_heads = std::collections::BTreeMap::from([
            (
                "events".to_owned(),
                canonical_value_sha256(&archive.events)?,
            ),
            (
                "agent-events".to_owned(),
                canonical_value_sha256(
                    &archive
                        .agent_runs
                        .iter()
                        .flat_map(|entry| entry.events.iter())
                        .collect::<Vec<_>>(),
                )?,
            ),
            (
                "execution".to_owned(),
                canonical_value_sha256(&archive.execution)?,
            ),
            (
                "research-plans".to_owned(),
                canonical_value_sha256(&archive.research_plans)?,
            ),
            (
                "science-artifacts".to_owned(),
                canonical_value_sha256(&archive.science_artifacts)?,
            ),
            (
                "standing-review".to_owned(),
                canonical_value_sha256(&archive.standing_review)?,
            ),
            (
                "dispatch-permits".to_owned(),
                canonical_value_sha256(&dispatch_permits)?,
            ),
        ]);
        if let Some(source_gate) = self.latest_source_gate_compilation(campaign_id)? {
            ledger_heads.insert(
                "source-gate".to_owned(),
                canonical_value_sha256(&source_gate)?,
            );
        }
        Ok(ReconcileCampaignRequest {
            generation,
            reconciler_owner_id: reconciler_owner_id.to_owned(),
            provider_snapshot_sha256,
            budget_snapshot_sha256,
            ledger_heads,
            disposition: ReconciliationDisposition::Clean,
            findings: vec![],
        })
    }

    /// Persist a watchdog trip. Once blocked, ordinary heartbeats and dispatch authorization stop;
    /// recovery must advance the campaign to a new generation.
    pub fn block_campaign_supervision(
        &self,
        campaign_id: &str,
        generation: u64,
        reason: &str,
    ) -> Result<()> {
        let reason = reason.trim();
        anyhow::ensure!(!reason.is_empty(), "watchdog block reason is required");
        let connection = self.connect()?;
        let changed = connection.execute(
            "UPDATE campaign_governors SET status='blocked',blocked_reason=?3,updated_at=?4 WHERE campaign_id=?1 AND generation=?2 AND status IN ('open','reconciling')",
            params![campaign_id, i64::try_from(generation)?, reason, Utc::now().to_rfc3339()],
        )?;
        anyhow::ensure!(
            changed == 1,
            "campaign governor generation is not blockable"
        );
        Ok(())
    }

    pub fn begin_scheduled_campaign_reconciliation(
        &self,
        campaign_id: &str,
        generation: u64,
        actor: &str,
    ) -> Result<()> {
        let actor = actor.trim();
        anyhow::ensure!(
            !actor.is_empty(),
            "scheduled reconciliation actor is required"
        );
        let connection = self.connect()?;
        let changed = connection.execute(
            "UPDATE campaign_governors SET status='reconciling',blocked_reason=?3,updated_at=?4 WHERE campaign_id=?1 AND generation=?2 AND status='open' AND last_reconciliation_sha256 IS NOT NULL",
            params![campaign_id, i64::try_from(generation)?, format!("scheduled reconciliation requested by {actor}"), Utc::now().to_rfc3339()],
        )?;
        anyhow::ensure!(
            changed == 1,
            "campaign governor is not open for scheduled reconciliation"
        );
        Ok(())
    }

    pub fn campaign_watchdog_findings(&self, campaign_id: &str) -> Result<Vec<String>> {
        let connection = self.connect()?;
        let mut findings = Vec::new();
        let over_budget = read_all_for_campaign(
            &connection,
            "SELECT id,cost_usd,budget_ceiling_usd FROM runs WHERE campaign_id=?1 AND status NOT IN ('completed','failed','cancelled') AND cost_usd IS NOT NULL AND budget_ceiling_usd IS NOT NULL AND cost_usd >= budget_ceiling_usd ORDER BY id",
            campaign_id,
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, f64>(1)?, row.get::<_, f64>(2)?)),
        )?;
        findings.extend(over_budget.into_iter().map(|(run_id, cost, ceiling)| {
            format!("run {run_id} reached its budget ceiling (${cost:.2} / ${ceiling:.2})")
        }));
        let invalid_budget_count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM budgets WHERE total < 0 OR spent < 0 OR exposure < 0 OR remaining_floor < 0",
            [],
            |row| row.get(0),
        )?;
        if invalid_budget_count > 0 {
            findings.push(format!(
                "{invalid_budget_count} budget account(s) violate non-negative invariants"
            ));
        }
        let interrupted_dispatches: i64 = connection.query_row(
            "SELECT COUNT(*) FROM campaign_dispatch_permits WHERE campaign_id=?1 AND status='interrupted'",
            params![campaign_id],
            |row| row.get(0),
        )?;
        if interrupted_dispatches > 0 {
            findings.push(format!(
                "{interrupted_dispatches} dispatch permit(s) require provider reconciliation"
            ));
        }
        Ok(findings)
    }

    pub fn authorize_campaign_dispatch(
        &self,
        campaign_id: &str,
        request: &AuthorizeCampaignDispatchRequest,
    ) -> Result<CampaignDispatchPermit> {
        request.validate()?;
        let now = Utc::now();
        let now_text = now.to_rfc3339();
        let deadline_at = (now
            + chrono::Duration::seconds(i64::try_from(request.maximum_elapsed_seconds)?))
        .to_rfc3339();
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let governor = transaction
            .query_row(
                "SELECT contract,campaign_id,generation,status,last_reconciliation_sha256,blocked_reason,updated_at FROM campaign_governors WHERE campaign_id=?1",
                params![campaign_id],
                campaign_governor_from_row,
            )
            .context("campaign has no active supervision governor")?;
        anyhow::ensure!(
            governor.status == GovernorStatus::Open,
            "campaign dispatch is closed while governor is {}",
            governor.status.as_str()
        );
        anyhow::ensure!(
            governor.generation == request.generation,
            "campaign generation conflict: expected {}, received {}",
            governor.generation,
            request.generation
        );
        let reconciliation_sha256 = governor
            .last_reconciliation_sha256
            .context("campaign dispatch requires a clean reconciliation")?;
        let services = campaign_service_leases_tx(&transaction, campaign_id, governor.generation)?;
        let live_roles = services
            .iter()
            .filter_map(|lease| {
                lease
                    .is_live_at(now)
                    .ok()
                    .filter(|live| *live)
                    .map(|_| lease.role)
            })
            .collect::<std::collections::BTreeSet<_>>();
        for role in SupervisorRole::REQUIRED {
            anyhow::ensure!(
                live_roles.contains(&role),
                "campaign dispatch is closed: {} singleton is missing or stale",
                role.as_str()
            );
        }
        let interrupted_count: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM campaign_dispatch_permits WHERE campaign_id=?1 AND status='interrupted'",
            params![campaign_id],
            |row| row.get(0),
        )?;
        anyhow::ensure!(
            interrupted_count == 0,
            "campaign dispatch is closed: {interrupted_count} interrupted permit(s) require provider reconciliation"
        );
        if let Some(budget_id) = request
            .budget_id
            .as_deref()
            .filter(|_| !request.budget_pre_reserved)
        {
            let remaining: f64 = transaction
                .query_row(
                    "SELECT remaining_floor FROM budgets WHERE id=?1",
                    params![budget_id],
                    |row| row.get(0),
                )
                .with_context(|| format!("unknown dispatch budget {budget_id}"))?;
            anyhow::ensure!(
                request.maximum_cost_usd <= remaining,
                "dispatch maximum cost ${:.2} exceeds remaining floor ${remaining:.2}",
                request.maximum_cost_usd
            );
        }
        let existing: Option<String> = transaction
            .query_row(
                "SELECT record_json FROM campaign_dispatch_permits WHERE campaign_id=?1 AND generation=?2 AND idempotency_key=?3",
                params![campaign_id, i64::try_from(request.generation)?, request.idempotency_key],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            let permit: CampaignDispatchPermit = serde_json::from_str(&existing)?;
            anyhow::ensure!(
                permit.operation == request.operation
                    && permit.target_id == request.target_id
                    && permit.budget_id == request.budget_id
                    && permit.maximum_cost_usd == request.maximum_cost_usd
                    && permit.reserve_budget == request.reserve_budget
                    && permit.budget_pre_reserved == request.budget_pre_reserved
                    && permit.epact == request.epact,
                "dispatch idempotency key was reused for a different operation"
            );
            transaction.commit()?;
            return Ok(permit);
        }
        let epact_requested_at = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        enforce_epact_dispatch_tx(&transaction, campaign_id, request, &epact_requested_at)?;
        if request.reserve_budget {
            let budget_id = request
                .budget_id
                .as_deref()
                .context("permit reservation requires a budget id")?;
            let changed = transaction.execute(
                "UPDATE budgets SET exposure=exposure+?2,remaining_floor=remaining_floor-?2,updated_at=?3 WHERE id=?1 AND remaining_floor>=?2",
                params![budget_id, request.maximum_cost_usd, now_text],
            )?;
            anyhow::ensure!(
                changed == 1,
                "dispatch budget changed before reservation could be committed"
            );
        }
        let token = format!("dispatch_{}", Uuid::new_v4().simple());
        let permit = CampaignDispatchPermit {
            contract: CAMPAIGN_DISPATCH_PERMIT_CONTRACT.to_owned(),
            token: token.clone(),
            campaign_id: campaign_id.to_owned(),
            generation: request.generation,
            idempotency_key: request.idempotency_key.clone(),
            actor: request.actor.trim().to_owned(),
            operation: request.operation,
            target_id: request.target_id.trim().to_owned(),
            budget_id: request.budget_id.clone(),
            maximum_cost_usd: request.maximum_cost_usd,
            reserve_budget: request.reserve_budget,
            budget_pre_reserved: request.budget_pre_reserved,
            epact: request.epact.clone(),
            reconciliation_sha256,
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
        transaction.execute(
            "INSERT INTO campaign_dispatch_permits(token,campaign_id,generation,idempotency_key,operation,target_id,record_json,status,consumed_at,settled_cost_usd,updated_at,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,'authorized',NULL,NULL,?8,?8)",
            params![token, campaign_id, i64::try_from(request.generation)?, request.idempotency_key, request.operation.as_str(), request.target_id, serde_json::to_string(&permit)?, now_text],
        )?;
        transaction.commit()?;
        Ok(permit)
    }

    /// The only successful transition from a dispatch permit to an external start. Exactly one
    /// caller can consume a token; retries observe the durable consumed record and fail closed.
    pub fn consume_campaign_dispatch(&self, token: &str) -> Result<CampaignDispatchPermit> {
        let now = Utc::now();
        let now_text = now.to_rfc3339();
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (raw, stored_status): (String, String) = transaction
            .query_row(
                "SELECT record_json,status FROM campaign_dispatch_permits WHERE token=?1",
                params![token],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .context("unknown campaign dispatch token")?;
        let mut permit: CampaignDispatchPermit = serde_json::from_str(&raw)?;
        permit.status = DispatchPermitStatus::parse(&stored_status)?;
        anyhow::ensure!(
            permit.status == DispatchPermitStatus::Authorized && permit.consumed_at.is_none(),
            "campaign dispatch token is not awaiting consumption"
        );
        let deadline = dispatch_permit_deadline(&permit)?;
        anyhow::ensure!(
            deadline > now,
            "campaign dispatch token expired before consumption"
        );
        let governor = transaction.query_row(
            "SELECT contract,campaign_id,generation,status,last_reconciliation_sha256,blocked_reason,updated_at FROM campaign_governors WHERE campaign_id=?1",
            params![permit.campaign_id],
            campaign_governor_from_row,
        )?;
        anyhow::ensure!(
            governor.status == GovernorStatus::Open
                && governor.generation == permit.generation
                && governor.last_reconciliation_sha256.as_deref()
                    == Some(permit.reconciliation_sha256.as_str()),
            "dispatch permit is no longer bound to the open reconciled generation"
        );
        anyhow::ensure!(
            !campaign_supervision_is_stale_tx(&transaction, &permit.campaign_id, now)?,
            "dispatch permit cannot be consumed while supervision is stale"
        );
        permit.consumed_at = Some(now_text.clone());
        permit.status = DispatchPermitStatus::Consumed;
        let changed = transaction.execute(
            "UPDATE campaign_dispatch_permits SET record_json=?2,status='consumed',consumed_at=?3,updated_at=?3 WHERE token=?1 AND status='authorized' AND consumed_at IS NULL",
            params![token, serde_json::to_string(&permit)?, now_text],
        )?;
        anyhow::ensure!(
            changed == 1,
            "campaign dispatch token lost its single-consumer race"
        );
        transaction.commit()?;
        Ok(permit)
    }

    pub fn settle_campaign_dispatch(
        &self,
        token: &str,
        actual_cost_usd: f64,
        settlement_basis: &str,
    ) -> Result<CampaignDispatchPermit> {
        anyhow::ensure!(
            actual_cost_usd.is_finite() && actual_cost_usd >= 0.0,
            "dispatch settlement cost must be finite and non-negative"
        );
        let settlement_basis = settlement_basis.trim();
        anyhow::ensure!(
            !settlement_basis.is_empty() && settlement_basis.len() <= 240,
            "dispatch settlement basis is required and must be at most 240 bytes"
        );
        let now = Utc::now().to_rfc3339();
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (raw, stored_status): (String, String) = transaction
            .query_row(
                "SELECT record_json,status FROM campaign_dispatch_permits WHERE token=?1",
                params![token],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .context("unknown campaign dispatch token")?;
        let mut permit: CampaignDispatchPermit = serde_json::from_str(&raw)?;
        permit.status = DispatchPermitStatus::parse(&stored_status)?;
        if permit.status == DispatchPermitStatus::Settled {
            anyhow::ensure!(
                permit.actual_cost_usd == Some(actual_cost_usd)
                    && permit.settlement_basis.as_deref() == Some(settlement_basis),
                "dispatch settlement was repeated with different provider evidence"
            );
            transaction.commit()?;
            return Ok(permit);
        }
        anyhow::ensure!(
            matches!(
                permit.status,
                DispatchPermitStatus::Consumed | DispatchPermitStatus::Interrupted
            ),
            "dispatch permit is not consumable settlement state"
        );
        if permit.reserve_budget {
            let budget_id = permit
                .budget_id
                .as_deref()
                .context("reserved dispatch permit lost its budget id")?;
            transaction.execute(
                r#"UPDATE budgets SET
                    spent=spent+?2,
                    exposure=MAX(0,exposure-?3),
                    remaining_floor=remaining_floor+(?3-?2),
                    updated_at=?4
                WHERE id=?1"#,
                params![budget_id, actual_cost_usd, permit.maximum_cost_usd, now],
            )?;
        }
        permit.status = DispatchPermitStatus::Settled;
        permit.settled_at = Some(now.clone());
        permit.actual_cost_usd = Some(actual_cost_usd);
        permit.settlement_basis = Some(settlement_basis.to_owned());
        permit.interruption = None;
        if actual_cost_usd > permit.maximum_cost_usd + 1e-9 {
            transaction.execute(
                "UPDATE campaign_governors SET status='blocked',blocked_reason=?2,updated_at=?3 WHERE campaign_id=?1 AND status IN ('open','reconciling')",
                params![permit.campaign_id, format!("dispatch cost overrun: ${actual_cost_usd:.6} settled against ${:.6} authorization", permit.maximum_cost_usd), now],
            )?;
        }
        let changed = transaction.execute(
            "UPDATE campaign_dispatch_permits SET record_json=?2,status='settled',settled_cost_usd=?3,updated_at=?4 WHERE token=?1 AND status IN ('consumed','interrupted')",
            params![token, serde_json::to_string(&permit)?, actual_cost_usd, now],
        )?;
        anyhow::ensure!(
            changed == 1,
            "dispatch settlement lost its terminal transition race"
        );
        transaction.commit()?;
        Ok(permit)
    }

    pub fn interrupt_campaign_dispatch(
        &self,
        token: &str,
        reason: &str,
    ) -> Result<CampaignDispatchPermit> {
        let reason = reason.trim();
        anyhow::ensure!(
            !reason.is_empty() && reason.len() <= 2_000,
            "dispatch interruption reason is required and must be at most 2000 bytes"
        );
        let now = Utc::now().to_rfc3339();
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (raw, stored_status): (String, String) = transaction
            .query_row(
                "SELECT record_json,status FROM campaign_dispatch_permits WHERE token=?1",
                params![token],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .context("unknown campaign dispatch token")?;
        let mut permit: CampaignDispatchPermit = serde_json::from_str(&raw)?;
        permit.status = DispatchPermitStatus::parse(&stored_status)?;
        if permit.status == DispatchPermitStatus::Interrupted {
            transaction.commit()?;
            return Ok(permit);
        }
        anyhow::ensure!(
            permit.status == DispatchPermitStatus::Consumed,
            "only a consumed dispatch can become interrupted"
        );
        permit.status = DispatchPermitStatus::Interrupted;
        permit.interruption = Some(reason.to_owned());
        transaction.execute(
            "UPDATE campaign_governors SET status='blocked',blocked_reason=?2,updated_at=?3 WHERE campaign_id=?1 AND status IN ('open','reconciling')",
            params![permit.campaign_id, format!("interrupted dispatch {} requires provider reconciliation", permit.token), now],
        )?;
        let changed = transaction.execute(
            "UPDATE campaign_dispatch_permits SET record_json=?2,status='interrupted',updated_at=?3 WHERE token=?1 AND status='consumed'",
            params![token, serde_json::to_string(&permit)?, now],
        )?;
        anyhow::ensure!(
            changed == 1,
            "dispatch interruption lost its transition race"
        );
        transaction.commit()?;
        Ok(permit)
    }

    pub fn resolve_interrupted_campaign_dispatch(
        &self,
        campaign_id: &str,
        token: &str,
        request: &ResolveInterruptedDispatchRequest,
    ) -> Result<CampaignDispatchPermit> {
        request.validate()?;
        let now = Utc::now().to_rfc3339();
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (raw, stored_status): (String, String) = transaction
            .query_row(
                "SELECT record_json,status FROM campaign_dispatch_permits WHERE token=?1",
                params![token],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .context("unknown campaign dispatch token")?;
        let mut permit: CampaignDispatchPermit = serde_json::from_str(&raw)?;
        permit.status = DispatchPermitStatus::parse(&stored_status)?;
        anyhow::ensure!(
            permit.campaign_id == campaign_id,
            "dispatch permit belongs to a different campaign"
        );
        anyhow::ensure!(
            permit.status == DispatchPermitStatus::Interrupted,
            "dispatch permit is not awaiting interruption resolution"
        );
        permit.resolution_evidence_sha256 = Some(request.evidence_sha256.clone());
        permit.resolved_by = Some(request.actor.trim().to_owned());
        match request.resolution {
            InterruptedDispatchResolution::NoProviderStart => {
                if permit.reserve_budget {
                    let budget_id = permit
                        .budget_id
                        .as_deref()
                        .context("reserved dispatch permit lost its budget id")?;
                    transaction.execute(
                        "UPDATE budgets SET exposure=MAX(0,exposure-?2),remaining_floor=remaining_floor+?2,updated_at=?3 WHERE id=?1",
                        params![budget_id, permit.maximum_cost_usd, now],
                    )?;
                }
                permit.status = DispatchPermitStatus::Released;
                permit.released_at = Some(now.clone());
                permit.settlement_basis = Some("verified_no_provider_start".to_owned());
                transaction.execute(
                    "UPDATE campaign_dispatch_permits SET record_json=?2,status='released',updated_at=?3 WHERE token=?1 AND status='interrupted'",
                    params![token, serde_json::to_string(&permit)?, now],
                )?;
            }
            InterruptedDispatchResolution::ProviderSettled => {
                let actual_cost_usd = request
                    .actual_cost_usd
                    .context("provider settlement cost disappeared after validation")?;
                let settlement_basis = request
                    .settlement_basis
                    .as_deref()
                    .context("provider settlement basis disappeared after validation")?;
                if permit.reserve_budget {
                    let budget_id = permit
                        .budget_id
                        .as_deref()
                        .context("reserved dispatch permit lost its budget id")?;
                    transaction.execute(
                        r#"UPDATE budgets SET
                            spent=spent+?2,
                            exposure=MAX(0,exposure-?3),
                            remaining_floor=remaining_floor+(?3-?2),
                            updated_at=?4
                        WHERE id=?1"#,
                        params![budget_id, actual_cost_usd, permit.maximum_cost_usd, now],
                    )?;
                }
                permit.status = DispatchPermitStatus::Settled;
                permit.settled_at = Some(now.clone());
                permit.actual_cost_usd = Some(actual_cost_usd);
                permit.settlement_basis = Some(settlement_basis.to_owned());
                permit.interruption = None;
                if actual_cost_usd > permit.maximum_cost_usd + 1e-9 {
                    transaction.execute(
                        "UPDATE campaign_governors SET status='blocked',blocked_reason=?2,updated_at=?3 WHERE campaign_id=?1 AND status IN ('open','reconciling')",
                        params![permit.campaign_id, format!("resolved dispatch cost overrun: ${actual_cost_usd:.6} settled against ${:.6} authorization", permit.maximum_cost_usd), now],
                    )?;
                }
                transaction.execute(
                    "UPDATE campaign_dispatch_permits SET record_json=?2,status='settled',settled_cost_usd=?3,updated_at=?4 WHERE token=?1 AND status='interrupted'",
                    params![token, serde_json::to_string(&permit)?, actual_cost_usd, now],
                )?;
            }
        }
        transaction.commit()?;
        Ok(permit)
    }

    pub fn release_campaign_dispatch(&self, token: &str) -> Result<CampaignDispatchPermit> {
        let now = Utc::now().to_rfc3339();
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (raw, stored_status): (String, String) = transaction
            .query_row(
                "SELECT record_json,status FROM campaign_dispatch_permits WHERE token=?1",
                params![token],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .context("unknown campaign dispatch token")?;
        let mut permit: CampaignDispatchPermit = serde_json::from_str(&raw)?;
        permit.status = DispatchPermitStatus::parse(&stored_status)?;
        if permit.status == DispatchPermitStatus::Released {
            transaction.commit()?;
            return Ok(permit);
        }
        anyhow::ensure!(
            permit.status == DispatchPermitStatus::Authorized && permit.consumed_at.is_none(),
            "only an unconsumed authorization can release its reservation"
        );
        if permit.reserve_budget {
            let budget_id = permit
                .budget_id
                .as_deref()
                .context("reserved dispatch permit lost its budget id")?;
            transaction.execute(
                "UPDATE budgets SET exposure=MAX(0,exposure-?2),remaining_floor=remaining_floor+?2,updated_at=?3 WHERE id=?1",
                params![budget_id, permit.maximum_cost_usd, now],
            )?;
        }
        permit.status = DispatchPermitStatus::Released;
        permit.released_at = Some(now.clone());
        let changed = transaction.execute(
            "UPDATE campaign_dispatch_permits SET record_json=?2,status='released',updated_at=?3 WHERE token=?1 AND status='authorized' AND consumed_at IS NULL",
            params![token, serde_json::to_string(&permit)?, now],
        )?;
        anyhow::ensure!(changed == 1, "dispatch release lost its transition race");
        transaction.commit()?;
        Ok(permit)
    }

    pub fn reap_stale_campaign_dispatches(
        &self,
        observed_at: chrono::DateTime<Utc>,
    ) -> Result<DispatchReapSummary> {
        let connection = self.connect()?;
        let candidates = read_all(
            &connection,
            "SELECT token,status,record_json FROM campaign_dispatch_permits WHERE status IN ('authorized','consumed') ORDER BY updated_at,token",
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)),
        )?;
        drop(connection);
        let mut summary = DispatchReapSummary::default();
        for (token, stored_status, raw) in candidates {
            let mut permit: CampaignDispatchPermit = serde_json::from_str(&raw)?;
            permit.status = DispatchPermitStatus::parse(&stored_status)?;
            if dispatch_permit_deadline(&permit)? > observed_at {
                continue;
            }
            match permit.status {
                DispatchPermitStatus::Authorized => {
                    self.release_campaign_dispatch(&token)?;
                    summary.released += 1;
                }
                DispatchPermitStatus::Consumed => {
                    self.interrupt_campaign_dispatch(
                        &token,
                        "dispatch deadline expired without provider settlement; reconciliation required",
                    )?;
                    summary.interrupted += 1;
                }
                _ => {}
            }
        }
        Ok(summary)
    }

    pub fn campaign_dispatch_permit(&self, token: &str) -> Result<Option<CampaignDispatchPermit>> {
        self.connect()?
            .query_row(
                "SELECT record_json,status FROM campaign_dispatch_permits WHERE token=?1",
                params![token],
                |row| {
                    let raw: String = row.get(0)?;
                    let status: String = row.get(1)?;
                    let mut permit: CampaignDispatchPermit = parse_json(raw, 0)?;
                    permit.status = DispatchPermitStatus::parse(&status).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            rusqlite::types::Type::Text,
                            error.into(),
                        )
                    })?;
                    Ok(permit)
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn campaign_dispatch_permits(
        &self,
        campaign_id: &str,
    ) -> Result<Vec<CampaignDispatchPermit>> {
        let connection = self.connect()?;
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM campaigns WHERE id=?1)",
            params![campaign_id],
            |row| row.get(0),
        )?;
        anyhow::ensure!(exists, "unknown campaign {campaign_id}");
        read_all_for_campaign(
            &connection,
            "SELECT record_json,status FROM campaign_dispatch_permits WHERE campaign_id=?1 ORDER BY created_at DESC,token LIMIT 500",
            campaign_id,
            |row| {
                let raw: String = row.get(0)?;
                let status: String = row.get(1)?;
                let mut permit: CampaignDispatchPermit = parse_json(raw, 0)?;
                permit.status = DispatchPermitStatus::parse(&status).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Text,
                        error.into(),
                    )
                })?;
                Ok(permit)
            },
        )
    }

    pub fn reconcile_campaign_supervision(
        &self,
        campaign_id: &str,
        request: &ReconcileCampaignRequest,
    ) -> Result<CampaignSupervisionSnapshot> {
        request.validate()?;
        let now = Utc::now();
        let now_text = now.to_rfc3339();
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let governor = transaction
            .query_row(
                "SELECT contract,campaign_id,generation,status,last_reconciliation_sha256,blocked_reason,updated_at FROM campaign_governors WHERE campaign_id=?1",
                params![campaign_id],
                campaign_governor_from_row,
            )
            .context("campaign recovery has not been initialized")?;
        anyhow::ensure!(
            governor.status == GovernorStatus::Reconciling,
            "campaign reconciliation requires a reconciling governor"
        );
        anyhow::ensure!(
            governor.generation == request.generation,
            "campaign generation conflict: expected {}, received {}",
            governor.generation,
            request.generation
        );
        let services = campaign_service_leases_tx(&transaction, campaign_id, governor.generation)?;
        let service_by_role = services
            .iter()
            .map(|service| (service.role, service))
            .collect::<std::collections::BTreeMap<_, _>>();
        for role in SupervisorRole::REQUIRED {
            let service = service_by_role
                .get(&role)
                .with_context(|| format!("missing {} singleton service", role.as_str()))?;
            anyhow::ensure!(
                service.is_live_at(now)?,
                "{} singleton service lease is stale",
                role.as_str()
            );
        }
        let reconciler = service_by_role
            .get(&SupervisorRole::Reconciler)
            .context("missing reconciler singleton service")?;
        anyhow::ensure!(
            reconciler.owner_id == request.reconciler_owner_id.trim(),
            "reconciliation owner does not hold the reconciler lease"
        );
        let mut record = CampaignReconciliation::build(campaign_id, request, &now_text)?;
        let existing: Option<String> = transaction
            .query_row(
                "SELECT record_json FROM campaign_reconciliations WHERE reconciliation_sha256=?1",
                params![record.reconciliation_sha256],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            let existing: CampaignReconciliation = serde_json::from_str(&existing)?;
            // Observation time is not hash-bound. Reusing unchanged evidence in a scheduled cycle
            // must recover the original immutable record rather than manufacture a collision.
            record.created_at = existing.created_at.clone();
            anyhow::ensure!(existing == record, "reconciliation identity collision");
            record = existing;
        } else {
            transaction.execute(
                "INSERT INTO campaign_reconciliations(id,campaign_id,generation,reconciliation_sha256,record_json,created_at) VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    record.id,
                    campaign_id,
                    i64::try_from(record.generation)?,
                    record.reconciliation_sha256,
                    serde_json::to_string(&record)?,
                    record.created_at,
                ],
            )?;
        }
        let (status, blocked_reason) = match record.disposition {
            ReconciliationDisposition::Clean => (GovernorStatus::Open, None),
            ReconciliationDisposition::Blocked => {
                (GovernorStatus::Blocked, Some(record.findings.join("; ")))
            }
        };
        transaction.execute(
            "UPDATE campaign_governors SET status=?2,last_reconciliation_sha256=?3,blocked_reason=?4,updated_at=?5 WHERE campaign_id=?1",
            params![
                campaign_id,
                status.as_str(),
                record.reconciliation_sha256,
                blocked_reason,
                now_text,
            ],
        )?;
        transaction.commit()?;
        self.campaign_supervision_snapshot(campaign_id, now)
    }

    pub fn closeout_campaign(
        &self,
        campaign_id: &str,
        request: &CloseoutCampaignRequest,
    ) -> Result<CampaignCloseout> {
        request.validate()?;
        let now = Utc::now();
        let record = CampaignCloseout::build(campaign_id, request, &now.to_rfc3339())?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = transaction
            .query_row(
                "SELECT record_json FROM campaign_closeouts WHERE campaign_id=?1",
                params![campaign_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            let existing: CampaignCloseout = serde_json::from_str(&existing)?;
            anyhow::ensure!(
                existing.closeout_sha256 == record.closeout_sha256,
                "campaign already has a different frozen closeout"
            );
            transaction.commit()?;
            return Ok(existing);
        }
        let governor = transaction
            .query_row(
                "SELECT contract,campaign_id,generation,status,last_reconciliation_sha256,blocked_reason,updated_at FROM campaign_governors WHERE campaign_id=?1",
                params![campaign_id],
                campaign_governor_from_row,
            )
            .context("campaign recovery has not been initialized")?;
        anyhow::ensure!(
            governor.status == GovernorStatus::Open
                && governor.last_reconciliation_sha256.is_some(),
            "campaign governor is not open and healthy"
        );
        anyhow::ensure!(
            governor.generation == request.generation,
            "campaign generation conflict: expected {}, received {}",
            governor.generation,
            request.generation
        );
        let services = campaign_service_leases_tx(&transaction, campaign_id, governor.generation)?;
        let mut live_roles = std::collections::BTreeSet::new();
        for service in &services {
            if service.is_live_at(now)? {
                live_roles.insert(service.role);
            }
        }
        let missing_roles = SupervisorRole::REQUIRED
            .into_iter()
            .filter(|role| !live_roles.contains(role))
            .map(SupervisorRole::as_str)
            .collect::<Vec<_>>();
        anyhow::ensure!(
            missing_roles.is_empty(),
            "campaign singleton services are missing or stale: {}",
            missing_roles.join(", ")
        );
        transaction.execute(
            "INSERT INTO campaign_closeouts(id,campaign_id,closeout_sha256,record_json,created_at) VALUES (?1,?2,?3,?4,?5)",
            params![
                record.id,
                campaign_id,
                record.closeout_sha256,
                serde_json::to_string(&record)?,
                record.created_at,
            ],
        )?;
        transaction.execute(
            "UPDATE campaign_governors SET status='closed',blocked_reason=?2,updated_at=?3 WHERE campaign_id=?1",
            params![
                campaign_id,
                format!("transactional closeout frozen: {}", record.closeout_sha256),
                now.to_rfc3339(),
            ],
        )?;
        transaction.commit()?;
        Ok(record)
    }

    pub fn append_agent_event(
        &self,
        agent_run_id: &str,
        expected_revision: u64,
        idempotency_key: &str,
        kind: AgentEventKind,
        payload: Value,
    ) -> Result<AgentRunEnvelope> {
        anyhow::ensure!(
            !idempotency_key.trim().is_empty(),
            "idempotency key is required"
        );
        let mut connection = self.connect()?;
        // Claim the single SQLite writer before reading the run revision. A deferred transaction
        // can read successfully and then fail immediately while upgrading to a writer when
        // independent agent children advance concurrently.
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = transaction
            .query_row(
                "SELECT contract,id,agent_run_id,sequence,idempotency_key,kind,from_status,to_status,payload_json,previous_event_sha256,event_sha256,created_at FROM agent_events WHERE agent_run_id=?1 AND idempotency_key=?2",
                params![agent_run_id, idempotency_key],
                agent_event_from_row,
            )
            .optional()?;
        if let Some(existing) = existing {
            anyhow::ensure!(
                existing.kind == kind && existing.payload == payload,
                "agent event idempotency key was reused with different content"
            );
            transaction.commit()?;
            return self
                .agent_run_envelope(agent_run_id)?
                .context("agent run disappeared after idempotent event read");
        }
        let mut run = transaction
            .query_row(
                "SELECT contract,id,campaign_id,provider_id,model,task,allowed_tools_json,budget_json,status,revision,model_calls,tool_calls,parent_run_id,parent_event_hash,created_at,updated_at,epact_json FROM agent_runs WHERE id=?1",
                params![agent_run_id],
                agent_run_from_row,
            )
            .optional()?
            .context("unknown agent run")?;
        anyhow::ensure!(
            run.revision == expected_revision,
            "agent revision conflict: expected {expected_revision}, current {}",
            run.revision
        );
        if kind == AgentEventKind::ModelRequested {
            crate::epact::enforce_epact_agent_binding_tx(
                &transaction,
                &run.campaign_id,
                run.epact.as_ref(),
                &run.budget,
            )?;
            anyhow::ensure!(
                run.model_calls < run.budget.max_model_calls,
                "agent model-call budget exhausted"
            );
            run.model_calls += 1;
        }
        if kind == AgentEventKind::ToolStarted {
            anyhow::ensure!(
                run.tool_calls < run.budget.max_tool_calls,
                "agent tool-call budget exhausted"
            );
            run.tool_calls += 1;
        }
        let previous_hash: Option<String> = transaction.query_row(
            "SELECT event_sha256 FROM agent_events WHERE agent_run_id=?1 ORDER BY sequence DESC LIMIT 1",
            params![agent_run_id],
            |row| row.get(0),
        )?;
        let now = Utc::now().to_rfc3339();
        let event = AgentEvent::build(
            format!("agent_event_{}", Uuid::new_v4().simple()),
            agent_run_id.to_owned(),
            run.revision + 1,
            idempotency_key.to_owned(),
            kind,
            run.status,
            payload,
            previous_hash,
            now.clone(),
        )?;
        run.status = event.to_status;
        run.revision = event.sequence;
        run.updated_at = now;
        insert_agent_event_tx(&transaction, &event)?;
        transaction.execute(
            "UPDATE agent_runs SET status=?2,revision=?3,model_calls=?4,tool_calls=?5,updated_at=?6 WHERE id=?1",
            params![
                run.id,
                agent_status_name(run.status)?,
                i64::try_from(run.revision)?,
                i64::from(run.model_calls),
                i64::from(run.tool_calls),
                run.updated_at,
            ],
        )?;
        if run.status.is_terminal() {
            let reservation: Option<(String, f64, f64)> = transaction
                .query_row(
                    "SELECT budget_id,reserved_usd,estimated_spent_usd FROM agent_budget_reservations WHERE agent_run_id=?1 AND status='reserved'",
                    params![run.id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            if let Some((budget_id, reserved, estimated_spent)) = reservation {
                transaction.execute(
                    "UPDATE budgets SET exposure=MAX(0,exposure-?2),remaining_floor=remaining_floor+(?2-?3),updated_at=?4 WHERE id=?1",
                    params![budget_id, reserved, estimated_spent, run.updated_at],
                )?;
                transaction.execute(
                    "UPDATE agent_budget_reservations SET status='settled_estimate',updated_at=?2 WHERE agent_run_id=?1",
                    params![run.id, run.updated_at],
                )?;
            }
        }
        transaction.commit()?;
        self.agent_run_envelope(agent_run_id)?
            .context("agent run disappeared after event append")
    }

    pub fn fork_agent_run(
        &self,
        parent_run_id: &str,
        expected_revision: u64,
        idempotency_key: &str,
        task: Option<&str>,
        allowed_tools: Option<&[String]>,
        budget: Option<&AgentBudget>,
        authority_rationale: Option<&str>,
    ) -> Result<AgentRunEnvelope> {
        anyhow::ensure!(
            !idempotency_key.trim().is_empty(),
            "fork idempotency key is required"
        );
        let digest = Sha256::digest(format!("{parent_run_id}\0{idempotency_key}").as_bytes());
        let child_id = format!("agent_fork_{:x}", digest);
        let child_id = child_id[..35].to_owned();
        if let Some(existing) = self.agent_run_envelope(&child_id)? {
            anyhow::ensure!(
                existing.run.parent_run_id.as_deref() == Some(parent_run_id),
                "fork identity collision"
            );
            if let Some(task) = task.map(str::trim).filter(|value| !value.is_empty()) {
                anyhow::ensure!(
                    existing.run.task == task,
                    "fork idempotency key was reused with a different task"
                );
            }
            if let Some(allowed_tools) = allowed_tools {
                anyhow::ensure!(
                    existing.run.allowed_tools == allowed_tools,
                    "fork idempotency key was reused with different tools"
                );
            }
            if let Some(budget) = budget {
                anyhow::ensure!(
                    existing.run.budget == *budget,
                    "fork idempotency key was reused with a different budget"
                );
            }
            if !existing.run.status.is_terminal()
                && existing
                    .run
                    .budget
                    .max_cost_usd
                    .is_some_and(|value| value > 0.0)
                && self.agent_budget_reservation(&existing.run.id)?.is_none()
            {
                let mut connection = self.connect()?;
                let transaction = connection.transaction()?;
                ensure_agent_fork_budget_reservation_tx(
                    &transaction,
                    &existing.run,
                    &Utc::now().to_rfc3339(),
                )?;
                transaction.commit()?;
            }
            return Ok(existing);
        }
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        let parent = transaction
            .query_row(
                "SELECT contract,id,campaign_id,provider_id,model,task,allowed_tools_json,budget_json,status,revision,model_calls,tool_calls,parent_run_id,parent_event_hash,created_at,updated_at,epact_json FROM agent_runs WHERE id=?1",
                params![parent_run_id],
                agent_run_from_row,
            )
            .optional()?
            .context("unknown parent agent run")?;
        anyhow::ensure!(
            parent.revision == expected_revision,
            "agent revision conflict: expected {expected_revision}, current {}",
            parent.revision
        );
        let parent_hash: String = transaction.query_row(
            "SELECT event_sha256 FROM agent_events WHERE agent_run_id=?1 ORDER BY sequence DESC LIMIT 1",
            params![parent_run_id],
            |row| row.get(0),
        )?;
        let child_allowed_tools = allowed_tools
            .map(<[String]>::to_vec)
            .unwrap_or_else(|| parent.allowed_tools.clone());
        let child_budget = budget.cloned().unwrap_or_else(|| parent.budget.clone());
        let authority_changed =
            child_allowed_tools != parent.allowed_tools || child_budget != parent.budget;
        let authority_rationale = authority_rationale
            .map(str::trim)
            .filter(|value| !value.is_empty());
        if authority_changed {
            anyhow::ensure!(
                authority_rationale.is_some(),
                "fork authority changes require an explicit rationale"
            );
        }
        if let Some(rationale) = authority_rationale {
            anyhow::ensure!(
                rationale.chars().count() <= 2_000,
                "fork authority rationale exceeds 2000 characters"
            );
        }
        CreateAgentRunRequest {
            campaign_id: parent.campaign_id.clone(),
            provider_id: parent.provider_id.clone(),
            model: Some(parent.model.clone()),
            task: task
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or(&parent.task)
                .to_owned(),
            allowed_tools: child_allowed_tools.clone(),
            budget: child_budget.clone(),
            epact: parent.epact.clone(),
            parent_run_id: Some(parent.id.clone()),
            parent_event_hash: Some(parent_hash.clone()),
        }
        .validate()?;
        crate::epact::enforce_epact_agent_binding_tx(
            &transaction,
            &parent.campaign_id,
            parent.epact.as_ref(),
            &child_budget,
        )?;
        let now = Utc::now().to_rfc3339();
        let child = AgentRun {
            contract: AGENT_RUN_CONTRACT.to_owned(),
            id: child_id,
            campaign_id: parent.campaign_id,
            provider_id: parent.provider_id,
            model: parent.model,
            task: task
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or(&parent.task)
                .to_owned(),
            allowed_tools: child_allowed_tools,
            budget: child_budget,
            epact: parent.epact.clone(),
            status: AgentRunStatus::Ready,
            revision: 0,
            model_calls: 0,
            tool_calls: 0,
            parent_run_id: Some(parent.id),
            parent_event_hash: Some(parent_hash.clone()),
            created_at: now.clone(),
            updated_at: now.clone(),
        };
        insert_agent_run_tx(&transaction, &child)?;
        ensure_agent_fork_budget_reservation_tx(&transaction, &child, &now)?;
        let created = AgentEvent::build(
            format!("agent_event_{}", Uuid::new_v4().simple()),
            child.id.clone(),
            0,
            format!("fork:{idempotency_key}"),
            AgentEventKind::RunCreated,
            AgentRunStatus::Ready,
            json!({
                "forkedFromRunId": child.parent_run_id,
                "forkedFromEventHash": parent_hash,
                "task": child.task,
                "epact": child.epact,
                "authorityChanged": authority_changed,
                "authorityRationale": authority_rationale,
                "parentAuthority": {
                    "allowedTools": parent.allowed_tools,
                    "budget": parent.budget,
                },
                "childAuthority": {
                    "allowedTools": child.allowed_tools,
                    "budget": child.budget,
                },
            }),
            child.parent_event_hash.clone(),
            now,
        )?;
        insert_agent_event_tx(&transaction, &created)?;
        transaction.commit()?;
        Ok(AgentRunEnvelope {
            run: child,
            events: vec![created],
        })
    }

    pub fn record_research_exchange(
        &self,
        user_message: &SemanticObject,
        assistant_message: &SemanticObject,
        relation: &SemanticRelation,
        action: &ActionRecord,
    ) -> Result<()> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        upsert_semantic_object_tx(&transaction, user_message)?;
        upsert_semantic_object_tx(&transaction, assistant_message)?;
        upsert_semantic_relation_tx(&transaction, relation)?;
        upsert_action_tx(&transaction, action)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn create_note(&self, request: &CreateNoteRequest) -> Result<NoteResponse> {
        let campaign_id = request.campaign_id.trim();
        let category = request.category.trim().to_ascii_lowercase();
        let severity = request.severity.trim().to_ascii_lowercase();
        let title = request.title.trim();
        let body = request.body.trim();
        let actor = request.actor.trim();
        anyhow::ensure!(!campaign_id.is_empty(), "campaignId is required");
        anyhow::ensure!(
            matches!(
                category.as_str(),
                "mistake"
                    | "warning"
                    | "rationale"
                    | "observation"
                    | "lesson"
                    | "decision"
                    | "handoff"
            ),
            "unsupported note category {category}"
        );
        anyhow::ensure!(
            matches!(severity.as_str(), "critical" | "high" | "normal" | "low"),
            "unsupported note severity {severity}"
        );
        anyhow::ensure!(
            !title.is_empty() && title.chars().count() <= 240,
            "note title must contain between 1 and 240 characters"
        );
        anyhow::ensure!(
            !body.is_empty() && body.chars().count() <= 32_000,
            "note body must contain between 1 and 32000 characters"
        );
        anyhow::ensure!(
            !actor.is_empty() && actor.chars().count() <= 160,
            "note actor must contain between 1 and 160 characters"
        );
        anyhow::ensure!(
            request.labels.len() <= 32,
            "notes support at most 32 labels"
        );

        let mut labels = request
            .labels
            .iter()
            .map(|label| label.trim())
            .filter(|label| !label.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        anyhow::ensure!(
            labels.iter().all(|label| label.chars().count() <= 80),
            "note labels may not exceed 80 characters"
        );
        labels.sort();
        labels.dedup();
        anyhow::ensure!(
            request.provenance.is_object(),
            "note provenance must be a JSON object"
        );

        let run_id = request
            .run_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        let supplied_target = request
            .target_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);

        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        let campaign_exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM campaigns WHERE id=?1)",
            params![campaign_id],
            |row| row.get(0),
        )?;
        anyhow::ensure!(campaign_exists, "unknown campaign {campaign_id}");

        if let Some(run_id) = run_id.as_deref() {
            let owner: Option<String> = transaction
                .query_row(
                    "SELECT campaign_id FROM runs WHERE id=?1",
                    params![run_id],
                    |row| row.get(0),
                )
                .optional()?;
            anyhow::ensure!(owner.is_some(), "unknown run {run_id}");
            anyhow::ensure!(
                owner.as_deref() == Some(campaign_id),
                "run {run_id} does not belong to campaign {campaign_id}"
            );
        }

        let target_id = supplied_target
            .or_else(|| run_id.clone())
            .unwrap_or_else(|| campaign_id.to_owned());
        if target_id != campaign_id && run_id.as_deref() != Some(target_id.as_str()) {
            let run_owner: Option<String> = transaction
                .query_row(
                    "SELECT campaign_id FROM runs WHERE id=?1",
                    params![target_id],
                    |row| row.get(0),
                )
                .optional()?;
            let object_owner: Option<Option<String>> = transaction
                .query_row(
                    "SELECT campaign_id FROM semantic_objects WHERE id=?1",
                    params![target_id],
                    |row| row.get(0),
                )
                .optional()?;
            let target_belongs = run_owner.as_deref() == Some(campaign_id)
                || object_owner.flatten().as_deref() == Some(campaign_id);
            anyhow::ensure!(
                target_belongs,
                "note target {target_id} is not part of campaign {campaign_id}"
            );
        }

        let now = Utc::now().to_rfc3339();
        let suffix = Uuid::new_v4().simple().to_string();
        let note = SemanticObject {
            id: format!("note:{suffix}"),
            campaign_id: Some(campaign_id.to_owned()),
            run_id: run_id.clone(),
            kind: "note".to_owned(),
            type_name: "concord.campaign_note/1".to_owned(),
            state: category.clone(),
            label: Some(title.to_owned()),
            payload: json!({
                "category": category,
                "severity": severity,
                "body": body,
                "actor": actor,
                "labels": labels,
                "targetId": target_id,
                "internal": true,
                "provenance": request.provenance,
            }),
            created_at: now.clone(),
            updated_at: now.clone(),
        };
        let relation = SemanticRelation {
            id: format!("relation:note:{suffix}:annotates"),
            campaign_id: note.campaign_id.clone(),
            run_id: run_id.clone(),
            subject_id: note.id.clone(),
            predicate: "annotates".to_owned(),
            object_id: target_id,
            payload: json!({"internal": true}),
            timestamp: now.clone(),
        };
        let action = ActionRecord {
            id: format!("action:note:{suffix}:created"),
            campaign_id: note.campaign_id.clone(),
            run_id: run_id.clone(),
            action_type: "note_created".to_owned(),
            actor: actor.to_owned(),
            target_id: Some(note.id.clone()),
            status: "completed".to_owned(),
            payload: json!({"category": category, "severity": severity, "internal": true}),
            timestamp: now.clone(),
        };
        upsert_semantic_object_tx(&transaction, &note)?;
        upsert_semantic_relation_tx(&transaction, &relation)?;
        upsert_action_tx(&transaction, &action)?;
        insert_event_tx(
            &transaction,
            &LedgerEvent {
                id: format!("event:note:{suffix}:recorded"),
                campaign_id: note.campaign_id.clone(),
                run_id,
                object_type: "campaign_note".to_owned(),
                object_id: note.id.clone(),
                verb: "note_recorded".to_owned(),
                timestamp: now,
                payload: json!({
                    "category": category,
                    "severity": severity,
                    "targetId": relation.object_id,
                    "internal": true
                }),
            },
        )?;
        transaction.commit()?;
        Ok(NoteResponse {
            note,
            action,
            relation,
        })
    }

    pub fn notes_for_campaign(&self, campaign_id: &str) -> Result<Vec<SemanticObject>> {
        let connection = self.connect()?;
        let campaign_exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM campaigns WHERE id=?1)",
            params![campaign_id],
            |row| row.get(0),
        )?;
        anyhow::ensure!(campaign_exists, "unknown campaign {campaign_id}");
        read_all_for_campaign(
            &connection,
            "SELECT id,campaign_id,run_id,kind,type_name,state,label,payload_json,created_at,updated_at FROM semantic_objects WHERE campaign_id=?1 AND type_name='concord.campaign_note/1' ORDER BY updated_at DESC",
            campaign_id,
            semantic_object_from_row,
        )
    }

    pub fn upsert_projection(&self, projection: &ObjectProjection) -> Result<()> {
        anyhow::ensure!(
            projection.x.is_finite()
                && projection.y.is_finite()
                && projection.z.is_none_or(f64::is_finite),
            "projection coordinates must be finite"
        );
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        upsert_projection_tx(&transaction, projection)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn campaign_archive(&self, campaign_id: &str) -> Result<CampaignArchive> {
        let research_plans = self.research_plans_for_campaign(campaign_id)?;
        let agent_runs = self.agent_run_envelopes(Some(campaign_id))?;
        let science_artifacts = self.science_artifact_workspace(campaign_id)?;
        let execution = self.execution_workspace(campaign_id)?;
        let standing_review = self.standing_review_workspace(campaign_id)?;
        let connection = self.connect()?;
        let campaign = read_campaigns(&connection)?
            .into_iter()
            .find(|campaign| campaign.id == campaign_id)
            .with_context(|| format!("unknown campaign {campaign_id}"))?;
        let capability_ids = &campaign.capability_ids;
        let capabilities = read_all(
            &connection,
            "SELECT id,name,kind,version,provider,description,trust_status,lifecycle_json,command_json,resources_json FROM capabilities ORDER BY kind,name",
            capability_from_row,
        )?
        .into_iter()
        .filter(|capability| capability_ids.contains(&capability.id))
        .collect();
        Ok(CampaignArchive {
            project_inputs: self.project_inputs(campaign_id)?,
            schema_version: "concord.campaign/0.1".to_owned(),
            exported_at: Utc::now().to_rfc3339(),
            campaign,
            capabilities,
            runs: read_all_for_campaign(
                &connection,
                "SELECT id,campaign_id,capability_id,name,status,phase,progress,started_at,finished_at,external_url,pid,budget_ceiling_usd,cost_usd,parameters_json,resources_json FROM runs WHERE campaign_id=?1 ORDER BY COALESCE(started_at,'')",
                campaign_id,
                run_from_row,
            )?,
            metrics: read_all_for_campaign(
                &connection,
                "SELECT m.run_id,m.name,m.step,m.value,m.timestamp FROM metrics m JOIN runs r ON r.id=m.run_id WHERE r.campaign_id=?1 ORDER BY m.run_id,m.name,m.step",
                campaign_id,
                |row| Ok(MetricPoint { run_id: row.get(0)?, name: row.get(1)?, step: row.get(2)?, value: row.get(3)?, timestamp: row.get(4)? }),
            )?,
            events: read_all_for_campaign(
                &connection,
                "SELECT id,campaign_id,run_id,object_type,object_id,verb,timestamp,payload_json FROM events WHERE campaign_id=?1 ORDER BY timestamp",
                campaign_id,
                event_from_row,
            )?,
            artifacts: read_all_for_campaign(
                &connection,
                "SELECT a.id,a.run_id,a.kind,a.media_type,a.byte_size,a.path,a.source_path,a.created_at FROM artifacts a WHERE EXISTS(SELECT 1 FROM runs r WHERE r.id=a.run_id AND r.campaign_id=?1) OR EXISTS(SELECT 1 FROM project_inputs i WHERE i.artifact_id=a.id AND i.campaign_id=?1) ORDER BY a.created_at",
                campaign_id,
                |row| Ok(Artifact { id: row.get(0)?, run_id: row.get(1)?, kind: row.get(2)?, media_type: row.get(3)?, byte_size: row.get::<_, i64>(4)? as u64, path: row.get(5)?, source_path: row.get(6)?, created_at: row.get(7)? }),
            )?,
            candidates: read_all_for_campaign(
                &connection,
                "SELECT id,campaign_id,basin_id,x,y,z,conflict,geometry,motif,selected,failure FROM candidates WHERE campaign_id=?1 ORDER BY id",
                campaign_id,
                |row| Ok(CandidatePoint { id: row.get(0)?, campaign_id: row.get(1)?, basin_id: row.get(2)?, x: row.get(3)?, y: row.get(4)?, z: row.get(5)?, conflict: row.get(6)?, geometry: row.get(7)?, motif: row.get(8)?, selected: row.get::<_, i64>(9)? != 0, failure: row.get(10)? }),
            )?,
            basins: read_all_for_campaign(
                &connection,
                "SELECT campaign_id,id,size,suspicion,dominant_failure,core_pass_rate,geometry_pass_rate,esm_pass_rate FROM basins WHERE campaign_id=?1 ORDER BY suspicion DESC",
                campaign_id,
                |row| Ok(BasinSummary { campaign_id: row.get(0)?, id: row.get(1)?, size: row.get(2)?, suspicion: row.get(3)?, dominant_failure: row.get(4)?, core_pass_rate: row.get(5)?, geometry_pass_rate: row.get(6)?, esm_pass_rate: row.get(7)? }),
            )?,
            objects: read_all_for_campaign(&connection, "SELECT id,campaign_id,run_id,kind,type_name,state,label,payload_json,created_at,updated_at FROM semantic_objects WHERE campaign_id=?1 ORDER BY updated_at", campaign_id, semantic_object_from_row)?,
            relations: read_all_for_campaign(&connection, "SELECT id,campaign_id,run_id,subject_id,predicate,object_id,payload_json,timestamp FROM semantic_relations WHERE campaign_id=?1 ORDER BY timestamp", campaign_id, semantic_relation_from_row)?,
            actions: read_all_for_campaign(&connection, "SELECT id,campaign_id,run_id,action_type,actor,target_id,status,payload_json,timestamp FROM actions WHERE campaign_id=?1 ORDER BY timestamp", campaign_id, action_from_row)?,
            external_jobs: read_all_for_campaign(&connection, "SELECT id,campaign_id,run_id,provider,external_id,label,status,chip,submitted_at,started_at,finished_at,rate_per_min_usd,max_cost_usd,cost_usd,queue_position,estimated_wait_seconds,payload_json,updated_at FROM external_jobs WHERE campaign_id=?1 ORDER BY updated_at", campaign_id, external_job_from_row)?,
            projections: read_all_for_campaign(&connection, "SELECT id,campaign_id,run_id,object_id,space,x,y,z,group_id,signals_json,selected,label,updated_at FROM object_projections WHERE campaign_id=?1 ORDER BY updated_at", campaign_id, projection_from_row)?,
            research_plans,
            agent_progressions: agent_runs.iter().map(|entry| self.agent_progressions(&entry.run.id)).collect::<Result<Vec<_>>>()?.into_iter().flatten().collect(),
            agent_runs,
            science_artifacts,
            execution,
            standing_review,
        })
    }

    pub fn record_event(
        &self,
        campaign_id: Option<String>,
        run_id: Option<String>,
        object_type: &str,
        object_id: &str,
        verb: &str,
        payload: Value,
    ) -> Result<LedgerEvent> {
        let event = LedgerEvent {
            id: format!("evt_{}", Uuid::new_v4().simple()),
            campaign_id,
            run_id,
            object_type: object_type.to_owned(),
            object_id: object_id.to_owned(),
            verb: verb.to_owned(),
            timestamp: Utc::now().to_rfc3339(),
            payload,
        };
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        insert_event_tx(&transaction, &event)?;
        transaction.commit()?;
        Ok(event)
    }

    pub fn insert_artifact(&self, artifact: &Artifact) -> Result<()> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        insert_artifact_tx(&transaction, artifact)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn artifact(&self, artifact_id: &str) -> Result<Option<Artifact>> {
        let connection = self.connect()?;
        connection.query_row(
            "SELECT id,run_id,kind,media_type,byte_size,path,source_path,created_at FROM artifacts WHERE id=?1",
            params![artifact_id],
            |row| Ok(Artifact { id: row.get(0)?, run_id: row.get(1)?, kind: row.get(2)?, media_type: row.get(3)?, byte_size: row.get::<_, i64>(4)? as u64, path: row.get(5)?, source_path: row.get(6)?, created_at: row.get(7)? }),
        ).optional().map_err(Into::into)
    }

    /// Runs that this Concord runtime owns and may safely reattach after a restart.
    ///
    /// Operational imports can contain nonterminal digital-twin rows, but they never create a
    /// `run_supervision` record. Requiring that durable ownership claim prevents local recovery
    /// from rewriting externally managed state.
    pub fn recoverable_local_runs(&self) -> Result<Vec<Run>> {
        let connection = self.connect()?;
        read_all(
            &connection,
            r#"SELECT r.id,r.campaign_id,r.capability_id,r.name,r.status,r.phase,r.progress,
            r.started_at,r.finished_at,r.external_url,r.pid,r.budget_ceiling_usd,r.cost_usd,
            r.parameters_json,r.resources_json
            FROM runs r INNER JOIN run_supervision s ON s.run_id=r.id
            WHERE r.status IN ('queued','running','recovering')"#,
            run_from_row,
        )
    }

    pub fn snapshot(&self, runtime: RuntimeStatus) -> Result<WorkspaceSnapshot> {
        let connection = self.connect()?;
        Ok(WorkspaceSnapshot {
            runtime,
            campaigns: read_campaigns(&connection)?,
            capabilities: read_all(&connection, "SELECT id,name,kind,version,provider,description,trust_status,lifecycle_json,command_json,resources_json FROM capabilities ORDER BY kind,name", capability_from_row)?,
            runs: read_all(&connection, "SELECT id,campaign_id,capability_id,name,status,phase,progress,started_at,finished_at,external_url,pid,budget_ceiling_usd,cost_usd,parameters_json,resources_json FROM runs ORDER BY started_at DESC", run_from_row)?,
            metrics: read_all(&connection, &format!(r#"SELECT run_id,name,step,value,timestamp FROM (
                SELECT run_id,name,step,value,timestamp,
                    ROW_NUMBER() OVER (PARTITION BY run_id,name ORDER BY step DESC) AS point_rank
                FROM metrics
            ) WHERE point_rank <= {SNAPSHOT_METRIC_POINTS_PER_SERIES}
            ORDER BY run_id,name,step"#), |row| Ok(MetricPoint { run_id: row.get(0)?, name: row.get(1)?, step: row.get(2)?, value: row.get(3)?, timestamp: row.get(4)? }))?,
            events: read_all(&connection, "SELECT id,campaign_id,run_id,object_type,object_id,verb,timestamp,payload_json FROM events ORDER BY timestamp DESC LIMIT 250", event_from_row)?,
            artifacts: read_all(&connection, "SELECT id,run_id,kind,media_type,byte_size,path,source_path,created_at FROM artifacts ORDER BY created_at DESC", |row| Ok(Artifact { id: row.get(0)?, run_id: row.get(1)?, kind: row.get(2)?, media_type: row.get(3)?, byte_size: row.get::<_, i64>(4)? as u64, path: row.get(5)?, source_path: row.get(6)?, created_at: row.get(7)? }))?,
            budgets: read_all(&connection, "SELECT id,name,source,currency,total,spent,exposure,remaining_floor,updated_at FROM budgets ORDER BY name", |row| Ok(BudgetAccount { id: row.get(0)?, name: row.get(1)?, source: row.get(2)?, currency: row.get(3)?, total: row.get(4)?, spent: row.get(5)?, exposure: row.get(6)?, remaining_floor: row.get(7)?, updated_at: row.get(8)? }))?,
            candidates: read_all(&connection, &format!("SELECT id,campaign_id,basin_id,x,y,z,conflict,geometry,motif,selected,failure FROM candidates ORDER BY selected DESC,campaign_id,id LIMIT {SNAPSHOT_CANDIDATE_LIMIT}"), |row| Ok(CandidatePoint { id: row.get(0)?, campaign_id: row.get(1)?, basin_id: row.get(2)?, x: row.get(3)?, y: row.get(4)?, z: row.get(5)?, conflict: row.get(6)?, geometry: row.get(7)?, motif: row.get(8)?, selected: row.get::<_, i64>(9)? != 0, failure: row.get(10)? }))?,
            basins: read_all(&connection, "SELECT campaign_id,id,size,suspicion,dominant_failure,core_pass_rate,geometry_pass_rate,esm_pass_rate FROM basins ORDER BY campaign_id,suspicion DESC", |row| Ok(BasinSummary { campaign_id: row.get(0)?, id: row.get(1)?, size: row.get(2)?, suspicion: row.get(3)?, dominant_failure: row.get(4)?, core_pass_rate: row.get(5)?, geometry_pass_rate: row.get(6)?, esm_pass_rate: row.get(7)? }))?,
            objects: read_all(&connection, "SELECT id,campaign_id,run_id,kind,type_name,state,label,payload_json,created_at,updated_at FROM semantic_objects ORDER BY updated_at DESC LIMIT 500", semantic_object_from_row)?,
            relations: read_all(&connection, "SELECT id,campaign_id,run_id,subject_id,predicate,object_id,payload_json,timestamp FROM semantic_relations ORDER BY timestamp DESC LIMIT 500", semantic_relation_from_row)?,
            actions: read_all(&connection, "SELECT id,campaign_id,run_id,action_type,actor,target_id,status,payload_json,timestamp FROM actions ORDER BY timestamp DESC LIMIT 500", action_from_row)?,
            external_jobs: read_all(&connection, "SELECT id,campaign_id,run_id,provider,external_id,label,status,chip,submitted_at,started_at,finished_at,rate_per_min_usd,max_cost_usd,cost_usd,queue_position,estimated_wait_seconds,payload_json,updated_at FROM external_jobs ORDER BY updated_at DESC LIMIT 250", external_job_from_row)?,
            providers: read_all(&connection, "SELECT id,name,kind,base_url,secret_ref,status,metadata_json,updated_at FROM provider_profiles ORDER BY name", provider_from_row)?,
            projections: read_all(&connection, "SELECT id,campaign_id,run_id,object_id,space,x,y,z,group_id,signals_json,selected,label,updated_at FROM object_projections ORDER BY updated_at DESC LIMIT 10000", projection_from_row)?,
            operational_imports: read_all(&connection, "SELECT import_id,contract,source_system,source_stream,source_repository,source_revision,source_url,generated_at,content_sha256,imported_at,record_count FROM operational_imports ORDER BY imported_at DESC LIMIT 250", operational_import_from_row)?,
            operational_sources: read_all(&connection, "SELECT source_system,source_stream,source_repository,source_revision,source_url,last_generated_at,last_checked_at,last_changed_at,latest_import_id,content_sha256,status FROM operational_sources ORDER BY source_system,source_stream", operational_source_from_row)?,
        })
    }
}

fn ensure_campaign_exists_tx(transaction: &Transaction<'_>, campaign_id: &str) -> Result<()> {
    anyhow::ensure!(!campaign_id.trim().is_empty(), "campaign id is required");
    let exists: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM campaigns WHERE id=?1)",
        params![campaign_id],
        |row| row.get(0),
    )?;
    anyhow::ensure!(exists, "unknown campaign {campaign_id}");
    Ok(())
}

fn campaign_governor_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CampaignGovernor> {
    let generation = u64::try_from(row.get::<_, i64>(2)?).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            2,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })?;
    let status = GovernorStatus::parse(&row.get::<_, String>(3)?).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, error.into())
    })?;
    Ok(CampaignGovernor {
        contract: row.get(0)?,
        campaign_id: row.get(1)?,
        generation,
        status,
        last_reconciliation_sha256: row.get(4)?,
        blocked_reason: row.get(5)?,
        updated_at: row.get(6)?,
    })
}

fn service_lease_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ServiceLease> {
    let role = SupervisorRole::parse(&row.get::<_, String>(1)?).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, error.into())
    })?;
    let generation = u64::try_from(row.get::<_, i64>(3)?).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            3,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })?;
    Ok(ServiceLease {
        campaign_id: row.get(0)?,
        role,
        owner_id: row.get(2)?,
        generation,
        status: ServiceLeaseStatus::Healthy,
        last_heartbeat_at: row.get(4)?,
        lease_expires_at: row.get(5)?,
        details: parse_json(row.get(6)?, 6)?,
    })
}

fn campaign_service_leases_tx(
    transaction: &Transaction<'_>,
    campaign_id: &str,
    generation: u64,
) -> Result<Vec<ServiceLease>> {
    let mut statement = transaction.prepare(
        "SELECT campaign_id,role,owner_id,generation,last_heartbeat_at,lease_expires_at,details_json FROM campaign_service_leases WHERE campaign_id=?1 AND generation=?2 ORDER BY role",
    )?;
    let leases = statement
        .query_map(
            params![campaign_id, i64::try_from(generation)?],
            service_lease_from_row,
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(leases)
}

fn campaign_supervision_is_stale_tx(
    transaction: &Transaction<'_>,
    campaign_id: &str,
    now: chrono::DateTime<Utc>,
) -> Result<bool> {
    let generation: u64 = transaction.query_row(
        "SELECT generation FROM campaign_governors WHERE campaign_id=?1",
        params![campaign_id],
        |row| {
            u64::try_from(row.get::<_, i64>(0)?).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Integer,
                    Box::new(error),
                )
            })
        },
    )?;
    let leases = campaign_service_leases_tx(transaction, campaign_id, generation)?;
    let by_role = leases
        .iter()
        .map(|lease| (lease.role, lease))
        .collect::<std::collections::BTreeMap<_, _>>();
    for role in SupervisorRole::REQUIRED {
        let Some(lease) = by_role.get(&role) else {
            return Ok(true);
        };
        if !lease.is_live_at(now)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn dispatch_permit_deadline(permit: &CampaignDispatchPermit) -> Result<chrono::DateTime<Utc>> {
    let value = if permit.deadline_at.trim().is_empty() {
        let issued = chrono::DateTime::parse_from_rfc3339(&permit.issued_at)
            .context("dispatch permit issuedAt is invalid")?
            .with_timezone(&Utc);
        return Ok(issued + chrono::Duration::minutes(5));
    } else {
        &permit.deadline_at
    };
    Ok(chrono::DateTime::parse_from_rfc3339(value)
        .context("dispatch permit deadlineAt is invalid")?
        .with_timezone(&Utc))
}

fn dispatch_accounting_summary(
    connection: &Connection,
    campaign_id: &str,
) -> Result<DispatchAccountingSummary> {
    let permits = read_all_for_campaign(
        connection,
        "SELECT status,record_json FROM campaign_dispatch_permits WHERE campaign_id=?1 ORDER BY created_at,token",
        campaign_id,
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    )?;
    let mut summary = DispatchAccountingSummary::default();
    for (status, raw) in permits {
        let status = DispatchPermitStatus::parse(&status)?;
        let permit: CampaignDispatchPermit = serde_json::from_str(&raw)?;
        match status {
            DispatchPermitStatus::Authorized => summary.authorized += 1,
            DispatchPermitStatus::Consumed => summary.consumed += 1,
            DispatchPermitStatus::Settled => summary.settled += 1,
            DispatchPermitStatus::Interrupted => summary.interrupted += 1,
            DispatchPermitStatus::Released => summary.released += 1,
        }
        if permit.reserve_budget
            && matches!(
                status,
                DispatchPermitStatus::Authorized
                    | DispatchPermitStatus::Consumed
                    | DispatchPermitStatus::Interrupted
            )
        {
            summary.reserved_usd += permit.maximum_cost_usd;
        }
    }
    Ok(summary)
}

fn upsert_operational_source_tx(
    transaction: &Transaction<'_>,
    envelope: &OperationalImportEnvelope,
    record: &OperationalImportRecord,
    checked_at: &str,
    changed: bool,
) -> Result<OperationalSourceStatus> {
    let previous_changed_at: Option<String> = transaction
        .query_row(
            "SELECT last_changed_at FROM operational_sources WHERE source_system=?1 AND source_stream=?2",
            params![envelope.source.system, envelope.source.stream],
            |row| row.get(0),
        )
        .optional()?;
    let last_changed_at = if changed {
        record.imported_at.clone()
    } else {
        previous_changed_at.unwrap_or_else(|| record.imported_at.clone())
    };
    let source = OperationalSourceStatus {
        source_system: envelope.source.system.clone(),
        source_stream: envelope.source.stream.clone(),
        source_repository: envelope.source.repository.clone(),
        source_revision: envelope.source.revision.clone(),
        source_url: envelope.source.url.clone(),
        last_generated_at: envelope.generated_at.clone(),
        last_checked_at: checked_at.to_owned(),
        last_changed_at,
        latest_import_id: record.import_id.clone(),
        content_sha256: record.content_sha256.clone(),
        status: "fresh".to_owned(),
    };
    transaction.execute(
        r#"INSERT INTO operational_sources
        (source_system,source_stream,source_repository,source_revision,source_url,
         last_generated_at,last_checked_at,last_changed_at,latest_import_id,content_sha256,status)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
        ON CONFLICT(source_system,source_stream) DO UPDATE SET
            source_repository=excluded.source_repository,source_revision=excluded.source_revision,
            source_url=excluded.source_url,last_generated_at=excluded.last_generated_at,
            last_checked_at=excluded.last_checked_at,last_changed_at=excluded.last_changed_at,
            latest_import_id=excluded.latest_import_id,content_sha256=excluded.content_sha256,
            status=excluded.status"#,
        params![
            source.source_system,
            source.source_stream,
            source.source_repository,
            source.source_revision,
            source.source_url,
            source.last_generated_at,
            source.last_checked_at,
            source.last_changed_at,
            source.latest_import_id,
            source.content_sha256,
            source.status,
        ],
    )?;
    Ok(source)
}

fn operational_record_count(bundle: &SeedBundle) -> u64 {
    [
        bundle.campaigns.len(),
        bundle.capabilities.len(),
        bundle.runs.len(),
        bundle.events.len(),
        bundle.artifacts.len(),
        bundle.budgets.len(),
        bundle.objects.len(),
        bundle.relations.len(),
        bundle.actions.len(),
        bundle.external_jobs.len(),
        bundle.providers.len(),
    ]
    .into_iter()
    .sum::<usize>() as u64
}

fn operational_import_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<OperationalImportRecord> {
    Ok(OperationalImportRecord {
        import_id: row.get(0)?,
        contract: row.get(1)?,
        source_system: row.get(2)?,
        source_stream: row.get(3)?,
        source_repository: row.get(4)?,
        source_revision: row.get(5)?,
        source_url: row.get(6)?,
        generated_at: row.get(7)?,
        content_sha256: row.get(8)?,
        imported_at: row.get(9)?,
        record_count: row.get::<_, i64>(10)? as u64,
    })
}

fn operational_source_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<OperationalSourceStatus> {
    Ok(OperationalSourceStatus {
        source_system: row.get(0)?,
        source_stream: row.get(1)?,
        source_repository: row.get(2)?,
        source_revision: row.get(3)?,
        source_url: row.get(4)?,
        last_generated_at: row.get(5)?,
        last_checked_at: row.get(6)?,
        last_changed_at: row.get(7)?,
        latest_import_id: row.get(8)?,
        content_sha256: row.get(9)?,
        status: row.get(10)?,
    })
}

fn agent_status_name(status: AgentRunStatus) -> Result<String> {
    serde_json::to_value(status)?
        .as_str()
        .map(str::to_owned)
        .context("agent status did not serialize as a string")
}

fn parse_agent_status(value: String) -> rusqlite::Result<AgentRunStatus> {
    serde_json::from_value(Value::String(value)).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })
}

fn ensure_agent_fork_budget_reservation_tx(
    transaction: &Transaction<'_>,
    run: &AgentRun,
    now: &str,
) -> Result<()> {
    let Some(ceiling) = run.budget.max_cost_usd.filter(|value| *value > 0.0) else {
        return Ok(());
    };
    let reservation_status: Option<String> = transaction
        .query_row(
            "SELECT status FROM agent_budget_reservations WHERE agent_run_id=?1",
            params![run.id],
            |row| row.get(0),
        )
        .optional()?;
    if reservation_status.as_deref() == Some("reserved") {
        return Ok(());
    }
    anyhow::ensure!(
        reservation_status.is_none(),
        "nonterminal agent fork has a settled spend reservation"
    );
    let selected: Option<(String, f64)> = if let Some(budget_id) = run.budget.budget_id.as_deref() {
        transaction
            .query_row(
                "SELECT id,remaining_floor FROM budgets WHERE id=?1",
                params![budget_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
    } else {
        transaction
            .query_row(
                "SELECT id,remaining_floor FROM budgets ORDER BY remaining_floor DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
    };
    let (budget_id, remaining_floor) =
        selected.context("paid agent fork requires a configured Concord budget account")?;
    anyhow::ensure!(
        ceiling <= remaining_floor,
        "agent fork cost ceiling ${ceiling:.2} exceeds remaining floor ${remaining_floor:.2}"
    );
    transaction.execute(
        "UPDATE budgets SET exposure=exposure+?2,remaining_floor=remaining_floor-?2,updated_at=?3 WHERE id=?1",
        params![budget_id, ceiling, now],
    )?;
    transaction.execute(
        r#"INSERT INTO agent_budget_reservations
        (agent_run_id,budget_id,reserved_usd,estimated_spent_usd,status,created_at,updated_at)
        VALUES (?1,?2,?3,0,'reserved',?4,?4)"#,
        params![run.id, budget_id, ceiling, now],
    )?;
    Ok(())
}

fn insert_agent_run_tx(transaction: &Transaction<'_>, run: &AgentRun) -> Result<()> {
    transaction.execute(
        r#"INSERT INTO agent_runs
        (id,contract,campaign_id,provider_id,model,task,allowed_tools_json,budget_json,status,
         revision,model_calls,tool_calls,parent_run_id,parent_event_hash,created_at,updated_at,epact_json)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)"#,
        params![
            run.id,
            run.contract,
            run.campaign_id,
            run.provider_id,
            run.model,
            run.task,
            serde_json::to_string(&run.allowed_tools)?,
            serde_json::to_string(&run.budget)?,
            agent_status_name(run.status)?,
            i64::try_from(run.revision)?,
            i64::from(run.model_calls),
            i64::from(run.tool_calls),
            run.parent_run_id,
            run.parent_event_hash,
            run.created_at,
            run.updated_at,
            run.epact.as_ref().map(serde_json::to_string).transpose()?,
        ],
    )?;
    Ok(())
}

fn insert_agent_event_tx(transaction: &Transaction<'_>, event: &AgentEvent) -> Result<()> {
    transaction.execute(
        r#"INSERT INTO agent_events
        (id,contract,agent_run_id,sequence,idempotency_key,kind,from_status,to_status,payload_json,
         previous_event_sha256,event_sha256,created_at)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)"#,
        params![
            event.id,
            event.contract,
            event.agent_run_id,
            i64::try_from(event.sequence)?,
            event.idempotency_key,
            event.kind.as_str(),
            agent_status_name(event.from_status)?,
            agent_status_name(event.to_status)?,
            serde_json::to_string(&event.payload)?,
            event.previous_event_sha256,
            event.event_sha256,
            event.created_at,
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_research_agent_tx(
    transaction: &Transaction<'_>,
    campaign_id: &str,
    task: String,
    allowed_tools: Vec<String>,
    budget: AgentBudget,
    parent_run_id: Option<String>,
    parent_event_hash: Option<String>,
    brief_payload: Value,
    execution: Option<&ResearchTaskExecution>,
    created_at: &str,
) -> Result<(AgentRun, AgentEvent)> {
    let request = CreateAgentRunRequest {
        campaign_id: campaign_id.to_owned(),
        provider_id: execution
            .map_or("concord-deterministic", |execution| &execution.provider_id)
            .to_owned(),
        model: Some(
            execution
                .map_or("concord-deterministic-v1", |execution| &execution.model)
                .to_owned(),
        ),
        task,
        allowed_tools,
        budget,
        epact: execution.and_then(|execution| execution.epact.clone()),
        parent_run_id,
        parent_event_hash,
    };
    request.validate()?;
    crate::epact::enforce_epact_agent_binding_tx(
        transaction,
        campaign_id,
        request.epact.as_ref(),
        &request.budget,
    )?;
    anyhow::ensure!(
        execution.is_some() || request.budget.max_cost_usd == Some(0.0),
        "research rehearsal dispatch must remain zero-spend"
    );
    let provider_exists: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM provider_profiles WHERE id=?1)",
        [&request.provider_id],
        |row| row.get(0),
    )?;
    anyhow::ensure!(
        provider_exists,
        "research execution provider is unavailable"
    );
    let run = AgentRun {
        contract: AGENT_RUN_CONTRACT.to_owned(),
        id: format!("agent_{}", Uuid::new_v4().simple()),
        campaign_id: request.campaign_id.clone(),
        provider_id: request.provider_id.clone(),
        model: request.model.clone().context("research model missing")?,
        task: request.task.clone(),
        allowed_tools: request.allowed_tools.clone(),
        budget: request.budget.clone(),
        epact: request.epact.clone(),
        status: AgentRunStatus::Ready,
        revision: 0,
        model_calls: 0,
        tool_calls: 0,
        parent_run_id: request.parent_run_id.clone(),
        parent_event_hash: request.parent_event_hash.clone(),
        created_at: created_at.to_owned(),
        updated_at: created_at.to_owned(),
    };
    insert_agent_run_tx(transaction, &run)?;
    ensure_agent_fork_budget_reservation_tx(transaction, &run, created_at)?;
    let event = AgentEvent::build(
        format!("agent_event_{}", Uuid::new_v4().simple()),
        run.id.clone(),
        0,
        "run-created".to_owned(),
        AgentEventKind::RunCreated,
        AgentRunStatus::Ready,
        json!({
            "task": run.task,
            "providerId": run.provider_id,
            "model": run.model,
            "allowedTools": run.allowed_tools,
            "budget": run.budget,
            "epact": run.epact,
            "parentRunId": run.parent_run_id,
            "parentEventHash": run.parent_event_hash,
            "researchBrief": brief_payload,
        }),
        request.parent_event_hash,
        created_at.to_owned(),
    )?;
    insert_agent_event_tx(transaction, &event)?;
    Ok((run, event))
}

fn agent_run_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AgentRun> {
    Ok(AgentRun {
        contract: row.get(0)?,
        id: row.get(1)?,
        campaign_id: row.get(2)?,
        provider_id: row.get(3)?,
        model: row.get(4)?,
        task: row.get(5)?,
        allowed_tools: parse_json(row.get(6)?, 6)?,
        budget: parse_json(row.get(7)?, 7)?,
        status: parse_agent_status(row.get(8)?)?,
        revision: row.get::<_, i64>(9)?.max(0) as u64,
        model_calls: row.get::<_, i64>(10)?.max(0) as u32,
        tool_calls: row.get::<_, i64>(11)?.max(0) as u32,
        parent_run_id: row.get(12)?,
        parent_event_hash: row.get(13)?,
        created_at: row.get(14)?,
        updated_at: row.get(15)?,
        epact: row
            .get::<_, Option<String>>(16)?
            .map(|value| parse_json(value, 16))
            .transpose()?,
    })
}

fn agent_event_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AgentEvent> {
    let kind: String = row.get(5)?;
    Ok(AgentEvent {
        contract: row.get(0)?,
        id: row.get(1)?,
        agent_run_id: row.get(2)?,
        sequence: row.get::<_, i64>(3)?.max(0) as u64,
        idempotency_key: row.get(4)?,
        kind: AgentEventKind::parse(&kind).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, error.into())
        })?,
        from_status: parse_agent_status(row.get(6)?)?,
        to_status: parse_agent_status(row.get(7)?)?,
        payload: parse_json(row.get(8)?, 8)?,
        previous_event_sha256: row.get(9)?,
        event_sha256: row.get(10)?,
        created_at: row.get(11)?,
    })
}

fn upsert_capability(transaction: &Transaction<'_>, capability: &Capability) -> Result<()> {
    transaction.execute(
        r#"INSERT OR REPLACE INTO capabilities
        (id,name,kind,version,provider,description,trust_status,lifecycle_json,command_json,resources_json)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)"#,
        params![capability.id, capability.name, capability.kind, capability.version, capability.provider,
            capability.description, capability.trust_status, serde_json::to_string(&capability.lifecycle)?,
            serde_json::to_string(&capability.command)?, serde_json::to_string(&capability.resources)?],
    )?;
    Ok(())
}

fn upsert_run(transaction: &Transaction<'_>, run: &Run) -> Result<()> {
    let status = canonical_execution_status(&run.status);
    transaction.execute(
        r#"INSERT OR REPLACE INTO runs
        (id,campaign_id,capability_id,name,status,phase,progress,started_at,finished_at,external_url,pid,budget_ceiling_usd,cost_usd,parameters_json,resources_json)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)"#,
        params![run.id, run.campaign_id, run.capability_id, run.name, status, run.phase, run.progress,
            run.started_at, run.finished_at, run.external_url, run.pid, run.budget_ceiling_usd, run.cost_usd,
            serde_json::to_string(&run.parameters)?, serde_json::to_string(&run.resources)?],
    )?;
    Ok(())
}

fn insert_metric_tx(transaction: &Transaction<'_>, metric: &MetricPoint) -> Result<()> {
    transaction.execute(
        "INSERT OR REPLACE INTO metrics(run_id,name,step,value,timestamp) VALUES (?1,?2,?3,?4,?5)",
        params![
            metric.run_id,
            metric.name,
            metric.step,
            metric.value,
            metric.timestamp
        ],
    )?;
    Ok(())
}

fn insert_event_tx(transaction: &Transaction<'_>, event: &LedgerEvent) -> Result<()> {
    transaction.execute(
        "INSERT OR REPLACE INTO events(id,campaign_id,run_id,object_type,object_id,verb,timestamp,payload_json) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![event.id, event.campaign_id, event.run_id, event.object_type, event.object_id, event.verb,
            event.timestamp, serde_json::to_string(&event.payload)?],
    )?;
    Ok(())
}

fn package_trust_name(status: &PackageTrustStatus) -> &'static str {
    match status {
        PackageTrustStatus::Quarantined => "quarantined",
        PackageTrustStatus::Inspected => "inspected",
        PackageTrustStatus::Qualified => "qualified",
        PackageTrustStatus::Revoked => "revoked",
    }
}

fn qualification_disposition_name(status: QualificationDisposition) -> &'static str {
    match status {
        QualificationDisposition::Inspected => "inspected",
        QualificationDisposition::Qualified => "qualified",
        QualificationDisposition::Rejected => "rejected",
        QualificationDisposition::Revoked => "revoked",
    }
}

fn capability_package_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<RegisteredCapabilityPackage> {
    let record = RegisteredCapabilityPackage {
        record_id: row.get(0)?,
        package: parse_json(row.get(1)?, 1)?,
        registered_at: row.get(2)?,
        updated_at: row.get(3)?,
    };
    record.package.validate().map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, error.into())
    })?;
    let expected_id = capability_package_record_id(&record.package).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, error.into())
    })?;
    if record.record_id != expected_id {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "capability package record identity mismatch",
            )
            .into(),
        ));
    }
    Ok(record)
}

fn mcp_discovery_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<McpDiscoveryRecord> {
    let record = McpDiscoveryRecord {
        record_id: row.get(0)?,
        package_record_id: row.get(1)?,
        package_content_sha256: row.get(2)?,
        snapshot: parse_json(row.get(3)?, 3)?,
        recorded_at: row.get(4)?,
    };
    record.snapshot.validate().map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, error.into())
    })?;
    Ok(record)
}

fn capability_qualification_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<CapabilityQualification> {
    let qualification: CapabilityQualification = parse_json(row.get(0)?, 0)?;
    qualification.validate().map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, error.into())
    })?;
    Ok(qualification)
}

fn settle_run_budget_tx(transaction: &Transaction<'_>, run_id: &str) -> Result<()> {
    let reservation: Option<(String, f64, f64, Option<f64>, String)> = transaction
        .query_row(
            r#"SELECT budget_id,reserved_usd,baseline_spent_usd,settled_usd,status FROM budget_reservations
            WHERE run_id=?1"#,
            params![run_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?;
    let Some((budget_id, reserved_usd, baseline_spent_usd, settled_usd, reservation_status)) =
        reservation
    else {
        return Ok(());
    };
    if reservation_status == "settled" {
        return Ok(());
    }

    let (run_status, cost_usd, campaign_id): (String, Option<f64>, String) = transaction
        .query_row(
            "SELECT status,cost_usd,campaign_id FROM runs WHERE id=?1",
            params![run_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
    if !matches!(run_status.as_str(), "completed" | "failed" | "cancelled") {
        return Ok(());
    }
    let Some(cost_usd) = cost_usd else {
        if reservation_status == "released_pending_reconciliation" {
            return Ok(());
        }
        let now = Utc::now().to_rfc3339();
        transaction.execute(
            r#"UPDATE budgets SET
                exposure=MAX(0,exposure-?2),
                remaining_floor=remaining_floor+?2,
                updated_at=?3
            WHERE id=?1"#,
            params![budget_id, reserved_usd, now],
        )?;
        transaction.execute(
            r#"UPDATE budget_reservations SET
                settled_usd=0,status='released_pending_reconciliation',updated_at=?2
            WHERE run_id=?1"#,
            params![run_id, now],
        )?;
        insert_event_tx(
            transaction,
            &LedgerEvent {
                id: format!("evt_{}", Uuid::new_v4().simple()),
                campaign_id: Some(campaign_id),
                run_id: Some(run_id.to_owned()),
                object_type: "budget_reservation".to_owned(),
                object_id: run_id.to_owned(),
                verb: "released_pending_reconciliation".to_owned(),
                timestamp: now,
                payload: json!({
                    "budgetId": budget_id,
                    "reservedUsd": reserved_usd,
                    "releasedUsd": reserved_usd,
                }),
            },
        )?;
        return Ok(());
    };

    anyhow::ensure!(
        cost_usd.is_finite() && cost_usd >= 0.0,
        "run cost must be finite and non-negative"
    );
    let now = Utc::now().to_rfc3339();
    if reservation_status == "released_pending_reconciliation" {
        let previous_cost = settled_usd.unwrap_or(0.0);
        let cost_delta = cost_usd - previous_cost;
        transaction.execute(
            r#"UPDATE budgets SET
                spent=MAX(spent,?5+?2),
                exposure=MAX(0,exposure+?4),
                remaining_floor=remaining_floor-?4,
                updated_at=?3
            WHERE id=?1"#,
            params![budget_id, cost_usd, now, cost_delta, baseline_spent_usd],
        )?;
    } else {
        transaction.execute(
            r#"UPDATE budgets SET
                spent=MAX(spent,?5+?2),
                exposure=MAX(0,exposure-?3+?2),
                remaining_floor=remaining_floor+?3-?2,
                updated_at=?4
            WHERE id=?1"#,
            params![budget_id, cost_usd, reserved_usd, now, baseline_spent_usd],
        )?;
    }
    transaction.execute(
        r#"UPDATE budget_reservations SET
            settled_usd=?2,status='settled',updated_at=?3
        WHERE run_id=?1"#,
        params![run_id, cost_usd, now],
    )?;
    insert_event_tx(
        transaction,
        &LedgerEvent {
            id: format!("evt_{}", Uuid::new_v4().simple()),
            campaign_id: Some(campaign_id),
            run_id: Some(run_id.to_owned()),
            object_type: "budget_reservation".to_owned(),
            object_id: run_id.to_owned(),
            verb: "settled".to_owned(),
            timestamp: now,
            payload: json!({
                "budgetId": budget_id,
                "reservedUsd": reserved_usd,
                "settledUsd": cost_usd,
                "releasedUsd": reserved_usd - cost_usd,
            }),
        },
    )?;
    Ok(())
}

fn insert_artifact_tx(transaction: &Transaction<'_>, artifact: &Artifact) -> Result<()> {
    let input_owned: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM project_inputs WHERE artifact_id=?1)",
        [&artifact.id],
        |row| row.get(0),
    )?;
    if input_owned {
        let identical: bool = transaction.query_row("SELECT EXISTS(SELECT 1 FROM artifacts WHERE id=?1 AND run_id IS ?2 AND kind=?3 AND media_type=?4 AND byte_size=?5 AND path=?6 AND source_path IS ?7 AND created_at=?8)", params![artifact.id, artifact.run_id, artifact.kind, artifact.media_type, artifact.byte_size as i64, artifact.path, artifact.source_path, artifact.created_at], |row| row.get(0))?;
        anyhow::ensure!(
            identical,
            "accepted project input artifact metadata is immutable"
        );
        return Ok(());
    }
    transaction.execute(
        "INSERT OR REPLACE INTO artifacts(id,run_id,kind,media_type,byte_size,path,source_path,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![artifact.id, artifact.run_id, artifact.kind, artifact.media_type, artifact.byte_size as i64,
            artifact.path, artifact.source_path, artifact.created_at],
    )?;
    Ok(())
}

fn upsert_semantic_object_tx(transaction: &Transaction<'_>, object: &SemanticObject) -> Result<()> {
    let input_json: Option<String> = transaction
        .query_row(
            "SELECT record_json FROM project_inputs WHERE id=?1",
            [&object.id],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(input_json) = input_json {
        let record: crate::ProjectInputVersion = serde_json::from_str(&input_json)?;
        record.validate()?;
        anyhow::ensure!(
            object.payload == serde_json::to_value(&record)?
                && object.type_name == crate::PROJECT_INPUT_CONTRACT
                && object.kind == "input"
                && object.campaign_id.as_deref() == Some(record.campaign_id.as_str())
                && object.run_id.is_none()
                && object.state == "attached"
                && object.label.as_deref() == Some(record.logical_path.as_str())
                && object.created_at == record.created_at
                && object.updated_at == record.created_at,
            "accepted project input projection is immutable"
        );
    } else {
        anyhow::ensure!(
            object.type_name != crate::PROJECT_INPUT_CONTRACT,
            "project input records must use the input attachment boundary"
        );
    }
    transaction.execute(
        r#"INSERT INTO semantic_objects
        (id,campaign_id,run_id,kind,type_name,state,label,payload_json,created_at,updated_at)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
        ON CONFLICT(id) DO UPDATE SET
            campaign_id=excluded.campaign_id,run_id=excluded.run_id,kind=excluded.kind,
            type_name=excluded.type_name,state=excluded.state,label=excluded.label,
            payload_json=excluded.payload_json,updated_at=excluded.updated_at"#,
        params![
            object.id,
            object.campaign_id,
            object.run_id,
            object.kind,
            object.type_name,
            object.state,
            object.label,
            serde_json::to_string(&object.payload)?,
            object.created_at,
            object.updated_at
        ],
    )?;
    Ok(())
}

fn persist_source_gate_epact_tx(
    transaction: &Transaction<'_>,
    campaign_id: &str,
    recorded_at: &str,
    input: &SourceGateInput,
    compiled: &SourceGateEpactCompilation,
) -> Result<()> {
    crate::source_gate::verify_source_gate_epact_binding(
        input,
        &compiled.projection,
        &compiled.image,
        &compiled.binding,
    )?;
    let image_json = serde_json::to_string(&compiled.image)?;
    transaction.execute(
        "INSERT OR IGNORE INTO epact_program_images(image_sha256,program_id,program_version,program_sha256,image_json,recorded_at) VALUES (?1,?2,?3,?4,?5,?6)",
        params![
            compiled.image.image_sha256,
            compiled.image.program.id,
            compiled.image.program.version,
            compiled.image.program_sha256,
            image_json,
            recorded_at,
        ],
    )?;
    let stored_image_json: String = transaction.query_row(
        "SELECT image_json FROM epact_program_images WHERE image_sha256=?1",
        params![compiled.image.image_sha256],
        |row| row.get(0),
    )?;
    anyhow::ensure!(
        stored_image_json == image_json,
        "Epact image hash collides with different stored content"
    );
    let binding_json = serde_json::to_string(&compiled.binding)?;
    transaction.execute(
        "INSERT OR IGNORE INTO source_gate_epact_bindings(projection_sha256,image_sha256,binding_json,recorded_at) VALUES (?1,?2,?3,?4)",
        params![
            compiled.projection.projection_sha256,
            compiled.image.image_sha256,
            binding_json,
            recorded_at,
        ],
    )?;
    let stored: (String, String) = transaction.query_row(
        "SELECT image_sha256,binding_json FROM source_gate_epact_bindings WHERE projection_sha256=?1",
        params![compiled.projection.projection_sha256],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    anyhow::ensure!(
        stored.0 == compiled.image.image_sha256 && stored.1 == binding_json,
        "source-gate projection is already bound to different Epact content"
    );
    let binding_object = SemanticObject {
        id: format!(
            "source-gate-epact:{}",
            &compiled.binding.epact_image_sha256[..16]
        ),
        campaign_id: Some(campaign_id.to_owned()),
        run_id: None,
        kind: "program_image".to_owned(),
        type_name: SOURCE_GATE_EPACT_BINDING_CONTRACT.to_owned(),
        state: "compiled".to_owned(),
        label: Some("Compiled Epact source-gate program".to_owned()),
        payload: serde_json::to_value(&compiled.binding)?,
        created_at: recorded_at.to_owned(),
        updated_at: recorded_at.to_owned(),
    };
    insert_immutable_semantic_object_tx(transaction, &binding_object)?;
    upsert_semantic_relation_tx(
        transaction,
        &SemanticRelation {
            id: format!(
                "relation:source-gate-projection:{}:compiled-as-epact",
                &compiled.projection.projection_sha256[..16]
            ),
            campaign_id: Some(campaign_id.to_owned()),
            run_id: None,
            subject_id: format!(
                "source-gate-projection:{}",
                &compiled.projection.projection_sha256[..16]
            ),
            predicate: "compiled_as_epact".to_owned(),
            object_id: binding_object.id,
            payload: json!({
                "imageSha256": compiled.binding.epact_image_sha256,
                "programSha256": compiled.binding.epact_program_sha256,
            }),
            timestamp: recorded_at.to_owned(),
        },
    )?;
    Ok(())
}

fn insert_immutable_semantic_object_tx(
    transaction: &Transaction<'_>,
    object: &SemanticObject,
) -> Result<()> {
    let existing = transaction
        .query_row(
            "SELECT id,campaign_id,run_id,kind,type_name,state,label,payload_json,created_at,updated_at FROM semantic_objects WHERE id=?1",
            params![object.id],
            semantic_object_from_row,
        )
        .optional()?;
    if let Some(existing) = existing {
        anyhow::ensure!(
            existing.campaign_id == object.campaign_id
                && existing.run_id == object.run_id
                && existing.kind == object.kind
                && existing.type_name == object.type_name
                && existing.state == object.state
                && existing.label == object.label
                && existing.payload == object.payload,
            "immutable semantic object {} differs from its accepted record",
            object.id
        );
        return Ok(());
    }
    upsert_semantic_object_tx(transaction, object)
}

fn upsert_semantic_relation_tx(
    transaction: &Transaction<'_>,
    relation: &SemanticRelation,
) -> Result<()> {
    transaction.execute(
        r#"INSERT OR REPLACE INTO semantic_relations
        (id,campaign_id,run_id,subject_id,predicate,object_id,payload_json,timestamp)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8)"#,
        params![
            relation.id,
            relation.campaign_id,
            relation.run_id,
            relation.subject_id,
            relation.predicate,
            relation.object_id,
            serde_json::to_string(&relation.payload)?,
            relation.timestamp
        ],
    )?;
    Ok(())
}

fn upsert_action_tx(transaction: &Transaction<'_>, action: &ActionRecord) -> Result<()> {
    let status = canonical_execution_status(&action.status);
    transaction.execute(
        r#"INSERT OR REPLACE INTO actions
        (id,campaign_id,run_id,action_type,actor,target_id,status,payload_json,timestamp)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)"#,
        params![
            action.id,
            action.campaign_id,
            action.run_id,
            action.action_type,
            action.actor,
            action.target_id,
            status,
            serde_json::to_string(&action.payload)?,
            action.timestamp
        ],
    )?;
    Ok(())
}

fn upsert_external_job_tx(transaction: &Transaction<'_>, job: &ExternalJob) -> Result<()> {
    let status = canonical_execution_status(&job.status);
    transaction.execute(
        r#"INSERT INTO external_jobs
        (id,campaign_id,run_id,provider,external_id,label,status,chip,submitted_at,started_at,
         finished_at,rate_per_min_usd,max_cost_usd,cost_usd,queue_position,estimated_wait_seconds,
         payload_json,updated_at)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)
        ON CONFLICT(provider,external_id) DO UPDATE SET
            campaign_id=COALESCE(excluded.campaign_id,external_jobs.campaign_id),
            run_id=COALESCE(excluded.run_id,external_jobs.run_id),label=excluded.label,
            status=excluded.status,chip=COALESCE(excluded.chip,external_jobs.chip),
            submitted_at=COALESCE(excluded.submitted_at,external_jobs.submitted_at),
            started_at=COALESCE(excluded.started_at,external_jobs.started_at),
            finished_at=COALESCE(excluded.finished_at,external_jobs.finished_at),
            rate_per_min_usd=COALESCE(excluded.rate_per_min_usd,external_jobs.rate_per_min_usd),
            max_cost_usd=COALESCE(excluded.max_cost_usd,external_jobs.max_cost_usd),
            cost_usd=COALESCE(excluded.cost_usd,external_jobs.cost_usd),
            queue_position=excluded.queue_position,
            estimated_wait_seconds=excluded.estimated_wait_seconds,
            payload_json=excluded.payload_json,updated_at=excluded.updated_at"#,
        params![
            job.id,
            job.campaign_id,
            job.run_id,
            job.provider,
            job.external_id,
            job.label,
            status,
            job.chip,
            job.submitted_at,
            job.started_at,
            job.finished_at,
            job.rate_per_min_usd,
            job.max_cost_usd,
            job.cost_usd,
            job.queue_position,
            job.estimated_wait_seconds,
            serde_json::to_string(&job.payload)?,
            job.updated_at
        ],
    )?;
    Ok(())
}

fn upsert_provider_tx(transaction: &Transaction<'_>, provider: &ProviderProfile) -> Result<()> {
    transaction.execute(
        r#"INSERT INTO provider_profiles
        (id,name,kind,base_url,secret_ref,status,metadata_json,updated_at)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
        ON CONFLICT(id) DO UPDATE SET
            name=excluded.name,kind=excluded.kind,base_url=excluded.base_url,
            secret_ref=excluded.secret_ref,status=excluded.status,
            metadata_json=excluded.metadata_json,updated_at=excluded.updated_at"#,
        params![
            provider.id,
            provider.name,
            provider.kind,
            provider.base_url,
            provider.secret_ref,
            provider.status,
            serde_json::to_string(&provider.metadata)?,
            provider.updated_at,
        ],
    )?;
    Ok(())
}

fn upsert_projection_tx(
    transaction: &Transaction<'_>,
    projection: &ObjectProjection,
) -> Result<()> {
    transaction.execute(
        r#"INSERT INTO object_projections
        (id,campaign_id,run_id,object_id,space,x,y,z,group_id,signals_json,selected,label,updated_at)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
        ON CONFLICT(campaign_id,object_id,space) DO UPDATE SET
            run_id=excluded.run_id,x=excluded.x,y=excluded.y,z=excluded.z,
            group_id=excluded.group_id,signals_json=excluded.signals_json,
            selected=excluded.selected,label=excluded.label,updated_at=excluded.updated_at"#,
        params![
            projection.id,
            projection.campaign_id,
            projection.run_id,
            projection.object_id,
            projection.space,
            projection.x,
            projection.y,
            projection.z,
            projection.group_id,
            serde_json::to_string(&projection.signals)?,
            projection.selected as i64,
            projection.label,
            projection.updated_at,
        ],
    )?;
    Ok(())
}

fn read_campaigns(connection: &Connection) -> Result<Vec<Campaign>> {
    let mut campaigns = read_all(
        connection,
        r#"SELECT c.id,c.name,c.domain,c.objective,c.status,c.created_at,
        p.id,p.name,p.language,p.language_version,p.source
        FROM campaigns c JOIN programs p ON p.id=c.program_id ORDER BY c.created_at"#,
        |row| {
            Ok(Campaign {
                id: row.get(0)?,
                name: row.get(1)?,
                domain: row.get(2)?,
                objective: row.get(3)?,
                status: row.get(4)?,
                created_at: row.get(5)?,
                program: DesignProgram {
                    id: row.get(6)?,
                    name: row.get(7)?,
                    language: row.get(8)?,
                    language_version: row.get(9)?,
                    source: row.get(10)?,
                },
                capability_ids: vec![],
            })
        },
    )?;
    for campaign in &mut campaigns {
        let mut statement = connection.prepare(
            "SELECT capability_id FROM campaign_capabilities WHERE campaign_id=?1 ORDER BY capability_id",
        )?;
        campaign.capability_ids = statement
            .query_map(params![campaign.id], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
    }
    Ok(campaigns)
}

fn read_all<T, F>(connection: &Connection, sql: &str, mut mapper: F) -> Result<Vec<T>>
where
    F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
{
    let mut statement = connection.prepare(sql)?;
    let rows = statement.query_map([], |row| mapper(row))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

fn canonical_value_sha256(value: &impl serde::Serialize) -> Result<String> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}

fn read_all_for_campaign<T, F>(
    connection: &Connection,
    sql: &str,
    campaign_id: &str,
    mut mapper: F,
) -> Result<Vec<T>>
where
    F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
{
    let mut statement = connection.prepare(sql)?;
    let rows = statement.query_map(params![campaign_id], |row| mapper(row))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

fn parse_json<T: DeserializeOwned>(value: String, column: usize) -> rusqlite::Result<T> {
    serde_json::from_str(&value)
        .map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                value.len(),
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })
        .map_err(|error| match error {
            rusqlite::Error::FromSqlConversionFailure(_, kind, source) => {
                rusqlite::Error::FromSqlConversionFailure(column, kind, source)
            }
            other => other,
        })
}

fn capability_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Capability> {
    Ok(Capability {
        id: row.get(0)?,
        name: row.get(1)?,
        kind: row.get(2)?,
        version: row.get(3)?,
        provider: row.get(4)?,
        description: row.get(5)?,
        trust_status: row.get(6)?,
        lifecycle: parse_json(row.get(7)?, 7)?,
        command: parse_json(row.get(8)?, 8)?,
        resources: parse_json(row.get(9)?, 9)?,
    })
}

fn run_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Run> {
    Ok(Run {
        id: row.get(0)?,
        campaign_id: row.get(1)?,
        capability_id: row.get(2)?,
        name: row.get(3)?,
        status: row.get(4)?,
        phase: row.get(5)?,
        progress: row.get(6)?,
        started_at: row.get(7)?,
        finished_at: row.get(8)?,
        external_url: row.get(9)?,
        pid: row.get(10)?,
        budget_ceiling_usd: row.get(11)?,
        cost_usd: row.get(12)?,
        parameters: parse_json(row.get(13)?, 13)?,
        resources: parse_json(row.get(14)?, 14)?,
    })
}

fn event_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<LedgerEvent> {
    Ok(LedgerEvent {
        id: row.get(0)?,
        campaign_id: row.get(1)?,
        run_id: row.get(2)?,
        object_type: row.get(3)?,
        object_id: row.get(4)?,
        verb: row.get(5)?,
        timestamp: row.get(6)?,
        payload: parse_json(row.get(7)?, 7)?,
    })
}

fn semantic_object_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SemanticObject> {
    Ok(SemanticObject {
        id: row.get(0)?,
        campaign_id: row.get(1)?,
        run_id: row.get(2)?,
        kind: row.get(3)?,
        type_name: row.get(4)?,
        state: row.get(5)?,
        label: row.get(6)?,
        payload: parse_json(row.get(7)?, 7)?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
    })
}

fn research_plan_decision_name(decision: ResearchPlanDecisionKind) -> &'static str {
    match decision {
        ResearchPlanDecisionKind::Approved => "approved",
        ResearchPlanDecisionKind::Rejected => "rejected",
        ResearchPlanDecisionKind::Withdrawn => "withdrawn",
    }
}

fn research_plan_decisions_for_plan(
    connection: &Connection,
    plan: &ResearchPlanVersion,
) -> Result<Vec<ResearchPlanDecision>> {
    let mut statement = connection.prepare(
        "SELECT decision_json FROM research_plan_decisions WHERE plan_id=?1 ORDER BY created_at,id",
    )?;
    let rows = statement
        .query_map(params![plan.id], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut decisions = Vec::with_capacity(rows.len());
    let mut previous_decision_sha256: Option<String> = None;
    for raw in rows {
        let decision: ResearchPlanDecision = serde_json::from_str(&raw)?;
        decision.validate()?;
        anyhow::ensure!(
            decision.plan_id == plan.id && decision.plan_sha256 == plan.plan_sha256,
            "research plan decision points to different evidence"
        );
        anyhow::ensure!(
            decision.previous_decision_sha256 == previous_decision_sha256,
            "research plan decision chain is incomplete"
        );
        previous_decision_sha256 = Some(decision.decision_sha256.clone());
        decisions.push(decision);
    }
    Ok(decisions)
}

fn research_phase_dispatches_for_plan(
    connection: &Connection,
    plan: &ResearchPlanVersion,
) -> Result<Vec<ResearchPhaseDispatch>> {
    let mut statement = connection.prepare(
        "SELECT dispatch_json FROM research_phase_dispatches WHERE plan_id=?1 ORDER BY created_at,id",
    )?;
    let rows = statement
        .query_map(params![plan.id], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut dispatches = Vec::with_capacity(rows.len());
    for raw in rows {
        let dispatch: ResearchPhaseDispatch = serde_json::from_str(&raw)?;
        dispatch.validate()?;
        anyhow::ensure!(
            dispatch.campaign_id == plan.campaign_id
                && dispatch.plan_id == plan.id
                && dispatch.plan_sha256 == plan.plan_sha256,
            "research phase dispatch points to different plan evidence"
        );
        let phase = plan
            .phases
            .iter()
            .find(|phase| phase.id == dispatch.phase_id)
            .context("research phase dispatch references an unknown phase")?;
        let expected_task_ids: Vec<&str> =
            phase.tasks.iter().map(|task| task.id.as_str()).collect();
        let actual_task_ids: Vec<&str> = dispatch
            .children
            .iter()
            .map(|child| child.task_id.as_str())
            .collect();
        anyhow::ensure!(
            actual_task_ids == expected_task_ids && dispatch.max_parallel == phase.max_parallel,
            "research phase dispatch does not match the frozen phase"
        );
        dispatches.push(dispatch);
    }
    Ok(dispatches)
}

fn science_records<T: DeserializeOwned>(
    connection: &Connection,
    sql: &str,
    campaign_id: &str,
) -> Result<Vec<T>> {
    let mut statement = connection.prepare(sql)?;
    let values = statement
        .query_map(params![campaign_id], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    values
        .into_iter()
        .map(|value| serde_json::from_str(&value).map_err(Into::into))
        .collect()
}

fn ensure_agent_campaign_tx(
    transaction: &Transaction<'_>,
    agent_run_id: &str,
    campaign_id: &str,
) -> Result<()> {
    let actual: String = transaction
        .query_row(
            "SELECT campaign_id FROM agent_runs WHERE id=?1",
            params![agent_run_id],
            |row| row.get(0),
        )
        .with_context(|| format!("agent run {agent_run_id} does not exist"))?;
    anyhow::ensure!(
        actual == campaign_id,
        "agent run does not belong to the science artifact campaign"
    );
    Ok(())
}

fn ensure_science_version_campaign_tx(
    transaction: &Transaction<'_>,
    version_id: &str,
    campaign_id: &str,
) -> Result<()> {
    let exists: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM science_artifact_versions WHERE id=?1 AND campaign_id=?2)",
        params![version_id, campaign_id],
        |row| row.get(0),
    )?;
    anyhow::ensure!(
        exists,
        "science artifact version {version_id} does not belong to the campaign"
    );
    Ok(())
}

fn semantic_relation_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SemanticRelation> {
    Ok(SemanticRelation {
        id: row.get(0)?,
        campaign_id: row.get(1)?,
        run_id: row.get(2)?,
        subject_id: row.get(3)?,
        predicate: row.get(4)?,
        object_id: row.get(5)?,
        payload: parse_json(row.get(6)?, 6)?,
        timestamp: row.get(7)?,
    })
}

fn action_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ActionRecord> {
    Ok(ActionRecord {
        id: row.get(0)?,
        campaign_id: row.get(1)?,
        run_id: row.get(2)?,
        action_type: row.get(3)?,
        actor: row.get(4)?,
        target_id: row.get(5)?,
        status: row.get(6)?,
        payload: parse_json(row.get(7)?, 7)?,
        timestamp: row.get(8)?,
    })
}

fn external_job_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ExternalJob> {
    Ok(ExternalJob {
        id: row.get(0)?,
        campaign_id: row.get(1)?,
        run_id: row.get(2)?,
        provider: row.get(3)?,
        external_id: row.get(4)?,
        label: row.get(5)?,
        status: row.get(6)?,
        chip: row.get(7)?,
        submitted_at: row.get(8)?,
        started_at: row.get(9)?,
        finished_at: row.get(10)?,
        rate_per_min_usd: row.get(11)?,
        max_cost_usd: row.get(12)?,
        cost_usd: row.get(13)?,
        queue_position: row.get(14)?,
        estimated_wait_seconds: row.get(15)?,
        payload: parse_json(row.get(16)?, 16)?,
        updated_at: row.get(17)?,
    })
}

fn provider_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProviderProfile> {
    let secret_ref: Option<String> = row.get(4)?;
    let status: String = row.get(5)?;
    let secret_available = secret_ref.as_deref().is_some_and(|reference| {
        reference
            .strip_prefix("env:")
            .is_some_and(|name| std::env::var_os(name).is_some())
            || (reference.starts_with("keychain:") && status == "ready")
    });
    Ok(ProviderProfile {
        id: row.get(0)?,
        name: row.get(1)?,
        kind: row.get(2)?,
        base_url: row.get(3)?,
        secret_ref,
        secret_available,
        status,
        metadata: parse_json(row.get(6)?, 6)?,
        updated_at: row.get(7)?,
    })
}

fn projection_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ObjectProjection> {
    Ok(ObjectProjection {
        id: row.get(0)?,
        campaign_id: row.get(1)?,
        run_id: row.get(2)?,
        object_id: row.get(3)?,
        space: row.get(4)?,
        x: row.get(5)?,
        y: row.get(6)?,
        z: row.get(7)?,
        group_id: row.get(8)?,
        signals: parse_json(row.get(9)?, 9)?,
        selected: row.get::<_, i64>(10)? != 0,
        label: row.get(11)?,
        updated_at: row.get(12)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn standing_review_is_idempotent_and_chains_changed_campaign_inputs() {
        let database_path = std::env::temp_dir().join(format!(
            "concord-standing-review-test-{}.sqlite3",
            Uuid::new_v4().simple()
        ));
        let database = Database::new(&database_path).unwrap();
        let campaign = database
            .create_campaign(&CreateCampaignRequest {
                name: "Standing review fixture".into(),
                domain: "test".into(),
                objective: "prove ambient review receipts".into(),
                program_source: None,
                capability_ids: vec![],
            })
            .unwrap();

        let first = database.run_standing_review(&campaign.id).unwrap();
        let unchanged = database.run_standing_review(&campaign.id).unwrap();
        assert_eq!(first, unchanged);
        assert_eq!(
            database
                .standing_review_workspace(&campaign.id)
                .unwrap()
                .history
                .len(),
            1
        );

        database
            .upsert_semantic_object(&SemanticObject {
                id: "reviewed-assistant-message".into(),
                campaign_id: Some(campaign.id.clone()),
                run_id: None,
                kind: "evidence".into(),
                type_name: "concord.research_message".into(),
                state: "recorded".into(),
                label: None,
                payload: json!({"role": "assistant", "content": "A provisional statement."}),
                created_at: "2026-08-23T00:00:00Z".into(),
                updated_at: "2026-08-23T00:00:00Z".into(),
            })
            .unwrap();
        let changed = database.run_standing_review(&campaign.id).unwrap();
        assert_ne!(first.review_sha256, changed.review_sha256);
        assert_eq!(
            changed.previous_review_sha256,
            Some(first.review_sha256.clone())
        );
        assert_eq!(changed.coverage.assistant_messages, 1);
        assert_eq!(
            database
                .standing_review_workspace(&campaign.id)
                .unwrap()
                .history
                .len(),
            2
        );
        database
            .upsert_semantic_object(&SemanticObject {
                id: "second-reviewed-assistant-message".into(),
                campaign_id: Some(campaign.id.clone()),
                run_id: None,
                kind: "evidence".into(),
                type_name: "concord.research_message".into(),
                state: "recorded".into(),
                label: None,
                payload: json!({"role": "assistant", "content": "Another provisional statement."}),
                created_at: "2026-08-23T00:00:01Z".into(),
                updated_at: "2026-08-23T00:00:01Z".into(),
            })
            .unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
        let handles = (0..4)
            .map(|_| {
                let database = database.clone();
                let campaign_id = campaign.id.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    database.run_standing_review(&campaign_id).unwrap()
                })
            })
            .collect::<Vec<_>>();
        let concurrent_hashes = handles
            .into_iter()
            .map(|handle| handle.join().unwrap().review_sha256)
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(concurrent_hashes.len(), 1);
        assert_eq!(
            database
                .standing_review_workspace(&campaign.id)
                .unwrap()
                .history
                .len(),
            3
        );
        std::fs::remove_file(database_path).unwrap();
    }

    pub(super) fn note_test_database() -> (Database, PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "concord-note-test-{}.sqlite",
            Uuid::new_v4().simple()
        ));
        let database = Database::new(&path).unwrap();
        let created_at = Utc::now().to_rfc3339();
        let campaign = |id: &str| Campaign {
            id: id.to_owned(),
            name: id.to_owned(),
            domain: "test".to_owned(),
            objective: "test notes".to_owned(),
            status: "active".to_owned(),
            created_at: created_at.clone(),
            program: DesignProgram {
                id: format!("program:{id}"),
                name: format!("{id} program"),
                language: EPACT_LANGUAGE.to_owned(),
                language_version: EPACT_LANGUAGE_VERSION.to_owned(),
                source: "test".to_owned(),
            },
            capability_ids: vec![],
        };
        let run = |id: &str, campaign_id: &str| Run {
            id: id.to_owned(),
            campaign_id: campaign_id.to_owned(),
            capability_id: "test".to_owned(),
            name: id.to_owned(),
            status: "completed".to_owned(),
            phase: "done".to_owned(),
            progress: 1.0,
            started_at: Some(created_at.clone()),
            finished_at: Some(created_at.clone()),
            external_url: None,
            pid: None,
            budget_ceiling_usd: None,
            cost_usd: None,
            parameters: json!({}),
            resources: ResourceRequest::default(),
        };
        database
            .seed(&SeedBundle {
                campaigns: vec![campaign("campaign:a"), campaign("campaign:b")],
                capabilities: vec![],
                runs: vec![run("run:a", "campaign:a"), run("run:b", "campaign:b")],
                metrics: vec![],
                events: vec![],
                artifacts: vec![],
                budgets: vec![],
                candidates: vec![],
                basins: vec![],
                objects: vec![],
                relations: vec![],
                actions: vec![],
                external_jobs: vec![],
                providers: vec![ProviderProfile {
                    id: "concord-deterministic".into(),
                    name: "Concord deterministic fixture".into(),
                    kind: "model_api".into(),
                    base_url: None,
                    secret_ref: None,
                    secret_available: true,
                    status: "ready".into(),
                    metadata: json!({"model": "concord-deterministic-v1", "transport": "deterministic"}),
                    updated_at: created_at.clone(),
                }],
                projections: vec![],
            })
            .unwrap();
        (database, path)
    }

    fn note_request() -> CreateNoteRequest {
        CreateNoteRequest {
            campaign_id: "campaign:a".to_owned(),
            run_id: Some("run:a".to_owned()),
            target_id: None,
            category: "mistake".to_owned(),
            severity: "critical".to_owned(),
            title: "Incorrect campaign execution".to_owned(),
            body: "Keep the failure visible and do not reuse it as confirmatory evidence."
                .to_owned(),
            actor: "primary-agent".to_owned(),
            labels: vec!["postmortem".to_owned(), "internal".to_owned()],
            provenance: json!({"source": "test fixture"}),
        }
    }

    fn digest(character: char) -> String {
        std::iter::repeat_n(character, 64).collect()
    }

    fn activate_campaign_supervision(database: &Database) -> CampaignSupervisionSnapshot {
        let recovery = database
            .begin_campaign_recovery(
                "campaign:a",
                &BeginCampaignRecoveryRequest {
                    owner_id: "primary-operator".into(),
                    reason: "restart from durable state".into(),
                },
            )
            .unwrap();
        assert_eq!(recovery.governor.generation, 1);
        for role in SupervisorRole::REQUIRED {
            database
                .heartbeat_campaign_service(
                    "campaign:a",
                    &ServiceHeartbeatRequest {
                        role,
                        owner_id: format!("{}-singleton", role.as_str()),
                        generation: 1,
                        lease_seconds: 300,
                        details: json!({"mode": "deterministic-test"}),
                    },
                )
                .unwrap();
        }
        database
            .reconcile_campaign_supervision(
                "campaign:a",
                &ReconcileCampaignRequest {
                    generation: 1,
                    reconciler_owner_id: "reconciler-singleton".into(),
                    provider_snapshot_sha256: digest('a'),
                    budget_snapshot_sha256: digest('b'),
                    ledger_heads: BTreeMap::from([
                        ("agent-events".into(), digest('c')),
                        ("provider-jobs".into(), digest('d')),
                    ]),
                    disposition: ReconciliationDisposition::Clean,
                    findings: vec![],
                },
            )
            .unwrap()
    }

    #[test]
    fn supervision_survives_restart_and_closeout_is_transactional() {
        let (database, path) = note_test_database();
        let active = activate_campaign_supervision(&database);
        assert!(active.dispatch_allowed);
        assert_eq!(active.services.len(), SupervisorRole::REQUIRED.len());

        let reopened = Database::new(&path).unwrap();
        let restored = reopened
            .campaign_supervision_snapshot("campaign:a", Utc::now())
            .unwrap();
        assert!(restored.dispatch_allowed);

        let request = CloseoutCampaignRequest {
            generation: 1,
            actor: "primary-operator".into(),
            decision_sha256: digest('e'),
            evidence_sha256: vec![digest('f'), digest('1')],
            ledger_heads: BTreeMap::from([
                ("agent-events".into(), digest('c')),
                ("provider-jobs".into(), digest('d')),
            ]),
        };
        let first = reopened.closeout_campaign("campaign:a", &request).unwrap();
        let second = reopened.closeout_campaign("campaign:a", &request).unwrap();
        assert_eq!(first, second);
        let closed = reopened
            .campaign_supervision_snapshot("campaign:a", Utc::now())
            .unwrap();
        assert!(!closed.dispatch_allowed);
        assert_eq!(closed.governor.status, GovernorStatus::Closed);
        assert!(reopened
            .begin_campaign_recovery(
                "campaign:a",
                &BeginCampaignRecoveryRequest {
                    owner_id: "primary-operator".into(),
                    reason: "attempt to reopen frozen campaign".into(),
                },
            )
            .is_err());
        assert!(reopened
            .closeout_campaign(
                "campaign:a",
                &CloseoutCampaignRequest {
                    decision_sha256: digest('2'),
                    ..request
                },
            )
            .is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn singleton_conflict_and_dead_man_switch_fail_closed() {
        let (database, path) = note_test_database();
        database
            .begin_campaign_recovery(
                "campaign:a",
                &BeginCampaignRecoveryRequest {
                    owner_id: "primary-operator".into(),
                    reason: "fresh boot".into(),
                },
            )
            .unwrap();
        database
            .heartbeat_campaign_service(
                "campaign:a",
                &ServiceHeartbeatRequest {
                    role: SupervisorRole::Watchdog,
                    owner_id: "watchdog-one".into(),
                    generation: 1,
                    lease_seconds: 300,
                    details: json!({}),
                },
            )
            .unwrap();
        assert!(database
            .heartbeat_campaign_service(
                "campaign:a",
                &ServiceHeartbeatRequest {
                    role: SupervisorRole::Watchdog,
                    owner_id: "watchdog-two".into(),
                    generation: 1,
                    lease_seconds: 300,
                    details: json!({}),
                },
            )
            .is_err());

        let future = Utc::now() + chrono::Duration::minutes(10);
        let stopped = database
            .campaign_supervision_snapshot("campaign:a", future)
            .unwrap();
        assert!(!stopped.dispatch_allowed);
        assert!(stopped
            .missing_or_stale_roles
            .contains(&SupervisorRole::Watchdog));
        assert_eq!(stopped.recovery_plan, RecoveryStep::ORDERED);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn dispatch_permit_is_reconciled_idempotent_and_single_use() {
        let (database, path) = note_test_database();
        let active = activate_campaign_supervision(&database);
        let request = AuthorizeCampaignDispatchRequest {
            generation: active.governor.generation,
            idempotency_key: "launch:fixture-one".into(),
            actor: "daemon-runner".into(),
            operation: DispatchOperation::ExecutionRun,
            target_id: "run_fixture_one".into(),
            budget_id: None,
            maximum_cost_usd: 0.0,
            reserve_budget: false,
            budget_pre_reserved: false,
            maximum_elapsed_seconds: 300,
            epact: None,
        };
        let first = database
            .authorize_campaign_dispatch("campaign:a", &request)
            .unwrap();
        let repeated = database
            .authorize_campaign_dispatch("campaign:a", &request)
            .unwrap();
        assert_eq!(first.token, repeated.token);
        let consumed = database.consume_campaign_dispatch(&first.token).unwrap();
        assert!(consumed.consumed_at.is_some());
        assert!(database.consume_campaign_dispatch(&first.token).is_err());

        let mut conflict = request;
        conflict.target_id = "run_fixture_two".into();
        assert!(database
            .authorize_campaign_dispatch("campaign:a", &conflict)
            .is_err());

        let stale_request = AuthorizeCampaignDispatchRequest {
            idempotency_key: "launch:stale-fixture".into(),
            target_id: "run_stale_fixture".into(),
            ..conflict
        };
        let stale = database
            .authorize_campaign_dispatch("campaign:a", &stale_request)
            .unwrap();
        database
            .connect()
            .unwrap()
            .execute(
                "UPDATE campaign_service_leases SET lease_expires_at='2020-01-01T00:00:00Z' WHERE campaign_id='campaign:a'",
                [],
            )
            .unwrap();
        assert!(database.consume_campaign_dispatch(&stale.token).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn interactive_dispatch_reserves_settles_reaps_and_resolves_ambiguity() {
        let (database, path) = note_test_database();
        let active = activate_campaign_supervision(&database);
        database
            .connect()
            .unwrap()
            .execute(
                "INSERT INTO budgets(id,name,source,currency,total,spent,exposure,remaining_floor,updated_at) VALUES ('interactive','Interactive inference','test','USD',100,0,0,100,?1)",
                params![Utc::now().to_rfc3339()],
            )
            .unwrap();
        let request = |generation: u64, key: &str, target: &str, maximum_cost_usd: f64| {
            AuthorizeCampaignDispatchRequest {
                generation,
                idempotency_key: key.into(),
                actor: "interactive-operator".into(),
                operation: DispatchOperation::AgentModelCall,
                target_id: target.into(),
                budget_id: Some("interactive".into()),
                maximum_cost_usd,
                reserve_budget: true,
                budget_pre_reserved: false,
                maximum_elapsed_seconds: 5,
                epact: None,
            }
        };

        let settled = database
            .authorize_campaign_dispatch(
                "campaign:a",
                &request(
                    active.governor.generation,
                    "interactive:settle",
                    "request-settle",
                    10.0,
                ),
            )
            .unwrap();
        database.consume_campaign_dispatch(&settled.token).unwrap();
        let settled = database
            .settle_campaign_dispatch(
                &settled.token,
                3.0,
                "provider_reported_token_usage:frozen_rate_card",
            )
            .unwrap();
        assert_eq!(settled.status, DispatchPermitStatus::Settled);
        let budget: (f64, f64, f64) = database
            .connect()
            .unwrap()
            .query_row(
                "SELECT spent,exposure,remaining_floor FROM budgets WHERE id='interactive'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(budget, (3.0, 0.0, 97.0));

        let abandoned = database
            .authorize_campaign_dispatch(
                "campaign:a",
                &request(
                    active.governor.generation,
                    "interactive:abandoned",
                    "request-abandoned",
                    5.0,
                ),
            )
            .unwrap();
        let reaped = database
            .reap_stale_campaign_dispatches(Utc::now() + chrono::Duration::seconds(10))
            .unwrap();
        assert_eq!(reaped.released, 1);
        assert_eq!(
            database
                .campaign_dispatch_permit(&abandoned.token)
                .unwrap()
                .unwrap()
                .status,
            DispatchPermitStatus::Released
        );

        let ambiguous = database
            .authorize_campaign_dispatch(
                "campaign:a",
                &request(
                    active.governor.generation,
                    "interactive:ambiguous",
                    "request-ambiguous",
                    7.0,
                ),
            )
            .unwrap();
        database
            .consume_campaign_dispatch(&ambiguous.token)
            .unwrap();
        let reaped = database
            .reap_stale_campaign_dispatches(Utc::now() + chrono::Duration::seconds(10))
            .unwrap();
        assert_eq!(reaped.interrupted, 1);
        assert!(database
            .authorize_campaign_dispatch(
                "campaign:a",
                &request(
                    active.governor.generation,
                    "interactive:blocked",
                    "request-blocked",
                    1.0
                ),
            )
            .is_err());
        let resolved = database
            .resolve_interrupted_campaign_dispatch(
                "campaign:a",
                &ambiguous.token,
                &ResolveInterruptedDispatchRequest {
                    actor: "operator".into(),
                    resolution: InterruptedDispatchResolution::NoProviderStart,
                    evidence_sha256: digest('e'),
                    actual_cost_usd: None,
                    settlement_basis: None,
                },
            )
            .unwrap();
        assert_eq!(resolved.status, DispatchPermitStatus::Released);
        assert_eq!(resolved.resolution_evidence_sha256, Some(digest('e')));

        let recovery = database
            .begin_campaign_recovery(
                "campaign:a",
                &BeginCampaignRecoveryRequest {
                    owner_id: "operator".into(),
                    reason: "interrupted dispatch was resolved".into(),
                },
            )
            .unwrap();
        for role in SupervisorRole::REQUIRED {
            database
                .heartbeat_campaign_service(
                    "campaign:a",
                    &ServiceHeartbeatRequest {
                        role,
                        owner_id: format!("{}-singleton-v2", role.as_str()),
                        generation: recovery.governor.generation,
                        lease_seconds: 300,
                        details: json!({}),
                    },
                )
                .unwrap();
        }
        database
            .reconcile_campaign_supervision(
                "campaign:a",
                &ReconcileCampaignRequest {
                    generation: recovery.governor.generation,
                    reconciler_owner_id: "reconciler-singleton-v2".into(),
                    provider_snapshot_sha256: digest('1'),
                    budget_snapshot_sha256: digest('2'),
                    ledger_heads: BTreeMap::from([("dispatch-permits".into(), digest('3'))]),
                    disposition: ReconciliationDisposition::Clean,
                    findings: vec![],
                },
            )
            .unwrap();

        let provider_settled = database
            .authorize_campaign_dispatch(
                "campaign:a",
                &request(
                    recovery.governor.generation,
                    "interactive:provider-settled",
                    "request-provider-settled",
                    9.0,
                ),
            )
            .unwrap();
        database
            .consume_campaign_dispatch(&provider_settled.token)
            .unwrap();
        database
            .interrupt_campaign_dispatch(&provider_settled.token, "connection lost after send")
            .unwrap();
        let provider_settled = database
            .resolve_interrupted_campaign_dispatch(
                "campaign:a",
                &provider_settled.token,
                &ResolveInterruptedDispatchRequest {
                    actor: "operator".into(),
                    resolution: InterruptedDispatchResolution::ProviderSettled,
                    evidence_sha256: digest('f'),
                    actual_cost_usd: Some(4.0),
                    settlement_basis: Some("provider_billing_receipt".into()),
                },
            )
            .unwrap();
        assert_eq!(provider_settled.status, DispatchPermitStatus::Settled);
        let final_budget: (f64, f64, f64) = database
            .connect()
            .unwrap()
            .query_row(
                "SELECT spent,exposure,remaining_floor FROM budgets WHERE id='interactive'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(final_budget, (7.0, 0.0, 93.0));
        let accounting = database
            .campaign_supervision_snapshot("campaign:a", Utc::now())
            .unwrap()
            .dispatch_accounting;
        assert_eq!(accounting.settled, 2);
        assert_eq!(accounting.released, 2);
        assert_eq!(accounting.interrupted, 0);
        assert_eq!(accounting.reserved_usd, 0.0);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn unchanged_scheduled_reconciliation_reuses_immutable_evidence() {
        let (database, path) = note_test_database();
        let active = activate_campaign_supervision(&database);
        database
            .begin_scheduled_campaign_reconciliation(
                "campaign:a",
                active.governor.generation,
                "daemon-runner",
            )
            .unwrap();
        let reopened = database
            .reconcile_campaign_supervision(
                "campaign:a",
                &ReconcileCampaignRequest {
                    generation: active.governor.generation,
                    reconciler_owner_id: "reconciler-singleton".into(),
                    provider_snapshot_sha256: digest('a'),
                    budget_snapshot_sha256: digest('b'),
                    ledger_heads: BTreeMap::from([
                        ("agent-events".into(), digest('c')),
                        ("provider-jobs".into(), digest('d')),
                    ]),
                    disposition: ReconciliationDisposition::Clean,
                    findings: vec![],
                },
            )
            .unwrap();
        assert!(reopened.dispatch_allowed);
        assert_eq!(
            reopened.governor.last_reconciliation_sha256,
            active.governor.last_reconciliation_sha256
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn dispatch_accounting_migrates_the_initial_permit_schema() {
        let path = std::env::temp_dir().join(format!(
            "concord-dispatch-migration-test-{}.sqlite3",
            Uuid::new_v4().simple()
        ));
        let database = Database::new(&path).unwrap();
        let connection = database.connect().unwrap();
        connection
            .execute_batch(
                r#"
                DROP TABLE campaign_dispatch_permits;
                CREATE TABLE campaign_dispatch_permits (
                    token TEXT PRIMARY KEY,
                    campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
                    generation INTEGER NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    consumed_at TEXT,
                    created_at TEXT NOT NULL,
                    UNIQUE(campaign_id,generation,idempotency_key)
                );
                "#,
            )
            .unwrap();
        drop(connection);
        drop(database);

        let reopened = Database::new(&path).unwrap();
        let connection = reopened.connect().unwrap();
        let columns = {
            let mut statement = connection
                .prepare("PRAGMA table_info(campaign_dispatch_permits)")
                .unwrap();
            statement
                .query_map([], |row| row.get::<_, String>(1))
                .unwrap()
                .collect::<rusqlite::Result<std::collections::BTreeSet<_>>>()
                .unwrap()
        };
        assert!(columns.contains("status"));
        assert!(columns.contains("settled_cost_usd"));
        assert!(columns.contains("updated_at"));
        drop(connection);
        drop(reopened);
        std::fs::remove_file(path).unwrap();
    }

    pub(super) fn research_plan_request(objective: &str) -> CreateResearchPlanRequest {
        CreateResearchPlanRequest {
            objective: objective.to_owned(),
            confidence: 0.8,
            confidence_basis: "Deterministic zero-spend fixture".into(),
            feasibility_limits: vec!["No external effects".into()],
            max_parallel: 1,
            max_cost_usd: 0.0,
            phases: vec![ResearchPlanPhase {
                id: "phase-one".into(),
                title: "Phase one".into(),
                objective: "Inspect retained records".into(),
                max_parallel: 1,
                tasks: vec![ResearchPlanTask {
                    id: "task-one".into(),
                    title: "Task one".into(),
                    specialist_role: "auditor".into(),
                    objective: "Inspect one frozen record".into(),
                    depends_on: vec![],
                    input_scope: vec!["campaign archive".into()],
                    allowed_tools: vec!["read_campaign_object".into()],
                    steps: vec!["Read the record".into()],
                    output_schema: json!({"type": "object"}),
                    deliverables: vec!["audit receipt".into()],
                    max_model_calls: 1,
                    max_tool_calls: 1,
                    max_elapsed_seconds: 60,
                    max_cost_usd: 0.0,
                    deterministic_fixture: true,
                    execution: None,
                }],
            }],
            created_by: "test-primary".into(),
        }
    }

    #[test]
    fn research_plans_are_immutable_and_decisions_cannot_approve_stale_versions() {
        let (database, path) = note_test_database();
        let first = database
            .record_research_plan("campaign:a", research_plan_request("First objective"))
            .unwrap();
        let approved = database
            .record_research_plan_decision(
                "campaign:a",
                &first.plan.id,
                ResearchPlanDecisionKind::Approved,
                "primary",
                "The exact fixture is bounded.",
            )
            .unwrap();
        assert_eq!(approved.decisions.len(), 1);
        let dispatch = database
            .dispatch_research_plan_phase("campaign:a", &first.plan.id, "phase-one", "primary")
            .unwrap();
        assert_eq!(dispatch.children.len(), 1);
        let repeated = database
            .dispatch_research_plan_phase("campaign:a", &first.plan.id, "phase-one", "primary")
            .unwrap();
        assert_eq!(dispatch.dispatch_sha256, repeated.dispatch_sha256);
        let child = database
            .agent_run_envelope(&dispatch.children[0].agent_run_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            child.events[0].payload["researchBrief"]["brief"]["id"],
            "task-one"
        );
        let second = database
            .record_research_plan("campaign:a", research_plan_request("Revised objective"))
            .unwrap();
        assert_eq!(second.plan.version, 2);
        assert_eq!(
            second.plan.previous_plan_sha256.as_deref(),
            Some(first.plan.plan_sha256.as_str())
        );
        assert!(database
            .record_research_plan_decision(
                "campaign:a",
                &first.plan.id,
                ResearchPlanDecisionKind::Rejected,
                "primary",
                "This is now stale.",
            )
            .is_err());
        let history = database.research_plans_for_campaign("campaign:a").unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(
            history[0].decisions[0].decision,
            ResearchPlanDecisionKind::Approved
        );
        let archive = database.campaign_archive("campaign:a").unwrap();
        assert_eq!(archive.research_plans.len(), 2);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn artifact_review_correction_and_acceptance_form_one_durable_loop() {
        let (database, path) = note_test_database();
        let mut request = research_plan_request("Review and correct one deterministic figure");
        let template = request.phases[0].tasks[0].clone();
        request.phases[0].tasks = [
            ("artifact-original", "producer"),
            ("artifact-review", "reviewer"),
            ("artifact-corrected", "producer"),
        ]
        .into_iter()
        .map(|(id, role)| ResearchPlanTask {
            id: id.into(),
            title: id.replace('-', " "),
            specialist_role: role.into(),
            objective: format!("Execute {id} in the zero-spend fixture"),
            ..template.clone()
        })
        .collect();
        let plan = database
            .record_research_plan("campaign:a", request)
            .unwrap();
        database
            .record_research_plan_decision(
                "campaign:a",
                &plan.plan.id,
                ResearchPlanDecisionKind::Approved,
                "primary",
                "The fixture has no external effects.",
            )
            .unwrap();
        let dispatch = database
            .dispatch_research_plan_phase("campaign:a", &plan.plan.id, "phase-one", "primary")
            .unwrap();
        let child_for = |task_id: &str| {
            dispatch
                .children
                .iter()
                .find(|child| child.task_id == task_id)
                .unwrap()
                .agent_run_id
                .clone()
        };
        let now = Utc::now().to_rfc3339();
        for id in ["figure-original", "review-report", "figure-corrected"] {
            database
                .insert_artifact(&Artifact {
                    id: id.into(),
                    run_id: None,
                    kind: "fixture".into(),
                    media_type: "application/json".into(),
                    byte_size: 2,
                    path: format!("/tmp/{id}.json"),
                    source_path: None,
                    created_at: now.clone(),
                })
                .unwrap();
        }
        let original = database
            .record_science_artifact_version(
                "campaign:a",
                CreateScienceArtifactVersionRequest {
                    title: "Decision figure".into(),
                    kind: "figure_bundle".into(),
                    producing_agent_run_id: child_for("artifact-original"),
                    parent_version_id: None,
                    artifact_ids: vec!["figure-original".into()],
                    source_version_ids: vec![],
                    plan_id: plan.plan.id.clone(),
                    phase_id: "phase-one".into(),
                    status: "review_required".into(),
                    metadata: json!({"deterministicFixture": true}),
                },
            )
            .unwrap();
        database
            .record_science_artifact_annotation(
                "campaign:a",
                CreateScienceArtifactAnnotationRequest {
                    artifact_version_id: original.id.clone(),
                    actor: "primary".into(),
                    category: "operator_inspection".into(),
                    body: "The title obscures the denominator.".into(),
                    anchor: json!({"scope":"artifact_version"}),
                },
            )
            .unwrap();
        let review = database
            .record_science_artifact_review(
                "campaign:a",
                CreateScienceArtifactReviewRequest {
                    artifact_version_id: original.id.clone(),
                    reviewer_agent_run_id: child_for("artifact-review"),
                    status: "finding".into(),
                    findings: vec![json!({"message":"Label the retained failure."})],
                    checked: vec!["figure-to-method consistency".into()],
                    review_artifact_ids: vec!["review-report".into()],
                },
            )
            .unwrap();
        database
            .record_science_artifact_disposition(
                "campaign:a",
                CreateScienceArtifactDispositionRequest {
                    artifact_version_id: original.id.clone(),
                    actor: "primary".into(),
                    disposition: ScienceArtifactDispositionKind::RevisionRequested,
                    rationale: "Correct the denominator label without replacing the original."
                        .into(),
                },
            )
            .unwrap();
        let corrected = database
            .record_science_artifact_version(
                "campaign:a",
                CreateScienceArtifactVersionRequest {
                    title: original.title.clone(),
                    kind: original.kind.clone(),
                    producing_agent_run_id: child_for("artifact-corrected"),
                    parent_version_id: Some(original.id.clone()),
                    artifact_ids: vec!["figure-corrected".into()],
                    source_version_ids: vec![original.id.clone()],
                    plan_id: plan.plan.id,
                    phase_id: "phase-one".into(),
                    status: "corrected".into(),
                    metadata: json!({"resolvedReviewId": review.id}),
                },
            )
            .unwrap();
        database
            .record_science_artifact_annotation(
                "campaign:a",
                CreateScienceArtifactAnnotationRequest {
                    artifact_version_id: corrected.id.clone(),
                    actor: "primary".into(),
                    category: "operator_inspection".into(),
                    body: "The corrected render exposes the retained failure.".into(),
                    anchor: json!({"scope":"artifact_version"}),
                },
            )
            .unwrap();
        let accepted = database
            .record_science_artifact_disposition(
                "campaign:a",
                CreateScienceArtifactDispositionRequest {
                    artifact_version_id: corrected.id.clone(),
                    actor: "primary".into(),
                    disposition: ScienceArtifactDispositionKind::Accepted,
                    rationale: "The correction resolves the independent finding.".into(),
                },
            )
            .unwrap();
        assert_eq!(accepted.review_ids, vec![review.id]);
        assert!(accepted.previous_disposition_sha256.is_some());
        let workspace = database.science_artifact_workspace("campaign:a").unwrap();
        assert_eq!(
            (workspace.versions.len(), workspace.dispositions.len()),
            (2, 2)
        );
        let standing = database.run_standing_review("campaign:a").unwrap();
        assert_eq!(standing.status, StandingReviewStatus::Clean);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn startup_recovery_requires_local_supervision_ownership() {
        let (database, path) = note_test_database();
        let now = Utc::now().to_rfc3339();
        let run = |id: &str, locality: &str| Run {
            id: id.to_owned(),
            campaign_id: "campaign:a".to_owned(),
            capability_id: format!("{locality}.capability"),
            name: id.to_owned(),
            status: "running".to_owned(),
            phase: "execute".to_owned(),
            progress: 0.5,
            started_at: Some(now.clone()),
            finished_at: None,
            external_url: None,
            pid: Some(1234),
            budget_ceiling_usd: None,
            cost_usd: None,
            parameters: if locality == "external" {
                json!({"operationalProvenance": {"sourceSystem": "test"}})
            } else {
                json!({})
            },
            resources: ResourceRequest {
                locality: locality.to_owned(),
                ..ResourceRequest::default()
            },
        };
        database
            .seed(&SeedBundle {
                campaigns: vec![],
                capabilities: vec![],
                runs: vec![run("external:run", "external"), run("local:run", "local")],
                metrics: vec![],
                events: vec![],
                artifacts: vec![],
                budgets: vec![],
                candidates: vec![],
                basins: vec![],
                objects: vec![],
                relations: vec![],
                actions: vec![],
                external_jobs: vec![],
                providers: vec![],
                projections: vec![],
            })
            .unwrap();
        database
            .initialize_run_supervision(
                "local:run",
                Path::new("/tmp/local-events.jsonl"),
                Path::new("/tmp/local-stderr.log"),
            )
            .unwrap();

        let recoverable = database.recoverable_local_runs().unwrap();
        assert_eq!(recoverable.len(), 1);
        assert_eq!(recoverable[0].id, "local:run");
        assert_eq!(
            database.run("external:run").unwrap().unwrap().status,
            "running"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn campaign_note_is_atomic_and_auditable() {
        let (database, path) = note_test_database();
        let response = database.create_note(&note_request()).unwrap();
        let snapshot = database
            .snapshot(RuntimeStatus {
                version: "0.1".into(),
                status: "connected".into(),
                state_path: path.display().to_string(),
                artifact_path: "artifacts".into(),
                started_at: Utc::now().to_rfc3339(),
                host: HostResources::default(),
            })
            .unwrap();
        assert_eq!(response.note.type_name, "concord.campaign_note/1");
        assert_eq!(response.note.state, "mistake");
        assert_eq!(response.note.payload["internal"], true);
        assert_eq!(response.relation.predicate, "annotates");
        assert_eq!(response.relation.object_id, "run:a");
        assert_eq!(response.action.action_type, "note_created");
        assert_eq!(database.notes_for_campaign("campaign:a").unwrap().len(), 1);
        assert!(snapshot
            .objects
            .iter()
            .any(|entry| entry.id == response.note.id));
        assert!(snapshot
            .relations
            .iter()
            .any(|entry| entry.id == response.relation.id));
        assert!(snapshot
            .actions
            .iter()
            .any(|entry| entry.id == response.action.id));
        assert!(snapshot
            .events
            .iter()
            .any(|entry| { entry.object_id == response.note.id && entry.verb == "note_recorded" }));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn campaign_note_rejects_invalid_category() {
        let (database, path) = note_test_database();
        let mut request = note_request();
        request.category = "wishful_thinking".to_owned();
        assert!(database
            .create_note(&request)
            .unwrap_err()
            .to_string()
            .contains("unsupported note category"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn agent_events_are_idempotent_hash_chained_and_revision_guarded() {
        let path = std::env::temp_dir().join(format!(
            "concord-agent-runtime-test-{}.sqlite",
            Uuid::new_v4().simple()
        ));
        let database = Database::new(&path).unwrap();
        database
            .upsert_provider(&ProviderProfile {
                id: "fixture".into(),
                name: "Fixture".into(),
                kind: "model_api".into(),
                base_url: None,
                secret_ref: None,
                secret_available: true,
                status: "ready".into(),
                metadata: json!({"model": "fixture-v1"}),
                updated_at: Utc::now().to_rfc3339(),
            })
            .unwrap();
        let campaign = database
            .create_campaign(&CreateCampaignRequest {
                name: "Agent test".into(),
                domain: "test".into(),
                objective: "test durable transitions".into(),
                program_source: None,
                capability_ids: vec![],
            })
            .unwrap();
        let created = database
            .create_agent_run(
                &CreateAgentRunRequest {
                    campaign_id: campaign.id.clone(),
                    provider_id: "fixture".into(),
                    model: None,
                    task: "Read the record".into(),
                    allowed_tools: vec!["read_campaign_object".into()],
                    budget: AgentBudget::default(),
                    epact: None,
                    parent_run_id: None,
                    parent_event_hash: None,
                },
                "fixture-v1",
            )
            .unwrap();
        assert_eq!(created.run.revision, 0);
        let listed = database.agent_run_envelopes(Some(&campaign.id)).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].run.id, created.run.id);
        assert_eq!(listed[0].events.len(), 1);
        let requested = database
            .append_agent_event(
                &created.run.id,
                0,
                "model-request-1",
                AgentEventKind::ModelRequested,
                json!({"requestId": "request-1"}),
            )
            .unwrap();
        assert_eq!(requested.run.status, AgentRunStatus::AwaitingModel);
        assert_eq!(requested.run.model_calls, 1);
        let repeated = database
            .append_agent_event(
                &created.run.id,
                0,
                "model-request-1",
                AgentEventKind::ModelRequested,
                json!({"requestId": "request-1"}),
            )
            .unwrap();
        assert_eq!(repeated.run.revision, 1);
        assert_eq!(repeated.events.len(), 2);
        assert_eq!(
            repeated.events[1].previous_event_sha256,
            Some(repeated.events[0].event_sha256.clone())
        );
        assert!(database
            .append_agent_event(
                &created.run.id,
                0,
                "model-request-1",
                AgentEventKind::ModelRequested,
                json!({"requestId": "different"}),
            )
            .is_err());
        assert!(database
            .append_agent_event(
                &created.run.id,
                0,
                "model-response-1",
                AgentEventKind::ModelResponded,
                json!({"output": []}),
            )
            .unwrap_err()
            .to_string()
            .contains("revision conflict"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn independent_agent_children_can_append_events_concurrently() {
        let (database, path) = note_test_database();
        let run_ids = (0..3)
            .map(|index| {
                database
                    .create_agent_run(
                        &CreateAgentRunRequest {
                            campaign_id: "campaign:a".into(),
                            provider_id: "concord-deterministic".into(),
                            model: None,
                            task: format!("Parallel child {index}"),
                            allowed_tools: vec![],
                            budget: AgentBudget::default(),
                            epact: None,
                            parent_run_id: None,
                            parent_event_hash: None,
                        },
                        "concord-deterministic-v1",
                    )
                    .unwrap()
                    .run
                    .id
            })
            .collect::<Vec<_>>();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(run_ids.len()));
        let handles = run_ids
            .into_iter()
            .map(|run_id| {
                let database = database.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    database.append_agent_event(
                        &run_id,
                        0,
                        "parallel-model-request",
                        AgentEventKind::ModelRequested,
                        json!({"runId": run_id}),
                    )
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            let envelope = handle.join().unwrap().unwrap();
            assert_eq!(envelope.run.revision, 1);
            assert_eq!(envelope.run.status, AgentRunStatus::AwaitingModel);
        }
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn campaign_note_rejects_run_from_another_campaign() {
        let (database, path) = note_test_database();
        let mut request = note_request();
        request.run_id = Some("run:b".to_owned());
        assert!(database
            .create_note(&request)
            .unwrap_err()
            .to_string()
            .contains("does not belong to campaign"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn seeds_and_reads_a_workspace() {
        let path = std::env::temp_dir().join(format!("concord-test-{}.sqlite", Uuid::new_v4()));
        let database = Database::new(&path).unwrap();
        let capability = Capability {
            id: "test.capability".into(),
            name: "Test".into(),
            kind: "utility".into(),
            version: "1".into(),
            provider: "test".into(),
            description: "test".into(),
            trust_status: "qualified".into(),
            lifecycle: vec!["execute".into()],
            command: vec![],
            resources: ResourceRequest::default(),
        };
        let campaign = Campaign {
            id: "campaign".into(),
            name: "Campaign".into(),
            domain: "test".into(),
            objective: "test".into(),
            status: "active".into(),
            created_at: Utc::now().to_rfc3339(),
            program: DesignProgram {
                id: "program".into(),
                name: "Program".into(),
                language: EPACT_LANGUAGE.into(),
                language_version: EPACT_LANGUAGE_VERSION.into(),
                source: "campaign test".into(),
            },
            capability_ids: vec![capability.id.clone()],
        };
        database
            .seed(&SeedBundle {
                campaigns: vec![campaign],
                capabilities: vec![capability],
                runs: vec![],
                metrics: vec![],
                events: vec![],
                artifacts: vec![],
                budgets: vec![],
                candidates: vec![],
                basins: vec![],
                objects: vec![],
                relations: vec![],
                actions: vec![],
                external_jobs: vec![],
                providers: vec![],
                projections: vec![],
            })
            .unwrap();
        let snapshot = database
            .snapshot(RuntimeStatus {
                version: "0.1".into(),
                status: "connected".into(),
                state_path: path.display().to_string(),
                artifact_path: "artifacts".into(),
                started_at: Utc::now().to_rfc3339(),
                host: HostResources::default(),
            })
            .unwrap();
        assert_eq!(snapshot.campaigns.len(), 1);
        assert_eq!(snapshot.capabilities.len(), 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn refresh_seed_inserts_a_missing_budget_into_an_existing_workspace() {
        let path = std::env::temp_dir().join(format!(
            "concord-budget-refresh-test-{}.sqlite",
            Uuid::new_v4()
        ));
        let database = Database::new(&path).unwrap();
        database
            .upsert_capability(&Capability {
                id: "existing.capability".into(),
                name: "Existing".into(),
                kind: "utility".into(),
                version: "1".into(),
                provider: "test".into(),
                description: "makes the workspace nonempty".into(),
                trust_status: "qualified".into(),
                lifecycle: vec!["execute".into()],
                command: vec![],
                resources: ResourceRequest::default(),
            })
            .unwrap();
        database
            .refresh_seed_reference_data(&SeedBundle {
                campaigns: vec![],
                capabilities: vec![],
                runs: vec![],
                metrics: vec![],
                events: vec![],
                artifacts: vec![],
                budgets: vec![BudgetAccount {
                    id: "budget".into(),
                    name: "Grant".into(),
                    source: "test".into(),
                    currency: "USD".into(),
                    total: 5_000.0,
                    spent: 528.96,
                    exposure: 0.0,
                    remaining_floor: 4_471.04,
                    updated_at: "2026-08-09T19:30:00+00:00".into(),
                }],
                candidates: vec![],
                basins: vec![],
                objects: vec![],
                relations: vec![],
                actions: vec![],
                external_jobs: vec![],
                providers: vec![],
                projections: vec![],
            })
            .unwrap();
        let snapshot = database
            .snapshot(RuntimeStatus {
                version: "0.1".into(),
                status: "connected".into(),
                state_path: path.display().to_string(),
                artifact_path: "artifacts".into(),
                started_at: Utc::now().to_rfc3339(),
                host: HostResources::default(),
            })
            .unwrap();
        assert_eq!(snapshot.budgets.len(), 1);
        assert_eq!(snapshot.budgets[0].remaining_floor, 4_471.04);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn campaign_lifecycle_binds_projects_exports_and_replays() {
        let path = std::env::temp_dir().join(format!(
            "concord-campaign-lifecycle-test-{}.sqlite",
            Uuid::new_v4()
        ));
        let database = Database::new(&path).unwrap();
        let capability = Capability {
            id: "test.generic".into(),
            name: "Generic capability".into(),
            kind: "analysis".into(),
            version: "1".into(),
            provider: "local".into(),
            description: "test".into(),
            trust_status: "qualified".into(),
            lifecycle: vec!["execute".into()],
            command: vec![],
            resources: ResourceRequest::default(),
        };
        database.upsert_capability(&capability).unwrap();
        let campaign = database
            .create_campaign(&CreateCampaignRequest {
                name: "Migration survey".into(),
                domain: "ecology".into(),
                objective: "Map seasonal movement".into(),
                program_source: None,
                capability_ids: vec![capability.id.clone()],
            })
            .unwrap();
        assert_eq!(campaign.capability_ids, vec![capability.id.clone()]);
        assert_eq!(campaign.program.language, EPACT_LANGUAGE);
        assert_eq!(campaign.program.language_version, EPACT_LANGUAGE_VERSION);
        assert!(campaign
            .program
            .source
            .starts_with(&format!("contract {EPACT_PROGRAM_CONTRACT}\n")));

        database
            .upsert_provider(&ProviderProfile {
                id: "provider".into(),
                name: "Provider".into(),
                kind: "model_api".into(),
                base_url: Some("https://example.invalid".into()),
                secret_ref: None,
                secret_available: false,
                status: "ready".into(),
                metadata: json!({}),
                updated_at: Utc::now().to_rfc3339(),
            })
            .unwrap();
        database
            .upsert_projection(&ObjectProjection {
                id: "projection:1".into(),
                campaign_id: campaign.id.clone(),
                run_id: None,
                object_id: "observation:1".into(),
                space: "migration-pca".into(),
                x: 1.0,
                y: 2.0,
                z: Some(3.0),
                group_id: Some("north-pacific".into()),
                signals: json!({"confidence": 0.9}),
                selected: true,
                label: Some("Observation 1".into()),
                updated_at: Utc::now().to_rfc3339(),
            })
            .unwrap();
        let archive = database.campaign_archive(&campaign.id).unwrap();
        assert_eq!(archive.schema_version, "concord.campaign/0.1");
        assert_eq!(archive.capabilities.len(), 1);
        assert_eq!(archive.projections.len(), 1);

        let replay = database.replay_campaign(&campaign.id, None).unwrap();
        assert_eq!(replay.domain, "ecology");
        assert_eq!(replay.capability_ids, campaign.capability_ids);
        assert_eq!(replay.program.language, EPACT_LANGUAGE);
        let snapshot = database
            .snapshot(RuntimeStatus {
                version: "0.1".into(),
                status: "connected".into(),
                state_path: path.display().to_string(),
                artifact_path: "artifacts".into(),
                started_at: Utc::now().to_rfc3339(),
                host: HostResources::default(),
            })
            .unwrap();
        assert_eq!(snapshot.campaigns.len(), 2);
        assert_eq!(snapshot.providers.len(), 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn paid_runs_reserve_budget_and_reject_overcommitment() {
        let path =
            std::env::temp_dir().join(format!("concord-budget-test-{}.sqlite", Uuid::new_v4()));
        let database = Database::new(&path).unwrap();
        let capability = Capability {
            id: "test.paid".into(),
            name: "Paid test".into(),
            kind: "evaluation".into(),
            version: "1".into(),
            provider: "test".into(),
            description: "test".into(),
            trust_status: "provisional".into(),
            lifecycle: vec!["execute".into()],
            command: vec!["true".into()],
            resources: ResourceRequest::default(),
        };
        let campaign = Campaign {
            id: "campaign".into(),
            name: "Campaign".into(),
            domain: "test".into(),
            objective: "test".into(),
            status: "active".into(),
            created_at: Utc::now().to_rfc3339(),
            program: DesignProgram {
                id: "program".into(),
                name: "Program".into(),
                language: EPACT_LANGUAGE.into(),
                language_version: EPACT_LANGUAGE_VERSION.into(),
                source: "campaign test".into(),
            },
            capability_ids: vec![capability.id.clone()],
        };
        database
            .seed(&SeedBundle {
                campaigns: vec![campaign],
                capabilities: vec![capability.clone()],
                runs: vec![],
                metrics: vec![],
                events: vec![],
                artifacts: vec![],
                budgets: vec![BudgetAccount {
                    id: "budget".into(),
                    name: "Grant".into(),
                    source: "test".into(),
                    currency: "USD".into(),
                    total: 1_000.0,
                    spent: 0.0,
                    exposure: 0.0,
                    remaining_floor: 1_000.0,
                    updated_at: Utc::now().to_rfc3339(),
                }],
                candidates: vec![],
                basins: vec![],
                objects: vec![],
                relations: vec![],
                actions: vec![],
                external_jobs: vec![],
                providers: vec![ProviderProfile {
                    id: "fixture".into(),
                    name: "Fixture".into(),
                    kind: "model_api".into(),
                    base_url: None,
                    secret_ref: None,
                    secret_available: true,
                    status: "ready".into(),
                    metadata: json!({"model": "fixture-v1"}),
                    updated_at: Utc::now().to_rfc3339(),
                }],
                projections: vec![],
            })
            .unwrap();

        let request = LaunchRequest {
            campaign_id: "campaign".into(),
            capability_id: capability.id.clone(),
            name: "Reserved run".into(),
            parameters: json!({}),
            budget_ceiling_usd: Some(250.0),
        };
        let run = database.create_run(&request, &capability).unwrap();
        let snapshot = database
            .snapshot(RuntimeStatus {
                version: "0.1".into(),
                status: "connected".into(),
                state_path: path.display().to_string(),
                artifact_path: "artifacts".into(),
                started_at: Utc::now().to_rfc3339(),
                host: HostResources::default(),
            })
            .unwrap();
        assert_eq!(snapshot.budgets[0].exposure, 250.0);
        assert_eq!(snapshot.budgets[0].remaining_floor, 750.0);

        let overcommitted = LaunchRequest {
            name: "Too expensive".into(),
            budget_ceiling_usd: Some(751.0),
            ..request.clone()
        };
        let error = database
            .create_run(&overcommitted, &capability)
            .unwrap_err();
        assert!(error.to_string().contains("exceeds remaining floor"));

        database.update_run_cost(&run.id, 40.0, "test").unwrap();
        database
            .update_run_status(&run.id, "completed", "finalize", 1.0, None)
            .unwrap();
        database
            .update_run_status(
                &run.id,
                "running",
                "stream",
                0.4,
                Some("late buffered worker event"),
            )
            .unwrap();
        let settled = database
            .snapshot(RuntimeStatus {
                version: "0.1".into(),
                status: "connected".into(),
                state_path: path.display().to_string(),
                artifact_path: "artifacts".into(),
                started_at: Utc::now().to_rfc3339(),
                host: HostResources::default(),
            })
            .unwrap();
        assert_eq!(settled.budgets[0].spent, 40.0);
        assert_eq!(settled.budgets[0].exposure, 40.0);
        assert_eq!(settled.budgets[0].remaining_floor, 960.0);
        assert_eq!(
            settled
                .runs
                .iter()
                .find(|entry| entry.id == run.id)
                .unwrap()
                .status,
            "completed"
        );

        let cancelled = database.create_run(&request, &capability).unwrap();
        database
            .update_run_status(
                &cancelled.id,
                "cancelled",
                "finalize",
                0.0,
                Some("cancelled before provider cost was available"),
            )
            .unwrap();
        let released = database
            .snapshot(RuntimeStatus {
                version: "0.1".into(),
                status: "connected".into(),
                state_path: path.display().to_string(),
                artifact_path: "artifacts".into(),
                started_at: Utc::now().to_rfc3339(),
                host: HostResources::default(),
            })
            .unwrap();
        assert_eq!(released.budgets[0].spent, 40.0);
        assert_eq!(released.budgets[0].exposure, 40.0);
        assert_eq!(released.budgets[0].remaining_floor, 960.0);

        database
            .update_run_cost(&cancelled.id, 5.0, "late provider reconciliation")
            .unwrap();
        let reconciled = database
            .snapshot(RuntimeStatus {
                version: "0.1".into(),
                status: "connected".into(),
                state_path: path.display().to_string(),
                artifact_path: "artifacts".into(),
                started_at: Utc::now().to_rfc3339(),
                host: HostResources::default(),
            })
            .unwrap();
        assert_eq!(reconciled.budgets[0].spent, 45.0);
        assert_eq!(reconciled.budgets[0].exposure, 45.0);
        assert_eq!(reconciled.budgets[0].remaining_floor, 955.0);

        let paid_agent = database
            .create_agent_run(
                &CreateAgentRunRequest {
                    campaign_id: "campaign".into(),
                    provider_id: "fixture".into(),
                    model: Some("fixture-v1".into()),
                    task: "Test paid fork reservation".into(),
                    allowed_tools: vec![],
                    budget: AgentBudget {
                        max_model_calls: 1,
                        max_tool_calls: 0,
                        max_elapsed_seconds: 60,
                        budget_id: Some("budget".into()),
                        max_cost_usd: Some(10.0),
                    },
                    epact: None,
                    parent_run_id: None,
                    parent_event_hash: None,
                },
                "fixture-v1",
            )
            .unwrap();
        let cancelled_agent = database
            .append_agent_event(
                &paid_agent.run.id,
                paid_agent.run.revision,
                "cancel-parent",
                AgentEventKind::Cancelled,
                json!({"reason": "exercise fork reservation"}),
            )
            .unwrap();
        assert!(database
            .agent_budget_reservation(&paid_agent.run.id)
            .unwrap()
            .is_none());
        let paid_fork = database
            .fork_agent_run(
                &paid_agent.run.id,
                cancelled_agent.run.revision,
                "paid-fork",
                None,
                None,
                None,
                None,
            )
            .unwrap();
        assert_eq!(
            database
                .agent_budget_reservation(&paid_fork.run.id)
                .unwrap(),
            Some(("budget".into(), 10.0, 0.0))
        );
        let fork_reserved = database
            .snapshot(RuntimeStatus {
                version: "0.1".into(),
                status: "connected".into(),
                state_path: path.display().to_string(),
                artifact_path: "artifacts".into(),
                started_at: Utc::now().to_rfc3339(),
                host: HostResources::default(),
            })
            .unwrap();
        assert_eq!(fork_reserved.budgets[0].remaining_floor, 945.0);

        for step in 0..5 {
            database
                .insert_metric_bounded(
                    &MetricPoint {
                        run_id: run.id.clone(),
                        name: "system/cpu_percent".into(),
                        step,
                        value: step as f64,
                        timestamp: Utc::now().to_rfc3339(),
                    },
                    3,
                )
                .unwrap();
        }
        assert_eq!(
            database.metrics_for_run(&run.id, None, 100).unwrap().len(),
            3
        );
        let now = Utc::now().to_rfc3339();
        database
            .upsert_semantic_object(&SemanticObject {
                id: "candidate:1".into(),
                campaign_id: Some("campaign".into()),
                run_id: Some(run.id.clone()),
                kind: "candidate".into(),
                type_name: "protein.sequence_candidate".into(),
                state: "evaluated".into(),
                label: Some("candidate 1".into()),
                payload: json!({"sequence": "GASG"}),
                created_at: now.clone(),
                updated_at: now.clone(),
            })
            .unwrap();
        database
            .upsert_action(&ActionRecord {
                id: "action:1".into(),
                campaign_id: Some("campaign".into()),
                run_id: Some(run.id.clone()),
                action_type: "evaluate".into(),
                actor: "test".into(),
                target_id: Some("candidate:1".into()),
                status: "completed".into(),
                payload: json!({}),
                timestamp: now.clone(),
            })
            .unwrap();
        database
            .upsert_external_job(&ExternalJob {
                id: "external:test:job-1".into(),
                campaign_id: Some("campaign".into()),
                run_id: Some(run.id.clone()),
                provider: "test".into(),
                external_id: "job-1".into(),
                label: "GPU test".into(),
                status: "running".into(),
                chip: Some("h100".into()),
                submitted_at: Some(now.clone()),
                started_at: None,
                finished_at: None,
                rate_per_min_usd: Some(0.05),
                max_cost_usd: Some(2.0),
                cost_usd: None,
                queue_position: None,
                estimated_wait_seconds: None,
                payload: json!({}),
                updated_at: now,
            })
            .unwrap();
        let snapshot = database
            .snapshot(RuntimeStatus {
                version: "0.1".into(),
                status: "connected".into(),
                state_path: path.display().to_string(),
                artifact_path: "artifacts".into(),
                started_at: Utc::now().to_rfc3339(),
                host: HostResources::default(),
            })
            .unwrap();
        assert_eq!(snapshot.objects.len(), 1);
        assert_eq!(snapshot.actions.len(), 1);
        assert_eq!(snapshot.external_jobs.len(), 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn operational_import_is_idempotent_and_rejects_endpoint_material() {
        let path = std::env::temp_dir().join(format!(
            "concord-operational-import-test-{}.sqlite",
            Uuid::new_v4()
        ));
        let database = Database::new(&path).unwrap();
        let generated_at = Utc::now().to_rfc3339();
        let campaign = Campaign {
            id: "external:campaign".into(),
            name: "External campaign".into(),
            domain: "test domain".into(),
            objective: "Exercise a domain-neutral import".into(),
            status: "active".into(),
            created_at: generated_at.clone(),
            program: DesignProgram {
                id: "external:program".into(),
                name: "External program".into(),
                language: "external-contract".into(),
                language_version: "1".into(),
                source: "sha256:abc".into(),
            },
            capability_ids: vec![],
        };
        let empty_bundle = || SeedBundle {
            campaigns: vec![campaign.clone()],
            capabilities: vec![],
            runs: vec![],
            metrics: vec![],
            events: vec![],
            artifacts: vec![],
            budgets: vec![],
            candidates: vec![],
            basins: vec![],
            objects: vec![],
            relations: vec![],
            actions: vec![],
            external_jobs: vec![],
            providers: vec![],
            projections: vec![],
        };
        let envelope = OperationalImportEnvelope {
            contract: "concord.operational-import/1".into(),
            import_id: "source:snapshot:1".into(),
            generated_at: generated_at.clone(),
            classification: "operational_metadata".into(),
            contains_scientific_endpoints: false,
            source: OperationalImportSource {
                system: "external-test".into(),
                stream: "campaign/1".into(),
                repository: "example/repository".into(),
                revision: "0123456789012345678901234567890123456789".into(),
                url: None,
            },
            bundle: empty_bundle(),
        };
        let first = database.import_operational(&envelope).unwrap();
        assert!(first.imported);
        assert_eq!(first.record.record_count, 1);
        assert_eq!(first.source.status, "fresh");
        assert_eq!(first.source.latest_import_id, envelope.import_id);
        let repeated = database.import_operational(&envelope).unwrap();
        assert!(!repeated.imported);
        assert_eq!(repeated.record.content_sha256, first.record.content_sha256);
        assert_eq!(
            repeated.source.latest_import_id,
            first.source.latest_import_id
        );

        let snapshot = database
            .snapshot(RuntimeStatus {
                version: "0.1".into(),
                status: "connected".into(),
                state_path: path.display().to_string(),
                artifact_path: "artifacts".into(),
                started_at: Utc::now().to_rfc3339(),
                host: HostResources::default(),
            })
            .unwrap();
        assert_eq!(snapshot.operational_sources.len(), 1);
        assert_eq!(snapshot.operational_sources[0].source_stream, "campaign/1");

        let mut stale_envelope = envelope.clone();
        stale_envelope.import_id = "source:snapshot:stale".into();
        stale_envelope.generated_at = "2020-01-01T00:00:00Z".into();
        assert!(database.import_operational(&stale_envelope).is_err());

        let mut endpoint_envelope = envelope.clone();
        endpoint_envelope.import_id = "source:snapshot:endpoint".into();
        endpoint_envelope.contains_scientific_endpoints = true;
        assert!(database.import_operational(&endpoint_envelope).is_err());

        let mut metric_envelope = envelope;
        metric_envelope.import_id = "source:snapshot:metric".into();
        metric_envelope.bundle.metrics.push(MetricPoint {
            run_id: "run".into(),
            name: "scientific/endpoint".into(),
            step: 1,
            value: 0.5,
            timestamp: generated_at,
        });
        assert!(database.import_operational(&metric_envelope).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn capability_package_registry_is_content_addressed_and_discovery_is_bound() {
        let path = std::env::temp_dir().join(format!(
            "concord-capability-package-test-{}.sqlite",
            Uuid::new_v4()
        ));
        let database = Database::new(&path).unwrap();
        let package = CapabilityPackage {
            contract: CAPABILITY_PACKAGE_CONTRACT.into(),
            package_id: "org.example/public-literature".into(),
            display_name: "Public literature".into(),
            version: "1.0.0".into(),
            kind: CapabilityPackageKind::McpServer,
            source: CapabilityPackageSource {
                uri: "https://mcp.example.org/mcp".into(),
                transport: CapabilityTransport::StreamableHttp,
                entrypoint: None,
                arguments: vec![],
                environment_keys: vec![],
                protocol_versions: vec!["2026-07-28".into()],
                authentication: CapabilityAuthentication::None,
            },
            content_sha256: "c".repeat(64),
            trust_status: PackageTrustStatus::Quarantined,
            declared_capabilities: vec!["literature_search".into()],
            permissions: vec![],
            upstream_allowed_tools: vec![],
            metadata: json!({}),
        };
        let first = database.register_capability_package(&package).unwrap();
        let repeated = database.register_capability_package(&package).unwrap();
        assert_eq!(first.record_id, repeated.record_id);
        assert_eq!(database.capability_packages().unwrap().len(), 1);

        let snapshot = McpDiscoverySnapshot::build(
            package.package_id.clone(),
            "2026-07-28".into(),
            "example-server".into(),
            "2.0.0".into(),
            Utc::now().to_rfc3339(),
            vec![McpToolSnapshot {
                name: "search".into(),
                description: "Search public literature".into(),
                input_schema: json!({"type":"object","properties":{"query":{"type":"string"}}}),
                output_schema: None,
            }],
        )
        .unwrap();
        let discovery = database
            .record_mcp_discovery(&first.record_id, &snapshot)
            .unwrap();
        assert_eq!(discovery.package_content_sha256, package.content_sha256);
        assert_eq!(
            database
                .mcp_discoveries_for_package(&first.record_id)
                .unwrap()
                .len(),
            1
        );
        let qualification = database
            .record_capability_qualification(
                &first.record_id,
                Some(&discovery.record_id),
                QualificationDisposition::Qualified,
                vec![CapabilityToolPolicy {
                    tool_name: "search".into(),
                    effect: EffectClass::NetworkRead,
                    approval: ApprovalMode::EveryCall,
                    data_classes: vec!["public_literature".into()],
                    reversibility: ReversibilityPolicy {
                        class: ReversibilityClass::ReadOnly,
                        reversal_action: None,
                        limitations: vec!["The source may retain access logs.".into()],
                    },
                }],
                "scientist@example.org",
                "The frozen search tool is limited to public literature and every call remains approval gated.",
            )
            .unwrap();
        assert_eq!(
            qualification.disposition,
            QualificationDisposition::Qualified
        );
        assert_eq!(qualification.tool_policies.len(), 1);
        let bindings = database.qualified_mcp_tools().unwrap();
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].tool.name, "search");
        assert_eq!(
            database
                .qualified_mcp_tool(&bindings[0].alias)
                .unwrap()
                .unwrap()
                .qualification_sha256,
            qualification.qualification_sha256
        );
        assert!(database
            .record_capability_qualification(
                &first.record_id,
                Some(&discovery.record_id),
                QualificationDisposition::Qualified,
                vec![],
                "scientist@example.org",
                "An incomplete policy must fail.",
            )
            .is_err());
        let revoked = database
            .record_capability_qualification(
                &first.record_id,
                None,
                QualificationDisposition::Revoked,
                vec![],
                "scientist@example.org",
                "Qualification withdrawn pending upstream review.",
            )
            .unwrap();
        assert_eq!(
            revoked.previous_qualification_sha256,
            Some(qualification.qualification_sha256)
        );
        assert_eq!(
            database
                .latest_capability_qualification(&first.record_id)
                .unwrap()
                .unwrap()
                .disposition,
            QualificationDisposition::Revoked
        );
        assert!(database.qualified_mcp_tools().unwrap().is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn source_gate_survives_restart_and_long_lineage_replay() {
        let (database, path) = note_test_database();
        let now = Utc::now().to_rfc3339();
        database
            .upsert_semantic_object(&SemanticObject {
                id: "evidence:source-gate:document".into(),
                campaign_id: Some("campaign:a".into()),
                run_id: None,
                kind: "evidence".into(),
                type_name: "test.source-document/1".into(),
                state: "accepted".into(),
                label: Some("Source gate test document".into()),
                payload: json!({"sha256": "d".repeat(64)}),
                created_at: now.clone(),
                updated_at: now,
            })
            .unwrap();
        let mut assertions = vec![SourceGateAssertion {
            contract: SOURCE_GATE_ASSERTION_CONTRACT.into(),
            id: "root".into(),
            campaign_id: "campaign:a".into(),
            source_id: "source".into(),
            requirement_id: "source.locator".into(),
            scope_id: "source-scope".into(),
            state: SourceEvidenceState::Unresolved,
            value: None,
            limitations: vec!["not frozen".into()],
            evidence_object_ids: vec!["evidence:source-gate:document".into()],
            method: "bounded fixture".into(),
            evidence_class: "official_document".into(),
            effective_sequence: 1,
            parent_assertion_id: None,
            amendment_kind: None,
        }];
        let mut parent = "root".to_owned();
        for sequence in 2..=130 {
            let id = format!("amendment-{sequence:03}");
            assertions.push(SourceGateAssertion {
                contract: SOURCE_GATE_ASSERTION_CONTRACT.into(),
                id: id.clone(),
                campaign_id: "campaign:a".into(),
                source_id: "source".into(),
                requirement_id: "source.locator".into(),
                scope_id: "source-scope".into(),
                state: if sequence == 130 {
                    SourceEvidenceState::Verified
                } else {
                    SourceEvidenceState::PartiallyVerified
                },
                value: Some(json!(format!("value-{sequence}"))),
                limitations: if sequence == 130 {
                    vec![]
                } else {
                    vec!["lineage continues".into()]
                },
                evidence_object_ids: vec!["evidence:source-gate:document".into()],
                method: "bounded fixture".into(),
                evidence_class: "official_document".into(),
                effective_sequence: sequence,
                parent_assertion_id: Some(parent),
                amendment_kind: Some(SourceAmendmentKind::Supersedes),
            });
            parent = id;
        }
        let input = SourceGateInput {
            contract: SOURCE_GATE_INPUT_CONTRACT.into(),
            campaign_id: "campaign:a".into(),
            campaign_snapshot_sha256: "0".repeat(64),
            program: SourceGateProgram {
                contract: SOURCE_GATE_PROGRAM_CONTRACT.into(),
                id: "restart-test".into(),
                version: "1".into(),
                campaign_id: "campaign:a".into(),
                sources: vec!["source".into()],
                scopes: vec![SourceGateScope {
                    id: "source-scope".into(),
                    description: "restart scope".into(),
                    dimensions: BTreeMap::new(),
                }],
                requirements: vec![SourceGateRequirement {
                    id: "source.locator".into(),
                    source_id: "source".into(),
                    scope_id: "source-scope".into(),
                    label: "Locator".into(),
                    class: SourceRequirementClass::Mandatory,
                    dependencies: vec![],
                    accepted_evidence_classes: vec!["official_document".into()],
                }],
                tranches: vec![SourceGateTranche {
                    id: "diagnostic".into(),
                    label: "Diagnostic".into(),
                    requirement_ids: vec!["source.locator".into()],
                    historical_only: false,
                }],
            },
            assertions,
            decisions: vec![],
            authorities: vec![],
            authorized_tranche_ids: vec![],
            previous_projection: None,
        };
        let first = database
            .compile_source_gate("campaign:a", input.clone())
            .unwrap();
        let first_epact = first.epact.as_ref().unwrap();
        assert_eq!(first_epact.requirements.len(), 1);
        assert_eq!(first_epact.tranches.len(), 1);
        assert_eq!(
            first.projection.assertions[0]
                .superseded_assertion_ids
                .len(),
            129
        );
        let mut migrated_input = input.clone();
        migrated_input.program.id = "restart-test-expanded".into();
        migrated_input.program.version = "2".into();
        let migrated = database
            .compile_source_gate("campaign:a", migrated_input.clone())
            .unwrap();
        assert_eq!(
            migrated.projection.previous_projection_sha256.as_deref(),
            Some(first.projection.projection_sha256.as_str())
        );
        let immediate_replay = database
            .compile_source_gate("campaign:a", migrated_input.clone())
            .unwrap();
        assert_eq!(immediate_replay.projection, migrated.projection);
        assert_eq!(immediate_replay.epact, migrated.epact);
        assert_eq!(immediate_replay.compiled_at, migrated.compiled_at);
        drop(database);

        let reopened = Database::new(&path).unwrap();
        let restored = reopened
            .latest_source_gate_compilation("campaign:a")
            .unwrap()
            .unwrap();
        assert_eq!(restored.projection, migrated.projection);
        assert_eq!(restored.epact, migrated.epact);
        verify_source_gate_projection(restored.input.clone(), &restored.projection).unwrap();
        let replayed = reopened
            .compile_source_gate("campaign:a", migrated_input)
            .unwrap();
        assert_eq!(replayed.projection, migrated.projection);
        assert_eq!(replayed.compiled_at, migrated.compiled_at);
        let archive = reopened.campaign_archive("campaign:a").unwrap();
        assert!(archive.relations.iter().any(|relation| {
            relation.predicate == "compiled_from"
                && relation.subject_id
                    == format!(
                        "source-gate-projection:{}",
                        &migrated.projection.projection_sha256[..16]
                    )
        }));
        assert!(archive.relations.iter().any(|relation| {
            relation.predicate == "compiled_as_epact"
                && relation.subject_id
                    == format!(
                        "source-gate-projection:{}",
                        &migrated.projection.projection_sha256[..16]
                    )
        }));
        drop(reopened);
        let _ = std::fs::remove_file(path);
    }
}
