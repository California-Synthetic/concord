use super::*;
use crate::project_inputs::*;

impl Database {
    /// Copying bytes precedes this transaction; accepting their ownership, version and event is atomic.
    pub fn attach_project_input(
        &self,
        campaign_id: &str,
        request: &AttachProjectInputRequest,
        artifact: &Artifact,
    ) -> Result<ProjectInputVersion> {
        request.validate()?;
        anyhow::ensure!(
            artifact.run_id.is_none() && artifact.kind == "project_input",
            "input artifact must be unattached to execution"
        );
        crate::artifacts::verify_existing_artifact(
            Path::new(&artifact.path),
            &format!("sha256:{}", request.content_sha256),
            artifact.byte_size,
        )?;
        let mut connection = self.connect()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM campaigns WHERE id=?1)",
            [campaign_id],
            |row| row.get(0),
        )?;
        anyhow::ensure!(exists, "unknown campaign {campaign_id}");
        if let Some(json) = tx.query_row("SELECT record_json FROM project_inputs WHERE campaign_id=?1 AND idempotency_key=?2", params![campaign_id, request.idempotency_key], |row| row.get::<_, String>(0)).optional()? {
            let existing: ProjectInputVersion = serde_json::from_str(&json)?;
            existing.validate()?;
            anyhow::ensure!(existing.logical_path == request.logical_path && existing.content_sha256 == request.content_sha256 && existing.previous_version_id == request.previous_version_id && existing.actor == request.actor && existing.media_type == artifact.media_type && existing.byte_size == artifact.byte_size, "input idempotency key is already bound to different content");
            return Ok(existing);
        }
        let closed: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM campaign_closeouts WHERE campaign_id=?1)",
            [campaign_id],
            |row| row.get(0),
        )?;
        anyhow::ensure!(!closed, "closed campaign cannot accept new input versions");
        let previous: Option<ProjectInputVersion> = tx.query_row("SELECT record_json FROM project_inputs WHERE campaign_id=?1 AND logical_path=?2 ORDER BY version DESC LIMIT 1", params![campaign_id, request.logical_path], |row| row.get::<_, String>(0)).optional()?.map(|json| serde_json::from_str(&json)).transpose()?;
        if let Some(previous) = &previous {
            previous.validate()?;
        }
        anyhow::ensure!(
            previous.as_ref().map(|record| &record.id) == request.previous_version_id.as_ref(),
            "input version conflict: refresh the current file version before replacing it"
        );
        let mut record = ProjectInputVersion {
            contract: PROJECT_INPUT_CONTRACT.into(),
            id: format!("project_input_{}", Uuid::new_v4().simple()),
            campaign_id: campaign_id.into(),
            logical_path: request.logical_path.clone(),
            version: previous.as_ref().map_or(Ok(1), |record| {
                record
                    .version
                    .checked_add(1)
                    .context("input version overflow")
            })?,
            artifact_id: artifact.id.clone(),
            content_sha256: request.content_sha256.clone(),
            byte_size: artifact.byte_size,
            media_type: artifact.media_type.clone(),
            previous_version_id: request.previous_version_id.clone(),
            previous_version_sha256: previous.map(|record| record.record_sha256),
            actor: request.actor.clone(),
            idempotency_key: request.idempotency_key.clone(),
            created_at: Utc::now().to_rfc3339(),
            record_sha256: String::new(),
        };
        record.record_sha256 = record.recompute_sha256()?;
        record.validate()?;
        let artifact_exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM artifacts WHERE id=?1)",
            [&artifact.id],
            |row| row.get(0),
        )?;
        anyhow::ensure!(
            !artifact_exists,
            "input attachment requires a fresh artifact identity"
        );
        insert_artifact_tx(&tx, artifact)?;
        tx.execute("INSERT INTO project_inputs(id,campaign_id,logical_path,version,artifact_id,idempotency_key,record_json,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)", params![record.id, campaign_id, record.logical_path, record.version, record.artifact_id, record.idempotency_key, serde_json::to_string(&record)?, record.created_at])?;
        insert_immutable_semantic_object_tx(
            &tx,
            &SemanticObject {
                id: record.id.clone(),
                campaign_id: Some(campaign_id.into()),
                run_id: None,
                kind: "input".into(),
                type_name: PROJECT_INPUT_CONTRACT.into(),
                state: "attached".into(),
                label: Some(record.logical_path.clone()),
                payload: serde_json::to_value(&record)?,
                created_at: record.created_at.clone(),
                updated_at: record.created_at.clone(),
            },
        )?;
        insert_event_tx(
            &tx,
            &LedgerEvent {
                id: format!("evt_{}", Uuid::new_v4().simple()),
                campaign_id: Some(campaign_id.into()),
                run_id: None,
                object_type: "project_input".into(),
                object_id: record.id.clone(),
                verb: "attached".into(),
                timestamp: record.created_at.clone(),
                payload: json!({ "recordSha256": record.record_sha256, "contentSha256": record.content_sha256, "previousVersionId": record.previous_version_id, "actor": record.actor }),
            },
        )?;
        tx.commit()?;
        Ok(record)
    }

    pub fn project_inputs(&self, campaign_id: &str) -> Result<Vec<ProjectInputVersion>> {
        let connection = self.connect()?;
        let jsons = connection.prepare("SELECT record_json FROM project_inputs WHERE campaign_id=?1 ORDER BY logical_path,version")?.query_map([campaign_id], |row| row.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        let records: Vec<ProjectInputVersion> = jsons
            .iter()
            .map(|json| serde_json::from_str(json))
            .collect::<std::result::Result<_, _>>()?;
        let mut previous = std::collections::HashMap::<&str, &ProjectInputVersion>::new();
        for record in &records {
            record.validate()?;
            let parent = previous.get(record.logical_path.as_str());
            anyhow::ensure!(
                record.campaign_id == campaign_id
                    && record.previous_version_id.as_deref()
                        == parent.map(|parent| parent.id.as_str())
                    && record.previous_version_sha256.as_deref()
                        == parent.map(|parent| parent.record_sha256.as_str())
                    && record.version == parent.map_or(1, |parent| parent.version + 1),
                "project input lineage mismatch"
            );
            previous.insert(&record.logical_path, record);
        }
        Ok(records)
    }

    pub fn project_input_for_artifact(
        &self,
        artifact_id: &str,
    ) -> Result<Option<ProjectInputVersion>> {
        let json: Option<String> = self
            .connect()?
            .query_row(
                "SELECT record_json FROM project_inputs WHERE artifact_id=?1",
                [artifact_id],
                |row| row.get(0),
            )
            .optional()?;
        json.map(|json| {
            let record: ProjectInputVersion = serde_json::from_str(&json)?;
            record.validate()?;
            anyhow::ensure!(
                record.artifact_id == artifact_id,
                "input artifact binding mismatch"
            );
            Ok(record)
        })
        .transpose()
    }

    pub fn project_input(
        &self,
        campaign_id: &str,
        id: &str,
    ) -> Result<Option<ProjectInputVersion>> {
        Ok(self
            .project_inputs(campaign_id)?
            .into_iter()
            .find(|record| record.id == id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ArtifactStore;

    #[test]
    fn input_versions_survive_restart_and_bind_original_bytes_and_exports() {
        let dir =
            std::env::temp_dir().join(format!("concord-input-test-{}", Uuid::new_v4().simple()));
        let db = Database::new(dir.join("state.sqlite")).unwrap();
        let campaign = db
            .create_campaign(&CreateCampaignRequest {
                name: "Inputs".into(),
                domain: "Research".into(),
                objective: "Compare samples".into(),
                program_source: None,
                capability_ids: vec![],
            })
            .unwrap();
        let source = dir.join("samples.csv");
        std::fs::write(&source, b"sample,value\na,1\n").unwrap();
        let store = ArtifactStore::new(dir.join("artifacts")).unwrap();
        let (digest, path, size) = store.ingest(&source).unwrap();
        let artifact = Artifact {
            id: "input-file-a".into(),
            run_id: None,
            kind: "project_input".into(),
            media_type: "text/csv".into(),
            byte_size: size,
            path: path.to_string_lossy().into(),
            source_path: Some("samples.csv".into()),
            created_at: Utc::now().to_rfc3339(),
        };
        let request = AttachProjectInputRequest {
            logical_path: "dataset/samples.csv".into(),
            content_sha256: digest.trim_start_matches("sha256:").into(),
            previous_version_id: None,
            actor: "researcher".into(),
            idempotency_key: "upload-1".into(),
        };
        let first = db
            .attach_project_input(&campaign.id, &request, &artifact)
            .unwrap();
        assert_eq!(
            first,
            db.attach_project_input(&campaign.id, &request, &artifact)
                .unwrap()
        );
        first.verify_content(b"sample,value\na,1\n").unwrap();
        assert!(first.verify_content(b"sample,value\na,9\n").is_err());
        assert_eq!(
            db.project_input_for_artifact(&artifact.id).unwrap(),
            Some(first.clone())
        );
        let mut conflict = request.clone();
        conflict.logical_path = "other.csv".into();
        assert!(db
            .attach_project_input(&campaign.id, &conflict, &artifact)
            .is_err());
        db.insert_artifact(&artifact).unwrap();
        let mut projection = db
            .campaign_archive(&campaign.id)
            .unwrap()
            .objects
            .into_iter()
            .find(|object| object.id == first.id)
            .unwrap();
        projection.payload["contentSha256"] = json!("0".repeat(64));
        assert!(db
            .upsert_semantic_object(&projection)
            .unwrap_err()
            .to_string()
            .contains("immutable"));
        let mut overwritten = artifact.clone();
        overwritten.media_type = "text/plain".into();
        assert!(db.insert_artifact(&overwritten).is_err());
        std::fs::write(&source, b"sample,value\na,2\n").unwrap();
        let (digest, path, size) = store.ingest(&source).unwrap();
        let second_artifact = Artifact {
            id: "input-file-b".into(),
            path: path.to_string_lossy().into(),
            byte_size: size,
            ..artifact.clone()
        };
        let mut revised = AttachProjectInputRequest {
            content_sha256: digest.trim_start_matches("sha256:").into(),
            previous_version_id: Some(first.id.clone()),
            idempotency_key: "upload-2".into(),
            ..request.clone()
        };
        let second = db
            .attach_project_input(&campaign.id, &revised, &second_artifact)
            .unwrap();
        revised.idempotency_key = "stale-upload".into();
        assert!(db
            .attach_project_input(&campaign.id, &revised, &second_artifact)
            .unwrap_err()
            .to_string()
            .contains("version conflict"));
        let reopened = Database::new(db.path()).unwrap();
        assert_eq!(
            reopened.project_inputs(&campaign.id).unwrap(),
            vec![first.clone(), second]
        );
        let archive = reopened.campaign_archive(&campaign.id).unwrap();
        assert_eq!(archive.project_inputs.len(), 2);
        assert_eq!(archive.artifacts.len(), 2);
        assert_eq!(
            archive
                .events
                .iter()
                .filter(|event| event.object_type == "project_input")
                .count(),
            2
        );
        assert!(reopened
            .project_input("other-campaign", &first.id)
            .unwrap()
            .is_none());
        std::fs::write(&artifact.path, vec![b'x'; artifact.byte_size as usize]).unwrap();
        assert!(reopened
            .attach_project_input(&campaign.id, &request, &artifact)
            .unwrap_err()
            .to_string()
            .contains("integrity"));
        let json = serde_json::to_string(&first)
            .unwrap()
            .replace("dataset/samples.csv", "altered.csv");
        reopened
            .connect()
            .unwrap()
            .execute(
                "UPDATE project_inputs SET record_json=?1 WHERE id=?2",
                params![json, first.id],
            )
            .unwrap();
        assert!(reopened
            .project_inputs(&campaign.id)
            .unwrap_err()
            .to_string()
            .contains("hash mismatch"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn portable_names_reject_traversal_and_absolute_paths() {
        for path in [
            "",
            "/etc/passwd",
            "../data",
            "a/../b",
            "a\\b",
            "C:/data",
            "a//b",
            "a\n.csv",
        ] {
            assert!(validate_logical_path(path).is_err(), "{path:?}");
        }
        assert!(validate_logical_path("experiment 1/α.csv").is_ok());
    }
}
