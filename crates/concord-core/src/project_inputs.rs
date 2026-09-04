//! Immutable, content-bound researcher inputs. Attachment is not execution or disclosure authority.
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PROJECT_INPUT_CONTRACT: &str = "concord.project-input/1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttachProjectInputRequest {
    pub logical_path: String,
    pub content_sha256: String,
    pub previous_version_id: Option<String>,
    pub actor: String,
    pub idempotency_key: String,
}

impl AttachProjectInputRequest {
    pub fn validate(&self) -> Result<()> {
        validate_logical_path(&self.logical_path)?;
        validate_digest(&self.content_sha256)?;
        ensure!(
            !self.actor.trim().is_empty() && self.actor.len() <= 256,
            "input actor is required and must fit 256 bytes"
        );
        ensure!(
            !self.idempotency_key.trim().is_empty() && self.idempotency_key.len() <= 256,
            "input idempotency key is required and must fit 256 bytes"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectInputVersion {
    pub contract: String,
    pub id: String,
    pub campaign_id: String,
    pub logical_path: String,
    pub version: u32,
    pub artifact_id: String,
    pub content_sha256: String,
    pub byte_size: u64,
    pub media_type: String,
    pub previous_version_id: Option<String>,
    pub previous_version_sha256: Option<String>,
    pub actor: String,
    pub idempotency_key: String,
    pub created_at: String,
    pub record_sha256: String,
}

impl ProjectInputVersion {
    /// Verify the exact bytes about to be displayed or disclosed, not just their storage path.
    pub fn verify_content(&self, bytes: &[u8]) -> Result<()> {
        self.validate()?;
        ensure!(
            bytes.len() as u64 == self.byte_size
                && format!("{:x}", Sha256::digest(bytes)) == self.content_sha256,
            "project input content integrity mismatch"
        );
        Ok(())
    }

    pub fn recompute_sha256(&self) -> Result<String> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .expect("input record serializes as an object")
            .remove("recordSha256");
        Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(&value)?)))
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.contract == PROJECT_INPUT_CONTRACT,
            "unsupported project input contract"
        );
        AttachProjectInputRequest {
            logical_path: self.logical_path.clone(),
            content_sha256: self.content_sha256.clone(),
            previous_version_id: self.previous_version_id.clone(),
            actor: self.actor.clone(),
            idempotency_key: self.idempotency_key.clone(),
        }
        .validate()?;
        ensure!(
            !self.id.is_empty() && !self.campaign_id.is_empty() && !self.artifact_id.is_empty(),
            "input identities are required"
        );
        ensure!(
            self.version > 0 && self.byte_size <= i64::MAX as u64,
            "invalid input version or size"
        );
        ensure!(
            !self.media_type.is_empty()
                && self.media_type.len() <= 256
                && !self.media_type.chars().any(char::is_control),
            "invalid input media type"
        );
        chrono::DateTime::parse_from_rfc3339(&self.created_at)?;
        ensure!(
            (self.version == 1) == self.previous_version_id.is_none()
                && self.previous_version_id.is_none() == self.previous_version_sha256.is_none(),
            "input predecessor is required for revisions only"
        );
        if let Some(hash) = &self.previous_version_sha256 {
            validate_digest(hash)?;
        }
        ensure!(
            self.record_sha256 == self.recompute_sha256()?,
            "project input record hash mismatch"
        );
        Ok(())
    }
}

pub fn validate_logical_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty()
            && path.len() <= 1024
            && !path
                .chars()
                .any(|ch| ch.is_control() || ch == '\\' || ch == ':'),
        "input name must be a portable relative path"
    );
    ensure!(
        path.split('/')
            .all(|part| !part.is_empty() && part != "." && part != ".."),
        "input name must not be absolute or traverse directories"
    );
    Ok(())
}

fn validate_digest(digest: &str) -> Result<()> {
    ensure!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "input digest must be lowercase SHA-256"
    );
    Ok(())
}
