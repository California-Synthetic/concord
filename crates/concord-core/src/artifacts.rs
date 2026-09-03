use anyhow::{bail, ensure, Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

const COPY_BUFFER_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone)]
pub struct ArtifactStore {
    root: PathBuf,
}

impl ArtifactStore {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)
            .with_context(|| format!("create artifact store {}", root.display()))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn ingest(&self, source: impl AsRef<Path>) -> Result<(String, PathBuf, u64)> {
        self.ingest_inner(source.as_ref(), None)
    }

    pub fn ingest_bounded(
        &self,
        source: impl AsRef<Path>,
        max_bytes: u64,
    ) -> Result<(String, PathBuf, u64)> {
        ensure!(max_bytes > 0, "artifact byte limit must be positive");
        self.ingest_inner(source.as_ref(), Some(max_bytes))
    }

    fn ingest_inner(
        &self,
        source: &Path,
        max_bytes: Option<u64>,
    ) -> Result<(String, PathBuf, u64)> {
        let metadata = fs::metadata(source)
            .with_context(|| format!("inspect artifact {}", source.display()))?;
        ensure!(metadata.is_file(), "artifact source must be a regular file");
        if max_bytes.is_some_and(|limit| metadata.len() > limit) {
            bail!(
                "artifact {} is {} bytes and exceeds the {} byte limit",
                source.display(),
                metadata.len(),
                max_bytes.unwrap_or_default()
            );
        }

        let incoming = self.root.join(".incoming");
        fs::create_dir_all(&incoming)?;
        let temporary = incoming.join(format!("{}.partial", Uuid::new_v4().simple()));
        let result = self.copy_into_store(source, &temporary, max_bytes);
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    fn copy_into_store(
        &self,
        source: &Path,
        temporary: &Path,
        max_bytes: Option<u64>,
    ) -> Result<(String, PathBuf, u64)> {
        let mut input =
            File::open(source).with_context(|| format!("read artifact {}", source.display()))?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(temporary)
            .with_context(|| format!("create temporary artifact {}", temporary.display()))?;
        let mut digest = Sha256::new();
        let mut byte_size = 0_u64;
        let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
        loop {
            let bytes = input.read(&mut buffer)?;
            if bytes == 0 {
                break;
            }
            byte_size = byte_size
                .checked_add(bytes as u64)
                .context("artifact byte count overflowed")?;
            if let Some(limit) = max_bytes {
                ensure!(
                    byte_size <= limit,
                    "artifact exceeds the {limit} byte limit"
                );
            }
            digest.update(&buffer[..bytes]);
            output.write_all(&buffer[..bytes])?;
        }
        output.flush()?;
        output.sync_all()?;
        drop(output);

        let digest = format!("sha256:{:x}", digest.finalize());
        let hex = digest.trim_start_matches("sha256:");
        let suffix = safe_suffix(source);
        let directory = self.root.join(&hex[..2]);
        fs::create_dir_all(&directory)?;
        let target = directory.join(format!("{hex}.{suffix}"));
        if target.exists() {
            verify_existing_artifact(&target, &digest, byte_size)?;
            fs::remove_file(temporary)?;
        } else if let Err(error) = fs::rename(temporary, &target) {
            if target.exists() {
                verify_existing_artifact(&target, &digest, byte_size)?;
                fs::remove_file(temporary)?;
            } else {
                return Err(error).with_context(|| {
                    format!(
                        "commit artifact {} to {}",
                        temporary.display(),
                        target.display()
                    )
                });
            }
        }
        Ok((digest, target, byte_size))
    }
}

fn safe_suffix(source: &Path) -> String {
    source
        .extension()
        .and_then(|value| value.to_str())
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 16
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        })
        .map(str::to_ascii_lowercase)
        .unwrap_or_else(|| "bin".to_owned())
}

fn verify_existing_artifact(path: &Path, expected_digest: &str, expected_size: u64) -> Result<()> {
    let metadata = fs::metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.len() == expected_size,
        "content-addressed artifact {} has an unexpected size",
        path.display()
    );
    let (actual_digest, actual_size) = digest_file(path)?;
    ensure!(
        actual_size == expected_size && actual_digest == expected_digest,
        "content-addressed artifact {} failed integrity verification",
        path.display()
    );
    Ok(())
}

fn digest_file(path: &Path) -> Result<(String, u64)> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut byte_size = 0_u64;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    loop {
        let bytes = file.read(&mut buffer)?;
        if bytes == 0 {
            break;
        }
        byte_size = byte_size
            .checked_add(bytes as u64)
            .context("artifact byte count overflowed")?;
        digest.update(&buffer[..bytes]);
    }
    Ok((format!("sha256:{:x}", digest.finalize()), byte_size))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_directory(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "concord-artifact-{label}-{}",
            Uuid::new_v4().simple()
        ))
    }

    #[test]
    fn streams_artifacts_atomically_and_verifies_existing_content() {
        let directory = test_directory("atomic");
        let source = directory.join("source.JSON");
        fs::create_dir_all(&directory).unwrap();
        fs::write(&source, br#"{"result":"durable"}"#).unwrap();
        let store = ArtifactStore::new(directory.join("store")).unwrap();

        let first = store.ingest(&source).unwrap();
        let repeated = store.ingest(&source).unwrap();
        assert_eq!(first, repeated);
        assert_eq!(
            first.1.extension().and_then(|value| value.to_str()),
            Some("json")
        );
        assert_eq!(fs::read(&first.1).unwrap(), fs::read(&source).unwrap());

        fs::write(&first.1, vec![b'x'; first.2 as usize]).unwrap();
        let error = store.ingest(&source).unwrap_err();
        assert!(error.to_string().contains("integrity verification"));
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn bounded_ingest_rejects_oversized_artifacts_without_a_partial_commit() {
        let directory = test_directory("bounded");
        let source = directory.join("large.bin");
        fs::create_dir_all(&directory).unwrap();
        fs::write(&source, vec![0_u8; 32]).unwrap();
        let store = ArtifactStore::new(directory.join("store")).unwrap();

        let error = store.ingest_bounded(&source, 16).unwrap_err();
        assert!(error.to_string().contains("exceeds the 16 byte limit"));
        let committed = fs::read_dir(store.root())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name() != ".incoming")
            .count();
        assert_eq!(committed, 0);
        let _ = fs::remove_dir_all(directory);
    }
}
