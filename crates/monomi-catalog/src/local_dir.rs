use std::path::{Path, PathBuf};

use async_trait::async_trait;
use monomi_core::{EcosystemId, Integrity, Verdict};
use tokio::io::AsyncWriteExt;

use crate::{
    layout::{by_integrity_path, latest_index_path, nv_pointer_path, NvPointer},
    CatalogError, CatalogReader, CatalogWriter, Result,
};

/// Filesystem-backed catalog. Useful for:
///
/// - **Tests** — no network, deterministic.
/// - **Production writers** — `monomi publish` writes into a staging
///   directory; operators sync it to R2 with `rclone` / `aws s3 sync`.
///   Keeps this crate free of any cloud-SDK dependency.
/// - **Air-gapped scanning** — `sakimori`'s proxy can point its reader
///   at a locally-rsync'd mirror.
pub struct LocalDirCatalog {
    root: PathBuf,
}

impl LocalDirCatalog {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn abs(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }
}

#[async_trait]
impl CatalogReader for LocalDirCatalog {
    async fn lookup_by_integrity(&self, i: &Integrity) -> Result<Option<Verdict>> {
        let rel = by_integrity_path(i)?;
        read_json(&self.abs(&rel)).await
    }

    async fn lookup_by_nv(
        &self,
        eco: EcosystemId,
        name: &str,
        version: &str,
    ) -> Result<Option<Verdict>> {
        let rel = nv_pointer_path(eco, name, version);
        let pointer: Option<NvPointer> = read_json(&self.abs(&rel)).await?;
        match pointer {
            None => Ok(None),
            Some(p) => read_json(&self.abs(&p.verdict_path)).await,
        }
    }
}

#[async_trait]
impl CatalogWriter for LocalDirCatalog {
    async fn put_verdict(&self, v: &Verdict) -> Result<()> {
        let canonical_rel = by_integrity_path(&v.artifact.integrity)?;
        let canonical_abs = self.abs(&canonical_rel);

        let body = serde_json::to_vec_pretty(v)?;
        write_atomic(&canonical_abs, &body).await?;

        let pointer = NvPointer {
            artifact: v.artifact.clone(),
            verdict_path: canonical_rel.clone(),
        };
        let pointer_rel =
            nv_pointer_path(v.artifact.ecosystem, &v.artifact.name, &v.artifact.version);
        let pointer_body = serde_json::to_vec_pretty(&pointer)?;
        write_atomic(&self.abs(&pointer_rel), &pointer_body).await?;

        // Append a single line to the rolling index. Done as a
        // best-effort append; concurrent writers can interleave at
        // the OS level but each whole line stays intact.
        let index_path = self.abs(latest_index_path());
        if let Some(parent) = index_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let line = serde_json::to_string(&IndexEntry {
            artifact: v.artifact.clone(),
            verdict_path: canonical_rel,
            status: format!("{:?}", v.final_verdict.status).to_lowercase(),
            analyzed_at: v.analyzed_at.to_rfc3339(),
        })?;
        let mut f = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&index_path)
            .await?;
        f.write_all(line.as_bytes()).await?;
        f.write_all(b"\n").await?;
        f.flush().await?;
        Ok(())
    }
}

#[derive(serde::Serialize)]
struct IndexEntry {
    artifact: monomi_core::ArtifactId,
    verdict_path: String,
    status: String,
    analyzed_at: String,
}

async fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match tokio::fs::read(path).await {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(CatalogError::Io(e)),
    }
}

async fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let tmp = path.with_extension("json.tmp");
    tokio::fs::write(&tmp, bytes).await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use monomi_core::{
        ArtifactId, FinalVerdict, HashAlgo, Stage1Result, Stage1Verdict, Status, Verdict,
        VerdictSource, SCHEMA_VERSION,
    };

    fn sample_verdict(name: &str, ver: &str, payload: &[u8]) -> Verdict {
        let integrity = Integrity::from_bytes(HashAlgo::Sha512, payload);
        Verdict {
            schema_version: SCHEMA_VERSION,
            artifact: ArtifactId {
                ecosystem: EcosystemId::Npm,
                name: name.into(),
                version: ver.into(),
                integrity,
            },
            analyzed_at: Utc::now(),
            analyzer_version: "test".into(),
            ruleset_version: "test".into(),
            stage1: Stage1Result {
                findings: vec![],
                score: 0,
                verdict: Stage1Verdict::Clean,
            },
            stage2: None,
            final_verdict: FinalVerdict {
                status: Status::Clean,
                confidence: 0.9,
                source: VerdictSource::Stage1,
            },
        }
    }

    #[tokio::test]
    async fn put_then_lookup_roundtrips() {
        let tmp = tempfile::tempdir().unwrap();
        let cat = LocalDirCatalog::new(tmp.path());
        let v = sample_verdict("pkg-a", "1.0.0", b"some bytes");
        cat.put_verdict(&v).await.unwrap();

        let by_int = cat
            .lookup_by_integrity(&v.artifact.integrity)
            .await
            .unwrap()
            .expect("verdict by integrity");
        assert_eq!(by_int.artifact.name, "pkg-a");

        let by_nv = cat
            .lookup_by_nv(EcosystemId::Npm, "pkg-a", "1.0.0")
            .await
            .unwrap()
            .expect("verdict by nv");
        assert_eq!(by_nv.artifact.integrity, v.artifact.integrity);
    }

    #[tokio::test]
    async fn lookup_missing_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let cat = LocalDirCatalog::new(tmp.path());
        let i = Integrity::from_bytes(HashAlgo::Sha512, b"never written");
        assert!(cat.lookup_by_integrity(&i).await.unwrap().is_none());
        assert!(cat
            .lookup_by_nv(EcosystemId::Npm, "missing", "0.0.0")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn put_appends_to_latest_index() {
        let tmp = tempfile::tempdir().unwrap();
        let cat = LocalDirCatalog::new(tmp.path());
        cat.put_verdict(&sample_verdict("a", "1", b"a-bytes"))
            .await
            .unwrap();
        cat.put_verdict(&sample_verdict("b", "1", b"b-bytes"))
            .await
            .unwrap();
        let idx = tokio::fs::read_to_string(tmp.path().join(latest_index_path()))
            .await
            .unwrap();
        let lines: Vec<_> = idx.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"name\":\"a\""));
        assert!(lines[1].contains("\"name\":\"b\""));
    }

    #[tokio::test]
    async fn put_is_idempotent_on_same_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let cat = LocalDirCatalog::new(tmp.path());
        let v = sample_verdict("p", "1", b"payload");
        cat.put_verdict(&v).await.unwrap();
        // Second put with the same artifact: must not panic and must
        // not corrupt the existing file.
        cat.put_verdict(&v).await.unwrap();
        let by_int = cat
            .lookup_by_integrity(&v.artifact.integrity)
            .await
            .unwrap();
        assert!(by_int.is_some());
    }
}
