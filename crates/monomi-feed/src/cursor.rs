use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::Result;

/// Persisted feed state. Lives at `<catalog>/feed-state.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FeedState {
    /// CouchDB sequence we have processed up to (inclusive).
    pub last_seq: Option<u64>,
}

pub struct Cursor {
    path: PathBuf,
    pub state: FeedState,
}

impl Cursor {
    pub async fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let state = match tokio::fs::read(&path).await {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => FeedState::default(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self { path, state })
    }

    pub async fn save(&self, last_seq: u64) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let state = FeedState {
            last_seq: Some(last_seq),
        };
        let body = serde_json::to_vec_pretty(&state)?;
        let tmp = self.path.with_extension("json.tmp");
        tokio::fs::write(&tmp, body).await?;
        tokio::fs::rename(&tmp, &self.path).await?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn load_returns_default_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let c = Cursor::load(tmp.path().join("state.json")).await.unwrap();
        assert!(c.state.last_seq.is_none());
    }

    #[tokio::test]
    async fn save_then_load_roundtrips() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("state.json");
        Cursor::load(&path)
            .await
            .unwrap()
            .save(12345)
            .await
            .unwrap();
        let c = Cursor::load(&path).await.unwrap();
        assert_eq!(c.state.last_seq, Some(12345));
    }
}
