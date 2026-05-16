//! Orchestrator: drives the `_changes` stream into the worker pool.

use std::path::PathBuf;
use std::sync::Arc;

use monomi_llm::Adjudicator;
use monomi_npm::NpmEcosystem;
use tokio::sync::Semaphore;

use crate::{
    changes::Changes,
    cursor::Cursor,
    worker::{CatalogReadWrite, Worker},
    Result,
};

#[derive(Debug, Clone)]
pub struct FeedConfig {
    /// Continuous `_changes` URL (CouchDB endpoint).
    pub changes_url: String,
    /// Registry base for packument + tarball fetches.
    pub registry_url: String,
    /// `<catalog>/feed-state.json` lives here.
    pub state_path: PathBuf,
    /// Maximum in-flight analyses.
    pub max_concurrent: usize,
    /// Save the cursor every N processed changes.
    pub checkpoint_every: u32,
    /// Optional starting sequence (overrides cursor when set).
    pub since: Option<u64>,
}

impl FeedConfig {
    pub fn npm_defaults(state_path: impl Into<PathBuf>) -> Self {
        Self {
            changes_url: "https://replicate.npmjs.com/registry/_changes".to_string(),
            registry_url: "https://registry.npmjs.org".to_string(),
            state_path: state_path.into(),
            max_concurrent: 4,
            checkpoint_every: 50,
            since: None,
        }
    }
}

/// Run the feed until the stream ends or the process is signalled.
///
/// Returns the highest `seq` processed.
pub async fn run(
    cfg: FeedConfig,
    catalog: Arc<dyn CatalogReadWrite>,
    adjudicator: Arc<dyn Adjudicator>,
) -> Result<u64> {
    let mut cursor = Cursor::load(&cfg.state_path).await?;
    let since = cfg.since.or(cursor.state.last_seq);
    tracing::info!(
        url = %cfg.changes_url,
        ?since,
        max_concurrent = cfg.max_concurrent,
        "starting feed"
    );

    let mut changes = Changes::open(&cfg.changes_url, since).await?;
    let worker = Arc::new(Worker::new(
        NpmEcosystem::new().with_registry(cfg.registry_url.clone()),
    ));
    let sem = Arc::new(Semaphore::new(cfg.max_concurrent.max(1)));

    let mut last_seq = since.unwrap_or(0);
    let mut processed_since_checkpoint: u32 = 0;

    while let Some(row) = changes.next().await {
        let row = match row {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("changes stream error: {e}; stopping");
                break;
            }
        };
        if row.deleted {
            last_seq = row.seq;
            continue;
        }

        let permit = sem.clone().acquire_owned().await.expect("semaphore");
        let worker = worker.clone();
        let catalog = catalog.clone();
        let adj = adjudicator.clone();
        let name = row.id.clone();
        let seq = row.seq;

        tokio::spawn(async move {
            let _permit = permit;
            let version = match worker.latest_version(&name).await {
                Ok(Some(v)) => v,
                Ok(None) => {
                    tracing::debug!(name, "packument missing (deleted?); skip");
                    return;
                }
                Err(e) => {
                    tracing::warn!(name, "packument fetch failed at seq {seq}: {e}");
                    return;
                }
            };
            if let Err(e) = worker
                .analyze_if_missing(&name, &version, adj.as_ref(), catalog.as_ref())
                .await
            {
                tracing::warn!(name, version, "analyze failed at seq {seq}: {e}");
            }
        });

        last_seq = row.seq;
        processed_since_checkpoint += 1;
        if processed_since_checkpoint >= cfg.checkpoint_every {
            if let Err(e) = cursor.save(last_seq).await {
                tracing::warn!("cursor save failed: {e}");
            }
            cursor.state.last_seq = Some(last_seq);
            processed_since_checkpoint = 0;
        }
    }

    if processed_since_checkpoint > 0 {
        let _ = cursor.save(last_seq).await;
    }
    tracing::info!(last_seq, "feed stopped");
    Ok(last_seq)
}
