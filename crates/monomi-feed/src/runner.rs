//! Orchestrator: drives the `_changes` stream into the worker pool.
//!
//! Operational concerns wired in here:
//!
//! - **Graceful shutdown** — `SIGTERM` / `SIGINT` stop accepting
//!   new changes, drain in-flight workers, and persist the cursor
//!   at the highest fully-processed seq before returning. Avoids
//!   the "restart loses a few changes" hole that a naive `loop {}`
//!   would have.
//! - **In-flight dedup** — npm's `_changes` feed re-emits the same
//!   package id within seconds when multiple versions land in a
//!   burst. A small `(EcosystemId, name)` set held while a worker
//!   is running on it prevents two workers from racing on the same
//!   packument fetch. (Idempotent catalog writes already guarantee
//!   correctness; this just removes wasted work.)
//! - **Rate-limit awareness** is delegated to the npm crate's
//!   `get_with_retry` helper.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use monomi_core::EcosystemId;
use monomi_llm::Adjudicator;
use monomi_npm::NpmEcosystem;
use tokio::signal;
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinSet;

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

/// Run the feed until SIGTERM / SIGINT, returning the highest
/// `seq` actually drained.
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
    let in_flight: Arc<Mutex<HashSet<(EcosystemId, String)>>> =
        Arc::new(Mutex::new(HashSet::new()));
    let mut tasks: JoinSet<()> = JoinSet::new();

    let mut last_seq = since.unwrap_or(0);
    let mut processed_since_checkpoint: u32 = 0;
    let mut shutdown = false;

    // Build the signal future once. tokio::signal::ctrl_c handles
    // SIGINT cross-platform; we also tap SIGTERM on Unix because
    // process managers (systemd, k8s, supervisord, fly.io) send
    // that one.
    let mut sigterm = unix_sigterm();

    while !shutdown {
        tokio::select! {
            biased;
            _ = signal::ctrl_c() => {
                tracing::info!("SIGINT received; entering graceful shutdown");
                shutdown = true;
            }
            _ = wait_sigterm(&mut sigterm) => {
                tracing::info!("SIGTERM received; entering graceful shutdown");
                shutdown = true;
            }
            // Reap any finished worker so the JoinSet doesn't grow
            // without bound between actual change rows.
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            row = changes.next() => {
                let Some(row) = row else {
                    tracing::info!("changes stream ended");
                    break;
                };
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
                let in_flight = in_flight.clone();
                let name = row.id.clone();
                let seq = row.seq;
                let eco = worker.ecosystem();
                let key = (eco, name.clone());

                // Dedup: if another worker is already on this
                // (eco, name) we skip without holding the semaphore.
                {
                    let mut set = in_flight.lock().await;
                    if !set.insert(key.clone()) {
                        tracing::debug!(name, "in-flight dedup hit; skip");
                        drop(permit);
                        last_seq = row.seq;
                        continue;
                    }
                }

                tasks.spawn(async move {
                    let _permit = permit;
                    let version = match worker.latest_version(&name).await {
                        Ok(Some(v)) => v,
                        Ok(None) => {
                            tracing::debug!(name, "packument missing (deleted?); skip");
                            in_flight.lock().await.remove(&key);
                            return;
                        }
                        Err(e) => {
                            tracing::warn!(name, "packument fetch failed at seq {seq}: {e}");
                            in_flight.lock().await.remove(&key);
                            return;
                        }
                    };
                    if let Err(e) = worker
                        .analyze_if_missing(&name, &version, adj.as_ref(), catalog.as_ref())
                        .await
                    {
                        tracing::warn!(name, version, "analyze failed at seq {seq}: {e}");
                    }
                    in_flight.lock().await.remove(&key);
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
        }
    }

    // Drain phase: don't acknowledge changes beyond what's already
    // committed to the catalog. We wait for every spawned worker
    // to finish so the cursor we persist is honest about what's
    // been analyzed.
    tracing::info!(in_flight = tasks.len(), "draining workers");
    while let Some(res) = tasks.join_next().await {
        if let Err(e) = res {
            tracing::warn!("worker join error: {e}");
        }
    }

    if let Err(e) = cursor.save(last_seq).await {
        tracing::warn!("final cursor save failed: {e}");
    }
    tracing::info!(last_seq, "feed stopped");
    Ok(last_seq)
}

// ----- platform-specific SIGTERM hookup -----

#[cfg(unix)]
fn unix_sigterm() -> Option<signal::unix::Signal> {
    signal::unix::signal(signal::unix::SignalKind::terminate()).ok()
}
#[cfg(not(unix))]
fn unix_sigterm() -> Option<()> {
    None
}

#[cfg(unix)]
async fn wait_sigterm(s: &mut Option<signal::unix::Signal>) {
    match s {
        Some(s) => {
            s.recv().await;
        }
        None => std::future::pending::<()>().await,
    }
}
#[cfg(not(unix))]
async fn wait_sigterm(_s: &mut Option<()>) {
    std::future::pending::<()>().await
}
