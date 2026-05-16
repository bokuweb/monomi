//! Backfill mode: process an explicit list of `(name, version)` tuples
//! against any `Ecosystem` impl.
//!
//! Used to warm-start the catalog from a list (top-N npm packages,
//! a Cargo.lock dump, a PyPI top-downloads list, etc.) without
//! waiting for any change stream to revisit them.

use std::sync::Arc;

use monomi_core::Ecosystem;
use monomi_llm::Adjudicator;
use tokio::sync::Semaphore;

use crate::{
    worker::{CatalogReadWrite, Worker},
    Result,
};

pub struct BackfillItem {
    pub name: String,
    /// If `None`, the worker resolves the ecosystem's notion of
    /// "latest" (typically `dist-tags.latest` / `max_stable_version`
    /// / `info.version`).
    pub version: Option<String>,
}

pub async fn run<E: Ecosystem + 'static>(
    eco: E,
    items: Vec<BackfillItem>,
    max_concurrent: usize,
    catalog: Arc<dyn CatalogReadWrite>,
    adjudicator: Arc<dyn Adjudicator>,
) -> Result<BackfillStats> {
    let worker = Arc::new(Worker::new(eco));
    let sem = Arc::new(Semaphore::new(max_concurrent.max(1)));
    let mut handles = Vec::with_capacity(items.len());

    for item in items {
        let permit = sem.clone().acquire_owned().await.expect("semaphore");
        let worker = worker.clone();
        let catalog = catalog.clone();
        let adj = adjudicator.clone();
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            let version = match item.version {
                Some(v) => v,
                None => match worker.latest_version(&item.name).await {
                    Ok(Some(v)) => v,
                    Ok(None) => return Outcome::Missing,
                    Err(_) => return Outcome::Failed,
                },
            };
            match worker
                .analyze_if_missing(&item.name, &version, adj.as_ref(), catalog.as_ref())
                .await
            {
                Ok(true) => Outcome::Analyzed,
                Ok(false) => Outcome::AlreadyPresent,
                Err(_) => Outcome::Failed,
            }
        }));
    }

    let mut stats = BackfillStats::default();
    for h in handles {
        match h.await.unwrap_or(Outcome::Failed) {
            Outcome::Analyzed => stats.analyzed += 1,
            Outcome::AlreadyPresent => stats.already_present += 1,
            Outcome::Missing => stats.missing += 1,
            Outcome::Failed => stats.failed += 1,
        }
    }
    Ok(stats)
}

#[derive(Debug, Default, Clone, Copy)]
pub struct BackfillStats {
    pub analyzed: u32,
    pub already_present: u32,
    pub missing: u32,
    pub failed: u32,
}

enum Outcome {
    Analyzed,
    AlreadyPresent,
    Missing,
    Failed,
}
