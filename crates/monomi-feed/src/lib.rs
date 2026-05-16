//! npm change-stream subscriber.
//!
//! Subscribes to a CouchDB `_changes` continuous feed
//! (`replicate.npmjs.com/registry/_changes`), and for every package
//! reported as changed:
//!
//! 1. Fetches the packument (`registry.npmjs.org/<pkg>`).
//! 2. Picks the `dist-tags.latest` version.
//! 3. Checks the catalog for an existing verdict
//!    (by the lockfile-integrity hash from `dist.integrity`).
//! 4. If missing, fetches the tarball, runs `monomi-pipeline::analyze`,
//!    and `put_verdict`s it.
//!
//! Cursor (last-seen `seq`) is persisted as `feed-state.json` inside
//! the catalog root so restarts resume.
//!
//! Backfill mode lets the daemon process an explicit `(name, version)`
//! list — useful for warm-starting the catalog from npm download stats.

pub mod backfill;
pub mod changes;
pub mod cursor;
pub mod runner;
pub mod worker;

pub use cursor::{Cursor, FeedState};
pub use runner::{run, FeedConfig};

#[derive(Debug, thiserror::Error)]
pub enum FeedError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("http: {0}")]
    Http(String),
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("catalog: {0}")]
    Catalog(#[from] monomi_catalog::CatalogError),
    #[error("pipeline: {0}")]
    Pipeline(#[from] monomi_pipeline::PipelineError),
    #[error("ecosystem: {0}")]
    Ecosystem(#[from] monomi_core::Error),
}

pub type Result<T> = std::result::Result<T, FeedError>;
