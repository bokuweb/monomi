//! Per-package analysis worker.
//!
//! Resolves a `(name, [version])` pair into a verdict by checking the
//! catalog first and only analyzing if missing.

use monomi_catalog::{CatalogReader, CatalogWriter};
use monomi_core::{Ecosystem, EcosystemId};
use monomi_llm::Adjudicator;

use crate::Result;

/// Trait-object catalog reference (read + write) so a single backend
/// (e.g. `LocalDirCatalog`) can be passed through one `&dyn`.
pub trait CatalogReadWrite: CatalogReader + CatalogWriter {}

impl<T: CatalogReader + CatalogWriter + ?Sized> CatalogReadWrite for T {}

/// Ecosystem-generic worker. Owns one ecosystem client and uses it
/// for both `latest_version` resolution and tarball fetch.
pub struct Worker<E: Ecosystem> {
    pub eco: E,
}

impl<E: Ecosystem> Worker<E> {
    pub fn new(eco: E) -> Self {
        Self { eco }
    }

    pub fn ecosystem(&self) -> EcosystemId {
        self.eco.id()
    }

    /// Resolve `(name)` → latest version via the ecosystem's
    /// registry. Returns `Ok(None)` when the registry has no
    /// usable version (deleted, all-yanked).
    pub async fn latest_version(&self, name: &str) -> Result<Option<String>> {
        Ok(self.eco.latest_version(name).await?)
    }

    /// Analyze `<name>@<version>` if the catalog does not already
    /// hold a verdict for it. Returns `true` if a new verdict was
    /// written.
    pub async fn analyze_if_missing(
        &self,
        name: &str,
        version: &str,
        adjudicator: &dyn Adjudicator,
        catalog: &dyn CatalogReadWrite,
    ) -> Result<bool> {
        if catalog
            .lookup_by_nv(self.eco.id(), name, version)
            .await?
            .is_some()
        {
            tracing::debug!(eco = ?self.eco.id(), name, version, "catalog hit; skip");
            return Ok(false);
        }
        let tar = self.eco.fetch(name, version).await?;
        let verdict = monomi_pipeline::analyze(&self.eco, tar, adjudicator).await?;
        catalog.put_verdict(&verdict).await?;
        tracing::info!(
            eco = ?self.eco.id(),
            name,
            version,
            status = ?verdict.final_verdict.status,
            "analyzed and published"
        );
        Ok(true)
    }
}
