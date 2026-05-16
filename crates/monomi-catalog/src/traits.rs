use async_trait::async_trait;
use monomi_core::{EcosystemId, Integrity, Verdict};

use crate::Result;

#[async_trait]
pub trait CatalogReader: Send + Sync {
    /// Primary lookup. Returns `Ok(None)` if no verdict exists for
    /// this exact integrity (NOT an error — the caller decides
    /// whether to fail open or trigger an on-demand scan).
    async fn lookup_by_integrity(&self, i: &Integrity) -> Result<Option<Verdict>>;

    /// Convenience lookup via the (ecosystem, name, version) pointer.
    /// One extra round-trip vs `lookup_by_integrity`.
    async fn lookup_by_nv(
        &self,
        eco: EcosystemId,
        name: &str,
        version: &str,
    ) -> Result<Option<Verdict>>;
}

#[async_trait]
pub trait CatalogWriter: Send + Sync {
    /// Idempotent publish: writes the canonical verdict file, the
    /// (eco, name, version) pointer, and appends to the rolling index.
    /// Writing the same verdict bytes twice is a no-op.
    async fn put_verdict(&self, v: &Verdict) -> Result<()>;
}
