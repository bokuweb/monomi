use async_trait::async_trait;
use monomi_core::{EcosystemId, Integrity, Verdict};

use crate::{
    layout::{by_integrity_path, nv_pointer_path, NvPointer},
    CatalogError, CatalogReader, Result,
};

/// Read-only catalog backed by HTTP GETs against a public (or
/// signed-URL-fronted) base URL.
///
/// `sakimori`'s proxy uses this on its hot path — one round-trip,
/// edge-cached at the CDN tier, no auth.
pub struct HttpCatalogReader {
    base_url: String,
    http: reqwest::Client,
}

impl HttpCatalogReader {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http: reqwest::Client::builder()
                .user_agent(concat!("monomi-catalog/", env!("CARGO_PKG_VERSION")))
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("reqwest client"),
        }
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, rel: &str) -> Result<Option<T>> {
        let url = format!("{}/{}", self.base_url, rel);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| CatalogError::Http(format!("{url}: {e}")))?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(CatalogError::Http(format!("{url}: HTTP {status}")));
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| CatalogError::Http(format!("{url}: {e}")))?;
        Ok(Some(serde_json::from_slice(&body)?))
    }
}

#[async_trait]
impl CatalogReader for HttpCatalogReader {
    async fn lookup_by_integrity(&self, i: &Integrity) -> Result<Option<Verdict>> {
        let rel = by_integrity_path(i)?;
        self.get_json(&rel).await
    }

    async fn lookup_by_nv(
        &self,
        eco: EcosystemId,
        name: &str,
        version: &str,
    ) -> Result<Option<Verdict>> {
        let rel = nv_pointer_path(eco, name, version);
        let pointer: Option<NvPointer> = self.get_json(&rel).await?;
        match pointer {
            None => Ok(None),
            Some(p) => self.get_json(&p.verdict_path).await,
        }
    }
}
