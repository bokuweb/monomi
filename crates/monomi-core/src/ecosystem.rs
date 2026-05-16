use std::collections::BTreeMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    artifact::{EcosystemId, Integrity},
    entry::Entry,
    error::Result,
    manifest::Manifest,
};

/// Raw fetched bytes for a package, plus a hint about its container format.
#[derive(Debug, Clone)]
pub struct Tarball {
    /// e.g. `https://registry.npmjs.org/foo/-/foo-1.2.3.tgz`
    pub source_url: Option<String>,
    /// gzip-compressed tar (npm), .crate (cargo), etc.
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleKind {
    /// npm: preinstall / install / postinstall / prepare.
    /// cargo: build.rs.
    /// pypi: setup.py / pyproject build-backend.
    InstallTime,
    /// npm: prepublish / publish.
    PublishTime,
    /// Other ecosystem-specific hooks.
    Other,
}

/// A script or entry point a package manager will execute on install/build.
#[derive(Debug, Clone)]
pub struct LifecycleEntry {
    /// Canonical hook name (e.g. `postinstall`, `build.rs`).
    pub name: String,
    pub kind: LifecycleKind,
    /// Source body if available inline (npm scripts). Empty if the
    /// entry references a path instead (e.g. cargo build.rs).
    pub body: String,
    /// Path within the package, if relevant.
    pub path: Option<String>,
}

/// Out-of-band metadata about a published version that lives at
/// the registry rather than inside the tarball — publish time,
/// maintainer history, package age, etc. Different registries
/// expose different subsets of these; `None` means the field is
/// not provided.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegistryMetadata {
    /// When this exact version was published to the registry.
    pub published_at: Option<DateTime<Utc>>,
    /// When the package (any version) was first seen.
    pub package_created_at: Option<DateTime<Utc>>,
    /// Login / id of the account that published this version.
    pub published_by: Option<String>,
    /// All maintainers currently listed for the package.
    pub maintainers: Vec<String>,
    /// Total count of versions ever published for this package.
    pub total_versions: Option<u32>,
    /// Publish timestamps of every version, keyed by version
    /// string. Useful for "how long has this package existed"
    /// signals without a per-version registry round-trip.
    pub version_publish_times: BTreeMap<String, DateTime<Utc>>,
}

/// Coarse diff result vs a previous version of the same package.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PackageDiff {
    pub prev_version: String,
    pub size_delta_bytes: i64,
    pub size_growth_ratio: f32,
    pub files_added: Vec<String>,
    pub files_removed: Vec<String>,
    pub files_modified: Vec<String>,
}

#[async_trait]
pub trait Ecosystem: Send + Sync {
    fn id(&self) -> EcosystemId;

    async fn fetch(&self, name: &str, version: &str) -> Result<Tarball>;

    fn integrity(&self, tar: &Tarball) -> Integrity;

    fn parse_manifest(&self, tar: &Tarball) -> Result<Manifest>;

    fn lifecycle_entrypoints(
        &self,
        tar: &Tarball,
        manifest: &Manifest,
    ) -> Result<Vec<LifecycleEntry>>;

    /// Walk the tarball into in-memory `Entry`s. Implementations
    /// enforce per-entry and aggregate size limits.
    fn walk(&self, tar: &Tarball) -> Result<Vec<Entry>>;

    async fn diff_against_previous(
        &self,
        _current: &Tarball,
        _name: &str,
    ) -> Result<Option<PackageDiff>> {
        Ok(None)
    }

    /// Resolve the registry's notion of "the version to scan" for
    /// `name` when the caller hasn't pinned one (typically the
    /// equivalent of npm's `dist-tags.latest`).
    ///
    /// Returns `Ok(None)` when the registry knows the package but
    /// has no usable latest version (yanked, deleted, missing
    /// stable release), and an `Err` for transport / parse failures.
    /// Default impl declines so an ecosystem only has to implement
    /// it when feed / backfill modes need it.
    async fn latest_version(&self, _name: &str) -> Result<Option<String>> {
        Ok(None)
    }

    /// Out-of-band registry metadata for `(name, version)`.
    ///
    /// Default impl returns `None` so an ecosystem only has to wire
    /// this up when rules that consume publish-time / maintainer
    /// signals (e.g. `NPM016`) need it.
    async fn fetch_registry_metadata(
        &self,
        _name: &str,
        _version: &str,
    ) -> Result<Option<RegistryMetadata>> {
        Ok(None)
    }
}
