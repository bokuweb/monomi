use crate::{
    artifact::{ArtifactId, EcosystemId},
    ecosystem::{LifecycleEntry, PackageDiff, RegistryMetadata},
    entry::Entry,
    finding::Finding,
    manifest::Manifest,
};

/// Reference data (top package names, exfil endpoint lists, etc.)
/// shared across rule evaluations.
#[derive(Debug, Default, Clone)]
pub struct Corpus {
    pub top_packages: Vec<String>,
    pub known_exfil_hosts: Vec<String>,
}

pub struct AnalysisCtx<'a> {
    pub artifact: &'a ArtifactId,
    pub manifest: &'a Manifest,
    pub lifecycle: &'a [LifecycleEntry],
    pub entries: &'a [Entry],
    pub diff: Option<&'a PackageDiff>,
    /// Out-of-band registry metadata (publish time, maintainers,
    /// etc.) when the ecosystem provides it; `None` for offline
    /// scans and ecosystems that haven't implemented
    /// `Ecosystem::fetch_registry_metadata`.
    pub registry: Option<&'a RegistryMetadata>,
    pub corpus: &'a Corpus,
}

pub trait Rule: Send + Sync {
    fn id(&self) -> &'static str;
    fn applies_to(&self, eco: EcosystemId) -> bool;
    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding>;
}
