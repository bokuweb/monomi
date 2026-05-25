use std::any::Any;

use crate::{
    artifact::{ArtifactId, EcosystemId},
    ecosystem::{LifecycleEntry, PackageDiff, RegistryMetadata},
    entry::Entry,
    finding::Finding,
    manifest::Manifest,
};

/// Opaque AST cache handle. The actual cache type lives in
/// `monomi-ast` (which depends on `oxc_parser`); we don't want
/// `monomi-core` to take that dependency since not every consumer
/// of `AnalysisCtx` (non-JS ecosystems, embedded users) wants the
/// parser linked in. Rules that need the AST downcast via
/// `AstHandle::downcast_ref::<AstCache>()`.
pub trait AstHandle: Any + Send + Sync {
    fn as_any(&self) -> &dyn Any;
}

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
    /// Optional JS/TS AST cache (`monomi_ast::AstCache`, behind a
    /// downcast). Wired in by the pipeline for npm scans; `None`
    /// for ecosystems that don't carry JS, for stage1-only tests
    /// that don't need AST confirmation, and for old verdict
    /// replays.
    pub ast: Option<&'a dyn AstHandle>,
}

pub trait Rule: Send + Sync {
    fn id(&self) -> &'static str;
    fn applies_to(&self, eco: EcosystemId) -> bool;
    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding>;
}
