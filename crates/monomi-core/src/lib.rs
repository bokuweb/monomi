//! Ecosystem-neutral types and traits for monomi.
//!
//! See `architecture.md` at the repo root for the design.

pub mod artifact;
pub mod ecosystem;
pub mod entry;
pub mod error;
pub mod finding;
pub mod manifest;
pub mod rule;
pub mod verdict;

pub use artifact::{ArtifactId, EcosystemId, HashAlgo, Integrity};
pub use ecosystem::{
    Ecosystem, LifecycleEntry, LifecycleKind, PackageDiff, RegistryMetadata, Tarball,
};
pub use entry::{Entry, EntryKind};
pub use error::{Error, Result};
pub use finding::{Category, Finding, Location, Severity};
pub use manifest::Manifest;
pub use rule::{AnalysisCtx, Corpus, Rule};
pub use verdict::{
    FinalVerdict, RecommendedAction, Stage1Result, Stage1Verdict, Stage2Result, Stage2Verdict,
    Status, Verdict, VerdictSource, SCHEMA_VERSION,
};
