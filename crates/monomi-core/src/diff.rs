//! Capability-diff baseline types (M8).
//!
//! The pipeline turns prior-version verdicts (fetched from the
//! catalog) into a `CapabilityBaseline`, then runs `diff_capabilities`
//! against the current scan's `CapabilitySet` to produce findings and
//! a structured `DiffOutcome` for telemetry. This module is pure;
//! all I/O (catalog reads, registry metadata) lives in
//! `monomi-pipeline::history`.

use serde::{Deserialize, Serialize};

use crate::capability::CapabilitySet;

/// Which prior-version selection strategy produced the baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineStrategy {
    /// Single version immediately before the current one by publish
    /// time. Strongest "this exact release changed" signal; weakest
    /// when the immediate previous version was itself malicious.
    ImmediatePrev,
    /// Union of capabilities across the last N publish-time-ordered
    /// versions (current excluded). A newly-introduced capability
    /// here means "absent from every recent version", which is the
    /// account-takeover shape.
    RecentUnion { window: usize },
}

/// A snapshot of what a package could do "before now".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityBaseline {
    pub strategy: BaselineStrategy,
    /// Union of capabilities over the baseline's versions.
    pub capabilities: CapabilitySet,
    /// Versions actually consulted (in publish-time order). May be
    /// shorter than the requested window when prior verdicts are
    /// missing from the catalog.
    pub versions: Vec<String>,
    /// `true` iff every version inside the intended baseline window
    /// contributed a verdict whose `capabilities_complete` was true.
    /// `false` means the baseline is incomplete and consumers should
    /// abstain — diffing against an incomplete baseline manufactures
    /// false positives.
    pub complete: bool,
}
