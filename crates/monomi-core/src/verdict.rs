use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    artifact::ArtifactId,
    capability::{Capability, CapabilitySet},
    finding::Finding,
};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage1Verdict {
    Clean,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage1Result {
    pub findings: Vec<Finding>,
    pub score: u32,
    pub verdict: Stage1Verdict,
    /// Union of every finding's capability label. Persisted in the
    /// verdict so future scans of the same package can diff against
    /// it (see milestone M8).
    #[serde(default, skip_serializing_if = "CapabilitySet::is_empty")]
    pub capabilities: CapabilitySet,
    /// Provenance flag: `true` iff this analyzer actually computed
    /// capabilities (i.e. ran M7-or-later code). Empty `capabilities`
    /// on an old verdict deserializes to `false`, which the M8 diff
    /// pass treats as "unknown — do not diff", avoiding false-positive
    /// escalation against a pre-M7 baseline.
    ///
    /// NOTE: If the capability vocabulary is ever extended in a way
    /// that breaks comparability, replace this boolean with a
    /// `capabilities_schema_version: u32`.
    #[serde(default)]
    pub capabilities_complete: bool,
    /// Outcome of the M8 version-over-version capability diff pass.
    /// Absent on Stage 1 results produced without a catalog input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff_outcome: Option<DiffOutcome>,
}

/// Structured telemetry for the M8 capability-diff pass. Lives on the
/// verdict so we can answer "did NPM030 actually run?" from the
/// catalog without re-deriving it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DiffOutcome {
    /// One or more capabilities were introduced vs the baseline.
    Produced {
        introduced: Vec<Capability>,
        baseline_versions: Vec<String>,
    },
    /// Baseline existed but its Stage1 verdict was already Malicious,
    /// so the diff would be unreliable.
    AbstainedPoisonedBaseline { prev_status: Stage1Verdict },
    /// Baseline existed but at least one of its prior verdicts had
    /// `capabilities_complete = false` (pre-M7), so the set we'd diff
    /// against is not trustworthy.
    AbstainedBaselineIncomplete,
    /// No prior versions, no catalog provided, or the requested
    /// baseline window resolved to zero versions.
    NotAttempted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage2Verdict {
    Clean,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendedAction {
    Allow,
    Warn,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage2Result {
    pub model: String,
    pub verdict: Stage2Verdict,
    pub confidence: f32,
    pub reasoning: String,
    pub indicators: Vec<String>,
    pub recommended_action: RecommendedAction,
    pub tokens_in: u32,
    pub tokens_out: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Clean,
    Warn,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictSource {
    Stage1,
    Stage2,
    StageMerged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalVerdict {
    pub status: Status,
    pub confidence: f32,
    pub source: VerdictSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub schema_version: u32,
    pub artifact: ArtifactId,
    pub analyzed_at: DateTime<Utc>,
    pub analyzer_version: String,
    pub ruleset_version: String,
    pub stage1: Stage1Result,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage2: Option<Stage2Result>,
    pub final_verdict: FinalVerdict,
}
