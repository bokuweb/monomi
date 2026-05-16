use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{artifact::ArtifactId, finding::Finding};

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
