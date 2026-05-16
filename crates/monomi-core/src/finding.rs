use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Score weight contributed to Stage 1's running total.
    pub fn weight(self) -> u32 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 3,
            Severity::High => 5,
            Severity::Critical => 10,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    LifecycleScript,
    Obfuscation,
    Exfil,
    Persistence,
    NativeBinary,
    SourceDivergence,
    Typosquat,
    Maintainer,
    Diff,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub path: String,
    pub line_start: Option<u32>,
    pub line_end: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub category: Category,
    pub locations: Vec<Location>,
    pub excerpt: Option<String>,
    pub message: String,
    /// If true, the analyzer should ask Stage 2 (LLM) to adjudicate
    /// rather than treating this finding as decisive on its own.
    pub defers_to_stage2: bool,
}
