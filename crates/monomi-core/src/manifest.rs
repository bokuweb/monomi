use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Ecosystem-neutral manifest view. Each ecosystem fills the fields it has.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Manifest {
    pub name: String,
    pub version: String,
    /// Repository URL if declared.
    pub repository: Option<String>,
    /// Homepage URL if declared.
    pub homepage: Option<String>,
    /// `bin` entries (name → relative path).
    pub bin: BTreeMap<String, String>,
    /// Lifecycle scripts indexed by their canonical name
    /// (npm: `preinstall`/`install`/`postinstall`/`prepare`).
    pub scripts: BTreeMap<String, String>,
    /// Direct dependencies (name → version range).
    pub dependencies: BTreeMap<String, String>,
    /// Raw manifest JSON for downstream consumers that need fields
    /// monomi-core doesn't model yet.
    pub raw: serde_json::Value,
}
