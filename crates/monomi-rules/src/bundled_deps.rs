//! NPM012 — `bundleDependencies` / `bundledDependencies` declared.
//!
//! Lets a publisher ship a copy of a dependency *inside* the
//! tarball. The dep doesn't appear in `package-lock.json` and is
//! invisible to `npm audit` / SBOM tools / SCA scanners. Used
//! historically to hide malicious sub-packages.
//!
//! Some legitimate use cases exist (CLI tools that want to ship
//! a self-contained binary), so this is High + defer to Stage 2
//! rather than decisive.

use monomi_core::{AnalysisCtx, Category, EcosystemId, Finding, Location, Rule, Severity};

pub struct BundleDependenciesDeclared;

impl Rule for BundleDependenciesDeclared {
    fn id(&self) -> &'static str {
        "NPM012"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(eco, EcosystemId::Npm)
    }

    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        let raw = &ctx.manifest.raw;
        let mut bundled: Vec<String> = Vec::new();
        for key in ["bundleDependencies", "bundledDependencies"] {
            if let Some(v) = raw.get(key) {
                match v {
                    // Conventional shape: array of dep names.
                    serde_json::Value::Array(arr) => {
                        for item in arr {
                            if let Some(s) = item.as_str() {
                                bundled.push(s.to_string());
                            }
                        }
                    }
                    // npm also tolerates a boolean (`true` means bundle
                    // everything in `dependencies`).
                    serde_json::Value::Bool(true) => bundled.push("*".into()),
                    _ => {}
                }
            }
        }
        if bundled.is_empty() {
            return Vec::new();
        }
        vec![Finding {
            rule_id: "NPM012".into(),
            severity: Severity::High,
            category: Category::Other,
            locations: vec![Location {
                path: "package.json".into(),
                line_start: None,
                line_end: None,
            }],
            excerpt: Some(bundled.join(", ")),
            message: format!(
                "package declares bundleDependencies ({} entries); bundled \
                 sub-packages bypass `npm audit` and SBOM tooling",
                bundled.len()
            ),
            defers_to_stage2: true,
        }]
    }
}
