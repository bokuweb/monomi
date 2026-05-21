use monomi_core::{Capability, AnalysisCtx, Category, EcosystemId, EntryKind, Finding, LifecycleKind, Location, Rule, Severity,};
use once_cell::sync::Lazy;
use regex::Regex;

/// NPM004 — code enumerates `process.env` wholesale. Routine reads of
/// a single named env (`process.env.NODE_ENV`) are not flagged; bulk
/// enumeration via `Object.keys` / `Object.entries` / `JSON.stringify`
/// / spread is the credential-harvesting shape.
pub struct EnvHarvest;

static ENV_BULK_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?x)
            \bObject\s*\.\s*(?:keys|entries|values|assign)\s*\(\s*process\s*\.\s*env\b
          | \bJSON\s*\.\s*stringify\s*\(\s*process\s*\.\s*env\b
          | \.\.\.\s*process\s*\.\s*env\b
          | \bfor\s*\(\s*(?:const|let|var)?\s*\w+\s+(?:in|of)\s+(?:Object\.[a-zA-Z]+\s*\(\s*)?process\s*\.\s*env\b
        ",
    )
    .expect("ENV_BULK_RE")
});

impl Rule for EnvHarvest {
    fn id(&self) -> &'static str {
        "NPM004"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(eco, EcosystemId::Npm)
    }

    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for life in ctx.lifecycle {
            if !matches!(life.kind, LifecycleKind::InstallTime) {
                continue;
            }
            if let Some(m) = ENV_BULK_RE.find(&life.body) {
                out.push(make_finding(
                    format!("package.json#scripts.{}", life.name),
                    m.as_str().to_string(),
                ));
            }
        }
        for entry in ctx.entries {
            if !matches!(entry.kind, EntryKind::JsSource | EntryKind::Text) {
                continue;
            }
            let Some(text) = entry.text() else { continue };
            if let Some(m) = ENV_BULK_RE.find(text) {
                out.push(make_finding(entry.path.clone(), m.as_str().to_string()));
            }
        }
        out
    }
}

fn make_finding(path: String, hit: String) -> Finding {
    Finding {
        rule_id: "NPM004".into(),
        severity: Severity::High,
        category: Category::Exfil,
        locations: vec![Location {
            path,
            line_start: None,
            line_end: None,
        }],
        excerpt: Some(hit),
        message: "bulk enumeration of `process.env` — credential-harvesting pattern".into(),
        defers_to_stage2: true,
        capabilities: [Capability::EnvBulkEnum].into_iter().collect(),
    }
}
