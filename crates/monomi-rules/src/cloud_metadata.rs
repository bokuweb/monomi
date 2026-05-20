use monomi_core::{Capability, AnalysisCtx, Category, EcosystemId, Finding, Location, Rule, Severity};
use once_cell::sync::Lazy;
use regex::Regex;

/// NPM006 — hardcoded cloud-metadata endpoint literal.
///
/// Catches the canonical credential-exfil pattern: any package that
/// names the AWS / GCP / Azure instance metadata service in source
/// or in a lifecycle script is treated as critical. There is no
/// legitimate reason for a published npm package to embed these.
pub struct CloudMetadataLiteral;

static METADATA_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?x)
            169\.254\.169\.254
          | metadata\.google\.internal
          | metadata\.azure\.com
          | 169\.254\.170\.2          # AWS ECS task metadata
        ",
    )
    .expect("METADATA_RE")
});

impl Rule for CloudMetadataLiteral {
    fn id(&self) -> &'static str {
        "NPM006"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(
            eco,
            EcosystemId::Npm | EcosystemId::Cargo | EcosystemId::Pypi | EcosystemId::Nuget
        )
    }

    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for entry in ctx.entries {
            if !entry.kind.is_scannable_source() {
                continue;
            }
            let Some(text) = entry.text() else { continue };
            if let Some(m) = METADATA_RE.find(text) {
                out.push(make_finding(entry.path.clone(), m.as_str().to_string()));
            }
        }
        for life in ctx.lifecycle {
            if let Some(m) = METADATA_RE.find(&life.body) {
                out.push(make_finding(
                    format!("package.json#scripts.{}", life.name),
                    m.as_str().to_string(),
                ));
            }
        }
        out
    }
}

fn make_finding(path: String, hit: String) -> Finding {
    Finding {
        rule_id: "NPM006".into(),
        severity: Severity::Critical,
        category: Category::Exfil,
        locations: vec![Location {
            path,
            line_start: None,
            line_end: None,
        }],
        excerpt: Some(hit.clone()),
        message: format!("hardcoded cloud-metadata endpoint `{hit}` — credential exfil pattern"),
        defers_to_stage2: false,
        capabilities: [Capability::NetHttp].into_iter().collect(),
    }
}
