use monomi_core::{
    AnalysisCtx, Category, EcosystemId, EntryKind, Finding, Location, Rule, Severity,
};

/// NPM009 — bundled native binary / wasm not declared in `package.json`'s
/// `bin` field. Legitimate native modules ship a build script or
/// prebuilt addon under a documented path; an undeclared ELF/Mach-O
/// next to plain JS is unusual.
pub struct NativeBinaryUndeclared;

impl Rule for NativeBinaryUndeclared {
    fn id(&self) -> &'static str {
        "NPM009"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(eco, EcosystemId::Npm)
    }

    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        let declared: Vec<&str> = ctx
            .manifest
            .bin
            .values()
            .map(|s| s.trim_start_matches("./"))
            .collect();
        let mut out = Vec::new();
        for entry in ctx.entries {
            if !matches!(entry.kind, EntryKind::NativeBinary) {
                continue;
            }
            let path = entry.path.as_str();
            if declared.iter().any(|d| path.ends_with(d) || *d == path) {
                continue;
            }
            out.push(Finding {
                rule_id: "NPM009".into(),
                severity: Severity::High,
                category: Category::NativeBinary,
                locations: vec![Location {
                    path: path.to_string(),
                    line_start: None,
                    line_end: None,
                }],
                excerpt: None,
                message: format!(
                    "undeclared native artifact `{path}` ({} bytes) — not referenced from `bin`",
                    entry.size
                ),
                defers_to_stage2: true,
            });
        }
        out
    }
}
