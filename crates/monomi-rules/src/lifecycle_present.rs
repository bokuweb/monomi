use monomi_core::{
    AnalysisCtx, Category, EcosystemId, Finding, LifecycleKind, Location, Rule, Severity,
};

/// NPM001 — any install-time lifecycle script is present.
///
/// On its own this is informational (legitimate packages have these),
/// but it tags the package as "needs to be looked at more carefully"
/// and downstream rules / Stage 2 may upgrade the severity.
pub struct LifecyclePresent;

impl Rule for LifecyclePresent {
    fn id(&self) -> &'static str {
        "NPM001"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(eco, EcosystemId::Npm)
    }

    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for entry in ctx.lifecycle {
            if !matches!(entry.kind, LifecycleKind::InstallTime) {
                continue;
            }
            out.push(Finding {
                rule_id: "NPM001".into(),
                severity: Severity::Info,
                category: Category::LifecycleScript,
                locations: vec![Location {
                    path: "package.json".into(),
                    line_start: None,
                    line_end: None,
                }],
                excerpt: Some(truncate(&entry.body, 240)),
                message: format!("install-time lifecycle script `{}` present", entry.name),
                defers_to_stage2: false,
            });
        }
        out
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}
