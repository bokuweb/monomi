use monomi_core::{Capability, AnalysisCtx, Category, EcosystemId, Finding, LifecycleKind, Location, Rule, Severity,};
use once_cell::sync::Lazy;
use regex::Regex;

/// NPM002 — install-time lifecycle script imports / spawns network or
/// child-process primitives. Single-handedly responsible for nearly
/// every Shai-Hulud-class incident: the postinstall opens a socket or
/// exec()s a shell.
pub struct DangerousLifecycleApi;

static DANGEROUS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
            \bchild_process\b
          | \brequire\s*\(\s*['"]child_process['"]\s*\)
          | \brequire\s*\(\s*['"](?:net|dns|tls|http|https|dgram)['"]\s*\)
          | \bspawn(?:Sync)?\s*\(
          | \bexec(?:File|Sync|FileSync)?\s*\(
          | \bfork\s*\(
        "#,
    )
    .expect("DANGEROUS_RE")
});

impl Rule for DangerousLifecycleApi {
    fn id(&self) -> &'static str {
        "NPM002"
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
            if let Some(m) = DANGEROUS_RE.find(&life.body) {
                out.push(Finding {
                    rule_id: "NPM002".into(),
                    severity: Severity::High,
                    category: Category::LifecycleScript,
                    locations: vec![Location {
                        path: format!("package.json#scripts.{}", life.name),
                        line_start: None,
                        line_end: None,
                    }],
                    excerpt: Some(m.as_str().to_string()),
                    message: format!(
                        "install-time script `{}` uses dangerous primitive `{}`",
                        life.name,
                        m.as_str()
                    ),
                    defers_to_stage2: true,
                    capabilities: [Capability::ProcSpawn, Capability::InstallTimeShell, Capability::LifecycleInstall].into_iter().collect(),
                });
            }
        }
        out
    }
}
