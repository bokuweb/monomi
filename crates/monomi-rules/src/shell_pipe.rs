//! NPM019 — `curl ... | sh` / `wget ... | sh` / `eval $(curl ...)` in
//! a lifecycle script body.
//!
//! The classic untrusted-script-execution shape. A package that
//! pipes a URL into a shell during install is essentially never
//! benign. Decisive Critical.

use monomi_core::{
    AnalysisCtx, Category, EcosystemId, Finding, LifecycleKind, Location, Rule, Severity,
};
use once_cell::sync::Lazy;
use regex::Regex;

pub struct LifecycleShellPipe;

static SHELL_PIPE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?ix)
            (?:curl|wget|fetch)\s+[^\|;\n]*\|\s*(?:sh|bash|zsh|fish|node|python|python3|perl|ruby)\b
          | \$\(\s*(?:curl|wget|fetch)\b[^)]*\)
          | `\s*(?:curl|wget|fetch)\b[^`]*`
        ",
    )
    .expect("SHELL_PIPE_RE")
});

impl Rule for LifecycleShellPipe {
    fn id(&self) -> &'static str {
        "NPM019"
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
            if let Some(m) = SHELL_PIPE_RE.find(&life.body) {
                out.push(Finding {
                    rule_id: "NPM019".into(),
                    severity: Severity::Critical,
                    category: Category::LifecycleScript,
                    locations: vec![Location {
                        path: format!("package.json#scripts.{}", life.name),
                        line_start: None,
                        line_end: None,
                    }],
                    excerpt: Some(m.as_str().to_string()),
                    message: format!(
                        "install-time script `{}` pipes a URL into a shell — \
                         untrusted-script-execution pattern",
                        life.name
                    ),
                    defers_to_stage2: false,
                });
            }
        }
        out
    }
}
