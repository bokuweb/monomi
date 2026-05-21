//! `NPM036` — chmod-to-executable inside an install-time
//! lifecycle script.
//!
//! Every "fetch-and-run" payload shape (ua-parser-js 2021, the
//! coa/rc 2021 family, generic miner droppers) has the same
//! shape: download a file, chmod it 0755, exec it. The chmod
//! step is the one that's hard to obfuscate.
//!
//! High + defer (rare false positives exist: native add-on
//! prebuilders that script-chmod a freshly-extracted binary).

use monomi_core::{
    AnalysisCtx, Capability, Category, EcosystemId, Finding, LifecycleKind, Location, Rule,
    Severity,
};
use once_cell::sync::Lazy;
use regex::Regex;

pub struct InstallTimeChmodExec;

static CHMOD_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
            \bfs\s*\.\s*chmod(?:Sync)?\s*\([^)]*0o?7[0-9]{2}
          | \bchmod\s+(?:\+x|7[0-9]{2}|0?7[0-9]{2})\b
        "#,
    )
    .expect("CHMOD_RE")
});

impl Rule for InstallTimeChmodExec {
    fn id(&self) -> &'static str {
        "NPM036"
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
            if let Some(m) = CHMOD_RE.find(&life.body) {
                out.push(Finding {
                    rule_id: "NPM036".into(),
                    severity: Severity::High,
                    category: Category::LifecycleScript,
                    locations: vec![Location {
                        path: format!("package.json#scripts.{}", life.name),
                        line_start: None,
                        line_end: None,
                    }],
                    excerpt: Some(m.as_str().to_string()),
                    message: format!(
                        "install-time script `{}` makes a file executable (`{}`) — \
                         fetch-and-run shape",
                        life.name,
                        m.as_str()
                    ),
                    defers_to_stage2: true,
                    capabilities: [
                        Capability::InstallTimeShell,
                        Capability::NativeBinary,
                        Capability::LifecycleInstall,
                    ]
                    .into_iter()
                    .collect(),
                });
            }
        }
        out
    }
}
