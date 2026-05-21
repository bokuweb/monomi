//! `NPM034` — npm CLI invoked inside an install-time lifecycle
//! script.
//!
//! Reference incident: Shai-Hulud worm 2024. A compromised
//! package's `postinstall` shells out to `npm publish` / `npm
//! token` to hijack the install-time user's other packages. There
//! is no legitimate reason for an install-time hook to invoke the
//! npm CLI — at that point npm is *already running* and the
//! install is being driven by it.
//!
//! Critical + decisive (block on hit; no Stage 2 needed).

use monomi_core::{
    AnalysisCtx, Capability, Category, EcosystemId, Finding, LifecycleKind, Location, Rule,
    Severity,
};
use once_cell::sync::Lazy;
use regex::Regex;

pub struct InstallTimeRegistryWrite;

static REGISTRY_CLI_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
            \bnpm\s+(?:publish|token|login|whoami|adduser|access|owner|hook)\b
          | \bnpx\s+
          | \byarn\s+publish\b
          | \bpnpm\s+publish\b
          | \bcargo\s+(?:publish|login|owner)\b
          | \btwine\s+upload\b
          | \bdotnet\s+nuget\s+push\b
        "#,
    )
    .expect("REGISTRY_CLI_RE")
});

impl Rule for InstallTimeRegistryWrite {
    fn id(&self) -> &'static str {
        "NPM034"
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
            if let Some(m) = REGISTRY_CLI_RE.find(&life.body) {
                out.push(Finding {
                    rule_id: "NPM034".into(),
                    severity: Severity::Critical,
                    category: Category::LifecycleScript,
                    locations: vec![Location {
                        path: format!("package.json#scripts.{}", life.name),
                        line_start: None,
                        line_end: None,
                    }],
                    excerpt: Some(m.as_str().to_string()),
                    message: format!(
                        "install-time script `{}` invokes a registry-write CLI `{}` \
                         — worm-propagation shape (Shai-Hulud 2024)",
                        life.name,
                        m.as_str()
                    ),
                    defers_to_stage2: false,
                    capabilities: [
                        Capability::InstallTimeShell,
                        Capability::RegistryWrite,
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
