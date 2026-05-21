//! `NPM035` — Linux privilege-escalation / recon path literals.
//!
//! Complements `NPM008` (which catches *credential* paths like
//! `~/.ssh/`). This rule catches the Linux-system files that
//! malicious dropper payloads enumerate before deciding what to
//! do: `/etc/shadow`, `/etc/passwd`, `/proc/self/environ`,
//! `/proc/*/cmdline`, `/var/log/auth*`, `/root/`. There is no
//! legitimate reason for a published package to reference these.
//!
//! High + defers to Stage 2 (some legitimate sysadmin libs *do*
//! reference these; the LLM judges from context).

use monomi_core::{
    AnalysisCtx, Capability, Category, EcosystemId, Finding, Location, Rule, Severity,
};
use once_cell::sync::Lazy;
use regex::Regex;

pub struct PrivescPathLiteral;

static PATH_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?x)
            /etc/shadow\b
          | /etc/passwd\b
          | /etc/sudoers\b
          | /proc/self/environ\b
          | /proc/[0-9]+/cmdline\b
          | /proc/[0-9]+/environ\b
          | /var/log/auth(?:\.log)?\b
          | /var/log/secure\b
          | /root/(?:\.ssh|\.bash_history|\.aws)\b
        ",
    )
    .expect("PRIVESC_PATH_RE")
});

impl Rule for PrivescPathLiteral {
    fn id(&self) -> &'static str {
        "NPM035"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(
            eco,
            EcosystemId::Npm | EcosystemId::Pypi | EcosystemId::Cargo | EcosystemId::Nuget
        )
    }

    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for entry in ctx.entries {
            if !entry.kind.is_scannable_source() {
                continue;
            }
            let Some(text) = entry.text() else { continue };
            if let Some(m) = PATH_RE.find(text) {
                out.push(Finding {
                    rule_id: "NPM035".into(),
                    severity: Severity::High,
                    category: Category::Persistence,
                    locations: vec![Location {
                        path: entry.path.clone(),
                        line_start: None,
                        line_end: None,
                    }],
                    excerpt: Some(m.as_str().to_string()),
                    message: format!(
                        "source references Linux privesc / recon path `{}`",
                        m.as_str()
                    ),
                    defers_to_stage2: true,
                    capabilities: [Capability::FsReadSensitive].into_iter().collect(),
                });
                break;
            }
        }
        out
    }
}
