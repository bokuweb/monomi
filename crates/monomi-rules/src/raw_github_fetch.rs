//! NPM017 — fetch from a raw GitHub / GitLab / Bitbucket URL.
//!
//! `raw.githubusercontent.com` and friends are the canonical
//! payload-delivery host for npm droppers: a small published
//! package fetches the *real* malicious script from a Gist or
//! private repo at install/import time, then runs it.
//!
//! In **lifecycle body**: decisive Critical (Block). No
//! legitimate postinstall fetches code from raw github URLs.
//! In **source**: High + defer to Stage 2 (some legit code
//! pulls config from raw GH content).

use monomi_core::{
    AnalysisCtx, Category, EcosystemId, Finding, LifecycleKind, Location, Rule, Severity,
};
use once_cell::sync::Lazy;
use regex::Regex;

pub struct RawScmFetch;

static RAW_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?ix)
            raw\.githubusercontent\.com
          | gist\.githubusercontent\.com
          | (?:^|//|/)gitlab\.com/[A-Za-z0-9_./~-]+/-/raw/
          | bitbucket\.org/[A-Za-z0-9_./~-]+/raw/
          | codeload\.github\.com
        ",
    )
    .expect("RAW_RE")
});

impl Rule for RawScmFetch {
    fn id(&self) -> &'static str {
        "NPM017"
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
            if let Some(m) = RAW_RE.find(&life.body) {
                out.push(Finding {
                    rule_id: "NPM017".into(),
                    severity: Severity::Critical,
                    category: Category::Exfil,
                    locations: vec![Location {
                        path: format!("package.json#scripts.{}", life.name),
                        line_start: None,
                        line_end: None,
                    }],
                    excerpt: Some(m.as_str().to_string()),
                    message: format!(
                        "install-time fetch from raw SCM URL `{}` — dropper pattern",
                        m.as_str()
                    ),
                    defers_to_stage2: false,
                });
            }
        }
        for entry in ctx.entries {
            if !entry.kind.is_scannable_source() {
                continue;
            }
            let Some(text) = entry.text() else { continue };
            if let Some(m) = RAW_RE.find(text) {
                out.push(Finding {
                    rule_id: "NPM017".into(),
                    severity: Severity::High,
                    category: Category::Exfil,
                    locations: vec![Location {
                        path: entry.path.clone(),
                        line_start: None,
                        line_end: None,
                    }],
                    excerpt: Some(m.as_str().to_string()),
                    message: format!("raw SCM URL `{}` in source", m.as_str()),
                    defers_to_stage2: true,
                });
            }
        }
        out
    }
}
