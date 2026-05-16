//! NPM027 — publish-time lifecycle hostility.
//!
//! npm's `prepack` / `prepublish` / `prepublishOnly` / `publish` /
//! `postpublish` scripts do NOT run on a *consumer's* install — they
//! run on the publisher's machine before/after `npm publish`. From
//! the proxy-block point of view they're harmless to the installer.
//!
//! From a supply-chain audit point of view, however, they are
//! *highly* suspicious in a published artifact: by the time a
//! consumer fetches the tarball, these hooks have already fired on
//! the publisher's machine. The presence of a network-shell-spawn
//! shape in a publish-time hook of a *downloaded* package suggests
//! that publisher's CI was compromised — and that the published
//! bytes may not match the source tree on the repo.
//!
//! Medium + defer to Stage 2: this is an audit signal, not a block
//! signal.

use monomi_core::{
    AnalysisCtx, Category, EcosystemId, Finding, LifecycleKind, Location, Rule, Severity,
};
use once_cell::sync::Lazy;
use regex::Regex;

pub struct PublishTimeHostility;

static DANGEROUS_RE: Lazy<Regex> = Lazy::new(|| {
    // Same dangerous-primitive set as NPM002 + a few additions
    // specific to publish-time (curl / wget literal shell usage).
    Regex::new(
        r#"(?x)
            \bchild_process\b
          | \brequire\s*\(\s*['"](?:child_process|net|dns|tls|http|https|dgram)['"]\s*\)
          | \bspawn(?:Sync)?\s*\(
          | \bexec(?:File|Sync|FileSync)?\s*\(
          | \bfork\s*\(
          | (?:curl|wget)\s+[^\|;\n]*\|\s*(?:sh|bash|zsh|node|python)\b
          | \$\(\s*(?:curl|wget)\b
        "#,
    )
    .expect("DANGEROUS_RE")
});

impl Rule for PublishTimeHostility {
    fn id(&self) -> &'static str {
        "NPM027"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(eco, EcosystemId::Npm)
    }

    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for life in ctx.lifecycle {
            if !matches!(life.kind, LifecycleKind::PublishTime) {
                continue;
            }
            if let Some(m) = DANGEROUS_RE.find(&life.body) {
                out.push(Finding {
                    rule_id: "NPM027".into(),
                    severity: Severity::Medium,
                    category: Category::LifecycleScript,
                    locations: vec![Location {
                        path: format!("package.json#scripts.{}", life.name),
                        line_start: None,
                        line_end: None,
                    }],
                    excerpt: Some(m.as_str().to_string()),
                    message: format!(
                        "publish-time hook `{}` contains a network/shell-spawn primitive \
                         `{}` — the publisher's CI/machine ran this before the tarball \
                         was uploaded; possible CI compromise",
                        life.name,
                        m.as_str()
                    ),
                    defers_to_stage2: true,
                });
            }
        }
        out
    }
}
