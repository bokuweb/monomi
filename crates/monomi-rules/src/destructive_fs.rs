//! `NPM039` — mass-deletion shape (rimraf / `fs.rm*` over a
//! homedir / cwd / root traversal).
//!
//! Distinct from `NPM018` (`fs.unlinkSync(__filename)`, which is
//! anti-forensic self-cleanup): this catches *destructive* payloads
//! that wipe the user's files. Reference incident: `node-ipc` /
//! `peacenotwar` 2022 — selective `fs.unlink` walks rooted at
//! `os.homedir()` with locale-gated activation.
//!
//! Critical + decisive: a `rimraf(os.homedir())` or `fs.rmSync(
//! process.cwd(), { recursive: true })` line has no defensible
//! purpose in a published package.
//!
//! Two-prong match (both must fire on the same source file):
//! 1. A destructive call — `rimraf(...)`, `fs.rm{,Sync}(...,
//!    { recursive: true })`, `fs.rmdirSync(..., { recursive: true })`,
//!    `child_process.exec*('rm -rf ...')`.
//! 2. A traversal seed in the same file — `os.homedir()`,
//!    `os.tmpdir()`, `process.cwd()`, `process.env.HOME`,
//!    `process.env.USERPROFILE`, a root-anchored path literal like
//!    `'/'`, `'/*'`, `'C:\\'`.
//!
//! Requiring both keeps FPs down: legitimate cleanup utilities use
//! `rimraf` against a *known* build dir, not a traversal seed.

use monomi_core::{
    AnalysisCtx, Capability, Category, EcosystemId, EntryKind, Finding, Location, Rule, Severity,
};
use once_cell::sync::Lazy;
use regex::Regex;

pub struct DestructiveFsTraversal;

static DESTRUCTIVE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
            \brimraf\s*\(
          | \bfs(?:\.promises)?\s*\.\s*rm(?:Sync)?\s*\(.{0,400}?recursive\s*:\s*true
          | \bfs(?:\.promises)?\s*\.\s*rmdir(?:Sync)?\s*\(.{0,400}?recursive\s*:\s*true
          | \brm\s+-rf?\b
          | \bdel\s+/[sq]\b
        "#,
    )
    .expect("DESTRUCTIVE_RE")
});

static TRAVERSAL_SEED_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
            \bos\s*\.\s*homedir\s*\(
          | \bos\s*\.\s*tmpdir\s*\(
          | \bprocess\s*\.\s*cwd\s*\(
          | \bprocess\s*\.\s*env\s*\.\s*(?:HOME|USERPROFILE|HOMEPATH)\b
          | \bprocess\s*\.\s*env\s*\[\s*['"](?:HOME|USERPROFILE|HOMEPATH)['"]\s*\]
          | ['"]/['"]
          | ['"]/\*['"]
          | ['"][A-Za-z]:[\\/]['"]
        "#,
    )
    .expect("TRAVERSAL_SEED_RE")
});

impl Rule for DestructiveFsTraversal {
    fn id(&self) -> &'static str {
        "NPM039"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(eco, EcosystemId::Npm)
    }

    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for entry in ctx.entries {
            if !matches!(entry.kind, EntryKind::JsSource | EntryKind::Text) {
                continue;
            }
            let Some(text) = entry.text() else { continue };
            let Some(d) = DESTRUCTIVE_RE.find(text) else {
                continue;
            };
            if !TRAVERSAL_SEED_RE.is_match(text) {
                continue;
            }
            // Drop when the destructive call sits in a comment or
            // string literal (security-research blog post embedded
            // as a docstring is the canonical FP).
            if !crate::ast_helpers::regex_hit_in_code(ctx, &entry.path, text, d.start()) {
                continue;
            }
            out.push(make_finding(entry.path.clone(), d.as_str().to_string()));
        }
        for life in ctx.lifecycle {
            let Some(d) = DESTRUCTIVE_RE.find(&life.body) else {
                continue;
            };
            if !TRAVERSAL_SEED_RE.is_match(&life.body) {
                continue;
            }
            out.push(make_finding(
                format!("package.json#scripts.{}", life.name),
                d.as_str().to_string(),
            ));
        }
        out
    }
}

fn make_finding(path: String, hit: String) -> Finding {
    Finding {
        rule_id: "NPM039".into(),
        severity: Severity::Critical,
        category: Category::Persistence,
        locations: vec![Location {
            path,
            line_start: None,
            line_end: None,
        }],
        excerpt: Some(hit),
        message: "destructive filesystem call paired with a homedir/cwd/root \
                  traversal seed — wiper shape (node-ipc/peacenotwar 2022)"
            .into(),
        defers_to_stage2: false,
        capabilities: [Capability::DestructiveFs].into_iter().collect(),
    }
}
