//! NPM018 — payload self-deletion (`fs.unlinkSync(__filename)` etc).
//!
//! Anti-forensics: malware deletes its own source after running so
//! forensic responders can't find what executed. Near-zero legit
//! use in a published npm package.

use monomi_core::{Capability, AnalysisCtx, Category, EcosystemId, EntryKind, Finding, Location, Rule, Severity,};
use once_cell::sync::Lazy;
use regex::Regex;

pub struct SelfDeletePayload;

static SELF_DELETE_RE: Lazy<Regex> = Lazy::new(|| {
    // Various spellings: unlink(Sync)?, rm(Sync)?, rmdir, rmSync from
    // fs / fsPromises, with the target being __filename / __dirname.
    Regex::new(
        r#"(?x)
            \bfs(?:\.promises)?\s*\.\s*(?:unlink|unlinkSync|rm|rmSync|rmdirSync)\s*\(\s*__(?:file|dir)name\b
          | \brequire\s*\(\s*['"]fs['"]\s*\)\s*\.\s*(?:unlink|unlinkSync|rm|rmSync)\s*\(\s*__(?:file|dir)name\b
        "#,
    )
    .expect("SELF_DELETE_RE")
});

impl Rule for SelfDeletePayload {
    fn id(&self) -> &'static str {
        "NPM018"
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
            if let Some(m) = SELF_DELETE_RE.find(text) {
                if !crate::ast_helpers::regex_hit_in_code(ctx, &entry.path, text, m.start()) {
                    continue;
                }
                out.push(make_finding(entry.path.clone(), m.as_str().to_string()));
            }
        }
        for life in ctx.lifecycle {
            // Lifecycle bodies are shell-ish (`node -e "..."` etc.),
            // not JS source — AST suppression doesn't apply.
            if let Some(m) = SELF_DELETE_RE.find(&life.body) {
                out.push(make_finding(
                    format!("package.json#scripts.{}", life.name),
                    m.as_str().to_string(),
                ));
            }
        }
        out
    }
}

fn make_finding(path: String, hit: String) -> Finding {
    Finding {
        rule_id: "NPM018".into(),
        severity: Severity::Critical,
        category: Category::Persistence,
        locations: vec![Location {
            path,
            line_start: None,
            line_end: None,
        }],
        excerpt: Some(hit),
        message: "self-deleting payload — code unlinks `__filename` / `__dirname` (anti-forensics)"
            .into(),
        defers_to_stage2: false,
        capabilities: [Capability::SelfDelete, Capability::FsRead].into_iter().collect(),
    }
}
