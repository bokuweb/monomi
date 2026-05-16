//! NPM020 — direct `eval(atob(...))` / `Function(atob(...))()` /
//! `eval(Buffer.from(..., 'base64').toString())` chain.
//!
//! Sibling of `NPM005` (large base64 + eval at distance). This
//! rule targets the *minimal* form where the decode call is
//! syntactically nested inside the eval — no blob-size threshold
//! to meet, no proximity slack. Catches the small-payload variant
//! that hides in dozens of bytes.

use monomi_core::{
    AnalysisCtx, Category, EcosystemId, EntryKind, Finding, Location, Rule, Severity,
};
use once_cell::sync::Lazy;
use regex::Regex;

pub struct EvalAtobChain;

static EVAL_ATOB_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
            \b(?:eval|Function)\s*\(\s*atob\s*\(
          | \b(?:eval|Function)\s*\(\s*Buffer\s*\.\s*from\s*\(
          | \b(?:eval|Function)\s*\(\s*decodeURIComponent\s*\(\s*escape\s*\(
          | \b\(\s*(?:async\s+)?(?:0\s*,\s*)?eval\s*\)\s*\(\s*atob\s*\(
          | \bnew\s+Function\s*\(\s*atob\s*\(
          | \b\(\)\s*=>\s*\{\s*\}\s*\.\s*constructor\s*\(\s*atob\s*\(
        "#,
    )
    .expect("EVAL_ATOB_RE")
});

impl Rule for EvalAtobChain {
    fn id(&self) -> &'static str {
        "NPM020"
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
            if let Some(m) = EVAL_ATOB_RE.find(text) {
                out.push(make_finding(entry.path.clone(), m.as_str().to_string()));
            }
        }
        for life in ctx.lifecycle {
            if let Some(m) = EVAL_ATOB_RE.find(&life.body) {
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
        rule_id: "NPM020".into(),
        severity: Severity::Critical,
        category: Category::Obfuscation,
        locations: vec![Location {
            path,
            line_start: None,
            line_end: None,
        }],
        excerpt: Some(hit),
        message: "direct `eval`/`Function` of a base64-decoded payload".into(),
        defers_to_stage2: false,
    }
}
