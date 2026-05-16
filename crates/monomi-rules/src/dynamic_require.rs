//! NPM013 — `require()` / dynamic `import()` with a non-literal arg.
//!
//! Catches the "decode a string, then load it as a module" pattern
//! that sits next to (but is not strictly part of) the
//! `eval(base64)` family caught by `NPM005`. Examples:
//!
//! ```js
//! require(Buffer.from(b64, 'base64').toString());
//! import(globalThis['nat' + 'ive']);
//! require(['lo', 'dash'].join(''));
//! ```
//!
//! High + defer to Stage 2: dynamic plugin loaders, transpilers,
//! and test runners legitimately do this.

use monomi_core::{
    AnalysisCtx, Category, EcosystemId, EntryKind, Finding, Location, Rule, Severity,
};
use once_cell::sync::Lazy;
use regex::Regex;

pub struct DynamicRequire;

static DYNAMIC_RE: Lazy<Regex> = Lazy::new(|| {
    // Rust regex doesn't support look-ahead, so instead of excluding
    // the static-string call form we match positively on
    // obfuscation primitives that only appear in *non-literal*
    // require/import calls. A normal `require('fs')` cannot match
    // any of these openers.
    Regex::new(
        r#"(?x)
            \b(?:require|import)\s*\(\s*
            (?:
                Buffer\s*\.\s*from
              | atob\s*\(
              | globalThis\s*\[
              | String\s*\.\s*fromCharCode
              | process\s*\.\s*env\s*\.
              | `[^`]*\$\{                # template literal with interpolation
            )
        "#,
    )
    .expect("DYNAMIC_RE")
});

impl Rule for DynamicRequire {
    fn id(&self) -> &'static str {
        "NPM013"
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
            if let Some(m) = DYNAMIC_RE.find(text) {
                out.push(make_finding(entry.path.clone(), m.as_str().to_string()));
            }
        }
        for life in ctx.lifecycle {
            if let Some(m) = DYNAMIC_RE.find(&life.body) {
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
        rule_id: "NPM013".into(),
        severity: Severity::High,
        category: Category::Obfuscation,
        locations: vec![Location {
            path,
            line_start: None,
            line_end: None,
        }],
        excerpt: Some(hit),
        message: "dynamic `require()` / `import()` with non-literal argument".into(),
        defers_to_stage2: true,
    }
}
