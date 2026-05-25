//! `NPM037` — payload branches on `require.main.filename` /
//! `process.mainModule` and string-matches the value against a
//! literal package-name list.
//!
//! Reference incident: `event-stream` / `flatmap-stream` 2018. The
//! payload only fired when imported by `copay-dash`; the source
//! contained an explicit check on `require.main.filename` for that
//! package name. There is no legitimate library reason to gate
//! behavior on the *identity of the consuming application*.
//!
//! Two-prong: (a) reads `require.main.filename` /
//! `process.mainModule.filename` and (b) the same file contains
//! a string literal comparison or `indexOf` / regex against a path
//! containing `node_modules/<name>` or a quoted package name. The
//! double match is what keeps FPs (CLI tools that legitimately
//! detect "am I being required vs run directly?") low.

use monomi_core::{
    AnalysisCtx, Capability, Category, EcosystemId, EntryKind, Finding, Location, Rule, Severity,
};
use once_cell::sync::Lazy;
use regex::Regex;

pub struct MainModuleBranch;

static MAIN_FILENAME_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
            \brequire\s*\.\s*main\s*\.\s*(?:filename|path)\b
          | \bprocess\s*\.\s*mainModule\s*\.\s*(?:filename|path)\b
          | \bprocess\s*\.\s*mainModule\b
        "#,
    )
    .expect("MAIN_FILENAME_RE")
});

// String-literal package-name comparison shapes:
//   "node_modules/foo"            (path fragment)
//   .indexOf("foo")               (substring search anywhere on the line)
//   === "foo"  /  == 'foo'        (direct equality with a quoted name)
// The literal must look like a package name (lowercase, dash/scope).
static PKG_NAME_COMPARE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
            ['"](?:\.{0,2}/)?node_modules/[@a-z0-9][\w./@-]*['"]
          | \.\s*indexOf\s*\(\s*['"][@a-z0-9][\w./@-]{2,}['"]\s*\)
          | (?:===|==)\s*['"][@a-z0-9][\w./@-]{2,}['"]
        "#,
    )
    .expect("PKG_NAME_COMPARE_RE")
});

impl Rule for MainModuleBranch {
    fn id(&self) -> &'static str {
        "NPM037"
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
            let Some(m) = MAIN_FILENAME_RE.find(text) else {
                continue;
            };
            if !PKG_NAME_COMPARE_RE.is_match(text) {
                continue;
            }
            out.push(Finding {
                rule_id: "NPM037".into(),
                severity: Severity::High,
                category: Category::Obfuscation,
                locations: vec![Location {
                    path: entry.path.clone(),
                    line_start: None,
                    line_end: None,
                }],
                excerpt: Some(m.as_str().to_string()),
                message: "code branches on the *consuming* application's identity \
                          (`require.main.filename` / `process.mainModule` + literal \
                          package-name comparison) — event-stream / flatmap-stream 2018 shape"
                    .into(),
                defers_to_stage2: true,
                capabilities: [Capability::DynamicEval, Capability::TimeBomb]
                    .into_iter()
                    .collect(),
            });
        }
        out
    }
}
