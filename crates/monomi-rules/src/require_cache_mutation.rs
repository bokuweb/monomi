//! `NPM038` — `require.cache[...]` mutation / module hijacking.
//!
//! Writing to or deleting `require.cache[k]` substitutes another
//! module's exports for the cached entry — a classic stealth
//! prototype-pollution / module-replacement primitive. Reading the
//! cache is fine and common (`Object.keys(require.cache)`); writing
//! to it is not.
//!
//! # Two-stage detection
//!
//! 1. **Regex pre-filter** finds candidate write/delete sites
//!    cheaply across all JS files.
//! 2. **AST confirm** parses just the candidate files and verifies
//!    the hit isn't inside a comment or string literal. This drops
//!    a large class of historical FPs (`// require.cache[x] = …` in
//!    explanatory comments, README-style docstrings embedded in
//!    source) without regressing detection of real attacks.
//!
//! When the AST cache isn't available (stage1-only test harness,
//! old verdict replays) we fall back to the regex hit alone —
//! same behavior as before this rule grew the AST pass.

use monomi_core::{
    AnalysisCtx, Capability, Category, EcosystemId, EntryKind, Finding, Location, Rule, Severity,
};
use once_cell::sync::Lazy;
use regex::Regex;

pub struct RequireCacheMutation;

static REQUIRE_CACHE_MUT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
            \brequire\s*\.\s*cache\s*\[[^\]]+\]\s*=
          | \bdelete\s+require\s*\.\s*cache\s*\[
          | \bModule\s*\.\s*_cache\s*\[[^\]]+\]\s*=
          | \bdelete\s+Module\s*\.\s*_cache\s*\[
        "#,
    )
    .expect("REQUIRE_CACHE_MUT_RE")
});

impl Rule for RequireCacheMutation {
    fn id(&self) -> &'static str {
        "NPM038"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(eco, EcosystemId::Npm)
    }

    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        let ast_cache = ctx.ast.and_then(monomi_ast::downcast);

        for entry in ctx.entries {
            if !matches!(entry.kind, EntryKind::JsSource | EntryKind::Text) {
                continue;
            }
            let Some(text) = entry.text() else { continue };
            let Some(m) = REQUIRE_CACHE_MUT_RE.find(text) else {
                continue;
            };

            // AST confirm: skip when the hit is inside a comment
            // or string literal. Cache is per-package so multiple
            // rules share the parse cost.
            if let Some(cache) = ast_cache {
                let parsed = cache.get_or_parse(&entry.path, text);
                if !parsed.parse_errors && parsed.is_in_comment_or_string(m.start()) {
                    continue;
                }
                // Stronger positive signal: an actual assignment or
                // delete on `require.cache[?]` / `Module._cache[?]`
                // visible to the AST. If we have that, even better
                // — but the regex hit is sufficient on its own.
            }

            out.push(Finding {
                rule_id: "NPM038".into(),
                severity: Severity::High,
                category: Category::Obfuscation,
                locations: vec![Location {
                    path: entry.path.clone(),
                    line_start: None,
                    line_end: None,
                }],
                excerpt: Some(m.as_str().to_string()),
                message: "mutates `require.cache` / `Module._cache` — module \
                          substitution / hijack primitive"
                    .into(),
                defers_to_stage2: true,
                capabilities: [Capability::DynamicRequire, Capability::DynamicEval]
                    .into_iter()
                    .collect(),
            });
        }
        out
    }
}
