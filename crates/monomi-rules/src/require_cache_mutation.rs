//! `NPM038` — `require.cache[...]` mutation / module hijacking.
//!
//! Writing to or deleting `require.cache[k]` substitutes another
//! module's exports for the cached entry — a classic stealth
//! prototype-pollution / module-replacement primitive. Reading the
//! cache is fine and common (`Object.keys(require.cache)`); writing
//! to it is not. We flag both writes (`require.cache[x] = ...`) and
//! `delete require.cache[x]` regardless of whether the key is
//! literal, since neither has a defensible production use.

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
        for entry in ctx.entries {
            if !matches!(entry.kind, EntryKind::JsSource | EntryKind::Text) {
                continue;
            }
            let Some(text) = entry.text() else { continue };
            if let Some(m) = REQUIRE_CACHE_MUT_RE.find(text) {
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
        }
        out
    }
}
