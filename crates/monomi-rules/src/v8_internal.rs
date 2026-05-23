//! `NPM044` — direct V8 / Node-core internal access.
//!
//! Reference: any payload that wants to load a `.node` addon without
//! tripping `require()` resolution, or call into an internal binding
//! that bypasses the documented Node API. Outside of Node-core
//! replacements (`node-pre-gyp`, `electron`, `pkg`), there is no
//! defensible reason for a library to touch these.
//!
//! Stage 2 sees the hit so the LLM can tell apart "this is `pkg`"
//! from "this is malware bypassing module loader".

use monomi_core::{
    AnalysisCtx, Capability, Category, EcosystemId, EntryKind, Finding, Location, Rule, Severity,
};
use once_cell::sync::Lazy;
use regex::Regex;

pub struct V8InternalAccess;

static V8_INTERNAL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
            \bprocess\s*\.\s*dlopen\s*\(
          | \bprocess\s*\.\s*binding\s*\(
          | \bprocess\s*\.\s*_linkedBinding\s*\(
          | \bprocess\s*\.\s*_rawDebug\s*\(
        "#,
    )
    .expect("V8_INTERNAL_RE")
});

impl Rule for V8InternalAccess {
    fn id(&self) -> &'static str {
        "NPM044"
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
            if let Some(m) = V8_INTERNAL_RE.find(text) {
                out.push(Finding {
                    rule_id: "NPM044".into(),
                    severity: Severity::High,
                    category: Category::Obfuscation,
                    locations: vec![Location {
                        path: entry.path.clone(),
                        line_start: None,
                        line_end: None,
                    }],
                    excerpt: Some(m.as_str().to_string()),
                    message: "direct V8/Node-core internal access — bypasses \
                              standard module loader / addon API"
                        .into(),
                    defers_to_stage2: true,
                    capabilities: [Capability::V8Internal, Capability::DynamicEval]
                        .into_iter()
                        .collect(),
                });
            }
        }
        out
    }
}
