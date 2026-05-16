//! CARGO004 — large `include_bytes!` / `include_str!` reference in
//! a build script.
//!
//! Cargo crates can embed arbitrary file contents at compile time
//! via `include_bytes!("payload.bin")`. When this happens inside
//! `build.rs`, the embedded bytes become available at build time
//! and can be unpacked / executed before any user code runs.
//! Defer to Stage 2 — the LLM is best placed to decide whether
//! the referenced filename looks legitimate (license / template)
//! or suspicious (encrypted payload).

use monomi_core::{
    AnalysisCtx, Category, EcosystemId, Finding, LifecycleKind, Location, Rule, Severity,
};
use once_cell::sync::Lazy;
use regex::Regex;

pub struct BuildRsIncludePayload;

static INCLUDE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
            \binclude_bytes\s*!\s*\(\s*["][^"]*["]
          | \binclude_str\s*!\s*\(\s*["][^"]*["]
        "#,
    )
    .expect("INCLUDE_RE")
});

impl Rule for BuildRsIncludePayload {
    fn id(&self) -> &'static str {
        "CARGO004"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(eco, EcosystemId::Cargo)
    }

    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for life in ctx.lifecycle {
            if !matches!(life.kind, LifecycleKind::InstallTime) {
                continue;
            }
            if let Some(m) = INCLUDE_RE.find(&life.body) {
                let path = life.path.clone().unwrap_or_else(|| "build.rs".into());
                out.push(Finding {
                    rule_id: "CARGO004".into(),
                    severity: Severity::High,
                    category: Category::Obfuscation,
                    locations: vec![Location {
                        path,
                        line_start: None,
                        line_end: None,
                    }],
                    excerpt: Some(m.as_str().to_string()),
                    message: format!(
                        "build script embeds a file at compile time via `{}` — \
                         verify the included bytes are benign",
                        m.as_str()
                    ),
                    defers_to_stage2: true,
                });
            }
        }
        out
    }
}
