//! CARGO003 — proc-macro crate.
//!
//! A crate with `[lib] proc-macro = true` runs as **compiler
//! plugin** at the build time of every downstream crate. That
//! means once a malicious proc-macro is pulled in (even
//! transitively), arbitrary code executes on the developer's
//! machine the next time they `cargo build` — without ever calling
//! the macro from user code.
//!
//! The vast majority of proc-macros are perfectly legitimate
//! (`serde_derive`, `tokio-macros`, `thiserror-impl`, …) so this
//! is High + defer to Stage 2. The point is to surface "this crate
//! has compiler-plugin powers" to the LLM, which can then weight
//! it against the other findings.

use monomi_core::{AnalysisCtx, Category, EcosystemId, Finding, Location, Rule, Severity};

pub struct ProcMacroCrate;

impl Rule for ProcMacroCrate {
    fn id(&self) -> &'static str {
        "CARGO003"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(eco, EcosystemId::Cargo)
    }

    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        let raw = &ctx.manifest.raw;
        let lib = raw.get("lib");
        let is_proc_macro = lib
            .and_then(|l| l.get("proc-macro"))
            .or_else(|| lib.and_then(|l| l.get("proc_macro")))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !is_proc_macro {
            return Vec::new();
        }
        vec![Finding {
            rule_id: "CARGO003".into(),
            severity: Severity::High,
            category: Category::Other,
            locations: vec![Location {
                path: "Cargo.toml".into(),
                line_start: None,
                line_end: None,
            }],
            excerpt: Some("[lib] proc-macro = true".into()),
            message: "crate is a proc-macro — runs at compile time inside every \
                      downstream crate; verify the macro body is benign"
                .into(),
            defers_to_stage2: true,
            capabilities: Default::default(),        }]
    }
}
