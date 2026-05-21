//! NPM023 — generic outbound HTTP / fetch in an install-time
//! lifecycle script body.
//!
//! Complements `NPM002` (which catches `require('http')` etc) and
//! `NPM017` / `NPM019` (which catch the specific raw-GitHub /
//! `curl|sh` shapes): this rule fires on the *call* itself when it
//! appears inside a postinstall body — `https.get(...)`, `fetch(...)`,
//! `axios.get(...)` — regardless of target host. Defer to Stage 2
//! because legitimate postinstall scripts do download prebuilt
//! native addons (node-gyp / prebuild-install), and the LLM is in a
//! better position than us to read the URL and decide.

use monomi_core::{
    AnalysisCtx, Capability, Category, EcosystemId, Finding, LifecycleKind, Location, Rule,
    Severity,
};
use once_cell::sync::Lazy;
use regex::Regex;

pub struct InstallTimeOutboundHttp;

static HTTP_CALL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
            \b(?:https?|http2)\s*\.\s*(?:get|request|post|put|delete|head)\s*\(
          | \brequire\s*\(\s*['"](?:https?|http2|node:https?|axios|node-fetch|got|undici|superagent)['"]\s*\)
              \s*\.\s*(?:get|request|post|put|delete|head)\s*\(
          | \bfetch\s*\(
          | \baxios\s*(?:\.\s*(?:get|post|put|delete|head|patch|request))?\s*\(
          | \bgot\s*(?:\.\s*(?:get|post|put|delete|head|stream))?\s*\(
          | \bsuperagent\s*\.\s*(?:get|post|put|delete|head)\s*\(
          | \bundici\s*\.\s*request\s*\(
          | \bnew\s+XMLHttpRequest\s*\(
          | \bnew\s+WebSocket\s*\(
        "#,
    )
    .expect("HTTP_CALL_RE")
});

impl Rule for InstallTimeOutboundHttp {
    fn id(&self) -> &'static str {
        "NPM023"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(eco, EcosystemId::Npm)
    }

    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for life in ctx.lifecycle {
            if !matches!(life.kind, LifecycleKind::InstallTime) {
                continue;
            }
            if let Some(m) = HTTP_CALL_RE.find(&life.body) {
                out.push(Finding {
                    rule_id: "NPM023".into(),
                    severity: Severity::High,
                    category: Category::LifecycleScript,
                    locations: vec![Location {
                        path: format!("package.json#scripts.{}", life.name),
                        line_start: None,
                        line_end: None,
                    }],
                    excerpt: Some(m.as_str().to_string()),
                    message: format!(
                        "install-time script `{}` issues an outbound HTTP/fetch call `{}` \
                         — destination URL must be vetted",
                        life.name,
                        m.as_str()
                    ),
                    defers_to_stage2: true,
                    capabilities: [
                        Capability::InstallTimeNetwork,
                        Capability::NetHttp,
                        Capability::LifecycleInstall,
                    ]
                    .into_iter()
                    .collect(),
                });
            }
        }
        out
    }
}
