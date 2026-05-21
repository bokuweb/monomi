//! NPM015 — encoded URL construction.
//!
//! Catches the "build the literal `http`/`https` prefix at runtime
//! from numeric character codes" obfuscation. The decimal sequence
//! `104, 116, 116, 112` (and its hex form `0x68, 0x74, 0x74, 0x70`)
//! spells `http`; with a `s` appended it spells `https`. Any
//! occurrence of these byte sequences in a published package is
//! near-certainly a static-scanner evasion attempt.

use monomi_core::{Capability, AnalysisCtx, Category, EcosystemId, Finding, Location, Rule, Severity};
use once_cell::sync::Lazy;
use regex::Regex;

pub struct EncodedUrlBytes;

static HTTP_BYTES_RE: Lazy<Regex> = Lazy::new(|| {
    // "http" = 104, 116, 116, 112 in decimal or 0x68, 0x74, 0x74, 0x70 in hex.
    // Accept any whitespace / commas between digits.
    Regex::new(
        r"(?ix)
            (?:104|0x0?68)\s*,\s*
            (?:116|0x0?74)\s*,\s*
            (?:116|0x0?74)\s*,\s*
            (?:112|0x0?70)
        ",
    )
    .expect("HTTP_BYTES_RE")
});

impl Rule for EncodedUrlBytes {
    fn id(&self) -> &'static str {
        "NPM015"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(eco, EcosystemId::Npm)
    }

    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for entry in ctx.entries {
            if !entry.kind.is_scannable_source() {
                continue;
            }
            let Some(text) = entry.text() else { continue };
            if let Some(m) = HTTP_BYTES_RE.find(text) {
                out.push(make_finding(entry.path.clone(), m.as_str().to_string()));
            }
        }
        for life in ctx.lifecycle {
            if let Some(m) = HTTP_BYTES_RE.find(&life.body) {
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
        rule_id: "NPM015".into(),
        severity: Severity::Critical,
        category: Category::Obfuscation,
        locations: vec![Location {
            path,
            line_start: None,
            line_end: None,
        }],
        excerpt: Some(hit),
        message: "byte sequence spelling `http` (104,116,116,112) in source — static-scanner \
             evasion, attempting to hide a URL"
            .into(),
        defers_to_stage2: false,
        capabilities: [Capability::EncodedPayload].into_iter().collect(),
    }
}
