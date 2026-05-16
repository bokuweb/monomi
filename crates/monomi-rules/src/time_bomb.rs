//! NPM028 — time-bomb / conditional activation.
//!
//! Catches code that compares the wall clock against a *future*
//! timestamp before deciding whether to run a payload. The shape
//! is exploited so the malware sleeps through any analysis window
//! and only activates after some date — perfect for evading
//! short-term sandbox / install-time scrutiny.
//!
//! Common JS patterns:
//!
//! ```js
//! if (Date.now() > 1_780_000_000_000) { activate(); }
//! if (new Date() > new Date('2026-01-01')) { ... }
//! if (Date.parse('2026-06-01') < Date.now()) { ... }
//! ```
//!
//! High + defer to Stage 2: feature-flag libraries legitimately
//! compare dates, so the LLM gets the final call.

use chrono::{Datelike, Utc};
use monomi_core::{
    AnalysisCtx, Category, EcosystemId, EntryKind, Finding, Location, Rule, Severity,
};
use once_cell::sync::Lazy;
use regex::Regex;

pub struct TimeBombActivation;

/// `Date.now() <op> <13-digit ms-since-epoch>` shape.
static DATE_NOW_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bDate\s*\.\s*now\s*\(\s*\)\s*([<>]=?)\s*(\d{12,14})").expect("DATE_NOW_RE")
});

/// `new Date() <op> new Date('YYYY-MM-DD…')` or
/// `Date.parse('YYYY-…')` literal date.
static DATE_LITERAL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"['"]((?:19|20)\d{2}-\d{2}-\d{2}[T\d:.Z+ -]*)['"]"#).expect("DATE_LITERAL_RE")
});

impl Rule for TimeBombActivation {
    fn id(&self) -> &'static str {
        "NPM028"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(eco, EcosystemId::Npm)
    }

    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        let now_ms = Utc::now().timestamp_millis() as u64;
        let mut out = Vec::new();

        for entry in ctx.entries {
            if !matches!(entry.kind, EntryKind::JsSource | EntryKind::Text) {
                continue;
            }
            let Some(text) = entry.text() else { continue };
            self.scan(text, &entry.path, now_ms, &mut out);
        }
        for life in ctx.lifecycle {
            self.scan(
                &life.body,
                &format!("package.json#scripts.{}", life.name),
                now_ms,
                &mut out,
            );
        }
        out
    }
}

impl TimeBombActivation {
    fn scan(&self, text: &str, path: &str, now_ms: u64, out: &mut Vec<Finding>) {
        // Date.now() compared to a future ms-since-epoch literal.
        for c in DATE_NOW_RE.captures_iter(text) {
            let Some(num_match) = c.get(2) else { continue };
            let Ok(target_ms) = num_match.as_str().parse::<u64>() else {
                continue;
            };
            // Only flag genuinely future timestamps. Past ones are
            // typically "if (Date.now() > someEpoch) { we've drifted }"
            // sanity checks.
            if target_ms <= now_ms {
                continue;
            }
            out.push(Finding {
                rule_id: "NPM028".into(),
                severity: Severity::High,
                category: Category::Other,
                locations: vec![Location {
                    path: path.to_string(),
                    line_start: None,
                    line_end: None,
                }],
                excerpt: Some(c.get(0).map(|m| m.as_str().to_string()).unwrap_or_default()),
                message: format!(
                    "comparison against future timestamp `{target_ms}` — time-bomb \
                     activation shape (current epoch ms: {now_ms})"
                ),
                defers_to_stage2: true,
            });
        }
        // Date literal in source, only flag when it's in the future.
        let current_year = Utc::now().year();
        for c in DATE_LITERAL_RE.captures_iter(text) {
            let Some(s) = c.get(1).map(|m| m.as_str()) else {
                continue;
            };
            // Cheap year extract; full parse would also work.
            let year = s.get(..4).and_then(|y| y.parse::<i32>().ok()).unwrap_or(0);
            if year <= current_year {
                continue;
            }
            out.push(Finding {
                rule_id: "NPM028".into(),
                severity: Severity::Medium,
                category: Category::Other,
                locations: vec![Location {
                    path: path.to_string(),
                    line_start: None,
                    line_end: None,
                }],
                excerpt: Some(s.to_string()),
                message: format!(
                    "hardcoded future date literal `{s}` (current year {current_year}) — \
                     possible time-bomb activation"
                ),
                defers_to_stage2: true,
            });
        }
    }
}
