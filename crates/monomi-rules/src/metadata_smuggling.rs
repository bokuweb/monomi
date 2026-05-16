//! NPM026 — payload smuggled into README / LICENSE / docs.
//!
//! Sometimes droppers hide their payload inside files that
//! conventionally aren't executed — `README.md`, `LICENSE`,
//! `CHANGELOG.md` — relying on a tooling pipeline that later
//! interprets them (`require('./README.md')` in some bespoke build
//! system, or just smuggling code past a casual reviewer who only
//! looks at `.js` files).
//!
//! Decisive Critical for executable patterns inside non-code
//! metadata files (`<script>`, `eval(`, `Function(`, base64 blob
//! > 1 KB next to suspicious nearby chars).

use monomi_core::{AnalysisCtx, Category, EcosystemId, Finding, Location, Rule, Severity};
use once_cell::sync::Lazy;
use regex::Regex;

pub struct MetadataPayloadSmuggling;

fn is_metadata_file(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "readme"
            | "readme.md"
            | "readme.markdown"
            | "readme.txt"
            | "readme.rst"
            | "license"
            | "license.md"
            | "license.txt"
            | "licence"
            | "licence.md"
            | "licence.txt"
            | "changelog"
            | "changelog.md"
            | "changelog.txt"
            | "contributing"
            | "contributing.md"
            | "notice"
            | "notice.md"
            | "notice.txt"
            | "authors"
            | "authors.md"
    )
}

static EXEC_PATTERNS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?ix)
            <script\b
          | \beval\s*\(
          | \bnew\s+Function\s*\(
          | \bFunction\s*\(\s*['"][^'"]+['"]
          | \brequire\s*\(\s*['"][^'"]+['"]\s*\)\s*\(
        "#,
    )
    .expect("EXEC_PATTERNS_RE")
});

static LARGE_B64_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[A-Za-z0-9+/]{1024,}={0,2}").expect("LARGE_B64_RE"));

impl Rule for MetadataPayloadSmuggling {
    fn id(&self) -> &'static str {
        "NPM026"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(eco, EcosystemId::Npm)
    }

    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for entry in ctx.entries {
            if !is_metadata_file(&entry.path) {
                continue;
            }
            let Some(text) = entry.text() else { continue };

            if let Some(m) = EXEC_PATTERNS_RE.find(text) {
                out.push(make_finding(
                    entry.path.clone(),
                    format!("executable construct in metadata file: {}", m.as_str()),
                ));
            } else if LARGE_B64_RE.is_match(text) {
                out.push(make_finding(
                    entry.path.clone(),
                    format!(
                        "{}-byte base64 blob smuggled inside metadata file",
                        text.len()
                    ),
                ));
            }
        }
        out
    }
}

fn make_finding(path: String, hit: String) -> Finding {
    Finding {
        rule_id: "NPM026".into(),
        severity: Severity::Critical,
        category: Category::Obfuscation,
        locations: vec![Location {
            path,
            line_start: None,
            line_end: None,
        }],
        excerpt: Some(hit.clone()),
        message: format!("payload smuggled into a metadata / docs file — {hit}"),
        defers_to_stage2: false,
    }
}
