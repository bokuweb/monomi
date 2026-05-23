//! `NPM050` — minified `dist/` payload with no source map.
//!
//! plan.md threat-model item 5: "Published `dist/` is minified, no
//! source map, no matching repo source — i.e. you can't read what
//! runs." `event-stream`'s flatmap-stream was famously shipped this
//! way: the malicious code only existed as a minified blob, never as
//! readable source, defeating casual code review.
//!
//! Heuristic per file:
//! - very long lines (max line ≥ 1000 chars and mean ≥ 250),
//! - high `\x` / `\u` hex-escape density (≥ 30 escapes per KB),
//! - and is shipped from a build-output path (`dist/`, `build/`,
//!   `out/`, `lib/` for some toolchains, or the package's `main`
//!   field).
//!
//! Becomes a finding when at least one such file is in the tarball
//! AND no companion `*.map` exists AND no readable original was
//! shipped alongside (we use ".ts" / unminified ".js" siblings as
//! the cheap "readable source present" proxy).
//!
//! Severity: Medium + defer. Many legitimate libraries do ship
//! minified bundles, so Stage 2 / the source-divergence detector
//! makes the final call. The new `Capability::MinifiedNoSource`
//! becomes a strong corroborator for `EvalLargeBlob`,
//! `EncodedPayload`, and the M8 diff: if a previously-readable
//! package starts shipping minified-only dist, that's worth a
//! Stage 2 look.

use std::collections::BTreeSet;

use monomi_core::{
    AnalysisCtx, Capability, Category, EcosystemId, EntryKind, Finding, Location, Rule, Severity,
};

pub struct MinifiedNoSource;

const MAX_LINE_THRESHOLD: usize = 1000;
const MEAN_LINE_THRESHOLD: usize = 250;
const HEX_ESCAPES_PER_KB: f64 = 30.0;

fn looks_like_dist_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.starts_with("dist/")
        || lower.starts_with("build/")
        || lower.starts_with("out/")
        || lower.starts_with("lib/")
        || lower.contains("/dist/")
        || lower.contains("/build/")
        || lower.contains("/bundle")
        || lower.contains(".min.js")
        || lower.contains(".bundle.js")
}

fn line_stats(text: &str) -> (usize, usize) {
    let mut max = 0usize;
    let mut sum = 0usize;
    let mut count = 0usize;
    for line in text.lines() {
        let len = line.len();
        if len > max {
            max = len;
        }
        sum += len;
        count += 1;
    }
    let mean = if count == 0 { 0 } else { sum / count };
    (max, mean)
}

fn hex_escape_density(text: &str) -> f64 {
    let bytes = text.len().max(1);
    let mut count = 0usize;
    let raw = text.as_bytes();
    let mut i = 0;
    while i + 1 < raw.len() {
        if raw[i] == b'\\' && (raw[i + 1] == b'x' || raw[i + 1] == b'u') {
            count += 1;
            i += 2;
        } else {
            i += 1;
        }
    }
    (count as f64) * 1024.0 / (bytes as f64)
}

fn is_minified(text: &str) -> bool {
    if text.is_empty() {
        return false;
    }
    let (max, mean) = line_stats(text);
    let dense_escapes = hex_escape_density(text);
    (max >= MAX_LINE_THRESHOLD && mean >= MEAN_LINE_THRESHOLD)
        || dense_escapes >= HEX_ESCAPES_PER_KB
}

impl Rule for MinifiedNoSource {
    fn id(&self) -> &'static str {
        "NPM050"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(eco, EcosystemId::Npm)
    }

    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        // Index for the "no map" and "no readable source" companion
        // checks.
        let mut all_paths: BTreeSet<&str> = BTreeSet::new();
        let mut readable_stems: BTreeSet<String> = BTreeSet::new();
        for e in ctx.entries {
            all_paths.insert(e.path.as_str());
            if !matches!(e.kind, EntryKind::JsSource) {
                continue;
            }
            // A non-minified .js / .ts companion at any path with
            // the same stem suggests the readable form is shipped.
            let stem = std::path::Path::new(&e.path)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            if !stem.is_empty()
                && (e.path.ends_with(".ts") || (e.path.ends_with(".js") && !is_minified_path_hint(&e.path)))
            {
                if let Some(text) = e.text() {
                    if !is_minified(text) {
                        readable_stems.insert(stem.to_string());
                    }
                }
            }
        }

        let mut out = Vec::new();
        for entry in ctx.entries {
            if !matches!(entry.kind, EntryKind::JsSource) {
                continue;
            }
            if !looks_like_dist_path(&entry.path) {
                continue;
            }
            let Some(text) = entry.text() else { continue };
            if !is_minified(text) {
                continue;
            }

            // Companion map?
            let map_candidate = format!("{}.map", entry.path);
            if all_paths.contains(map_candidate.as_str()) {
                continue;
            }

            // Readable companion with same stem?
            let stem = std::path::Path::new(&entry.path)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            if !stem.is_empty() && readable_stems.contains(stem) {
                continue;
            }

            out.push(Finding {
                rule_id: "NPM050".into(),
                severity: Severity::Medium,
                category: Category::SourceDivergence,
                locations: vec![Location {
                    path: entry.path.clone(),
                    line_start: None,
                    line_end: None,
                }],
                excerpt: None,
                message: "minified JS shipped from a dist/build path with no \
                          companion source map and no readable original — \
                          code cannot be audited before install (plan.md \
                          threat-model item 5)"
                    .into(),
                defers_to_stage2: true,
                capabilities: [Capability::MinifiedNoSource].into_iter().collect(),
            });
        }
        out
    }
}

fn is_minified_path_hint(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains(".min.js") || lower.contains(".bundle.js")
}
