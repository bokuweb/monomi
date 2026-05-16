//! NPM021 — `files` field vs. actual tarball contents mismatch.
//!
//! The `files` field of `package.json` is an allow-list; npm's
//! pack step only includes matching paths plus a hardcoded
//! always-include set (`package.json`, `README*`, `LICENSE*`,
//! `LICENCE*`, the `main`/`bin`/`browser`/`man` entries). When a
//! published tarball contains *extra* files outside that envelope,
//! one of two things happened:
//!
//! - the publisher accidentally shipped scratch files (low risk
//!   but worth surfacing), or
//! - the publisher intentionally hid payload files that are not
//!   advertised in the manifest (classic stealth-publish trick).
//!
//! High + defer to Stage 2 because the second case is the alarming
//! one and we want the LLM to look at *which* files are extra.

use monomi_core::{AnalysisCtx, Category, EcosystemId, Finding, Location, Rule, Severity};

pub struct FilesFieldMismatch {
    /// Cap on how many extra paths we list in the finding excerpt.
    pub max_listed: usize,
}

impl Default for FilesFieldMismatch {
    fn default() -> Self {
        Self { max_listed: 10 }
    }
}

impl Rule for FilesFieldMismatch {
    fn id(&self) -> &'static str {
        "NPM021"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(eco, EcosystemId::Npm)
    }

    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        // `files` only matters when it's actually declared.
        let raw_files = match ctx.manifest.raw.get("files") {
            Some(serde_json::Value::Array(arr)) => arr,
            _ => return Vec::new(),
        };
        let mut allow_patterns: Vec<String> = Vec::new();
        for v in raw_files {
            if let Some(s) = v.as_str() {
                allow_patterns.push(s.trim_start_matches("./").to_string());
            }
        }

        let always_implicit = always_implicit_paths(ctx);

        let mut extras: Vec<String> = Vec::new();
        for entry in ctx.entries {
            let p = entry.path.as_str();
            if always_implicit.iter().any(|i| paths_eq(p, i)) {
                continue;
            }
            if allow_patterns.iter().any(|pat| matches_pattern(pat, p)) {
                continue;
            }
            extras.push(p.to_string());
        }
        if extras.is_empty() {
            return Vec::new();
        }

        let preview: Vec<String> = extras.iter().take(self.max_listed).cloned().collect();
        let preview = if extras.len() > self.max_listed {
            format!(
                "{} (+{} more)",
                preview.join(", "),
                extras.len() - self.max_listed
            )
        } else {
            preview.join(", ")
        };

        vec![Finding {
            rule_id: "NPM021".into(),
            severity: Severity::High,
            category: Category::Other,
            locations: vec![Location {
                path: "package.json".into(),
                line_start: None,
                line_end: None,
            }],
            excerpt: Some(preview),
            message: format!(
                "tarball ships {} file(s) not covered by `files` allow-list",
                extras.len()
            ),
            defers_to_stage2: true,
        }]
    }
}

/// Files npm always includes regardless of the `files` field:
/// `package.json`, top-level README/LICENSE variants, anything
/// referenced by `main` / `bin` / `browser` / `module` / `types`.
fn always_implicit_paths(ctx: &AnalysisCtx<'_>) -> Vec<String> {
    let mut out = vec![
        "package.json".to_string(),
        "package-lock.json".to_string(),
        "npm-shrinkwrap.json".to_string(),
        "README".to_string(),
        "README.md".to_string(),
        "README.markdown".to_string(),
        "README.txt".to_string(),
        "LICENSE".to_string(),
        "LICENSE.md".to_string(),
        "LICENSE.txt".to_string(),
        "LICENCE".to_string(),
        "LICENCE.md".to_string(),
        "LICENCE.txt".to_string(),
        "CHANGELOG".to_string(),
        "CHANGELOG.md".to_string(),
        ".npmrc".to_string(), // not normally shipped but tolerated
    ];
    if let Some(serde_json::Value::String(m)) = ctx.manifest.raw.get("main") {
        out.push(m.trim_start_matches("./").to_string());
    }
    if let Some(serde_json::Value::String(m)) = ctx.manifest.raw.get("module") {
        out.push(m.trim_start_matches("./").to_string());
    }
    if let Some(serde_json::Value::String(m)) = ctx.manifest.raw.get("types") {
        out.push(m.trim_start_matches("./").to_string());
    }
    for p in ctx.manifest.bin.values() {
        out.push(p.trim_start_matches("./").to_string());
    }
    out
}

fn paths_eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Minimal glob: handles `*`, `**`, plain directory prefix, and
/// exact filename. Sufficient for npm's `files` syntax in V1;
/// extended patterns (negations, character classes) fall through
/// to "no match" which only causes false-positive findings — Stage
/// 2 sees the full file list and can de-escalate.
fn matches_pattern(pattern: &str, path: &str) -> bool {
    let pat = pattern.trim_end_matches('/');
    // Bare directory: any path under it counts.
    if !pat.contains(['*', '?']) {
        return path == pat || path.starts_with(&format!("{pat}/"));
    }
    // `**` → match any subpath.
    if let Some(suffix) = pat.strip_prefix("**/") {
        return path.ends_with(suffix) || matches_simple(suffix, path);
    }
    if let Some(prefix) = pat.strip_suffix("/**") {
        return path.starts_with(&format!("{prefix}/")) || path == prefix;
    }
    matches_simple(pat, path)
}

/// Match a `*`-only pattern against a path.
fn matches_simple(pattern: &str, path: &str) -> bool {
    // Translate pattern segments separated by `*` into substring matches.
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return parts[0] == path;
    }
    let mut cursor = 0usize;
    for (i, seg) in parts.iter().enumerate() {
        if seg.is_empty() {
            continue;
        }
        if i == 0 {
            if !path[cursor..].starts_with(seg) {
                return false;
            }
            cursor += seg.len();
        } else if i == parts.len() - 1 {
            if !path[cursor..].ends_with(seg) {
                return false;
            }
        } else {
            match path[cursor..].find(seg) {
                Some(idx) => cursor += idx + seg.len(),
                None => return false,
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_directory_prefix() {
        assert!(matches_pattern("dist", "dist/index.js"));
        assert!(matches_pattern("dist/", "dist/sub/x.js"));
        assert!(!matches_pattern("dist", "dist2/x.js"));
    }

    #[test]
    fn matches_star() {
        assert!(matches_pattern("*.d.ts", "index.d.ts"));
        assert!(!matches_pattern("*.d.ts", "index.js"));
    }

    #[test]
    fn matches_double_star() {
        assert!(matches_pattern("dist/**", "dist/sub/x.js"));
        assert!(matches_pattern("**/*.js", "src/x.js"));
    }
}
