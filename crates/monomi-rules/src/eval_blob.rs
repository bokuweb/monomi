use monomi_core::{Capability, AnalysisCtx, Category, EcosystemId, Entry, EntryKind, Finding, Location, Rule, Severity,};
use once_cell::sync::Lazy;
use regex::Regex;

/// NPM005 — large base64/hex blob in proximity to a dynamic-execution
/// primitive (`eval` / `new Function` / `vm.runIn*`).
///
/// The pattern is the dominant npm-malware obfuscation shape:
/// ship a giant string, decode it at install/import time, and
/// `eval` the result.
pub struct EvalLargeBlob {
    pub blob_min_chars: usize,
    pub window_chars: usize,
}

impl Default for EvalLargeBlob {
    fn default() -> Self {
        Self {
            // 1 KB of contiguous base64/hex is well past anything legitimate
            // typically inlines (favicon data URIs are usually shorter and
            // don't appear next to eval).
            blob_min_chars: 1024,
            window_chars: 4096,
        }
    }
}

static EXEC_RE: Lazy<Regex> = Lazy::new(|| {
    // `eval(` , `new Function(` , `vm.runInNewContext(` , `vm.runInThisContext(` , `vm.runInContext(`
    Regex::new(
        r"(?x)
            \beval\s*\(
          | \bnew\s+Function\s*\(
          | \bvm\s*\.\s*runIn(?:NewContext|ThisContext|Context)\s*\(
        ",
    )
    .expect("EXEC_RE")
});

static B64_RE: Lazy<Regex> = Lazy::new(|| {
    // Long runs of base64 alphabet — at least 1024 chars, lets `=` padding pass.
    Regex::new(r"[A-Za-z0-9+/]{1024,}={0,2}").expect("B64_RE")
});

static HEX_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"[0-9a-fA-F]{1024,}").expect("HEX_RE"));

impl Rule for EvalLargeBlob {
    fn id(&self) -> &'static str {
        "NPM005"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(eco, EcosystemId::Npm)
    }

    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        // Inspect JS sources and lifecycle script bodies.
        for entry in ctx.entries {
            if !matches!(entry.kind, EntryKind::JsSource | EntryKind::Text) {
                continue;
            }
            let Some(text) = entry.text() else { continue };
            // AST suppression filter: skip exec/blob hits whose
            // byte position is inside a comment or string literal.
            // README content embedded as a template literal that
            // happens to mention `eval(...)` near a base64 blob
            // shouldn't trip this rule.
            let in_code = |pos: usize| {
                crate::ast_helpers::regex_hit_in_code(ctx, &entry.path, text, pos)
            };
            if let Some(excerpt) = self.find_proximity(text, &in_code) {
                out.push(make_finding(entry.path.clone(), excerpt));
            }
        }
        for life in ctx.lifecycle {
            // Lifecycle bodies aren't JS files; trust the regex.
            if let Some(excerpt) = self.find_proximity(&life.body, &|_| true) {
                out.push(make_finding(
                    format!("package.json#scripts.{}", life.name),
                    excerpt,
                ));
            }
        }
        out
    }
}

impl EvalLargeBlob {
    fn find_proximity(&self, text: &str, in_code: &dyn Fn(usize) -> bool) -> Option<String> {
        let blob_hits: Vec<(usize, usize)> = B64_RE
            .find_iter(text)
            .chain(HEX_RE.find_iter(text))
            .filter(|m| m.as_str().len() >= self.blob_min_chars)
            .map(|m| (m.start(), m.end()))
            .collect();
        if blob_hits.is_empty() {
            return None;
        }
        let exec_hits: Vec<(usize, usize)> = EXEC_RE
            .find_iter(text)
            // The exec call is the load-bearing part — if it's in a
            // comment, this whole pattern doesn't actually run. We
            // *don't* filter blobs the same way because a big base64
            // string is often surrounded by quotes (which is fine —
            // that's how it's loaded). The blob being in a string
            // literal is the *expected* shape.
            .filter(|m| in_code(m.start()))
            .map(|m| (m.start(), m.end()))
            .collect();
        if exec_hits.is_empty() {
            return None;
        }
        for (bs, be) in &blob_hits {
            for (es, _) in &exec_hits {
                let distance = if es > be {
                    es - be
                } else if bs > es {
                    bs - es
                } else {
                    0
                };
                if distance <= self.window_chars {
                    let start = (*bs).saturating_sub(40);
                    let end = (be + 40).min(text.len());
                    return Some(format!(
                        "…{}…",
                        text[start..end].chars().take(200).collect::<String>()
                    ));
                }
            }
        }
        None
    }
}

fn make_finding(path: String, excerpt: String) -> Finding {
    Finding {
        rule_id: "NPM005".into(),
        severity: Severity::Critical,
        category: Category::Obfuscation,
        locations: vec![Location {
            path,
            line_start: None,
            line_end: None,
        }],
        excerpt: Some(excerpt),
        message:
            "large base64/hex blob in proximity to eval/Function/vm.runIn* — likely obfuscated \
             dynamic execution"
                .into(),
        defers_to_stage2: false,
        capabilities: [Capability::DynamicEval, Capability::EncodedPayload].into_iter().collect(),
    }
}

#[allow(dead_code)]
fn _entry_assertion(_: &Entry) {}
