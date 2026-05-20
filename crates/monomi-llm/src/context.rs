use monomi_core::{
    EcosystemId, Finding, LifecycleEntry, LifecycleKind, Manifest, RegistryMetadata, Stage1Result,
};

/// Bounded text view of a package suitable for sending to an LLM.
///
/// Built by `build_context`; never holds raw tarball bytes.
#[derive(Debug, Clone)]
pub struct Stage2Context {
    /// Which package registry the artifact came from. Lets the
    /// system prompt key off ecosystem-specific norms.
    pub ecosystem: EcosystemId,
    pub manifest_summary: String,
    /// Optional registry-side context (publish times, maintainers,
    /// version count). Empty string when the analyzer ran offline
    /// or the ecosystem doesn't surface metadata.
    pub registry_summary: String,
    pub lifecycle_blocks: Vec<LifecycleBlock>,
    pub finding_excerpts: Vec<FindingExcerpt>,
    /// Stage 1 score and verdict for at-a-glance framing.
    pub stage1_summary: String,
    /// Rough char-count budget consumed by the context, for the
    /// adjudicator's pre-flight token estimate.
    pub approx_chars: usize,
}

#[derive(Debug, Clone)]
pub struct LifecycleBlock {
    pub name: String,
    pub body: String,
}

#[derive(Debug, Clone)]
pub struct FindingExcerpt {
    pub rule_id: String,
    pub severity: String,
    pub location: String,
    pub excerpt: String,
    pub message: String,
    /// Whether the rule itself marked this finding as block-grade
    /// vs. "needs Stage 2 to decide". Shown so the LLM can weight
    /// each finding properly.
    pub decisive: bool,
}

/// Context-builder limits.
#[derive(Debug, Clone, Copy)]
pub struct ContextLimits {
    pub max_lifecycle_body_chars: usize,
    pub max_excerpt_chars: usize,
    pub max_total_chars: usize,
}

impl Default for ContextLimits {
    fn default() -> Self {
        Self {
            max_lifecycle_body_chars: 8 * 1024,
            max_excerpt_chars: 1024,
            // ~15k tokens at the conservative 4-chars/token estimate.
            // Plenty of headroom for any realistic package and ~2× cheaper
            // per call than the previous 30k budget.
            max_total_chars: 60_000,
        }
    }
}

pub fn build_context(
    ecosystem: EcosystemId,
    manifest: &Manifest,
    lifecycle: &[LifecycleEntry],
    stage1: &Stage1Result,
    registry: Option<&RegistryMetadata>,
    limits: ContextLimits,
) -> Stage2Context {
    let manifest_summary = summarize_manifest(manifest);
    let registry_summary = registry.map(summarize_registry).unwrap_or_default();
    let stage1_summary = summarize_stage1(stage1);
    let mut approx = manifest_summary.len() + registry_summary.len() + stage1_summary.len();

    let mut lifecycle_blocks = Vec::new();
    for life in lifecycle {
        if !matches!(life.kind, LifecycleKind::InstallTime) {
            continue;
        }
        let body = truncate(&life.body, limits.max_lifecycle_body_chars);
        approx += body.len() + life.name.len() + 32;
        lifecycle_blocks.push(LifecycleBlock {
            name: life.name.clone(),
            body,
        });
    }

    let mut finding_excerpts = Vec::new();
    for f in &stage1.findings {
        if approx > limits.max_total_chars {
            break;
        }
        let excerpt = f
            .excerpt
            .as_deref()
            .map(|s| truncate(s, limits.max_excerpt_chars))
            .unwrap_or_default();
        let location = f
            .locations
            .first()
            .map(|l| l.path.clone())
            .unwrap_or_default();
        approx += excerpt.len() + f.rule_id.len() + f.message.len() + location.len() + 64;
        finding_excerpts.push(FindingExcerpt {
            rule_id: f.rule_id.clone(),
            severity: format!("{:?}", f.severity).to_lowercase(),
            location,
            excerpt,
            message: f.message.clone(),
            decisive: !f.defers_to_stage2,
        });
    }

    Stage2Context {
        ecosystem,
        manifest_summary,
        registry_summary,
        lifecycle_blocks,
        finding_excerpts,
        stage1_summary,
        approx_chars: approx,
    }
}

fn summarize_registry(r: &RegistryMetadata) -> String {
    let mut s = String::new();
    if let Some(t) = r.published_at {
        let age = chrono::Utc::now().signed_duration_since(t).num_days();
        s.push_str(&format!(
            "published_at: {} ({} days ago)\n",
            t.to_rfc3339(),
            age
        ));
    }
    if let Some(t) = r.package_created_at {
        let age = chrono::Utc::now().signed_duration_since(t).num_days();
        s.push_str(&format!(
            "package_created_at: {} ({} days ago)\n",
            t.to_rfc3339(),
            age
        ));
    }
    if let Some(by) = &r.published_by {
        s.push_str(&format!("published_by: {by}\n"));
    }
    if !r.maintainers.is_empty() {
        let preview: Vec<&str> = r.maintainers.iter().take(8).map(String::as_str).collect();
        s.push_str(&format!(
            "maintainers ({}): {}{}\n",
            r.maintainers.len(),
            preview.join(", "),
            if r.maintainers.len() > 8 { ", …" } else { "" }
        ));
    }
    if let Some(n) = r.total_versions {
        s.push_str(&format!("total_versions: {n}\n"));
    }
    s
}

fn summarize_stage1(s1: &Stage1Result) -> String {
    format!(
        "stage1_verdict: {:?}\nstage1_score: {}\nstage1_findings: {}\n",
        s1.verdict,
        s1.score,
        s1.findings.len()
    )
}

fn summarize_manifest(m: &Manifest) -> String {
    let mut s = String::new();
    s.push_str(&format!("name: {}\nversion: {}\n", m.name, m.version));
    if let Some(r) = &m.repository {
        s.push_str(&format!("repository: {r}\n"));
    }
    if let Some(h) = &m.homepage {
        s.push_str(&format!("homepage: {h}\n"));
    }
    if !m.bin.is_empty() {
        s.push_str("bin:\n");
        for (k, v) in &m.bin {
            s.push_str(&format!("  - {k}: {v}\n"));
        }
    }
    if !m.dependencies.is_empty() {
        s.push_str(&format!("dependency_count: {}\n", m.dependencies.len()));
    }
    s
}

#[allow(dead_code)]
fn _finding_assertion(_: &Finding) {}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        let mut end = n;
        // Avoid splitting a UTF-8 codepoint.
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…[truncated {} bytes]", &s[..end], s.len() - end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use monomi_core::{Category, Finding, Location, Severity, Stage1Verdict};

    #[test]
    fn includes_lifecycle_and_findings() {
        let m = Manifest {
            name: "pkg".into(),
            version: "1.0.0".into(),
            ..Manifest::default()
        };
        let life = vec![LifecycleEntry {
            name: "postinstall".into(),
            kind: LifecycleKind::InstallTime,
            body: "node hook.js".into(),
            path: None,
        }];
        let stage1 = Stage1Result {
            findings: vec![Finding {
                rule_id: "NPM002".into(),
                severity: Severity::High,
                category: Category::LifecycleScript,
                locations: vec![Location {
                    path: "package.json#scripts.postinstall".into(),
                    line_start: None,
                    line_end: None,
                }],
                excerpt: Some("child_process".into()),
                message: "uses child_process".into(),
                defers_to_stage2: true,
                capabilities: Default::default(),            }],
            score: 5,
            verdict: Stage1Verdict::Suspicious,
            capabilities: Default::default(),
        };
        let ctx = build_context(
            EcosystemId::Npm,
            &m,
            &life,
            &stage1,
            None,
            ContextLimits::default(),
        );
        assert_eq!(ctx.lifecycle_blocks.len(), 1);
        assert_eq!(ctx.finding_excerpts.len(), 1);
        assert!(ctx.manifest_summary.contains("name: pkg"));
    }

    #[test]
    fn truncates_oversized_body() {
        let big = "A".repeat(20_000);
        let m = Manifest {
            name: "pkg".into(),
            ..Manifest::default()
        };
        let life = vec![LifecycleEntry {
            name: "postinstall".into(),
            kind: LifecycleKind::InstallTime,
            body: big.clone(),
            path: None,
        }];
        let stage1 = Stage1Result {
            findings: vec![],
            score: 0,
            verdict: Stage1Verdict::Clean,
            capabilities: Default::default(),
        };
        let ctx = build_context(
            EcosystemId::Npm,
            &m,
            &life,
            &stage1,
            None,
            ContextLimits::default(),
        );
        assert!(ctx.lifecycle_blocks[0].body.contains("truncated"));
        assert!(ctx.lifecycle_blocks[0].body.len() < big.len());
    }
}
