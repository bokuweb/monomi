//! End-to-end analysis pipeline shared by CLI and the feed daemon.
//!
//! Wraps the conventional Stage 1 → Stage 2 → merge sequence in one
//! function so that callers (`monomi-cli`, `monomi-feed`) don't have
//! to duplicate the choreography.

use chrono::Utc;
use monomi_core::{
    ArtifactId, Corpus, Ecosystem, FinalVerdict, LifecycleEntry, Manifest, RecommendedAction,
    RegistryMetadata, Stage1Result, Stage1Verdict, Stage2Result, Stage2Verdict, Status, Tarball,
    Verdict, VerdictSource, SCHEMA_VERSION,
};
use monomi_catalog::CatalogReader;
use monomi_llm::{build_context, Adjudicator, Stage2Context};
use monomi_rules::{default_corpus, default_ruleset, run, RULESET_VERSION};

pub mod diff;
pub mod history;

pub use diff::CapabilityDiffInput;
pub use history::DEFAULT_BASELINE_WINDOW;

#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    #[error("ecosystem: {0}")]
    Ecosystem(#[from] monomi_core::Error),
}

pub type Result<T> = std::result::Result<T, PipelineError>;

/// Run Stage 1 + Stage 2 + verdict-merge for a fetched tarball.
/// Backwards-compatible wrapper around `analyze_with_diff` with no
/// capability-diff baseline.
pub async fn analyze<E: Ecosystem>(
    eco: &E,
    tar: Tarball,
    adjudicator: &dyn Adjudicator,
) -> Result<Verdict> {
    analyze_with_diff(eco, tar, adjudicator, &CapabilityDiffInput::default()).await
}

/// Convenience wrapper that resolves the capability-diff baseline
/// against a catalog and then calls `analyze_with_diff`. The cost is
/// one extra `fetch_registry_metadata` call (the inner `analyze`
/// repeats it); refactoring `analyze` to accept a prefetched
/// manifest/registry is tracked in ISSUES.md.
pub async fn analyze_with_catalog<E: Ecosystem>(
    eco: &E,
    tar: Tarball,
    adjudicator: &dyn Adjudicator,
    catalog: &dyn CatalogReader,
    window: usize,
) -> Result<Verdict> {
    let manifest = eco.parse_manifest(&tar)?;
    let registry = eco
        .fetch_registry_metadata(&manifest.name, &manifest.version)
        .await
        .unwrap_or(None);
    let input = history::resolve(
        catalog,
        eco.id(),
        &manifest.name,
        &manifest.version,
        registry.as_ref(),
        window,
    )
    .await;
    analyze_with_diff(eco, tar, adjudicator, &input).await
}

/// Same as `analyze` but also runs the M8 capability-diff pass
/// against the provided baseline(s). Callers typically use
/// `history::resolve` to populate `diff_input` from a `CatalogReader`.
pub async fn analyze_with_diff<E: Ecosystem>(
    eco: &E,
    tar: Tarball,
    adjudicator: &dyn Adjudicator,
    diff_input: &CapabilityDiffInput,
) -> Result<Verdict> {
    let manifest = eco.parse_manifest(&tar)?;
    let lifecycle = eco.lifecycle_entrypoints(&tar, &manifest)?;
    let entries = eco.walk(&tar)?;
    let integrity = eco.integrity(&tar);
    let artifact = ArtifactId {
        ecosystem: eco.id(),
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        integrity,
    };

    // Best-effort registry metadata: ecosystem returns `None` if it
    // hasn't implemented `fetch_registry_metadata`, transport
    // failures degrade to `None` rather than aborting the scan.
    let registry = eco
        .fetch_registry_metadata(&manifest.name, &manifest.version)
        .await
        .unwrap_or_else(|e| {
            tracing::debug!("fetch_registry_metadata failed: {e}");
            None
        });

    let corpus: Corpus = default_corpus();
    let ctx = monomi_core::AnalysisCtx {
        artifact: &artifact,
        manifest: &manifest,
        lifecycle: &lifecycle,
        entries: &entries,
        diff: None,
        registry: registry.as_ref(),
        corpus: &corpus,
    };

    let rules = default_ruleset();
    let outcome = run(&rules, &ctx);
    let mut stage1 = outcome.stage1;

    // M8: capability-diff pass runs after rules so it sees the full
    // aggregated capability set. Pure function — all I/O already
    // happened in `history::resolve` upstream.
    diff::apply(&mut stage1, diff_input);

    let stage2 = maybe_stage2(
        adjudicator,
        &artifact,
        &manifest,
        &lifecycle,
        registry.as_ref(),
        &stage1,
    )
    .await;
    let final_verdict = merge(&stage1, stage2.as_ref());

    Ok(Verdict {
        schema_version: SCHEMA_VERSION,
        artifact,
        analyzed_at: Utc::now(),
        analyzer_version: env!("CARGO_PKG_VERSION").to_string(),
        ruleset_version: RULESET_VERSION.to_string(),
        stage1,
        stage2,
        final_verdict,
    })
}

async fn maybe_stage2(
    adj: &dyn Adjudicator,
    artifact: &ArtifactId,
    manifest: &Manifest,
    lifecycle: &[LifecycleEntry],
    registry: Option<&RegistryMetadata>,
    stage1: &Stage1Result,
) -> Option<Stage2Result> {
    if !should_invoke(stage1) {
        return None;
    }
    let context: Stage2Context = build_context(
        artifact.ecosystem,
        manifest,
        lifecycle,
        stage1,
        registry,
        Default::default(),
    );
    match adj.adjudicate(artifact, stage1, &context).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("stage 2 adjudication failed: {e}; falling back to Stage 1");
            None
        }
    }
}

/// Stage 2 invocation criteria.
///
/// We ask the LLM when *either*:
/// - Stage 1's verdict is `Suspicious` (mid-range — the model's
///   judgment is the deciding vote), OR
/// - any individual finding is marked `defers_to_stage2` (the
///   rule that fired explicitly wants a second opinion, even if
///   the overall verdict is Clean or Malicious).
///
/// We deliberately skip Stage 2 when:
/// - Stage 1 is `Clean` with zero findings — nothing to weigh; and
/// - Stage 1 is `Malicious` *and* every finding is decisive (the
///   evidence is already block-grade and the LLM cannot downgrade
///   a decisive finding below `Warn` anyway — see `merge`).
fn should_invoke(stage1: &Stage1Result) -> bool {
    matches!(stage1.verdict, Stage1Verdict::Suspicious)
        || stage1.findings.iter().any(|f| f.defers_to_stage2)
}

/// Merge logic — see architecture.md §"Two-stage pipeline".
///
/// - No Stage 2 result → Stage 1 alone decides.
/// - Stage 2 present  → Stage 2's recommended_action wins, but only if
///   its confidence is at least 0.5. Lower-confidence verdicts fall
///   back to Stage 1.
/// - **Safety rail**: Stage 2 cannot downgrade a decisive Stage 1 Block
///   below Warn. A hardcoded cloud-metadata IP doesn't stop being
///   suspicious just because the model thinks the rest looks fine.
pub fn merge(stage1: &Stage1Result, stage2: Option<&Stage2Result>) -> FinalVerdict {
    let stage1_status = match stage1.verdict {
        Stage1Verdict::Clean => Status::Clean,
        Stage1Verdict::Suspicious => Status::Warn,
        Stage1Verdict::Malicious => Status::Block,
    };
    let stage1_conf = match stage1.verdict {
        Stage1Verdict::Clean => 0.9,
        Stage1Verdict::Suspicious => 0.5,
        Stage1Verdict::Malicious => 0.85,
    };

    let Some(s2) = stage2 else {
        return FinalVerdict {
            status: stage1_status,
            confidence: stage1_conf,
            source: VerdictSource::Stage1,
        };
    };

    if s2.confidence < 0.5 {
        return FinalVerdict {
            status: stage1_status,
            confidence: stage1_conf,
            source: VerdictSource::Stage1,
        };
    }

    let s2_status = match s2.recommended_action {
        RecommendedAction::Allow => Status::Clean,
        RecommendedAction::Warn => Status::Warn,
        RecommendedAction::Block => Status::Block,
    };

    let final_status = match (stage1_status, s2_status) {
        (Status::Block, Status::Clean) => Status::Warn,
        (a, b) if rank(b) >= rank(a) => b,
        (a, _) => a,
    };

    FinalVerdict {
        status: final_status,
        confidence: s2.confidence,
        source: match (stage1.verdict, s2.verdict) {
            (Stage1Verdict::Clean, Stage2Verdict::Clean) => VerdictSource::Stage1,
            _ => VerdictSource::StageMerged,
        },
    }
}

fn rank(s: Status) -> u8 {
    match s {
        Status::Clean => 0,
        Status::Warn => 1,
        Status::Block => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s1(v: Stage1Verdict) -> Stage1Result {
        Stage1Result {
            findings: vec![],
            score: 0,
            verdict: v,
            capabilities: Default::default(),
            capabilities_complete: true,
            diff_outcome: None,
        }
    }

    fn s2(verdict: Stage2Verdict, action: RecommendedAction, conf: f32) -> Stage2Result {
        Stage2Result {
            model: "test".into(),
            verdict,
            confidence: conf,
            reasoning: String::new(),
            indicators: vec![],
            recommended_action: action,
            tokens_in: 0,
            tokens_out: 0,
        }
    }

    #[test]
    fn merge_without_stage2_uses_stage1() {
        let f = merge(&s1(Stage1Verdict::Suspicious), None);
        assert_eq!(f.status, Status::Warn);
        assert_eq!(f.source, VerdictSource::Stage1);
    }

    #[test]
    fn merge_low_confidence_stage2_is_ignored() {
        let f = merge(
            &s1(Stage1Verdict::Suspicious),
            Some(&s2(Stage2Verdict::Clean, RecommendedAction::Allow, 0.2)),
        );
        assert_eq!(f.status, Status::Warn);
        assert_eq!(f.source, VerdictSource::Stage1);
    }

    #[test]
    fn merge_stage2_can_upgrade_suspicious_to_block() {
        let f = merge(
            &s1(Stage1Verdict::Suspicious),
            Some(&s2(Stage2Verdict::Malicious, RecommendedAction::Block, 0.9)),
        );
        assert_eq!(f.status, Status::Block);
        assert_eq!(f.source, VerdictSource::StageMerged);
    }

    #[test]
    fn merge_stage2_cannot_downgrade_block_to_clean() {
        let f = merge(
            &s1(Stage1Verdict::Malicious),
            Some(&s2(Stage2Verdict::Clean, RecommendedAction::Allow, 0.95)),
        );
        assert_eq!(f.status, Status::Warn);
    }
}
