//! Post-Stage1 capability-diff pass (`NPM030`, M8).
//!
//! This is *not* a `Rule` — rules emit capabilities, and a rule that
//! reads the aggregated `CapabilitySet` would have ordering problems
//! with the rules that contribute to it. Instead the diff pass runs
//! after `monomi_rules::run` has produced the full `Stage1Result`,
//! and appends `Finding`s of its own.
//!
//! Decisive subset is intentionally narrow — see
//! `Capability::is_decisive_on_introduction` and codex review notes
//! in `ISSUES.md`.

use monomi_core::{
    Capability, CapabilityBaseline, Category, DiffOutcome, Finding, Location, Severity,
    Stage1Result, Stage1Verdict,
};
#[cfg(test)]
use monomi_core::BaselineStrategy;

/// Baselines available to the diff pass. Both fields are optional —
/// the caller passes whichever it was able to resolve from the
/// catalog. If both are `None` the pass records `NotAttempted` and
/// exits cleanly.
#[derive(Debug, Clone, Default)]
pub struct CapabilityDiffInput {
    pub immediate_prev: Option<CapabilityBaseline>,
    pub recent_union: Option<CapabilityBaseline>,
    /// Stage1 verdict of the *immediate previous* version, if known.
    /// Used to abstain when the baseline was itself malicious — a
    /// diff against a poisoned baseline manufactures false negatives
    /// (everything looks "unchanged").
    pub immediate_prev_status: Option<Stage1Verdict>,
}

/// Run the capability-diff pass and mutate `stage1` in place:
/// - appends one `Finding` per newly-introduced capability
/// - bumps `score` accordingly
/// - sets `diff_outcome`
/// - re-derives `verdict` if a decisive Critical was added
pub fn apply(stage1: &mut Stage1Result, input: &CapabilityDiffInput) {
    let outcome = compute(stage1, input);
    if let DiffOutcome::Produced {
        ref introduced, ..
    } = outcome
    {
        for cap in introduced {
            let finding = finding_for_introduced(*cap, &outcome);
            stage1.score = stage1.score.saturating_add(finding.severity.weight());
            // Only escalate to Malicious on a *decisive* introduction;
            // defer-tagged findings let Stage 2 weigh in.
            if matches!(finding.severity, Severity::Critical) && !finding.defers_to_stage2 {
                stage1.verdict = Stage1Verdict::Malicious;
            } else if matches!(stage1.verdict, Stage1Verdict::Clean) {
                stage1.verdict = Stage1Verdict::Suspicious;
            }
            stage1.findings.push(finding);
        }
    }
    stage1.diff_outcome = Some(outcome);
}

fn compute(stage1: &Stage1Result, input: &CapabilityDiffInput) -> DiffOutcome {
    // Abstain if the prior version was itself malicious — diffing
    // against a poisoned baseline produces meaningless results.
    if matches!(input.immediate_prev_status, Some(Stage1Verdict::Malicious)) {
        return DiffOutcome::AbstainedPoisonedBaseline {
            prev_status: Stage1Verdict::Malicious,
        };
    }

    // Both baselines must be complete to trust the diff. An
    // incomplete baseline (missing prior verdicts, pre-M7 verdicts)
    // would manufacture false positives.
    let baseline = match preferred_baseline(input) {
        None => return DiffOutcome::NotAttempted,
        Some(b) if !b.complete => return DiffOutcome::AbstainedBaselineIncomplete,
        Some(b) => b,
    };

    let introduced: Vec<Capability> = stage1
        .capabilities
        .difference(&baseline.capabilities)
        .copied()
        .collect();

    if introduced.is_empty() {
        // Still record the attempt — telemetry needs to distinguish
        // "ran and produced nothing" from "didn't run".
        return DiffOutcome::Produced {
            introduced: vec![],
            baseline_versions: baseline.versions.clone(),
        };
    }

    DiffOutcome::Produced {
        introduced,
        baseline_versions: baseline.versions.clone(),
    }
}

/// Prefer `recent_union` (higher-precision — capability absent from
/// *every* recent version) and fall back to `immediate_prev`. The
/// caller may supply either or both.
fn preferred_baseline(input: &CapabilityDiffInput) -> Option<&CapabilityBaseline> {
    input
        .recent_union
        .as_ref()
        .or(input.immediate_prev.as_ref())
}

fn finding_for_introduced(cap: Capability, outcome: &DiffOutcome) -> Finding {
    let (severity, defers) = if cap.is_decisive_on_introduction() {
        (Severity::Critical, false)
    } else {
        (Severity::High, true)
    };

    let baseline_versions = match outcome {
        DiffOutcome::Produced {
            baseline_versions, ..
        } => baseline_versions.clone(),
        _ => vec![],
    };

    let baseline_str = if baseline_versions.is_empty() {
        "(unknown)".to_string()
    } else {
        baseline_versions.join(", ")
    };

    Finding {
        rule_id: "NPM030".into(),
        severity,
        category: Category::Diff,
        locations: vec![Location {
            path: format!("capability:{:?}", cap),
            line_start: None,
            line_end: None,
        }],
        excerpt: None,
        message: format!(
            "capability `{:?}` is newly introduced in this version vs baseline ({})",
            cap, baseline_str,
        ),
        defers_to_stage2: defers,
        capabilities: [cap].into_iter().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use monomi_core::CapabilitySet;

    fn baseline(caps: &[Capability], complete: bool, strategy: BaselineStrategy) -> CapabilityBaseline {
        CapabilityBaseline {
            strategy,
            capabilities: caps.iter().copied().collect(),
            versions: vec!["1.0.0".into(), "1.0.1".into()],
            complete,
        }
    }

    fn stage1(caps: &[Capability]) -> Stage1Result {
        Stage1Result {
            findings: vec![],
            score: 0,
            verdict: Stage1Verdict::Clean,
            capabilities: caps.iter().copied().collect(),
            capabilities_complete: true,
            diff_outcome: None,
        }
    }

    #[test]
    fn no_input_records_not_attempted() {
        let mut s = stage1(&[Capability::LifecycleInstall]);
        apply(&mut s, &CapabilityDiffInput::default());
        assert!(matches!(s.diff_outcome, Some(DiffOutcome::NotAttempted)));
        assert!(s.findings.is_empty());
        assert_eq!(s.verdict, Stage1Verdict::Clean);
    }

    #[test]
    fn incomplete_baseline_abstains() {
        let mut s = stage1(&[Capability::SelfDelete]);
        let input = CapabilityDiffInput {
            recent_union: Some(baseline(
                &[],
                /*complete=*/ false,
                BaselineStrategy::RecentUnion { window: 5 },
            )),
            ..Default::default()
        };
        apply(&mut s, &input);
        assert!(matches!(
            s.diff_outcome,
            Some(DiffOutcome::AbstainedBaselineIncomplete)
        ));
        assert!(s.findings.is_empty());
    }

    #[test]
    fn poisoned_baseline_abstains() {
        let mut s = stage1(&[Capability::SelfDelete]);
        let input = CapabilityDiffInput {
            immediate_prev: Some(baseline(
                &[],
                true,
                BaselineStrategy::ImmediatePrev,
            )),
            immediate_prev_status: Some(Stage1Verdict::Malicious),
            ..Default::default()
        };
        apply(&mut s, &input);
        assert!(matches!(
            s.diff_outcome,
            Some(DiffOutcome::AbstainedPoisonedBaseline { .. })
        ));
        assert!(s.findings.is_empty());
    }

    #[test]
    fn decisive_capability_newly_introduced_blocks() {
        // Clean baseline → current adds SelfDelete (decisive) →
        // verdict escalates to Malicious with one NPM030 finding.
        let mut s = stage1(&[Capability::SelfDelete, Capability::FsRead]);
        let input = CapabilityDiffInput {
            recent_union: Some(baseline(
                &[Capability::FsRead],
                true,
                BaselineStrategy::RecentUnion { window: 5 },
            )),
            ..Default::default()
        };
        apply(&mut s, &input);
        assert_eq!(s.findings.len(), 1);
        assert_eq!(s.findings[0].rule_id, "NPM030");
        assert_eq!(s.findings[0].severity, Severity::Critical);
        assert!(!s.findings[0].defers_to_stage2);
        assert_eq!(s.verdict, Stage1Verdict::Malicious);
    }

    #[test]
    fn non_decisive_capability_introduction_defers() {
        // NetHttp is *not* in the decisive set — adding it triggers
        // High+defer so Stage 2 reviews. node-gyp/prebuild legitimately
        // adds outbound fetches.
        let mut s = stage1(&[Capability::NetHttp]);
        let input = CapabilityDiffInput {
            recent_union: Some(baseline(
                &[],
                true,
                BaselineStrategy::RecentUnion { window: 5 },
            )),
            ..Default::default()
        };
        apply(&mut s, &input);
        assert_eq!(s.findings.len(), 1);
        assert_eq!(s.findings[0].severity, Severity::High);
        assert!(s.findings[0].defers_to_stage2);
    }

    #[test]
    fn no_new_capabilities_produces_empty_finding_set() {
        let mut s = stage1(&[Capability::NetHttp]);
        let input = CapabilityDiffInput {
            recent_union: Some(baseline(
                &[Capability::NetHttp, Capability::LifecycleInstall],
                true,
                BaselineStrategy::RecentUnion { window: 5 },
            )),
            ..Default::default()
        };
        apply(&mut s, &input);
        assert!(s.findings.is_empty());
        match s.diff_outcome {
            Some(DiffOutcome::Produced { ref introduced, .. }) => {
                assert!(introduced.is_empty());
            }
            other => panic!("expected Produced{{introduced:[]}}, got {:?}", other),
        }
    }

    #[test]
    fn recent_union_preferred_over_immediate_prev() {
        // Adversary publishes recently-clean immediate prev but
        // recent_union still shows the cap was absent earlier — the
        // recent_union should still apply, NOT immediate_prev.
        let mut s = stage1(&[Capability::SelfDelete]);
        let input = CapabilityDiffInput {
            immediate_prev: Some(baseline(
                &[Capability::SelfDelete],
                true,
                BaselineStrategy::ImmediatePrev,
            )),
            recent_union: Some(baseline(
                &[],
                true,
                BaselineStrategy::RecentUnion { window: 5 },
            )),
            ..Default::default()
        };
        apply(&mut s, &input);
        assert_eq!(s.findings.len(), 1, "recent_union should win");
    }

    // Suppress unused-let-binding warning emitted for the helper.
    #[allow(dead_code)]
    fn _used(s: CapabilitySet) -> usize {
        s.len()
    }
}
