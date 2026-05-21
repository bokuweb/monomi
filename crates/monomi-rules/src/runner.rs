use monomi_core::{AnalysisCtx, CapabilitySet, Finding, Rule, Stage1Result, Stage1Verdict};

pub const RULESET_VERSION: &str = "0.1.0";

#[derive(Debug, Clone)]
pub struct RunOutcome {
    pub stage1: Stage1Result,
}

/// Run every applicable rule and aggregate into a Stage1Result.
///
/// Verdict heuristic (intentionally simple for V1; will tune):
/// - any decisive (`!defers_to_stage2`) Critical → Malicious
/// - score == 0                                  → Clean
/// - score ≥ 7 AND at least one decisive finding → Malicious
/// - score ≥ 7 with every finding deferring      → Suspicious
///   (Stage 2 is the arbiter; we accumulated weak signals but
///   none alone is conclusive, so we won't block on the sum)
/// - else                                        → Suspicious
pub fn run(rules: &[Box<dyn Rule>], ctx: &AnalysisCtx<'_>) -> RunOutcome {
    let mut findings: Vec<Finding> = Vec::new();
    for rule in rules {
        if !rule.applies_to(ctx.artifact.ecosystem) {
            continue;
        }
        findings.extend(rule.evaluate(ctx));
    }

    let score: u32 = findings.iter().map(|f| f.severity.weight()).sum();

    let has_decisive_critical = findings
        .iter()
        .any(|f| matches!(f.severity, monomi_core::Severity::Critical) && !f.defers_to_stage2);

    let has_decisive_any = findings
        .iter()
        .any(|f| !f.defers_to_stage2 && f.severity.weight() > 0);

    let verdict = if has_decisive_critical {
        Stage1Verdict::Malicious
    } else if score == 0 {
        Stage1Verdict::Clean
    } else if score >= 7 && has_decisive_any {
        Stage1Verdict::Malicious
    } else {
        Stage1Verdict::Suspicious
    };

    let capabilities: CapabilitySet = findings
        .iter()
        .flat_map(|f| f.capabilities.iter().copied())
        .collect();

    RunOutcome {
        stage1: Stage1Result {
            findings,
            score,
            verdict,
            capabilities,
            // M7+ analyzer: capabilities were actually computed.
            // The M8 diff pass keys off this to refuse to compare
            // against pre-M7 verdicts (where the field defaults to
            // `false` on deserialize).
            capabilities_complete: true,
            diff_outcome: None,
        },
    }
}
