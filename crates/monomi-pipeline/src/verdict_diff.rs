//! Ad-hoc verdict-to-verdict diff for the `monomi diff` CLI.
//!
//! Distinct from `diff.rs` (which is the M8 capability-diff *rule*
//! that runs as part of `analyze` against catalog history). This
//! module is the user-facing comparison between two arbitrary
//! verdicts the user passed on the command line, e.g.
//! `monomi diff axios@1.6.0 axios@1.7.0`.
//!
//! Pure function — no IO, no concurrency. Serializable so the CLI
//! can emit it as JSON; renderable as text via the CLI layer.

use std::collections::{BTreeMap, BTreeSet};

use monomi_core::{Capability, Severity, Stage1Result, Stage1Verdict, Status, Verdict};
use serde::{Deserialize, Serialize};

/// Comparison between two verdicts. Each field is the *delta* —
/// items only present in one side, plus side-by-side scalars where
/// both sides have a value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictDiff {
    pub a: VerdictSide,
    pub b: VerdictSide,
    pub capabilities: CapabilityDiff,
    pub findings: FindingsDiff,
    pub stage1_verdict_changed: bool,
    pub final_status_changed: bool,
    pub score_delta: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictSide {
    pub name: String,
    pub version: String,
    pub stage1_verdict: Stage1Verdict,
    pub final_status: Status,
    pub score: u32,
    pub finding_count: usize,
    pub capability_count: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapabilityDiff {
    /// In `b` but not `a` — net-new exposure surface.
    pub introduced: Vec<Capability>,
    /// In `a` but not `b` — removed (often noise, occasionally
    /// suspicious if it looks like an attacker pruning detection
    /// signal).
    pub removed: Vec<Capability>,
    /// In both. Reported separately so the JSON consumer doesn't
    /// have to re-derive it.
    pub shared: Vec<Capability>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FindingsDiff {
    /// Rule IDs that fire in `b` but not in `a` (with the severity
    /// they fire at in `b`).
    pub added: Vec<RuleHit>,
    /// Rule IDs that fired in `a` but no longer in `b`.
    pub removed: Vec<RuleHit>,
    /// Rule IDs that fired in both, but the severity moved.
    pub severity_changes: Vec<SeverityChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleHit {
    pub rule_id: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityChange {
    pub rule_id: String,
    pub from: Severity,
    pub to: Severity,
}

/// Compute the verdict-to-verdict diff. Always succeeds — empty
/// diffs (when `a` and `b` are byte-identical) just produce
/// empty lists.
pub fn diff_verdicts(a: &Verdict, b: &Verdict) -> VerdictDiff {
    VerdictDiff {
        a: side(a),
        b: side(b),
        capabilities: diff_capabilities(&a.stage1, &b.stage1),
        findings: diff_findings(&a.stage1, &b.stage1),
        stage1_verdict_changed: a.stage1.verdict != b.stage1.verdict,
        final_status_changed: a.final_verdict.status != b.final_verdict.status,
        score_delta: i64::from(b.stage1.score) - i64::from(a.stage1.score),
    }
}

fn side(v: &Verdict) -> VerdictSide {
    VerdictSide {
        name: v.artifact.name.clone(),
        version: v.artifact.version.clone(),
        stage1_verdict: v.stage1.verdict,
        final_status: v.final_verdict.status,
        score: v.stage1.score,
        finding_count: v.stage1.findings.len(),
        capability_count: v.stage1.capabilities.len(),
    }
}

fn diff_capabilities(a: &Stage1Result, b: &Stage1Result) -> CapabilityDiff {
    let ac: &BTreeSet<Capability> = &a.capabilities;
    let bc: &BTreeSet<Capability> = &b.capabilities;
    CapabilityDiff {
        introduced: bc.difference(ac).copied().collect(),
        removed: ac.difference(bc).copied().collect(),
        shared: ac.intersection(bc).copied().collect(),
    }
}

fn diff_findings(a: &Stage1Result, b: &Stage1Result) -> FindingsDiff {
    // Strongest-severity hit per rule_id, on each side. Multiple
    // findings of the same rule_id at different sites get collapsed
    // — the rule either fires or it doesn't, severity-wise.
    let a_by_rule = group_by_rule(a);
    let b_by_rule = group_by_rule(b);

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut severity_changes = Vec::new();

    for (rule_id, sev_b) in &b_by_rule {
        match a_by_rule.get(rule_id) {
            None => added.push(RuleHit {
                rule_id: rule_id.clone(),
                severity: *sev_b,
            }),
            Some(sev_a) if sev_a != sev_b => severity_changes.push(SeverityChange {
                rule_id: rule_id.clone(),
                from: *sev_a,
                to: *sev_b,
            }),
            _ => {}
        }
    }
    for (rule_id, sev_a) in &a_by_rule {
        if !b_by_rule.contains_key(rule_id) {
            removed.push(RuleHit {
                rule_id: rule_id.clone(),
                severity: *sev_a,
            });
        }
    }
    FindingsDiff {
        added,
        removed,
        severity_changes,
    }
}

fn group_by_rule(s: &Stage1Result) -> BTreeMap<String, Severity> {
    let mut out: BTreeMap<String, Severity> = BTreeMap::new();
    for f in &s.findings {
        // Severity is `PartialOrd` via derive; keep the max so the
        // worst hit wins on each side.
        out.entry(f.rule_id.clone())
            .and_modify(|cur| {
                if f.severity > *cur {
                    *cur = f.severity;
                }
            })
            .or_insert(f.severity);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use monomi_core::{
        ArtifactId, Capability, Category, EcosystemId, FinalVerdict, Finding, HashAlgo, Integrity,
        Location, Severity, Stage1Verdict, Status, VerdictSource,
    };
    use std::collections::BTreeSet;

    fn integrity() -> Integrity {
        Integrity::from_bytes(HashAlgo::Sha512, b"x")
    }

    fn make_verdict(
        version: &str,
        findings: Vec<Finding>,
        caps: BTreeSet<Capability>,
        stage1: Stage1Verdict,
        status: Status,
    ) -> Verdict {
        let score = findings
            .iter()
            .map(|f| match f.severity {
                Severity::Info => 0,
                Severity::Low => 1,
                Severity::Medium => 5,
                Severity::High => 10,
                Severity::Critical => 25,
            })
            .sum();
        Verdict {
            schema_version: 1,
            artifact: ArtifactId {
                ecosystem: EcosystemId::Npm,
                name: "demo".into(),
                version: version.into(),
                integrity: integrity(),
            },
            analyzed_at: chrono::Utc::now(),
            analyzer_version: "test".into(),
            ruleset_version: "test".into(),
            stage1: Stage1Result {
                findings,
                score,
                verdict: stage1,
                capabilities: caps,
                capabilities_complete: true,
                diff_outcome: None,
            },
            stage2: None,
            final_verdict: FinalVerdict {
                status,
                confidence: 1.0,
                source: VerdictSource::Stage1,
            },
        }
    }

    fn finding(rule_id: &str, sev: Severity) -> Finding {
        Finding {
            rule_id: rule_id.into(),
            severity: sev,
            category: Category::LifecycleScript,
            locations: vec![Location {
                path: "x".into(),
                line_start: None,
                line_end: None,
            }],
            excerpt: None,
            message: "m".into(),
            defers_to_stage2: false,
            capabilities: BTreeSet::new(),
        }
    }

    #[test]
    fn introduced_capability_is_reported_as_b_only() {
        let a = make_verdict(
            "1.0.0",
            vec![],
            BTreeSet::from([Capability::LifecycleInstall]),
            Stage1Verdict::Clean,
            Status::Clean,
        );
        let b = make_verdict(
            "1.1.0",
            vec![],
            BTreeSet::from([Capability::LifecycleInstall, Capability::NetHttp]),
            Stage1Verdict::Clean,
            Status::Clean,
        );
        let d = diff_verdicts(&a, &b);
        assert_eq!(d.capabilities.introduced, vec![Capability::NetHttp]);
        assert!(d.capabilities.removed.is_empty());
        assert_eq!(
            d.capabilities.shared,
            vec![Capability::LifecycleInstall]
        );
    }

    #[test]
    fn rule_added_in_b_and_severity_bump_are_categorized() {
        let a = make_verdict(
            "1.0.0",
            vec![finding("NPM001", Severity::Info), finding("NPM002", Severity::Low)],
            BTreeSet::new(),
            Stage1Verdict::Suspicious,
            Status::Warn,
        );
        let b = make_verdict(
            "1.0.1",
            vec![
                finding("NPM001", Severity::Info),
                finding("NPM002", Severity::High), // severity bumped
                finding("NPM005", Severity::Critical), // new
            ],
            BTreeSet::new(),
            Stage1Verdict::Malicious,
            Status::Block,
        );
        let d = diff_verdicts(&a, &b);
        assert_eq!(d.findings.added.len(), 1);
        assert_eq!(d.findings.added[0].rule_id, "NPM005");
        assert!(d.findings.removed.is_empty());
        assert_eq!(d.findings.severity_changes.len(), 1);
        assert_eq!(d.findings.severity_changes[0].rule_id, "NPM002");
        assert!(d.stage1_verdict_changed);
        assert!(d.final_status_changed);
        assert!(d.score_delta > 0);
    }

    #[test]
    fn identical_verdicts_produce_empty_diff() {
        let a = make_verdict(
            "1.0.0",
            vec![finding("NPM001", Severity::Info)],
            BTreeSet::from([Capability::LifecycleInstall]),
            Stage1Verdict::Clean,
            Status::Clean,
        );
        let b = a.clone();
        let d = diff_verdicts(&a, &b);
        assert!(d.capabilities.introduced.is_empty());
        assert!(d.capabilities.removed.is_empty());
        assert!(d.findings.added.is_empty());
        assert!(d.findings.removed.is_empty());
        assert!(d.findings.severity_changes.is_empty());
        assert!(!d.stage1_verdict_changed);
        assert_eq!(d.score_delta, 0);
    }
}
