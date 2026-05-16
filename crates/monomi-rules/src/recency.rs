//! NPM016 — publish / maintainer-change recency.
//!
//! Flags two related but distinct signals:
//!
//! 1. **Brand-new package** — `package_created_at` is < N days old
//!    AND this is one of its first few versions. Newly-published
//!    packages are over-represented in malware (typosquats + fresh
//!    exfil dropships) and the proxy should surface them.
//! 2. **Newly-added maintainer published the version** — the version
//!    is < N days old AND `total_versions` is high (= established
//!    package). This is the "maintainer takeover" shape.
//!
//! Both are deferred to Stage 2 — they are *suggestive* signals
//! that compound with the rest, not standalone block-grade verdicts.

use chrono::{Duration, Utc};
use monomi_core::{AnalysisCtx, Category, EcosystemId, Finding, Location, Rule, Severity};

pub struct RecencySignals {
    pub fresh_package_max_age_days: i64,
    pub fresh_package_max_versions: u32,
    pub takeover_recent_version_max_age_days: i64,
    pub takeover_established_min_versions: u32,
}

impl Default for RecencySignals {
    fn default() -> Self {
        Self {
            fresh_package_max_age_days: 30,
            fresh_package_max_versions: 3,
            takeover_recent_version_max_age_days: 7,
            takeover_established_min_versions: 20,
        }
    }
}

impl Rule for RecencySignals {
    fn id(&self) -> &'static str {
        "NPM016"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        // Any ecosystem whose `Ecosystem::fetch_registry_metadata`
        // surfaces `package_created_at` + `total_versions` works
        // with this rule; npm and cargo do, others currently do not.
        matches!(eco, EcosystemId::Npm | EcosystemId::Cargo)
    }

    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        let Some(reg) = ctx.registry else {
            return Vec::new();
        };
        let now = Utc::now();
        let mut out = Vec::new();

        // 1. Brand-new package
        if let (Some(created), Some(total)) = (reg.package_created_at, reg.total_versions) {
            let age = now.signed_duration_since(created);
            if age < Duration::days(self.fresh_package_max_age_days)
                && total <= self.fresh_package_max_versions
            {
                out.push(Finding {
                    rule_id: "NPM016".into(),
                    severity: Severity::Medium,
                    category: Category::Maintainer,
                    locations: vec![Location {
                        path: "package.json".into(),
                        line_start: None,
                        line_end: None,
                    }],
                    excerpt: Some(format!(
                        "package_created_at = {} ({} days ago), total_versions = {}",
                        created,
                        age.num_days(),
                        total
                    )),
                    message: format!(
                        "brand-new package: created {} days ago with only {} version(s) total",
                        age.num_days(),
                        total
                    ),
                    defers_to_stage2: true,
                });
            }
        }

        // 2. Recently-published version on an established package
        // (= possible maintainer-takeover dropship).
        if let (Some(published), Some(total)) = (reg.published_at, reg.total_versions) {
            let age = now.signed_duration_since(published);
            if age < Duration::days(self.takeover_recent_version_max_age_days)
                && total >= self.takeover_established_min_versions
            {
                let by = reg.published_by.as_deref().unwrap_or("<unknown>");
                out.push(Finding {
                    rule_id: "NPM016".into(),
                    severity: Severity::High,
                    category: Category::Maintainer,
                    locations: vec![Location {
                        path: "package.json".into(),
                        line_start: None,
                        line_end: None,
                    }],
                    excerpt: Some(format!(
                        "published {} days ago by `{by}` (total_versions = {})",
                        age.num_days(),
                        total
                    )),
                    message: format!(
                        "established package ({} versions) shipped a version {} days ago — \
                         maintainer-takeover shape; LLM should weigh this with the rest",
                        total,
                        age.num_days()
                    ),
                    defers_to_stage2: true,
                });
            }
        }

        out
    }
}
