//! Resolve `CapabilityDiffInput` from a `CatalogReader` + the
//! current `RegistryMetadata` (M8).
//!
//! Kept separate from `analyze` so the pipeline core stays pure
//! (input: tarball + baseline; no catalog I/O). The CLI / feed
//! daemon call this helper, then pass the result into `analyze`.

use chrono::{DateTime, Utc};
use monomi_catalog::CatalogReader;
use monomi_core::{
    BaselineStrategy, CapabilityBaseline, CapabilitySet, EcosystemId, RegistryMetadata, Verdict,
};

use crate::diff::CapabilityDiffInput;

/// Default recent-baseline window. Five versions is a balance between
/// catalog round-trips and surviving a single-version compromise
/// poisoning the immediate prior.
pub const DEFAULT_BASELINE_WINDOW: usize = 5;

/// Resolve baselines for `(eco, name, current_version)` against the
/// catalog. Never errors — every failure mode (no metadata, no prior
/// versions, no catalog hits, missing timestamps) degrades to "skip
/// the corresponding baseline" and the diff pass records the right
/// `DiffOutcome` from the resulting empty/partial input.
pub async fn resolve(
    catalog: &dyn CatalogReader,
    eco: EcosystemId,
    name: &str,
    current_version: &str,
    registry: Option<&RegistryMetadata>,
    window: usize,
) -> CapabilityDiffInput {
    let Some(registry) = registry else {
        return CapabilityDiffInput::default();
    };

    let prior = prior_versions(registry, current_version);
    if prior.is_empty() {
        return CapabilityDiffInput::default();
    }

    let immediate_prev_version = prior.last().cloned();

    // Fetch prior verdicts (latest -> oldest of the most recent window).
    let take = prior.iter().rev().take(window).cloned().collect::<Vec<_>>();
    let mut prior_verdicts: Vec<(String, Option<Verdict>)> = Vec::with_capacity(take.len());
    for v in &take {
        let r = catalog.lookup_by_nv(eco, name, v).await.ok().flatten();
        prior_verdicts.push((v.clone(), r));
    }

    let immediate_prev_status = prior_verdicts
        .first()
        .and_then(|(_, vd)| vd.as_ref().map(|v| v.stage1.verdict));

    let immediate_prev = prior_verdicts.first().and_then(|(version, vd)| {
        vd.as_ref().map(|v| CapabilityBaseline {
            strategy: BaselineStrategy::ImmediatePrev,
            capabilities: v.stage1.capabilities.clone(),
            versions: vec![version.clone()],
            complete: v.stage1.capabilities_complete,
        })
    });

    // Recent-union covers the full requested window. Mark
    // `complete = false` if any version inside the window was missing
    // a verdict OR contributed a pre-M7 (incomplete) verdict.
    let mut union_caps: CapabilitySet = CapabilitySet::new();
    let mut union_versions: Vec<String> = Vec::new();
    let mut union_complete = take.len() == window;
    for (version, vd) in &prior_verdicts {
        match vd {
            Some(v) => {
                if !v.stage1.capabilities_complete {
                    union_complete = false;
                }
                union_caps.extend(v.stage1.capabilities.iter().copied());
                union_versions.push(version.clone());
            }
            None => {
                union_complete = false;
            }
        }
    }
    // Preserve publish order (oldest → newest of window).
    union_versions.reverse();

    let recent_union = if union_versions.is_empty() {
        None
    } else {
        Some(CapabilityBaseline {
            strategy: BaselineStrategy::RecentUnion { window },
            capabilities: union_caps,
            versions: union_versions,
            complete: union_complete,
        })
    };

    // The lint here would otherwise flag the unused binding — it
    // documents the resolved-but-not-attached field for readers.
    let _ = immediate_prev_version;

    CapabilityDiffInput {
        immediate_prev,
        recent_union,
        immediate_prev_status,
    }
}

/// Publish-time-ordered list of versions strictly before
/// `current_version`. Tie-break on the version string so the order is
/// deterministic. Versions whose timestamp is missing are dropped,
/// EXCEPT the caller can still observe their absence via baseline
/// `complete = false` downstream.
///
/// Returns oldest → newest. Excludes `current_version` by exact
/// string match (NOT timestamp), so republished or otherwise
/// timestamp-weird rows for the current version don't silently
/// exclude the wrong baseline row.
fn prior_versions(registry: &RegistryMetadata, current_version: &str) -> Vec<String> {
    let mut rows: Vec<(DateTime<Utc>, String)> = registry
        .version_publish_times
        .iter()
        .filter(|(v, _)| v.as_str() != current_version)
        .map(|(v, t)| (*t, v.clone()))
        .collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    rows.into_iter().map(|(_, v)| v).collect()
}

/// Convenience: the helper returned by `resolve` can be turned into
/// the same shape regardless of which baseline(s) were resolved.
pub fn empty() -> CapabilityDiffInput {
    CapabilityDiffInput::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::collections::BTreeMap;

    fn ts(year: i32, month: u32, day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).unwrap()
    }

    #[test]
    fn prior_versions_excludes_current_and_sorts_by_publish_time() {
        let mut m: BTreeMap<String, DateTime<Utc>> = BTreeMap::new();
        m.insert("1.0.0".into(), ts(2025, 1, 1));
        m.insert("1.0.1".into(), ts(2025, 2, 1));
        m.insert("1.1.0".into(), ts(2025, 3, 1));
        // current = 1.0.2, published BETWEEN 1.0.1 and 1.1.0
        m.insert("1.0.2".into(), ts(2025, 2, 15));
        let reg = RegistryMetadata {
            version_publish_times: m,
            ..Default::default()
        };
        let out = prior_versions(&reg, "1.0.2");
        assert_eq!(out, vec!["1.0.0".to_string(), "1.0.1".into(), "1.1.0".into()]);
    }

    #[test]
    fn prior_versions_excludes_current_by_exact_string_match() {
        // Two rows share a timestamp; only the exact-string-matching
        // current row should be excluded.
        let mut m: BTreeMap<String, DateTime<Utc>> = BTreeMap::new();
        m.insert("1.0.0".into(), ts(2025, 1, 1));
        m.insert("1.0.0-rc.1".into(), ts(2025, 1, 1));
        let reg = RegistryMetadata {
            version_publish_times: m,
            ..Default::default()
        };
        let out = prior_versions(&reg, "1.0.0");
        assert_eq!(out, vec!["1.0.0-rc.1".to_string()]);
    }
}
