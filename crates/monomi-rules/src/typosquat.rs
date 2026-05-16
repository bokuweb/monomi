//! NPM014 — typosquat candidate.
//!
//! Flags packages whose name is within Levenshtein edit distance ≤ 2
//! of a popular npm name (per the bundled top-N corpus), is *not*
//! itself in the corpus, and was published recently.
//!
//! The "recently" half is best-effort: when the analyzer has a
//! `RegistryMetadata.package_created_at` newer than 90 days the rule
//! fires; when the metadata is absent (offline scan) the rule still
//! fires on the name match alone so it remains useful without
//! network access.

use chrono::{Duration, Utc};
use monomi_core::{AnalysisCtx, Category, EcosystemId, Finding, Location, Rule, Severity};

pub struct TyposquatCandidate {
    pub max_distance: usize,
    pub max_age_days: i64,
}

impl Default for TyposquatCandidate {
    fn default() -> Self {
        Self {
            max_distance: 2,
            max_age_days: 90,
        }
    }
}

impl Rule for TyposquatCandidate {
    fn id(&self) -> &'static str {
        "NPM014"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(eco, EcosystemId::Npm)
    }

    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        let name = ctx.artifact.name.to_ascii_lowercase();
        let corpus = ctx.corpus;
        if corpus.top_packages.is_empty() {
            return Vec::new();
        }
        // If we ARE the popular package, by definition not a
        // typosquat. Compare lowercased to match npm normalization.
        if corpus
            .top_packages
            .iter()
            .any(|p| p.eq_ignore_ascii_case(&name))
        {
            return Vec::new();
        }

        // Find the closest popular name within `max_distance`.
        let mut best: Option<(usize, &str)> = None;
        for top in &corpus.top_packages {
            let top_l = top.to_ascii_lowercase();
            // Skip if length differs by more than max_distance — the
            // distance can't be lower than the length difference.
            let len_diff = name.len().abs_diff(top_l.len());
            if len_diff > self.max_distance {
                continue;
            }
            let d = levenshtein(&name, &top_l, self.max_distance);
            if d == 0 || d > self.max_distance {
                continue;
            }
            match best {
                None => best = Some((d, top.as_str())),
                Some((bd, _)) if d < bd => best = Some((d, top.as_str())),
                _ => {}
            }
        }
        let Some((distance, target)) = best else {
            return Vec::new();
        };

        // Recency gate: only escalate if the package is newish or
        // metadata is absent (offline).
        let is_recent = match ctx.registry.and_then(|r| r.package_created_at) {
            None => true, // offline / unknown → don't suppress
            Some(created) => {
                Utc::now().signed_duration_since(created) < Duration::days(self.max_age_days)
            }
        };
        if !is_recent {
            return Vec::new();
        }

        vec![Finding {
            rule_id: "NPM014".into(),
            severity: Severity::High,
            category: Category::Typosquat,
            locations: vec![Location {
                path: "package.json".into(),
                line_start: None,
                line_end: None,
            }],
            excerpt: Some(format!("{} ~= {} (distance {})", name, target, distance)),
            message: format!(
                "name `{name}` is within edit distance {distance} of popular package `{target}` \
                 (typosquat candidate)"
            ),
            defers_to_stage2: true,
        }]
    }
}

/// Bounded Levenshtein: returns `max + 1` early if it can prove the
/// distance is larger than `max`. ~5× faster than full DP for our
/// corpus traversal because most candidates short-circuit.
fn levenshtein(a: &str, b: &str, max: usize) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let n = a.len();
    let m = b.len();
    if n == 0 {
        return m;
    }
    if m == 0 {
        return n;
    }
    if n.abs_diff(m) > max {
        return max + 1;
    }

    let mut prev: Vec<usize> = (0..=m).collect();
    let mut curr: Vec<usize> = vec![0; m + 1];

    for i in 1..=n {
        curr[0] = i;
        let mut row_min = curr[0];
        for j in 1..=m {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
            row_min = row_min.min(curr[j]);
        }
        if row_min > max {
            return max + 1;
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[m]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levenshtein_basics() {
        assert_eq!(levenshtein("react", "react", 2), 0);
        assert_eq!(levenshtein("react", "reactt", 2), 1);
        assert_eq!(levenshtein("react", "reaktt", 2), 2);
        // Bounded: way over → returns max+1
        assert_eq!(levenshtein("react", "babel-loader", 2), 3);
    }
}
