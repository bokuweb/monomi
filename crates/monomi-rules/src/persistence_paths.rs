use monomi_core::{AnalysisCtx, Category, EcosystemId, Finding, Location, Rule, Severity};
use once_cell::sync::Lazy;
use regex::Regex;

/// NPM008 — string literal referencing a path used for OS-level
/// persistence or credential reads. There is no legitimate reason
/// for a published npm package to embed any of these.
pub struct PersistencePathLiteral;

static PATH_RE: Lazy<Regex> = Lazy::new(|| {
    // Anchor each alternative so we do not match incidental words.
    // The leading `(?:~|/)` covers both `~/.ssh/...` literals and
    // `homedir() + '/.ssh/...'` style concatenations where the
    // surfaced literal starts with `/`.
    Regex::new(
        r"(?x)
            (?:~|/)\.ssh/(?:authorized_keys|id_[a-z]+|config|known_hosts)
          | (?:~|/)\.aws/(?:credentials|config)
          | (?:~|/)\.npmrc\b
          | (?:~|/)\.netrc\b
          | (?:~|/)Library/Launch(?:Agents|Daemons)\b
          | /Library/Launch(?:Agents|Daemons)\b
          | (?:~|/)\.config/systemd/user\b
          | /etc/systemd/system\b
          | /etc/cron(?:\.[a-z]+|tab)\b
          | /var/spool/cron\b
          | (?:~|/)\.bashrc\b
          | (?:~|/)\.zshrc\b
          | (?:~|/)\.profile\b
        ",
    )
    .expect("PATH_RE")
});

impl Rule for PersistencePathLiteral {
    fn id(&self) -> &'static str {
        "NPM008"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(
            eco,
            EcosystemId::Npm | EcosystemId::Cargo | EcosystemId::Pypi | EcosystemId::Nuget
        )
    }

    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for entry in ctx.entries {
            if !entry.kind.is_scannable_source() {
                continue;
            }
            let Some(text) = entry.text() else { continue };
            if let Some(m) = PATH_RE.find(text) {
                out.push(make_finding(entry.path.clone(), m.as_str().to_string()));
            }
        }
        for life in ctx.lifecycle {
            if let Some(m) = PATH_RE.find(&life.body) {
                out.push(make_finding(
                    format!("package.json#scripts.{}", life.name),
                    m.as_str().to_string(),
                ));
            }
        }
        out
    }
}

fn make_finding(path: String, hit: String) -> Finding {
    // Legitimate libraries embed these paths (requests reads
    // `~/.netrc`, AWS SDKs read `~/.aws/credentials`, paramiko
    // touches `~/.ssh/`, etc.) so the literal alone is suggestive
    // but not decisive. Stage 2 looks at *how* the path is used.
    Finding {
        rule_id: "NPM008".into(),
        severity: Severity::High,
        category: Category::Persistence,
        locations: vec![Location {
            path,
            line_start: None,
            line_end: None,
        }],
        excerpt: Some(hit.clone()),
        message: format!("sensitive-path literal `{hit}` (persistence / credential pattern)"),
        defers_to_stage2: true,
    }
}
