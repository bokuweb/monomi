//! NPM011 — CI / registry token theft pattern.
//!
//! Targets the credential-stealer family driven by stolen
//! maintainer tokens (Shai-Hulud lineage). A published package
//! reading `NPM_TOKEN` / `GITHUB_TOKEN` / `.npmrc _authToken` /
//! `~/.docker/config.json` is essentially never legitimate.
//!
//! In **install-time lifecycle** body: decisive Critical (Block).
//! In **regular source**: High + defer to Stage 2 (a legitimate
//! CI helper library can read these in *its* runtime by design).

use monomi_core::{Capability, AnalysisCtx, Category, EcosystemId, Finding, LifecycleKind, Location, Rule, Severity,};
use once_cell::sync::Lazy;
use regex::Regex;

pub struct CiTokenTheft;

static TOKEN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
            \bprocess\s*\.\s*env\s*\.\s*(?:
                NPM_TOKEN
              | NODE_AUTH_TOKEN
              | GITHUB_TOKEN
              | GH_TOKEN
              | NPM_AUTH
              | NPM_CONFIG_AUTH(?:_TOKEN)?
              | CI_JOB_TOKEN
              | GITLAB_TOKEN
              | CIRCLECI_TOKEN
              | CODECOV_TOKEN
              | DOCKER_PASSWORD
              | DOCKER_AUTH
              | AWS_ACCESS_KEY_ID
              | AWS_SECRET_ACCESS_KEY
              | AWS_SESSION_TOKEN
              | GOOGLE_APPLICATION_CREDENTIALS
              | GCP_SERVICE_ACCOUNT_KEY
            )\b
          | \bprocess\s*\.\s*env\s*\[\s*['"](?:
                NPM_TOKEN
              | NODE_AUTH_TOKEN
              | GITHUB_TOKEN
              | GH_TOKEN
              | NPM_AUTH
              | AWS_ACCESS_KEY_ID
              | AWS_SECRET_ACCESS_KEY
            )['"]\s*\]
          | \b_authToken\s*=
          | \bnpm\s+config\s+get\s+_authToken\b
          | (?:^|/)\.npmrc[^a-zA-Z0-9_]
          | (?:^|/)\.docker/config\.json\b
          | (?:^|/)\.git-credentials\b
        "#,
    )
    .expect("TOKEN_RE")
});

impl Rule for CiTokenTheft {
    fn id(&self) -> &'static str {
        "NPM011"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(eco, EcosystemId::Npm)
    }

    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        // Lifecycle reads are unambiguous — there is no legitimate
        // postinstall use for NPM_TOKEN / GITHUB_TOKEN.
        for life in ctx.lifecycle {
            if !matches!(life.kind, LifecycleKind::InstallTime) {
                continue;
            }
            if let Some(m) = TOKEN_RE.find(&life.body) {
                out.push(Finding {
                    rule_id: "NPM011".into(),
                    severity: Severity::Critical,
                    category: Category::Exfil,
                    locations: vec![Location {
                        path: format!("package.json#scripts.{}", life.name),
                        line_start: None,
                        line_end: None,
                    }],
                    excerpt: Some(m.as_str().to_string()),
                    message: format!(
                        "install-time read of credential env / file `{}` — \
                         token-theft pattern (no legitimate use)",
                        m.as_str()
                    ),
                    defers_to_stage2: false,
                    capabilities: [Capability::EnvSecretLookup, Capability::InstallTimeNetwork, Capability::LifecycleInstall].into_iter().collect(),
                });
            }
        }
        // Same pattern in normal source is suspicious but a CI
        // helper library can read these by design; defer.
        for entry in ctx.entries {
            if !entry.kind.is_scannable_source() {
                continue;
            }
            let Some(text) = entry.text() else { continue };
            if let Some(m) = TOKEN_RE.find(text) {
                out.push(Finding {
                    rule_id: "NPM011".into(),
                    severity: Severity::High,
                    category: Category::Exfil,
                    locations: vec![Location {
                        path: entry.path.clone(),
                        line_start: None,
                        line_end: None,
                    }],
                    excerpt: Some(m.as_str().to_string()),
                    message: format!("read of credential env / file `{}`", m.as_str()),
                    defers_to_stage2: true,
                    capabilities: [Capability::EnvSecretLookup].into_iter().collect(),
                });
            }
        }
        out
    }
}
