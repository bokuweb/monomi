use monomi_core::{AnalysisCtx, Category, EcosystemId, Finding, Location, Rule, Severity};
use once_cell::sync::Lazy;
use regex::Regex;

/// NPM007 — hostname literal pointing at a well-known exfil /
/// out-of-band-callback endpoint (webhook.site, oast.fun, Discord
/// webhooks, paste services, transfer.sh, etc).
///
/// These services are not inherently malicious, but no legitimate
/// published npm package embeds a webhook.site URL at install or
/// import time.
pub struct KnownExfilEndpoint;

static EXFIL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?x)
            (?:^|[^A-Za-z0-9_.-])(
                webhook\.site
              | oast\.(?:fun|live|me|site|pro|online)
              | requestbin\.(?:com|net)
              | pipedream\.net
              | beeceptor\.com
              | hookbin\.com
              | hookb\.in
              | interact\.sh
              | burpcollaborator\.net
              | canarytokens\.com
              | transfer\.sh
              | termbin\.com
              | dpaste\.(?:com|org)
              | pastebin\.com
              | ix\.io
              | discord\.com/api/webhooks
              | discordapp\.com/api/webhooks
              | hooks\.slack\.com/services
              | api\.telegram\.org/bot
            )(?:[^A-Za-z0-9_.-]|$)
        ",
    )
    .expect("EXFIL_RE")
});

impl Rule for KnownExfilEndpoint {
    fn id(&self) -> &'static str {
        "NPM007"
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
            if let Some(c) = EXFIL_RE.captures(text) {
                let host = c.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
                out.push(make_finding(entry.path.clone(), host));
            }
        }
        for life in ctx.lifecycle {
            if let Some(c) = EXFIL_RE.captures(&life.body) {
                let host = c.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
                out.push(make_finding(
                    format!("package.json#scripts.{}", life.name),
                    host,
                ));
            }
        }
        out
    }
}

fn make_finding(path: String, host: String) -> Finding {
    Finding {
        rule_id: "NPM007".into(),
        severity: Severity::Critical,
        category: Category::Exfil,
        locations: vec![Location {
            path,
            line_start: None,
            line_end: None,
        }],
        excerpt: Some(host.clone()),
        message: format!("known exfil / OOB-callback endpoint `{host}`"),
        defers_to_stage2: false,
    }
}
