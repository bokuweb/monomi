//! `NPM041` — dataflow-lite token taint.
//!
//! `NPM011` matches *literal* env reads (`process.env.NPM_TOKEN`).
//! Real Shai-Hulud-family payloads now hide the literal:
//!
//! - `const env = process.env; post(env.NPM_TOKEN);`
//! - `const {NPM_TOKEN: t, ...rest} = process.env; leak(t);`
//! - `for (const k in process.env) { send(process.env[k]); }`
//! - `fetch(url, { body: JSON.stringify(process.env) });`
//! - `process.env['NPM_' + 'TOKEN']`
//!
//! This rule looks for a *bulk* `process.env` consumer — anything
//! that grabs the whole object, enumerates keys, or aliases it —
//! AND a network / process-spawn sink in the same file. The
//! combination is what makes the FP rate manageable: a library
//! that just enumerates `process.env` for config (dotenv-style)
//! without networking is fine, and a library that uses `fetch`
//! without reading env in bulk is fine. Both together is the
//! actual exfil shape.
//!
//! In an install-time lifecycle the same shape is upgraded to
//! Critical + decisive.

use monomi_core::{
    AnalysisCtx, Capability, Category, EcosystemId, EntryKind, Finding, LifecycleKind, Location,
    Rule, Severity,
};
use once_cell::sync::Lazy;
use regex::Regex;

pub struct EnvExfilFlow;

/// "Bulk" or "indirect" `process.env` consumers. Note that
/// `process.env.NAME` (literal property access) is intentionally
/// *not* here — that's NPM011's job. We want everything *else*.
static BULK_ENV_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
            \bObject\s*\.\s*(?:keys|entries|values|assign|fromEntries)\s*\(\s*process\s*\.\s*env\b
          | \bJSON\s*\.\s*stringify\s*\(\s*process\s*\.\s*env\b
          | \.\.\.\s*process\s*\.\s*env\b
          | \bfor\s*\(\s*(?:const|let|var)\s+\w+\s+(?:in|of)\s+(?:Object\s*\.\s*\w+\s*\(\s*)?process\s*\.\s*env\b
          | \b(?:const|let|var)\s+\{[^}]*\}\s*=\s*process\s*\.\s*env\b
          | \b(?:const|let|var)\s+\w+\s*=\s*process\s*\.\s*env\s*[;,\n]
          | \bprocess\s*\.\s*env\s*\[\s*[^'"\s\]]
          | \bprocess\s*\.\s*env\s*\[\s*['"][^'"]*['"]\s*\+
          | \bprocess\s*\.\s*env\s*\[\s*[^'"]*\+
        "#,
    )
    .expect("BULK_ENV_RE")
});

/// Network / exec / DNS sinks. Same set used by other capability
/// rules; kept local so this rule is self-contained.
static SINK_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
            \bfetch\s*\(
          | \brequire\s*\(\s*['"](?:node-fetch|axios|got|undici|superagent|request|node:https?|https?)['"]\s*\)
          | \bimport\s*\(\s*['"](?:node-fetch|axios|got|undici)['"]\s*\)
          | \bhttps?\s*\.\s*(?:request|get)\s*\(
          | \baxios\s*[.(]
          | \bgot\s*[.(]
          | \bnew\s+XMLHttpRequest\s*\(
          | \bnew\s+WebSocket\s*\(
          | \bchild_process\s*\.\s*(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\(
          | \brequire\s*\(\s*['"]child_process['"]\s*\)
          | \bimport\s*\(\s*['"]child_process['"]\s*\)
          | \bimport\s+\w+\s+from\s+['"]child_process['"]
          | \bnet\s*\.\s*(?:Socket|connect|createConnection)\s*\(
          | \bdgram\s*\.\s*createSocket\s*\(
          | \bdns\s*\.\s*(?:lookup|resolve|resolveTxt)\s*\(
        "#,
    )
    .expect("SINK_RE")
});

impl Rule for EnvExfilFlow {
    fn id(&self) -> &'static str {
        "NPM041"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(eco, EcosystemId::Npm)
    }

    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        let mut out = Vec::new();

        // Lifecycle bodies: same-body bulk-env + sink is decisive.
        for life in ctx.lifecycle {
            if !matches!(life.kind, LifecycleKind::InstallTime) {
                continue;
            }
            let Some(env_m) = BULK_ENV_RE.find(&life.body) else {
                continue;
            };
            let Some(sink_m) = SINK_RE.find(&life.body) else {
                continue;
            };
            out.push(Finding {
                rule_id: "NPM041".into(),
                severity: Severity::Critical,
                category: Category::Exfil,
                locations: vec![Location {
                    path: format!("package.json#scripts.{}", life.name),
                    line_start: None,
                    line_end: None,
                }],
                excerpt: Some(format!("{} … {}", env_m.as_str(), sink_m.as_str())),
                message: "install-time script bulk-reads `process.env` and uses a \
                          network/exec sink in the same body — token exfil shape \
                          (Shai-Hulud lineage)"
                    .into(),
                defers_to_stage2: false,
                capabilities: [
                    Capability::EnvBulkEnum,
                    Capability::EnvSecretLookup,
                    Capability::InstallTimeNetwork,
                    Capability::LifecycleInstall,
                ]
                .into_iter()
                .collect(),
            });
        }

        // Regular source: same-file bulk-env + sink. Defers to
        // Stage 2 — a CI helper / logger library has legitimate
        // reasons to read process.env and send telemetry; the LLM
        // is in a better position to judge intent than a regex.
        for entry in ctx.entries {
            if !matches!(entry.kind, EntryKind::JsSource | EntryKind::Text) {
                continue;
            }
            let Some(text) = entry.text() else { continue };
            let Some(env_m) = BULK_ENV_RE.find(text) else {
                continue;
            };
            let Some(sink_m) = SINK_RE.find(text) else {
                continue;
            };
            out.push(Finding {
                rule_id: "NPM041".into(),
                severity: Severity::High,
                category: Category::Exfil,
                locations: vec![Location {
                    path: entry.path.clone(),
                    line_start: None,
                    line_end: None,
                }],
                excerpt: Some(format!("{} … {}", env_m.as_str(), sink_m.as_str())),
                message: "bulk `process.env` read paired with a network/exec sink \
                          in the same file — possible token exfil"
                    .into(),
                defers_to_stage2: true,
                capabilities: [Capability::EnvBulkEnum, Capability::EnvSecretLookup]
                    .into_iter()
                    .collect(),
            });
        }

        out
    }
}
