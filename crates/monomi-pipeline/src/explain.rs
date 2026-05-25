//! Human-readable narrative rendering for a `Verdict`.
//!
//! The output is what `monomi explain <integrity>` and (eventually)
//! `sakimori` step summaries show — "why was this version blocked?"
//! in a form a release engineer can read in five seconds.
//!
//! # Why this lives here, not as `Display` on `Verdict`
//!
//! Three reasons:
//! - Some narrative content (reference incidents, recommended
//!   action language) is policy, not data. It evolves independently
//!   of the verdict schema.
//! - Renderers may want HTML / Slack mrkdwn / plain text from the
//!   same inputs.
//! - The `RULE_NARRATIVES` table is the place we surface our
//!   "explainable" differentiator vs Socket/Snyk — their reasoning
//!   is proprietary; ours is checked into the repo and citable in
//!   audits.

use std::collections::HashMap;
use std::sync::OnceLock;

use monomi_core::{Finding, Stage1Verdict, Status, Verdict};

/// Static narrative for a rule — what it means, what historical
/// incident motivated it, and what a maintainer should do when it
/// fires. Optional per-rule; rules without an entry fall back to
/// the `Finding::message` from Stage 1.
pub struct RuleNarrative {
    pub title: &'static str,
    /// One-paragraph plain-language description of the threat shape.
    pub what: &'static str,
    /// One-line reference to the historical incident(s) that motivated
    /// the rule. Empty when the rule is a generic heuristic.
    pub reference: &'static str,
    /// One-line action — what should the release engineer do *next*?
    pub action: &'static str,
}

fn table() -> &'static HashMap<&'static str, RuleNarrative> {
    static T: OnceLock<HashMap<&'static str, RuleNarrative>> = OnceLock::new();
    T.get_or_init(|| {
        let mut m = HashMap::new();
        m.insert(
            "NPM005",
            RuleNarrative {
                title: "Large encoded blob next to dynamic execution",
                what: "A long base64/hex string sits within a few KB of an `eval(...)`, \
                       `new Function(...)`, or `vm.runIn*(...)` call. This is the dominant \
                       npm-malware obfuscation shape: ship an opaque payload, decode it at \
                       import time, hand it to a dynamic executor.",
                reference: "event-stream / flatmap-stream (2018) — base64 blob gated on \
                            `require.main.filename`, decoded and evaled at import.",
                action: "Read the unobfuscated payload yourself before allowing the install. \
                         If the package isn't a minified bundle host, treat this as a block.",
            },
        );
        m.insert(
            "NPM006",
            RuleNarrative {
                title: "Cloud-metadata host literal",
                what: "Source references the EC2 / GCP / Azure instance-metadata service IP \
                       or hostname (`169.254.169.254`, `metadata.google.internal`, etc.). \
                       Reaching that endpoint at install or import time is how attackers \
                       harvest cloud IAM credentials.",
                reference: "Multiple Snyk/Phylum-flagged 2023–2024 npm crypto-stealers.",
                action: "Block. There is no legitimate reason for a published library to \
                         talk to the cloud metadata service.",
            },
        );
        m.insert(
            "NPM011",
            RuleNarrative {
                title: "Credential / CI-token theft",
                what: "Source reads `process.env.NPM_TOKEN`, `GITHUB_TOKEN`, `~/.npmrc`, \
                       or `~/.docker/config.json` — secrets only useful to whoever steals \
                       them.",
                reference: "Shai-Hulud worm 2024 — postinstall reads NPM_TOKEN and \
                            republishes the maintainer's other packages.",
                action: "Block on install-time reads (no defensible use). On regular source \
                         reads, treat as Stage 2 — a CI-helper library has legitimate cause.",
            },
        );
        m.insert(
            "NPM015",
            RuleNarrative {
                title: "Encoded URL byte sequence",
                what: "Source builds the literal `http` or `https` prefix at runtime from \
                       numeric character codes (e.g. `[104, 116, 116, 112]`). Static \
                       scanners that grep for `http://` miss this; humans usually don't \
                       write it.",
                reference: "Generic obfuscation shape across multiple npm malware families.",
                action: "Treat as decisive when paired with any network or exec sink in the \
                         same file. Otherwise Stage 2.",
            },
        );
        m.insert(
            "NPM018",
            RuleNarrative {
                title: "Anti-forensic self-deletion",
                what: "Code unlinks `__filename` / `__dirname` after running. There is no \
                       legitimate npm package reason; the only known use is hiding what \
                       executed from incident responders.",
                reference: "Multiple post-2020 npm credential-stealers (generic shape).",
                action: "Block.",
            },
        );
        m.insert(
            "NPM030",
            RuleNarrative {
                title: "Newly-introduced capability vs previous version",
                what: "The package gained a capability (`SelfDelete`, `WalletAccess`, \
                       `RegistryWrite`, `DestructiveFs`, etc.) that none of the recent prior \
                       versions had. Sudden capability jumps are the single strongest \
                       version-over-version signal for supply-chain compromise.",
                reference: "Capability-diff approach generalized from event-stream (2018), \
                            ua-parser-js (2021), Shai-Hulud (2024).",
                action: "Read the diff between the two versions. If the new capability is \
                         decisive-on-introduction (SelfDelete, WalletAccess, etc.), block.",
            },
        );
        m.insert(
            "NPM033",
            RuleNarrative {
                title: "Cryptographic key / mnemonic literal",
                what: "Source references private-key, mnemonic, or BIP-39 seed-phrase \
                       shapes — patterns that exist only when the package is in the wallet \
                       business or actively stealing keys from one.",
                reference: "@solana/web3.js 2024 phishing-driven hijack; multiple bignum \
                            typosquats.",
                action: "Block on a non-wallet library. On a wallet library, demand a \
                         human review.",
            },
        );
        m.insert(
            "NPM034",
            RuleNarrative {
                title: "Registry write inside install lifecycle",
                what: "Install-time script shells out to `npm publish`, `npm token`, or \
                       similar registry-mutating commands. The defining shape of the \
                       Shai-Hulud worm: a compromised package republishes its owner's \
                       other packages.",
                reference: "Shai-Hulud 2024.",
                action: "Block. There is no legitimate reason for a postinstall to call \
                         `npm publish`.",
            },
        );
        m.insert(
            "NPM037",
            RuleNarrative {
                title: "Branch on `require.main.filename` / package identity",
                what: "Payload reads `require.main.filename` or `process.mainModule` and \
                       string-matches it against a target package name list before \
                       activating. Selective-payload shape — the malicious code stays \
                       dormant until consumed by a specific downstream package.",
                reference: "event-stream / flatmap-stream 2018 — payload only fired when \
                            loaded by `copay-dash`.",
                action: "Block when the target list looks attacker-curated. Stage 2 \
                         otherwise.",
            },
        );
        m.insert(
            "NPM038",
            RuleNarrative {
                title: "`require.cache` / `Module._cache` mutation",
                what: "Code writes to or deletes from Node's module cache with a non-literal \
                       key. Module-substitution primitive: swap a popular library's exports \
                       for a malicious replacement after the cache is warm.",
                reference: "Generic stealth-hijack shape.",
                action: "Stage 2 — the AST already suppresses comment/string FPs, so a \
                         remaining hit is real but may be a security tool itself.",
            },
        );
        m.insert(
            "NPM039",
            RuleNarrative {
                title: "Destructive filesystem traversal",
                what: "A `rimraf` / `fs.rm({recursive:true})` / `rm -rf` call paired with \
                       a homedir / cwd / root traversal seed (`os.homedir()`, \
                       `process.cwd()`, `/`, `C:\\`) in the same file. The wiper shape.",
                reference: "node-ipc / peacenotwar 2022 — selective `fs.unlink` walks \
                            rooted at `os.homedir()` with locale-gated activation.",
                action: "Block.",
            },
        );
        m.insert(
            "NPM041",
            RuleNarrative {
                title: "Dataflow-lite token exfil",
                what: "A bulk `process.env` consumer (Object.keys/entries, JSON.stringify, \
                       spread, for-in, destructure, computed-key bracket access) sits in \
                       the same body as a network or exec sink. Catches Shai-Hulud variants \
                       that hide the literal `NPM_TOKEN` from the simple regex.",
                reference: "Shai-Hulud 2024 indirect-read variants.",
                action: "Block when in install lifecycle. Stage 2 in regular source — a \
                         logger or CI helper has legitimate cause for both halves.",
            },
        );
        m.insert(
            "NPM046",
            RuleNarrative {
                title: "SetUID / SetGID bit in tarball",
                what: "A file in the tarball carries `0o4000` / `0o2000` mode bits. \
                       There is no legitimate reason for a published npm package to ship a \
                       setuid binary; npm itself doesn't preserve these on install.",
                reference: "Generic privilege-escalation primitive.",
                action: "Block.",
            },
        );
        m.insert(
            "NPM050",
            RuleNarrative {
                title: "Minified dist with no source map / no readable original",
                what: "The published `dist/` directory contains minified JavaScript with \
                       no companion `*.map` and no readable original (`.ts` / unminified \
                       `.js` sibling) elsewhere in the tarball. Code that can't be audited \
                       can't be trusted.",
                reference: "event-stream 2018 — the malicious payload only existed as a \
                            minified blob, defeating casual review.",
                action: "Stage 2 — many legit libraries ship minified bundles. The signal \
                         is a strong corroborator, not decisive on its own.",
            },
        );
        m.insert(
            "CARGO002",
            RuleNarrative {
                title: "Dangerous API used in `build.rs`",
                what: "The crate's build script (`build.rs`) invokes a process-spawn, \
                       network, or filesystem-write API. `build.rs` runs on the developer's \
                       machine at every `cargo build` of a downstream crate, so anything \
                       it does has the developer's local privileges.",
                reference: "Generic supply-chain shape for the Rust ecosystem.",
                action: "Read the build.rs yourself. Even legitimate uses (linking native \
                         libs) deserve review.",
            },
        );
        m
    })
}

/// Look up the static narrative for a rule, if any.
pub fn narrative(rule_id: &str) -> Option<&'static RuleNarrative> {
    table().get(rule_id)
}

/// Render `verdict` as a human-readable, terminal-friendly
/// narrative. No color escapes — safe for CI logs and Slack
/// snippets.
pub fn render_text(v: &Verdict) -> String {
    use std::fmt::Write;
    let mut o = String::new();
    let a = &v.artifact;
    let _ = writeln!(
        o,
        "{}@{}  ({:?})",
        a.name, a.version, a.ecosystem,
    );
    let _ = writeln!(
        o,
        "  integrity      : {}-{}",
        match a.integrity.algo {
            monomi_core::HashAlgo::Sha256 => "sha256",
            monomi_core::HashAlgo::Sha512 => "sha512",
        },
        truncate(&a.integrity.digest_b64, 32),
    );
    let _ = writeln!(
        o,
        "  stage1 verdict : {:?}   (score {})",
        v.stage1.verdict, v.stage1.score
    );
    let _ = writeln!(o, "  final status   : {:?}", v.final_verdict.status);
    if let Some(s2) = &v.stage2 {
        let _ = writeln!(o, "  stage2 model   : {}", s2.model);
        let _ = writeln!(o, "  stage2 verdict : {:?}", s2.verdict);
    }

    if v.stage1.findings.is_empty() {
        let _ = writeln!(o, "\nNo Stage 1 findings.");
        return summary(v, o);
    }

    let _ = writeln!(o, "\nFindings:");
    for (i, f) in v.stage1.findings.iter().enumerate() {
        let _ = writeln!(o);
        render_finding(&mut o, i + 1, f);
    }

    if !v.stage1.capabilities.is_empty() {
        let _ = writeln!(o, "\nCapabilities aggregated:");
        for cap in &v.stage1.capabilities {
            let flag = if cap.is_decisive_on_introduction() {
                " [decisive-on-introduction]"
            } else {
                ""
            };
            let _ = writeln!(o, "  - {cap:?}{flag}");
        }
    }
    summary(v, o)
}

fn render_finding(o: &mut String, idx: usize, f: &Finding) {
    use std::fmt::Write;
    let header = format!(
        "  {idx}. {} [{:?}] {}",
        f.rule_id,
        f.severity,
        narrative(&f.rule_id)
            .map(|n| n.title)
            .unwrap_or("(no narrative)"),
    );
    let _ = writeln!(o, "{header}");
    if let Some(n) = narrative(&f.rule_id) {
        let _ = writeln!(o, "     what    : {}", wrap(n.what, 6));
        if !n.reference.is_empty() {
            let _ = writeln!(o, "     ref     : {}", wrap(n.reference, 6));
        }
        let _ = writeln!(o, "     action  : {}", wrap(n.action, 6));
    } else {
        let _ = writeln!(o, "     message : {}", wrap(&f.message, 6));
    }
    if let Some(loc) = f.locations.first() {
        let _ = writeln!(o, "     where   : {}", loc.path);
    }
    if let Some(excerpt) = &f.excerpt {
        let _ = writeln!(o, "     excerpt : {}", truncate(excerpt, 200));
    }
}

fn summary(v: &Verdict, mut o: String) -> String {
    use std::fmt::Write;
    let verdict_advice = match (v.stage1.verdict, v.final_verdict.status) {
        (_, Status::Block) => "Stage 1 says block. Do not allow this artifact past the proxy.",
        (Stage1Verdict::Malicious, _) => {
            "Stage 1 marked malicious; the final status is set by the Stage 2 merge."
        }
        (Stage1Verdict::Suspicious, Status::Warn) => {
            "Suspicious — review the Stage 2 reasoning before deciding."
        }
        (Stage1Verdict::Suspicious, _) => {
            "Suspicious — Stage 2 should escalate or de-escalate; current status reflects the merge."
        }
        (Stage1Verdict::Clean, Status::Clean) => "Clean — no Stage 1 signals fired.",
        (Stage1Verdict::Clean, _) => "Stage 1 clean; final status set by other inputs.",
    };
    let _ = writeln!(o, "\n{verdict_advice}");
    o
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let head: String = s.chars().take(max).collect();
        format!("{head}…")
    }
}

/// Soft line-wrap at ~70 chars, indenting continuation lines so the
/// output reads as a single bullet.
fn wrap(text: &str, indent: usize) -> String {
    const W: usize = 70;
    let pad: String = " ".repeat(indent);
    let mut out = String::new();
    let mut line_len = 0;
    for (i, word) in text.split_whitespace().enumerate() {
        if line_len + word.len() + 1 > W && i > 0 {
            out.push('\n');
            out.push_str(&pad);
            line_len = 0;
        } else if i > 0 {
            out.push(' ');
            line_len += 1;
        }
        out.push_str(word);
        line_len += word.len();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use monomi_core::{
        ArtifactId, Category, EcosystemId, FinalVerdict, Finding, HashAlgo, Integrity, Location,
        Severity, Stage1Result, Status, VerdictSource,
    };
    use std::collections::BTreeSet;

    fn mk_verdict(rule_id: &str, severity: Severity) -> Verdict {
        Verdict {
            schema_version: 1,
            artifact: ArtifactId {
                ecosystem: EcosystemId::Npm,
                name: "demo".into(),
                version: "1.0.0".into(),
                integrity: Integrity::from_bytes(HashAlgo::Sha512, b"abc"),
            },
            analyzed_at: chrono::Utc::now(),
            analyzer_version: "test".into(),
            ruleset_version: "test".into(),
            stage1: Stage1Result {
                findings: vec![Finding {
                    rule_id: rule_id.into(),
                    severity,
                    category: Category::Exfil,
                    locations: vec![Location {
                        path: "index.js".into(),
                        line_start: None,
                        line_end: None,
                    }],
                    excerpt: Some("process.env.NPM_TOKEN".into()),
                    message: "raw rule message".into(),
                    defers_to_stage2: false,
                    capabilities: BTreeSet::new(),
                }],
                score: 10,
                verdict: Stage1Verdict::Malicious,
                capabilities: BTreeSet::new(),
                capabilities_complete: true,
                diff_outcome: None,
            },
            stage2: None,
            final_verdict: FinalVerdict {
                status: Status::Block,
                confidence: 1.0,
                source: VerdictSource::Stage1,
            },
        }
    }

    #[test]
    fn rules_with_narrative_show_what_and_action() {
        let v = mk_verdict("NPM011", Severity::Critical);
        let out = render_text(&v);
        assert!(out.contains("Credential / CI-token theft"), "{out}");
        assert!(out.contains("Shai-Hulud"), "{out}");
        assert!(out.contains("what    :"), "{out}");
        assert!(out.contains("action  :"), "{out}");
    }

    #[test]
    fn rules_without_narrative_fall_back_to_message() {
        let v = mk_verdict("NPM999", Severity::Low);
        let out = render_text(&v);
        assert!(out.contains("(no narrative)"), "{out}");
        assert!(out.contains("raw rule message"), "{out}");
    }

    #[test]
    fn clean_verdict_says_so() {
        let mut v = mk_verdict("NPM011", Severity::Critical);
        v.stage1.findings.clear();
        v.stage1.score = 0;
        v.stage1.verdict = Stage1Verdict::Clean;
        v.final_verdict.status = Status::Clean;
        let out = render_text(&v);
        assert!(out.contains("No Stage 1 findings"));
        assert!(out.contains("Clean"));
    }
}
