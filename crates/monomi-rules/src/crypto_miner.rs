//! NPM024 — crypto-miner indicators.
//!
//! Targets the ua-parser-js / event-stream / rc-style attack family
//! where a published package ships a Monero / cryptonight miner.
//! Decisive Critical: no published JS package legitimately spawns
//! a hash pipeline against a stratum pool.
//!
//! Looked-for patterns:
//!
//! - `stratum+tcp://` / `stratum+ssl://` URLs (mining protocol)
//! - Well-known public XMR / ETH / RandomX pool hostnames
//! - Known JS miner library / WASM module identifiers
//! - Hardcoded XMR wallet-address shape
//!   (95–106 chars from `[1-9A-HJ-NP-Za-km-z]`, starting with `4`
//!   or `8` — Monero base58 standard / sub-address prefix)

use monomi_core::{Capability, AnalysisCtx, Category, EcosystemId, Finding, Location, Rule, Severity};
use once_cell::sync::Lazy;
use regex::Regex;

pub struct CryptoMinerLiteral;

static MINER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?ix)
            \bstratum\+(?:tcp|ssl)://
          | (?:^|[^A-Za-z0-9_.-])(?:
                pool\.minexmr\.com
              | xmrpool\.eu
              | nanopool\.org
              | supportxmr\.com
              | minexmr\.com
              | moneroocean\.stream
              | herominers\.com
              | hashvault\.pro
              | c3pool\.com
              | f2pool\.com
              | ethermine\.org
              | flexpool\.io
              | 2miners\.com
              | crypto-pool\.fr
              | coin-hive\.com
              | coinhive\.com
              | webminerpool\.com
              | cryptoloot\.com
              | crypto-loot\.com
              | cryptonight\.cc
            )(?:[^A-Za-z0-9_.-]|$)
          | \bcryptonight(?:-wasm|-asm|-aes|_hash)?\b
          | \brandomx_(?:hash|init|create_vm)\b
          | \bcoinhive\b
          | \bcryptoloot\b
          | \bjsecoin\b
          | \bwebminerpool\b
          | \bCoinHive\s*\.\s*(?:Anonymous|User|Token|setKey)
        ",
    )
    .expect("MINER_RE")
});

static XMR_ADDR_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b[48][1-9A-HJ-NP-Za-km-z]{94,105}\b").expect("XMR_ADDR_RE"));

impl Rule for CryptoMinerLiteral {
    fn id(&self) -> &'static str {
        "NPM024"
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
            if let Some(m) = MINER_RE.find(text) {
                out.push(make_finding(entry.path.clone(), m.as_str().to_string()));
            } else if let Some(m) = XMR_ADDR_RE.find(text) {
                out.push(make_finding(
                    entry.path.clone(),
                    format!("Monero address shape: {}", m.as_str()),
                ));
            }
        }
        for life in ctx.lifecycle {
            if let Some(m) = MINER_RE.find(&life.body) {
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
    Finding {
        rule_id: "NPM024".into(),
        severity: Severity::Critical,
        category: Category::Exfil,
        locations: vec![Location {
            path,
            line_start: None,
            line_end: None,
        }],
        excerpt: Some(hit.clone()),
        message: format!(
            "crypto-miner indicator `{hit}` — published packages do not legitimately \
             ship miner code"
        ),
        defers_to_stage2: false,
        capabilities: [Capability::CryptoMiner].into_iter().collect(),
    }
}
