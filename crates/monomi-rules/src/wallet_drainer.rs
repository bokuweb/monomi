//! NPM010 — crypto-wallet drainer pattern.
//!
//! Catches the dominant npm-malware family of 2024–2025: a
//! published package that names a wallet artifact in source or
//! lifecycle. There is no legitimate reason for an npm package
//! to embed any of these:
//!
//! - `wallet.dat` / `keystore` / `mnemonic` filenames
//! - Per-vendor wallet directories (Exodus, Phantom, Yoroi, …)
//! - Browser extension IDs for major wallets (MetaMask, Phantom)
//! - Ledger / Trezor device-path probes

use monomi_core::{Capability, AnalysisCtx, Category, EcosystemId, Finding, Location, Rule, Severity};
use once_cell::sync::Lazy;
use regex::Regex;

pub struct WalletDrainerLiteral;

static WALLET_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?ix)
            \bwallet\.dat\b
          | \bkeystore\.json\b
          | \bUTC--\d{4}-\d{2}-\d{2}T  # Geth keystore filename prefix
          | (?:^|/)Library/Application\s+Support/(?:
                Exodus|Atomic|Phantom|Coinomi|Electrum|Bitcoin|Litecoin|Ethereum|Wasabi
            )\b
          | (?:^|/)\.config/(?:
                yoroi|electrum|bitcoin|litecoin|ethereum|exodus|atomic|wasabi
            )\b
          | (?:^|/)AppData/Roaming/(?:
                Exodus|Atomic|Phantom|Coinomi|Electrum|Bitcoin|Litecoin|Ethereum
            )\b
          # MetaMask Chrome extension ID
          | \bnkbihfbeogaeaoehlefnkodbefgpgknn\b
          # Phantom Chrome extension ID
          | \bbfnaelmomeimhlpmgjnjophhpkkoljpa\b
          # Coinbase Wallet extension ID
          | \bhnfanknocfeofbddgcijnmhnfnkdnaad\b
          # Trust Wallet extension ID
          | \bealhdmppppfdbnlkjkjeohpoacajcanj\b
          | \brecovery[\s_-]?phrase\b
          | \bseed[\s_-]?phrase\b
        "#,
    )
    .expect("WALLET_RE")
});

impl Rule for WalletDrainerLiteral {
    fn id(&self) -> &'static str {
        "NPM010"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(eco, EcosystemId::Npm)
    }

    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for entry in ctx.entries {
            if !entry.kind.is_scannable_source() {
                continue;
            }
            let Some(text) = entry.text() else { continue };
            if let Some(m) = WALLET_RE.find(text) {
                out.push(make_finding(entry.path.clone(), m.as_str().to_string()));
            }
        }
        for life in ctx.lifecycle {
            if let Some(m) = WALLET_RE.find(&life.body) {
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
        rule_id: "NPM010".into(),
        severity: Severity::Critical,
        category: Category::Exfil,
        locations: vec![Location {
            path,
            line_start: None,
            line_end: None,
        }],
        excerpt: Some(hit.clone()),
        message: format!(
            "wallet-drainer literal `{hit}` — no legitimate reason for a \
             published package to reference this"
        ),
        defers_to_stage2: false,
        capabilities: [Capability::WalletAccess].into_iter().collect(),
    }
}
