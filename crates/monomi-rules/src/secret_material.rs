//! `NPM033` — cryptocurrency private-key / mnemonic / seed-phrase
//! literals embedded in source.
//!
//! Reference incidents: `@solana/web3.js` 2024 phishing-driven
//! hijack (env grep for Solana keys), electron-native-notify
//! (discord/electron credential theft), multiple `bignum*`
//! typosquats. Legitimate libraries that *generate* keys do not
//! embed these literals; libraries that *manage* keys (wallets,
//! key derivation libs) do — Stage 2 is the arbiter.

use monomi_core::{
    AnalysisCtx, Capability, Category, EcosystemId, Finding, Location, Rule, Severity,
};
use once_cell::sync::Lazy;
use regex::Regex;

pub struct SecretMaterialLiteral;

static SECRET_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
            \b(?:PRIVATE_KEY|MNEMONIC|SEED_PHRASE|SECRET_KEY|API_SECRET)\b
          | \b(?:bip39|BIP39)\.wordlist\b
          | \bderive(?:Path|FromMnemonic)\s*\(
          | \bmnemonicToSeed(?:Sync)?\s*\(
          | \bkeyPair\s*\.\s*secretKey\b
          | \bsolana(?:Connection|Keypair)\b.*\bsecretKey\b
        "#,
    )
    .expect("SECRET_RE")
});

/// Ethereum-style 0x-prefixed 64-hex-char private-key shape.
static ETH_PRIV_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"['\x22]0x[0-9a-fA-F]{64}['\x22]").expect("ETH_PRIV_RE"));

impl Rule for SecretMaterialLiteral {
    fn id(&self) -> &'static str {
        "NPM033"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(
            eco,
            EcosystemId::Npm | EcosystemId::Pypi | EcosystemId::Cargo
        )
    }

    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for entry in ctx.entries {
            if !entry.kind.is_scannable_source() {
                continue;
            }
            let Some(text) = entry.text() else { continue };
            if let Some(m) = SECRET_RE.find(text).or_else(|| ETH_PRIV_RE.find(text)) {
                out.push(Finding {
                    rule_id: "NPM033".into(),
                    severity: Severity::High,
                    category: Category::Exfil,
                    locations: vec![Location {
                        path: entry.path.clone(),
                        line_start: None,
                        line_end: None,
                    }],
                    excerpt: Some(m.as_str().to_string()),
                    message: format!(
                        "source references cryptographic key / mnemonic literal `{}`",
                        m.as_str()
                    ),
                    defers_to_stage2: true,
                    capabilities: [Capability::SecretMaterial, Capability::EnvSecretLookup]
                        .into_iter()
                        .collect(),
                });
                break;
            }
        }
        out
    }
}
