//! NuGet `tools/install.ps1`–oriented rules.
//!
//! - `NUGET001` — any install-time PowerShell hook is present.
//!   Modern `PackageReference` doesn't run these, but the legacy
//!   `packages.config` workflow still does and the proxy can't
//!   tell which consumer will use the package.
//! - `NUGET002` — the hook uses primitives that would let it
//!   exfiltrate data or spawn a child process. The NuGet analog
//!   of `NPM002` / `CARGO002` / `PYPI002`.

use monomi_core::{
    AnalysisCtx, Category, EcosystemId, Finding, LifecycleKind, Location, Rule, Severity,
};
use once_cell::sync::Lazy;
use regex::Regex;

pub struct InstallPs1Present;

impl Rule for InstallPs1Present {
    fn id(&self) -> &'static str {
        "NUGET001"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(eco, EcosystemId::Nuget)
    }

    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for life in ctx.lifecycle {
            if !matches!(life.kind, LifecycleKind::InstallTime) {
                continue;
            }
            let path = life.path.clone().unwrap_or_else(|| life.name.clone());
            out.push(Finding {
                rule_id: "NUGET001".into(),
                severity: Severity::Info,
                category: Category::LifecycleScript,
                locations: vec![Location {
                    path,
                    line_start: None,
                    line_end: None,
                }],
                excerpt: Some(truncate(&life.body, 240)),
                message: format!("install-time PowerShell hook `{}` present", life.name),
                defers_to_stage2: false,
                capabilities: Default::default(),            });
        }
        out
    }
}

pub struct InstallPs1DangerousApi;

static DANGEROUS_RE: Lazy<Regex> = Lazy::new(|| {
    // (?i) — PowerShell is case-insensitive.
    Regex::new(
        r#"(?ix)
            \bInvoke-WebRequest\b
          | \bInvoke-RestMethod\b
          | \bIWR\b
          | \bWget\b
          | \bcurl\b
          | \bStart-Process\b
          | \bSaps\b
          | \bNew-Object\s+(?:System\.)?Net\.WebClient\b
          | \bSystem\.Net\.Sockets\.TcpClient\b
          | \bDownloadFile\s*\(
          | \bDownloadString\s*\(
          | \bInvoke-Expression\b
          | \bIEX\b
          | \[System\.Reflection\.Assembly\]::Load
          | \[System\.Convert\]::FromBase64String
          | -EncodedCommand\b
        "#,
    )
    .expect("DANGEROUS_RE")
});

impl Rule for InstallPs1DangerousApi {
    fn id(&self) -> &'static str {
        "NUGET002"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(eco, EcosystemId::Nuget)
    }

    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for life in ctx.lifecycle {
            if !matches!(life.kind, LifecycleKind::InstallTime) {
                continue;
            }
            if let Some(m) = DANGEROUS_RE.find(&life.body) {
                let path = life.path.clone().unwrap_or_else(|| life.name.clone());
                out.push(Finding {
                    rule_id: "NUGET002".into(),
                    severity: Severity::High,
                    category: Category::LifecycleScript,
                    locations: vec![Location {
                        path,
                        line_start: None,
                        line_end: None,
                    }],
                    excerpt: Some(m.as_str().to_string()),
                    message: format!(
                        "install-time hook `{}` uses dangerous PowerShell primitive `{}`",
                        life.name,
                        m.as_str()
                    ),
                    defers_to_stage2: true,
                    capabilities: Default::default(),                });
            }
        }
        out
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}
