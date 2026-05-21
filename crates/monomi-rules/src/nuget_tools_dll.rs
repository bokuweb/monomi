//! NUGET003 — native DLL / EXE shipped under `tools/`.
//!
//! `tools/` is where NuGet's legacy `packages.config` workflow
//! invokes `install.ps1`. A `.dll` or `.exe` sitting alongside the
//! PowerShell entry point gives the script a native payload to
//! load (`Add-Type -Path`, `[Reflection.Assembly]::LoadFrom`),
//! escaping AMSI / script-based scrutiny. High + defer.

use monomi_core::{AnalysisCtx, Category, EcosystemId, Finding, Location, Rule, Severity};

pub struct ToolsNativeBinary;

impl Rule for ToolsNativeBinary {
    fn id(&self) -> &'static str {
        "NUGET003"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(eco, EcosystemId::Nuget)
    }

    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        // Only meaningful when the package also ships a tools-
        // dir PowerShell hook — alone, `tools/foo.exe` is just a
        // legitimate command-line tool ship.
        let has_install_hook = ctx.entries.iter().any(|e| {
            let p = e.path.to_ascii_lowercase();
            p == "tools/install.ps1" || p == "tools/init.ps1"
        });
        if !has_install_hook {
            return Vec::new();
        }
        let mut out = Vec::new();
        for entry in ctx.entries {
            let p = entry.path.as_str();
            let lower = p.to_ascii_lowercase();
            if !lower.starts_with("tools/") {
                continue;
            }
            if !(lower.ends_with(".dll") || lower.ends_with(".exe")) {
                continue;
            }
            out.push(Finding {
                rule_id: "NUGET003".into(),
                severity: Severity::High,
                category: Category::NativeBinary,
                locations: vec![Location {
                    path: p.to_string(),
                    line_start: None,
                    line_end: None,
                }],
                excerpt: None,
                message: format!(
                    "native binary `{p}` ships alongside `tools/install.ps1` / \
                     `init.ps1` — install hook can load it via Add-Type / \
                     [Reflection.Assembly]::LoadFrom"
                ),
                defers_to_stage2: true,
                capabilities: Default::default(),            });
        }
        out
    }
}
