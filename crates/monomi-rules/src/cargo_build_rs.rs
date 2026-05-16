//! Cargo build.rs–oriented rules.
//!
//! - `CARGO001` — `build.rs` (or the `package.build` override) is
//!   present. Informational; downstream rules / Stage 2 may upgrade.
//! - `CARGO002` — the build script uses primitives that would let it
//!   exec a child process, open a socket, or hit the filesystem in
//!   surprising places at *compile time*. This is the cargo analog
//!   of npm's `NPM002`.

use monomi_core::{
    AnalysisCtx, Category, EcosystemId, Finding, LifecycleKind, Location, Rule, Severity,
};
use once_cell::sync::Lazy;
use regex::Regex;

pub struct BuildRsPresent;

impl Rule for BuildRsPresent {
    fn id(&self) -> &'static str {
        "CARGO001"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(eco, EcosystemId::Cargo)
    }

    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for life in ctx.lifecycle {
            if !matches!(life.kind, LifecycleKind::InstallTime) {
                continue;
            }
            let path = life.path.clone().unwrap_or_else(|| "build.rs".into());
            out.push(Finding {
                rule_id: "CARGO001".into(),
                severity: Severity::Info,
                category: Category::LifecycleScript,
                locations: vec![Location {
                    path,
                    line_start: None,
                    line_end: None,
                }],
                excerpt: Some(truncate(&life.body, 240)),
                message: format!("compile-time build script `{}` present", life.name),
                defers_to_stage2: false,
            });
        }
        out
    }
}

pub struct BuildRsDangerousApi;

static DANGEROUS_RE: Lazy<Regex> = Lazy::new(|| {
    // Rust's compile-time mischief surface: spawning processes,
    // opening sockets, reading sensitive env vars, downloading
    // tarballs at build time.
    Regex::new(
        r"(?x)
            \bstd\s*::\s*process\s*::\s*Command\b
          | \bCommand\s*::\s*new\s*\(
          | \bstd\s*::\s*process\s*::\s*exit\s*\(
          | \bstd\s*::\s*net\s*::\s*(?:TcpStream|TcpListener|UdpSocket)\b
          | \bTcpStream\s*::\s*connect\s*\(
          | \bTcpListener\s*::\s*bind\s*\(
          | \bUdpSocket\s*::\s*bind\s*\(
          | \breqwest\s*::\b
          | \bhyper\s*::\b
          | \bcurl\s*::\b
          | \bunsafe\s*\{[^}]*libc\s*::
        ",
    )
    .expect("DANGEROUS_RE")
});

impl Rule for BuildRsDangerousApi {
    fn id(&self) -> &'static str {
        "CARGO002"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(eco, EcosystemId::Cargo)
    }

    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for life in ctx.lifecycle {
            if !matches!(life.kind, LifecycleKind::InstallTime) {
                continue;
            }
            if let Some(m) = DANGEROUS_RE.find(&life.body) {
                let path = life.path.clone().unwrap_or_else(|| "build.rs".into());
                out.push(Finding {
                    rule_id: "CARGO002".into(),
                    severity: Severity::High,
                    category: Category::LifecycleScript,
                    locations: vec![Location {
                        path,
                        line_start: None,
                        line_end: None,
                    }],
                    excerpt: Some(m.as_str().to_string()),
                    message: format!(
                        "build script uses compile-time-dangerous primitive `{}`",
                        m.as_str()
                    ),
                    defers_to_stage2: true,
                });
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
