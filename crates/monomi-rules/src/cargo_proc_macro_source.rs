//! `CARGO005` / `CARGO006` / `CARGO007` — proc-macro *source*
//! capability surface.
//!
//! `CARGO003` only flags that a crate has compiler-plugin powers.
//! This module walks the proc-macro crate's own `src/` and checks
//! what those compiler-plugin powers are actually used for at
//! compile time. A `Command::new` / `std::net::TcpStream` /
//! `reqwest::Client::new` in a proc-macro body runs against the
//! developer's machine the next time they `cargo build`, without
//! any user code calling the macro.
//!
//! Three sibling rules share the same scaffolding (proc-macro
//! detection + source walk) and emit different finding IDs based
//! on what they matched. Each emits at most one finding per source
//! file so 100k-line files don't explode the report.

use monomi_core::{
    AnalysisCtx, Capability, Category, EcosystemId, Finding, Location, Rule, Severity,
};
use once_cell::sync::Lazy;
use regex::Regex;

fn is_proc_macro(ctx: &AnalysisCtx<'_>) -> bool {
    let lib = ctx.manifest.raw.get("lib");
    lib.and_then(|l| l.get("proc-macro"))
        .or_else(|| lib.and_then(|l| l.get("proc_macro")))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

fn is_rust_source(path: &str) -> bool {
    path.ends_with(".rs")
}

// ---------- CARGO005: process spawn ----------

static PROC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?x)
            \bstd\s*::\s*process\s*::\s*Command\b
          | \bCommand\s*::\s*new\s*\(
          | \bstd\s*::\s*os\s*::\s*unix\s*::\s*process\b
        ",
    )
    .expect("PROC_RE")
});

pub struct ProcMacroProcessSpawn;

impl Rule for ProcMacroProcessSpawn {
    fn id(&self) -> &'static str {
        "CARGO005"
    }
    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(eco, EcosystemId::Cargo)
    }
    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        if !is_proc_macro(ctx) {
            return Vec::new();
        }
        scan_source(ctx, &PROC_RE, "CARGO005", "process spawn", Capability::ProcSpawn)
    }
}

// ---------- CARGO006: filesystem read/write ----------

static FS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?x)
            \bstd\s*::\s*fs\s*::\s*(?:read|read_to_string|read_dir|write|create_dir|remove_file|remove_dir|File)\b
          | \bstd\s*::\s*fs\s*::\s*OpenOptions\b
          | \bOpenOptions\s*::\s*new\s*\(
          | \bFile\s*::\s*(?:open|create)\s*\(
        ",
    )
    .expect("FS_RE")
});

pub struct ProcMacroFsAccess;

impl Rule for ProcMacroFsAccess {
    fn id(&self) -> &'static str {
        "CARGO006"
    }
    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(eco, EcosystemId::Cargo)
    }
    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        if !is_proc_macro(ctx) {
            return Vec::new();
        }
        scan_source(ctx, &FS_RE, "CARGO006", "filesystem access", Capability::FsRead)
    }
}

// ---------- CARGO007: network ----------

static NET_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?x)
            \bstd\s*::\s*net\s*::\s*(?:TcpStream|TcpListener|UdpSocket)\b
          | \b(?:TcpStream|TcpListener|UdpSocket)\s*::\s*(?:connect|bind)\s*\(
          | \breqwest\s*::\b
          | \bureq\s*::\b
          | \bhyper\s*::\b
          | \bcurl\s*::\b
          | \btokio\s*::\s*net\b
        ",
    )
    .expect("NET_RE")
});

pub struct ProcMacroNetAccess;

impl Rule for ProcMacroNetAccess {
    fn id(&self) -> &'static str {
        "CARGO007"
    }
    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(eco, EcosystemId::Cargo)
    }
    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        if !is_proc_macro(ctx) {
            return Vec::new();
        }
        // Network out of a proc-macro is the worst of the three —
        // build.rs network at least is somewhat visible; proc-macro
        // network runs silently inside every `cargo build`. Same
        // severity for now (High + defer) but Stage 2 should weight
        // it heavily.
        scan_source(ctx, &NET_RE, "CARGO007", "network", Capability::NetHttp)
    }
}

fn scan_source(
    ctx: &AnalysisCtx<'_>,
    re: &Regex,
    rule_id: &'static str,
    what: &str,
    cap: Capability,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for entry in ctx.entries {
        if !is_rust_source(&entry.path) {
            continue;
        }
        let Some(text) = entry.text() else { continue };
        if let Some(m) = re.find(text) {
            out.push(Finding {
                rule_id: rule_id.into(),
                severity: Severity::High,
                category: Category::Other,
                locations: vec![Location {
                    path: entry.path.clone(),
                    line_start: None,
                    line_end: None,
                }],
                excerpt: Some(m.as_str().to_string()),
                message: format!(
                    "proc-macro source uses {} primitive `{}` — executes at compile time \
                     in every downstream crate",
                    what,
                    m.as_str()
                ),
                defers_to_stage2: true,
                capabilities: [cap].into_iter().collect(),
            });
        }
    }
    out
}
