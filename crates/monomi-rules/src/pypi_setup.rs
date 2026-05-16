//! PyPI sdist-oriented rules.
//!
//! - `PYPI001` — `setup.py` or a non-stdlib `build-backend` is
//!   present. Informational; flags the package as RCE-capable at
//!   install time.
//! - `PYPI002` — install-time entry uses primitives that would let
//!   it exec a child process, open a socket, or hit the filesystem
//!   in surprising places. The python analog of `NPM002` / `CARGO002`.

use monomi_core::{
    AnalysisCtx, Category, EcosystemId, Finding, LifecycleKind, Location, Rule, Severity,
};
use once_cell::sync::Lazy;
use regex::Regex;

pub struct SetupPyPresent;

impl Rule for SetupPyPresent {
    fn id(&self) -> &'static str {
        "PYPI001"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(eco, EcosystemId::Pypi)
    }

    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for life in ctx.lifecycle {
            if !matches!(life.kind, LifecycleKind::InstallTime) {
                continue;
            }
            let path = life.path.clone().unwrap_or_else(|| life.name.clone());
            out.push(Finding {
                rule_id: "PYPI001".into(),
                severity: Severity::Info,
                category: Category::LifecycleScript,
                locations: vec![Location {
                    path,
                    line_start: None,
                    line_end: None,
                }],
                excerpt: Some(truncate(&life.body, 240)),
                message: format!("install-time entry `{}` present", life.name),
                defers_to_stage2: false,
            });
        }
        out
    }
}

pub struct SetupPyDangerousApi;

static DANGEROUS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
            \bimport\s+(?:subprocess|socket|urllib|http\.client|telnetlib|smtplib|ftplib|paramiko|requests|httpx)\b
          | \bfrom\s+(?:subprocess|socket|urllib|http\.client|telnetlib|smtplib|ftplib|paramiko|requests|httpx)\s+import\b
          | \bos\s*\.\s*(?:system|popen|exec[lv]?[pe]?|spawn[lv]?[pe]?)\s*\(
          | \bsubprocess\s*\.\s*(?:Popen|call|run|check_call|check_output|getoutput)\s*\(
          | \bsocket\s*\.\s*(?:socket|create_connection)\s*\(
          | \burllib(?:\.request)?\s*\.\s*(?:urlopen|urlretrieve)\s*\(
          | \brequests\s*\.\s*(?:get|post|put|delete|head|options|patch|request)\s*\(
          | \b__import__\s*\(\s*['"](?:subprocess|socket|urllib|requests|http)
          | \beval\s*\(
          | \bexec\s*\(
          | \bcompile\s*\([^,]+,[^,]+,\s*['"](?:exec|eval)
        "#,
    )
    .expect("DANGEROUS_RE")
});

impl Rule for SetupPyDangerousApi {
    fn id(&self) -> &'static str {
        "PYPI002"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(eco, EcosystemId::Pypi)
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
                    rule_id: "PYPI002".into(),
                    severity: Severity::High,
                    category: Category::LifecycleScript,
                    locations: vec![Location {
                        path,
                        line_start: None,
                        line_end: None,
                    }],
                    excerpt: Some(m.as_str().to_string()),
                    message: format!(
                        "install-time entry `{}` uses dangerous primitive `{}`",
                        life.name,
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
