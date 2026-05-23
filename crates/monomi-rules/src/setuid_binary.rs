//! `NPM046` — file in the tarball carries SetUID / SetGID bits.
//!
//! The tar header's mode bits `0o4000` (setuid) and `0o2000` (setgid)
//! cause the OS to elevate the running user's privileges when the
//! file is executed. There is no legitimate reason for a published
//! package to ship a setuid binary — npm/cargo/PyPI install flows
//! all run as the invoking user, and even if extracted as root the
//! bit usually trips package-manager safety checks.
//!
//! Critical + decisive: a single hit blocks. Pairs with `NPM015`
//! (native binary undeclared) when both fire.
//!
//! Only fires on ecosystems whose extractor populates `Entry::mode`
//! (npm tar, cargo .crate, PyPI sdist). NuGet `.nupkg` is a zip
//! archive without unix permissions, so this rule is a no-op there.

use monomi_core::{
    AnalysisCtx, Capability, Category, EcosystemId, Finding, Location, Rule, Severity,
};

pub struct SetuidBinaryInTarball;

const SETUID: u32 = 0o4000;
const SETGID: u32 = 0o2000;

impl Rule for SetuidBinaryInTarball {
    fn id(&self) -> &'static str {
        "NPM046"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(
            eco,
            EcosystemId::Npm | EcosystemId::Cargo | EcosystemId::Pypi
        )
    }

    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for entry in ctx.entries {
            let Some(mode) = entry.mode else { continue };
            let setuid = mode & SETUID != 0;
            let setgid = mode & SETGID != 0;
            if !setuid && !setgid {
                continue;
            }
            let which = match (setuid, setgid) {
                (true, true) => "setuid+setgid",
                (true, false) => "setuid",
                (false, true) => "setgid",
                _ => unreachable!(),
            };
            out.push(Finding {
                rule_id: "NPM046".into(),
                severity: Severity::Critical,
                category: Category::Persistence,
                locations: vec![Location {
                    path: entry.path.clone(),
                    line_start: None,
                    line_end: None,
                }],
                excerpt: Some(format!("mode=0o{mode:o}")),
                message: format!(
                    "tarball ships a {which} file (mode 0o{mode:o}) — no \
                     legitimate package needs elevated execution bits"
                ),
                defers_to_stage2: false,
                capabilities: [Capability::SetuidBinary].into_iter().collect(),
            });
        }
        out
    }
}
