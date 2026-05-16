use crate::context::Stage2Context;

pub const SYSTEM_PROMPT: &str = include_str!("system.txt");

pub fn build_user_message(ctx: &Stage2Context, name: &str, version: &str) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "Adjudicate the following package for supply-chain malware.\n\n\
         Ecosystem: {eco}\n\
         Package: {name}@{version}\n\n\
         === Stage 1 summary ===\n{stage1}\n\
         === Manifest ===\n{manifest}\n",
        eco = ctx.ecosystem.as_str(),
        stage1 = ctx.stage1_summary,
        manifest = ctx.manifest_summary,
    ));

    if !ctx.registry_summary.is_empty() {
        s.push_str("=== Registry metadata ===\n");
        s.push_str(&ctx.registry_summary);
        s.push('\n');
    }

    if !ctx.lifecycle_blocks.is_empty() {
        s.push_str("=== Install-time lifecycle entries ===\n");
        for b in &ctx.lifecycle_blocks {
            s.push_str(&format!("--- {} ---\n{}\n", b.name, b.body));
        }
    }

    if !ctx.finding_excerpts.is_empty() {
        s.push_str("=== Stage 1 findings ===\n");
        s.push_str(
            "(`decisive=true` means the rule alone is block-grade evidence; \
             `decisive=false` means weak signal that needs your judgment.)\n",
        );
        for f in &ctx.finding_excerpts {
            s.push_str(&format!(
                "[{rule}] severity={sev} decisive={decisive} @ {loc}\n  \
                 message: {msg}\n  excerpt: {excerpt}\n",
                rule = f.rule_id,
                sev = f.severity,
                decisive = f.decisive,
                loc = f.location,
                msg = f.message,
                excerpt = f.excerpt,
            ));
        }
    }

    s.push_str(
        "\nReturn your decision via the `record_verdict` tool. Be conservative: \
         prefer `suspicious` over `malicious` unless the evidence is unambiguous. \
         Legitimate native-addon builds, postinstall echo statements, and config \
         scripts are not malicious on their own.",
    );
    s
}
