//! Shared helpers for rules that opt into AST-confirm precision.
//!
//! See `monomi-ast` for the underlying summary type. These helpers
//! encode the project-wide convention for how a regex-based rule
//! decides whether to keep a hit:
//!
//! - If the `AstCache` isn't wired into this scan, trust the regex
//!   (back-compat with stage1-only test harnesses and embedded
//!   users that don't ship the parser).
//! - If the cache is present but the file failed to parse, also
//!   trust the regex — half-parsed minified payloads are exactly
//!   what we want to keep flagging.
//! - Otherwise, drop the hit when it falls inside a comment or
//!   string/template literal. Those are the dominant FP shapes
//!   (`// fs.rmSync(homedir())` in a docstring, README content
//!   embedded as a template literal).

use monomi_core::AnalysisCtx;

/// `true` if a regex hit starting at `hit_start` byte offset in
/// `text` for the file at `entry_path` is real code (not buried in
/// a comment or string literal).
///
/// Rules call this *after* their regex matched and use it as the
/// "still real?" gate before pushing a `Finding`.
pub fn regex_hit_in_code(
    ctx: &AnalysisCtx<'_>,
    entry_path: &str,
    text: &str,
    hit_start: usize,
) -> bool {
    let Some(cache) = ctx.ast.and_then(monomi_ast::downcast) else {
        return true;
    };
    let parsed = cache.get_or_parse(entry_path, text);
    if parsed.parse_errors {
        return true;
    }
    !parsed.is_in_comment_or_string(hit_start)
}
