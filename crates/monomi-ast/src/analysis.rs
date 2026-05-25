//! Materialized AST summary.
//!
//! `analyze_js` parses a single source file once, walks the program,
//! and returns a `JsAnalysis` containing the queries we actually
//! care about. The caller never sees the AST lifetime.

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, ComputedMemberExpression, Expression, StaticMemberExpression, StringLiteral,
};
use oxc_ast_visit::{walk, Visit};
use oxc_parser::Parser;
use oxc_span::{SourceType, Span};

/// What we know about an argument at a call site, in just enough
/// detail for the precision-confirm rules to decide whether a
/// suspicious-looking call is real.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgShape {
    /// String literal — `"foo"`. Carries the value.
    StringLit(String),
    /// Numeric literal — `42`, `0o755`.
    NumLit(String),
    /// Bare identifier — `foo`, `__filename`.
    Ident(String),
    /// Member expression rendered as a dotted path — `os.homedir`,
    /// `process.env`. Computed access becomes `obj[?]`.
    Member(String),
    /// Another call — `foo()`, `require("x")`.
    Call(String),
    /// String concatenation (`+`-chain of literals/idents).
    Concat,
    /// Template literal.
    Template,
    /// Anything else we didn't bother classifying.
    Other,
}

#[derive(Debug, Clone)]
pub struct CallSite {
    /// Resolved callee name. Identifier → `"foo"`; member chain →
    /// `"a.b.c"`; computed member → `"a.b[?]"`; anything else →
    /// `None`.
    pub callee_name: Option<String>,
    pub args: Vec<ArgShape>,
    pub span: (usize, usize),
}

#[derive(Debug, Clone)]
pub struct MemberAccess {
    /// Dotted form (e.g. `process.env`, `require.cache`). Computed
    /// indexes appear as `[?]` segments.
    pub path: String,
    /// True for `a[expr]` where `expr` is not a string literal.
    pub computed_dynamic: bool,
    pub span: (usize, usize),
}

#[derive(Debug, Clone)]
pub struct StringLit {
    pub value: String,
    pub span: (usize, usize),
}

#[derive(Debug, Clone)]
pub struct RequireCall {
    /// `Some("fs")` for `require("fs")`. `None` if the argument
    /// isn't a string literal — flagged as a dynamic require.
    pub target: Option<String>,
    pub span: (usize, usize),
}

#[derive(Debug, Clone)]
pub struct CommentSpan {
    pub span: (usize, usize),
}

#[derive(Debug, Default, Clone)]
pub struct JsAnalysis {
    pub calls: Vec<CallSite>,
    pub member_accesses: Vec<MemberAccess>,
    pub string_literals: Vec<StringLit>,
    pub requires: Vec<RequireCall>,
    pub comments: Vec<CommentSpan>,
    pub source_len: usize,
    /// True when the parser produced syntactic errors. Rules may
    /// choose to bail rather than emit AST-derived findings on a
    /// half-parsed file.
    pub parse_errors: bool,
}

impl JsAnalysis {
    /// Iterate calls whose resolved name matches `name` exactly
    /// (e.g. `"eval"`, `"require"`, `"fs.unlinkSync"`).
    pub fn calls_to<'s>(&'s self, name: &'s str) -> impl Iterator<Item = &'s CallSite> + 's {
        self.calls
            .iter()
            .filter(move |c| c.callee_name.as_deref() == Some(name))
    }

    /// Iterate calls whose resolved name ends with `.suffix`.
    /// Useful for matching member methods regardless of receiver
    /// (`unlinkSync` matches `fs.unlinkSync`, `require("fs").
    /// unlinkSync`, etc., when we resolved the dotted form).
    pub fn calls_method<'s>(&'s self, suffix: &'s str) -> impl Iterator<Item = &'s CallSite> + 's {
        let needle = format!(".{suffix}");
        self.calls.iter().filter(move |c| {
            c.callee_name
                .as_deref()
                .is_some_and(|n| n == suffix.strip_prefix('.').unwrap_or(suffix) || n.ends_with(&needle))
        })
    }

    /// All member-expression access paths matching `path` exactly
    /// (e.g. `"process.env"`, `"require.cache"`).
    pub fn member_accesses_to<'s>(
        &'s self,
        path: &'s str,
    ) -> impl Iterator<Item = &'s MemberAccess> + 's {
        self.member_accesses
            .iter()
            .filter(move |m| m.path == path)
    }

    /// True if `byte_pos` falls inside any comment span.
    pub fn is_in_comment(&self, byte_pos: usize) -> bool {
        self.comments
            .iter()
            .any(|c| byte_pos >= c.span.0 && byte_pos < c.span.1)
    }

    /// True if `byte_pos` falls inside any string-literal span.
    pub fn is_in_string_literal(&self, byte_pos: usize) -> bool {
        self.string_literals
            .iter()
            .any(|s| byte_pos >= s.span.0 && byte_pos < s.span.1)
    }

    /// Convenience: comment OR string. The common "false positive
    /// in non-code text" suppression check.
    pub fn is_in_comment_or_string(&self, byte_pos: usize) -> bool {
        self.is_in_comment(byte_pos) || self.is_in_string_literal(byte_pos)
    }
}

/// Parse `source` as JS/TS and return the materialized summary.
///
/// The source type is inferred from `filename` when given (`.ts` →
/// TypeScript module, `.cjs` → CommonJS, etc.); falls back to a
/// JavaScript module otherwise. Parse errors don't fail this
/// function — they're recorded in `JsAnalysis::parse_errors` so
/// callers can decide what to do.
pub fn analyze_js(source: &str, filename: Option<&str>) -> JsAnalysis {
    let allocator = Allocator::default();
    let source_type = filename
        .and_then(|f| SourceType::from_path(f).ok())
        .unwrap_or_else(SourceType::default);

    let ret = Parser::new(&allocator, source, source_type).parse();

    let mut analysis = JsAnalysis {
        source_len: source.len(),
        parse_errors: !ret.errors.is_empty(),
        ..Default::default()
    };

    // Comments come from the parser return directly, not via Visit.
    for c in &ret.program.comments {
        analysis.comments.push(CommentSpan {
            span: span_to_tuple(c.span),
        });
    }

    let mut visitor = Collector {
        analysis: &mut analysis,
    };
    visitor.visit_program(&ret.program);

    analysis
}

fn span_to_tuple(s: Span) -> (usize, usize) {
    (s.start as usize, s.end as usize)
}

struct Collector<'r> {
    analysis: &'r mut JsAnalysis,
}

impl<'r> Collector<'r> {
    fn resolve_callee_name(&self, expr: &Expression<'_>) -> Option<String> {
        match expr {
            Expression::Identifier(id) => Some(id.name.to_string()),
            Expression::StaticMemberExpression(m) => Some(static_member_path(m)),
            Expression::ComputedMemberExpression(m) => Some(computed_member_path(m)),
            // `(foo.bar)()` etc.
            Expression::ParenthesizedExpression(p) => self.resolve_callee_name(&p.expression),
            _ => None,
        }
    }

    fn arg_shape(&self, arg: &Argument<'_>) -> ArgShape {
        let expr = match arg {
            Argument::SpreadElement(_) => return ArgShape::Other,
            _ => arg.to_expression(),
        };
        expr_shape(expr)
    }
}

fn expr_shape(expr: &Expression<'_>) -> ArgShape {
    match expr {
        Expression::StringLiteral(s) => ArgShape::StringLit(s.value.to_string()),
        Expression::NumericLiteral(n) => {
            ArgShape::NumLit(n.raw.map(|s| s.to_string()).unwrap_or_default())
        }
        Expression::Identifier(id) => ArgShape::Ident(id.name.to_string()),
        Expression::StaticMemberExpression(m) => ArgShape::Member(static_member_path(m)),
        Expression::ComputedMemberExpression(m) => ArgShape::Member(computed_member_path(m)),
        Expression::CallExpression(c) => {
            let name = match &c.callee {
                Expression::Identifier(id) => id.name.to_string(),
                Expression::StaticMemberExpression(m) => static_member_path(m),
                _ => "_".into(),
            };
            ArgShape::Call(name)
        }
        Expression::BinaryExpression(b) if matches!(b.operator, oxc_ast::ast::BinaryOperator::Addition) => {
            ArgShape::Concat
        }
        Expression::TemplateLiteral(_) => ArgShape::Template,
        _ => ArgShape::Other,
    }
}

fn static_member_path(m: &StaticMemberExpression<'_>) -> String {
    let mut head = match &m.object {
        Expression::Identifier(id) => id.name.to_string(),
        Expression::StaticMemberExpression(inner) => static_member_path(inner),
        Expression::ComputedMemberExpression(inner) => computed_member_path(inner),
        Expression::ThisExpression(_) => "this".into(),
        _ => "_".into(),
    };
    head.push('.');
    head.push_str(&m.property.name);
    head
}

fn computed_member_path(m: &ComputedMemberExpression<'_>) -> String {
    let head = match &m.object {
        Expression::Identifier(id) => id.name.to_string(),
        Expression::StaticMemberExpression(inner) => static_member_path(inner),
        Expression::ComputedMemberExpression(inner) => computed_member_path(inner),
        _ => "_".into(),
    };
    // If the index is a string literal, render it; otherwise mark as
    // dynamic for downstream queries.
    match &m.expression {
        Expression::StringLiteral(s) => format!("{head}.{}", s.value),
        _ => format!("{head}[?]"),
    }
}

fn computed_is_dynamic(m: &ComputedMemberExpression<'_>) -> bool {
    !matches!(&m.expression, Expression::StringLiteral(_) | Expression::NumericLiteral(_))
}

impl<'a, 'r> Visit<'a> for Collector<'r> {
    fn visit_call_expression(&mut self, expr: &oxc_ast::ast::CallExpression<'a>) {
        let callee_name = self.resolve_callee_name(&expr.callee);
        let args = expr.arguments.iter().map(|a| self.arg_shape(a)).collect::<Vec<_>>();

        // Specialize `require("x")` so consumers don't have to grub
        // through args for it.
        if callee_name.as_deref() == Some("require") {
            let target = match expr.arguments.first() {
                Some(Argument::StringLiteral(s)) => Some(s.value.to_string()),
                _ => None,
            };
            self.analysis.requires.push(RequireCall {
                target,
                span: span_to_tuple(expr.span),
            });
        }

        self.analysis.calls.push(CallSite {
            callee_name,
            args,
            span: span_to_tuple(expr.span),
        });
        walk::walk_call_expression(self, expr);
    }

    fn visit_static_member_expression(&mut self, expr: &StaticMemberExpression<'a>) {
        self.analysis.member_accesses.push(MemberAccess {
            path: static_member_path(expr),
            computed_dynamic: false,
            span: span_to_tuple(expr.span),
        });
        walk::walk_static_member_expression(self, expr);
    }

    fn visit_computed_member_expression(&mut self, expr: &ComputedMemberExpression<'a>) {
        self.analysis.member_accesses.push(MemberAccess {
            path: computed_member_path(expr),
            computed_dynamic: computed_is_dynamic(expr),
            span: span_to_tuple(expr.span),
        });
        walk::walk_computed_member_expression(self, expr);
    }

    fn visit_string_literal(&mut self, lit: &StringLiteral<'a>) {
        self.analysis.string_literals.push(StringLit {
            value: lit.value.to_string(),
            span: span_to_tuple(lit.span),
        });
        // No recursion — string literals have no children we care
        // about.
    }

    fn visit_template_literal(&mut self, lit: &oxc_ast::ast::TemplateLiteral<'a>) {
        // Treat the full template span as "in string literal" for
        // `is_in_comment_or_string` callers. Quasi expressions
        // (`${...}`) interleave with text, but for FP-suppression
        // purposes the inner expression bytes don't matter — we
        // just need regex hits on quasi *text* to look like
        // strings, which the full-span entry achieves.
        self.analysis.string_literals.push(StringLit {
            value: String::new(),
            span: span_to_tuple(lit.span),
        });
        walk::walk_template_literal(self, lit);
    }
}

