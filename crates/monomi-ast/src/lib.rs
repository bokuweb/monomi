//! JS/TS AST analysis for monomi rules.
//!
//! # Why this crate exists
//!
//! Stage 1 rules historically used regex over raw source. Regex has
//! two structural failure modes:
//!
//! - **False positives** in comments and string literals
//!   (`// fs.rmSync(homedir())` should not trip `NPM039`).
//! - **False negatives** in minified payloads where packing breaks
//!   the surrounding tokens the regex expected (`;fs.rmSync(os.
//!   homedir(),{recursive:!0})`).
//!
//! `monomi-ast` parses with `oxc_parser` and exposes a *summary*
//! struct (`JsAnalysis`) that rules query via small combinators.
//! The summary is materialized eagerly in one walk, so consumers
//! never see the AST lifetime (`'a` tied to an `Allocator`) — which
//! sidesteps the self-referential-struct problem that plagues most
//! Rust AST consumers.
//!
//! # Why a summary rather than a YAML DSL
//!
//! At 50 rules monomi is small enough that a per-rule Rust file is
//! still the cheapest editing experience, and many rules need
//! cross-cut state (lifecycle bodies, registry metadata, top-1k
//! corpus) a pure-AST DSL cannot express. The combinator layer
//! gives the *expressive* parts of an ESLint selector ("all calls
//! to `eval`", "any string concatenation of arity ≥ 3") while
//! keeping the type-safe Rust authoring experience. If external
//! contributors ever justify a YAML DSL, this summary becomes its
//! runtime.

mod analysis;
mod cache;

pub use analysis::{
    analyze_js, ArgShape, CallSite, CommentSpan, JsAnalysis, MemberAccess, RequireCall, StringLit,
};
pub use cache::{downcast, AstCache};
