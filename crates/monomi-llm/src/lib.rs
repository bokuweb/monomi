//! Stage 2 — LLM adjudication of Stage 1's ambiguous findings.
//!
//! Design contract (see architecture.md):
//! - Called *only* for packages Stage 1 flagged Suspicious, or those
//!   whose findings explicitly set `defers_to_stage2: true`.
//! - Sends *text*, never tarball bytes.
//! - Hard input-token cap; over-budget packages return `None` and the
//!   caller falls back to the Stage 1 verdict (with the reason logged).
//! - Any error (network, malformed response, schema mismatch) →
//!   fail-open: `Ok(None)`. The Stage 1 verdict still ships.

mod anthropic;
mod context;
mod noop;
mod openai_compat;
mod prompt;

pub use anthropic::AnthropicAdjudicator;
pub use context::{build_context, Stage2Context};
pub use noop::NoopAdjudicator;
pub use openai_compat::OpenAiCompatAdjudicator;

use async_trait::async_trait;
use monomi_core::{ArtifactId, Stage1Result, Stage2Result};

#[async_trait]
pub trait Adjudicator: Send + Sync {
    /// Returns `Ok(None)` when Stage 2 declined or failed open — the
    /// caller MUST treat the Stage 1 verdict as final in that case.
    async fn adjudicate(
        &self,
        artifact: &ArtifactId,
        stage1: &Stage1Result,
        context: &Stage2Context,
    ) -> Result<Option<Stage2Result>, AdjudicatorError>;
}

#[derive(Debug, thiserror::Error)]
pub enum AdjudicatorError {
    #[error("transport: {0}")]
    Transport(String),
    #[error("api: {0}")]
    Api(String),
    #[error("invalid response: {0}")]
    InvalidResponse(String),
}
