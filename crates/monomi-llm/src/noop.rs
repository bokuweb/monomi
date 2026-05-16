use async_trait::async_trait;
use monomi_core::{ArtifactId, Stage1Result, Stage2Result};

use crate::{Adjudicator, AdjudicatorError, Stage2Context};

/// Adjudicator that always declines (`Ok(None)`).
///
/// Used when no API key is configured, when the CLI is invoked with
/// `--stage1-only`, or in tests / air-gapped environments.
pub struct NoopAdjudicator;

#[async_trait]
impl Adjudicator for NoopAdjudicator {
    async fn adjudicate(
        &self,
        _artifact: &ArtifactId,
        _stage1: &Stage1Result,
        _context: &Stage2Context,
    ) -> Result<Option<Stage2Result>, AdjudicatorError> {
        Ok(None)
    }
}
