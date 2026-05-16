//! Token-budget cap for Stage 2.
//!
//! Production deployments need a hard ceiling on LLM spend so a
//! burst of suspicious packages doesn't drain an API account. The
//! `BudgetedAdjudicator` wrapper enforces an hourly and a daily
//! token cap; once the cap is hit, calls return `Ok(None)` and
//! the merge logic falls back to the Stage 1 verdict — same
//! semantics as any other Stage 2 failure (fail-open).
//!
//! Counts are best-effort: we reserve an *estimated* token cost
//! up front (so two parallel workers can't both squeak through a
//! near-zero remainder) and reconcile with the actual usage
//! reported by the provider when the call returns. If the actual
//! is higher than the reservation, we're temporarily over-budget
//! by at most one call's worth.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use monomi_core::{ArtifactId, Stage1Result, Stage2Result};

use crate::{context::Stage2Context, Adjudicator, AdjudicatorError};

#[derive(Debug, Clone, Copy)]
pub struct BudgetConfig {
    pub hourly_input_tokens: u32,
    pub hourly_output_tokens: u32,
    pub daily_input_tokens: u32,
    pub daily_output_tokens: u32,
    /// Per-call output cost reservation. We don't know the response
    /// size in advance, so we set this to the adjudicator's
    /// `max_output_tokens` value (1024 by default).
    pub per_call_output_reserve: u32,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        // Sensible upper bound that maps to roughly $5 / day on
        // Claude Sonnet at current pricing. Operators tune via CLI.
        Self {
            hourly_input_tokens: 500_000,
            hourly_output_tokens: 30_000,
            daily_input_tokens: 5_000_000,
            daily_output_tokens: 250_000,
            per_call_output_reserve: 1024,
        }
    }
}

pub struct TokenBudget {
    cfg: BudgetConfig,
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    hour_start: Instant,
    hour_in: u32,
    hour_out: u32,
    day_start: Instant,
    day_in: u32,
    day_out: u32,
}

impl TokenBudget {
    pub fn new(cfg: BudgetConfig) -> Self {
        let now = Instant::now();
        Self {
            cfg,
            state: Mutex::new(State {
                hour_start: now,
                hour_in: 0,
                hour_out: 0,
                day_start: now,
                day_in: 0,
                day_out: 0,
            }),
        }
    }

    /// Reserve `est_in` input tokens + `per_call_output_reserve`
    /// output tokens. Returns false when reservation would exceed
    /// either window's cap.
    fn try_reserve(&self, est_in: u32) -> bool {
        let mut s = self.state.lock().expect("budget mutex");
        let now = Instant::now();
        if now.duration_since(s.hour_start) >= Duration::from_secs(3600) {
            s.hour_start = now;
            s.hour_in = 0;
            s.hour_out = 0;
        }
        if now.duration_since(s.day_start) >= Duration::from_secs(86_400) {
            s.day_start = now;
            s.day_in = 0;
            s.day_out = 0;
        }
        let reserve_out = self.cfg.per_call_output_reserve;
        if s.hour_in.saturating_add(est_in) > self.cfg.hourly_input_tokens
            || s.hour_out.saturating_add(reserve_out) > self.cfg.hourly_output_tokens
            || s.day_in.saturating_add(est_in) > self.cfg.daily_input_tokens
            || s.day_out.saturating_add(reserve_out) > self.cfg.daily_output_tokens
        {
            return false;
        }
        s.hour_in = s.hour_in.saturating_add(est_in);
        s.hour_out = s.hour_out.saturating_add(reserve_out);
        s.day_in = s.day_in.saturating_add(est_in);
        s.day_out = s.day_out.saturating_add(reserve_out);
        true
    }

    /// Reconcile reserved vs actual after a successful LLM call.
    fn reconcile(&self, est_in: u32, actual_in: u32, actual_out: u32) {
        let mut s = self.state.lock().expect("budget mutex");
        let reserve_out = self.cfg.per_call_output_reserve;
        // Refund the difference (or charge more) for input.
        if actual_in >= est_in {
            let extra = actual_in - est_in;
            s.hour_in = s.hour_in.saturating_add(extra);
            s.day_in = s.day_in.saturating_add(extra);
        } else {
            let refund = est_in - actual_in;
            s.hour_in = s.hour_in.saturating_sub(refund);
            s.day_in = s.day_in.saturating_sub(refund);
        }
        // Output: replace the reservation with the actual.
        if actual_out >= reserve_out {
            let extra = actual_out - reserve_out;
            s.hour_out = s.hour_out.saturating_add(extra);
            s.day_out = s.day_out.saturating_add(extra);
        } else {
            let refund = reserve_out - actual_out;
            s.hour_out = s.hour_out.saturating_sub(refund);
            s.day_out = s.day_out.saturating_sub(refund);
        }
    }

    /// Refund a full reservation when the LLM call errored before
    /// consuming anything.
    fn refund(&self, est_in: u32) {
        let mut s = self.state.lock().expect("budget mutex");
        s.hour_in = s.hour_in.saturating_sub(est_in);
        s.hour_out = s.hour_out.saturating_sub(self.cfg.per_call_output_reserve);
        s.day_in = s.day_in.saturating_sub(est_in);
        s.day_out = s.day_out.saturating_sub(self.cfg.per_call_output_reserve);
    }
}

pub struct BudgetedAdjudicator {
    inner: std::sync::Arc<dyn Adjudicator>,
    budget: std::sync::Arc<TokenBudget>,
}

impl BudgetedAdjudicator {
    pub fn new(
        inner: std::sync::Arc<dyn Adjudicator>,
        budget: std::sync::Arc<TokenBudget>,
    ) -> Self {
        Self { inner, budget }
    }
}

#[async_trait]
impl Adjudicator for BudgetedAdjudicator {
    async fn adjudicate(
        &self,
        artifact: &ArtifactId,
        stage1: &Stage1Result,
        context: &Stage2Context,
    ) -> Result<Option<Stage2Result>, AdjudicatorError> {
        // ~4 chars per token is a conservative estimate for the
        // mixed prose + code we send.
        let est_in = ((context.approx_chars / 4) as u32).max(1);
        if !self.budget.try_reserve(est_in) {
            tracing::warn!(
                package = %artifact.name,
                version = %artifact.version,
                est_in,
                "stage 2 budget exhausted; declining"
            );
            return Ok(None);
        }
        match self.inner.adjudicate(artifact, stage1, context).await {
            Ok(Some(r)) => {
                self.budget.reconcile(est_in, r.tokens_in, r.tokens_out);
                Ok(Some(r))
            }
            Ok(None) => {
                self.budget.refund(est_in);
                Ok(None)
            }
            Err(e) => {
                self.budget.refund(est_in);
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> BudgetConfig {
        BudgetConfig {
            hourly_input_tokens: 10,
            hourly_output_tokens: 10,
            daily_input_tokens: 100,
            daily_output_tokens: 100,
            per_call_output_reserve: 5,
        }
    }

    #[test]
    fn reserve_succeeds_under_budget_and_fails_over_it() {
        let b = TokenBudget::new(cfg());
        // Reserve 3 in + 5 out → fits.
        assert!(b.try_reserve(3));
        // Reserve 7 in + 5 out → would exceed hourly out (5 + 5 = 10
        // exactly == cap; cap is `>`, so equal is OK).
        // Second 3-in call lands at (6, 10); cap is `>`, so 10 == 10 fits.
        assert!(b.try_reserve(3));
        // Any further reservation has to exceed the 10-out cap.
        assert!(!b.try_reserve(1));
    }

    #[test]
    fn refund_releases_capacity() {
        let b = TokenBudget::new(cfg());
        assert!(b.try_reserve(10));
        b.refund(10);
        assert!(b.try_reserve(10));
    }

    #[test]
    fn reconcile_actual_below_reservation_refunds() {
        let b = TokenBudget::new(cfg());
        assert!(b.try_reserve(10));
        b.reconcile(10, 4, 2); // actual much lower
                               // Should free capacity again.
        assert!(b.try_reserve(5));
    }
}
