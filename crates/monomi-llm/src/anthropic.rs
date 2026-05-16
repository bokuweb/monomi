//! Anthropic Messages-API adjudicator.
//!
//! Uses tool-use to force the model into a structured `record_verdict`
//! call. Anything off-spec (wrong tool, malformed args, network error)
//! is mapped to `Ok(None)` — Stage 1's verdict stands.

use async_trait::async_trait;
use monomi_core::{ArtifactId, RecommendedAction, Stage1Result, Stage2Result, Stage2Verdict};
use serde::{Deserialize, Serialize};

use crate::{
    context::Stage2Context,
    prompt::{build_user_message, SYSTEM_PROMPT},
    Adjudicator, AdjudicatorError,
};

const ENDPOINT: &str = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION: &str = "2023-06-01";

pub struct AnthropicAdjudicator {
    api_key: String,
    model: String,
    max_input_chars: usize,
    max_output_tokens: u32,
    http: reqwest::Client,
}

impl AnthropicAdjudicator {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            // Conservative default — Sonnet is ~10× cheaper than
            // top-tier Opus and adequate for this judging task.
            model: "claude-sonnet-4-6".to_string(),
            // Matches the V1 ContextLimits default; bigger callers
            // can raise this. Larger contexts get declined fail-open.
            max_input_chars: 60_000,
            max_output_tokens: 1024,
            http: reqwest::Client::builder()
                .user_agent(concat!("monomi-llm/", env!("CARGO_PKG_VERSION")))
                // Explicit per-call deadline so a slow Anthropic
                // response can never wedge the feed worker pool.
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .expect("reqwest client"),
        }
    }

    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }
}

#[async_trait]
impl Adjudicator for AnthropicAdjudicator {
    async fn adjudicate(
        &self,
        artifact: &ArtifactId,
        _stage1: &Stage1Result,
        context: &Stage2Context,
    ) -> Result<Option<Stage2Result>, AdjudicatorError> {
        if context.approx_chars > self.max_input_chars {
            tracing::warn!(
                approx_chars = context.approx_chars,
                limit = self.max_input_chars,
                "Stage 2 context exceeds budget; declining"
            );
            return Ok(None);
        }

        let user_msg = build_user_message(context, &artifact.name, &artifact.version);

        let body = serde_json::json!({
            "model": self.model,
            "max_tokens": self.max_output_tokens,
            "system": SYSTEM_PROMPT,
            "tools": [tool_schema()],
            "tool_choice": { "type": "tool", "name": "record_verdict" },
            "messages": [{
                "role": "user",
                "content": user_msg,
            }],
        });

        let resp = self
            .http
            .post(ENDPOINT)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| AdjudicatorError::Transport(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AdjudicatorError::Api(format!("HTTP {status}: {text}")));
        }

        let parsed: AnthropicResponse = resp
            .json()
            .await
            .map_err(|e| AdjudicatorError::InvalidResponse(e.to_string()))?;

        let tool_input = parsed
            .content
            .into_iter()
            .find_map(|c| match c {
                AnthropicBlock::ToolUse { name, input, .. } if name == "record_verdict" => {
                    Some(input)
                }
                _ => None,
            })
            .ok_or_else(|| {
                AdjudicatorError::InvalidResponse("no record_verdict tool call".into())
            })?;

        let verdict: ToolInput = serde_json::from_value(tool_input)
            .map_err(|e| AdjudicatorError::InvalidResponse(e.to_string()))?;

        let usage = parsed.usage.unwrap_or_default();
        Ok(Some(Stage2Result {
            model: self.model.clone(),
            verdict: verdict.verdict,
            confidence: verdict.confidence.clamp(0.0, 1.0),
            reasoning: verdict.reasoning,
            indicators: verdict.indicators,
            recommended_action: verdict.recommended_action,
            tokens_in: usage.input_tokens,
            tokens_out: usage.output_tokens,
        }))
    }
}

fn tool_schema() -> serde_json::Value {
    serde_json::json!({
        "name": "record_verdict",
        "description": "Record the final adjudication for this package.",
        "input_schema": {
            "type": "object",
            "required": ["verdict", "confidence", "reasoning", "indicators", "recommended_action"],
            "properties": {
                "verdict": {
                    "type": "string",
                    "enum": ["clean", "suspicious", "malicious"],
                },
                "confidence": {
                    "type": "number",
                    "minimum": 0.0,
                    "maximum": 1.0,
                },
                "reasoning": {
                    "type": "string",
                    "description": "One or two sentences citing the strongest evidence.",
                },
                "indicators": {
                    "type": "array",
                    "items": { "type": "string" },
                },
                "recommended_action": {
                    "type": "string",
                    "enum": ["allow", "warn", "block"],
                },
            },
        },
    })
}

#[derive(Debug, Deserialize, Serialize)]
struct ToolInput {
    verdict: Stage2Verdict,
    confidence: f32,
    reasoning: String,
    #[serde(default)]
    indicators: Vec<String>,
    recommended_action: RecommendedAction,
}

#[derive(Debug, Deserialize)]
struct AnthropicResponse {
    content: Vec<AnthropicBlock>,
    #[serde(default)]
    usage: Option<Usage>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum AnthropicBlock {
    Text {
        #[allow(dead_code)]
        text: String,
    },
    ToolUse {
        #[allow(dead_code)]
        id: String,
        name: String,
        input: serde_json::Value,
    },
}

#[derive(Debug, Default, Deserialize)]
struct Usage {
    #[serde(default)]
    input_tokens: u32,
    #[serde(default)]
    output_tokens: u32,
}
