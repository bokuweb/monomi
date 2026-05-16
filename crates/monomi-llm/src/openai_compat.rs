//! OpenAI-compatible Chat Completions adjudicator.
//!
//! One adjudicator covers three common deployments:
//!
//! - **Ollama** — `base_url = http://localhost:11434/v1`, `model = "llama3.1"`
//!   (or any Ollama-served model that supports tool calling).
//! - **LM Studio / vLLM / llama.cpp server** — same shape, different host.
//! - **OpenAI** — `base_url = https://api.openai.com/v1`, `api_key` set.
//!
//! The model is asked to call a `record_verdict` function-tool with our
//! schema. If the model responds with plain JSON in `content` instead of
//! a proper tool call (some local models do this), we extract the first
//! `{…}` object as a fallback. Anything off-spec → `Ok(None)` so Stage
//! 1's verdict stands.

use async_trait::async_trait;
use monomi_core::{ArtifactId, RecommendedAction, Stage1Result, Stage2Result, Stage2Verdict};
use serde::{Deserialize, Serialize};

use crate::{
    context::Stage2Context,
    prompt::{build_user_message, SYSTEM_PROMPT},
    Adjudicator, AdjudicatorError,
};

pub struct OpenAiCompatAdjudicator {
    base_url: String,
    api_key: Option<String>,
    model: String,
    max_input_chars: usize,
    max_output_tokens: u32,
    http: reqwest::Client,
}

impl OpenAiCompatAdjudicator {
    /// Convenience constructor for a local Ollama instance.
    pub fn ollama(model: impl Into<String>) -> Self {
        let base = std::env::var("OLLAMA_HOST")
            .ok()
            .map(|h| {
                let h = h.trim_end_matches('/');
                if h.ends_with("/v1") {
                    h.to_string()
                } else {
                    format!("{h}/v1")
                }
            })
            .unwrap_or_else(|| "http://localhost:11434/v1".to_string());
        Self::new(base, None, model)
    }

    pub fn new(
        base_url: impl Into<String>,
        api_key: Option<String>,
        model: impl Into<String>,
    ) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            api_key,
            model: model.into(),
            max_input_chars: 120_000,
            // Local models may need a bit more headroom for tool-call JSON.
            max_output_tokens: 1024,
            http: reqwest::Client::builder()
                .user_agent(concat!("monomi-llm/", env!("CARGO_PKG_VERSION")))
                // Local inference can be slow; give the server time to
                // load the model on the first call.
                .timeout(std::time::Duration::from_secs(120))
                .build()
                .expect("reqwest client"),
        }
    }

    pub fn with_max_output_tokens(mut self, n: u32) -> Self {
        self.max_output_tokens = n;
        self
    }
}

#[async_trait]
impl Adjudicator for OpenAiCompatAdjudicator {
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
            "temperature": 0.0,
            "messages": [
                { "role": "system", "content": SYSTEM_PROMPT },
                { "role": "user",   "content": user_msg },
            ],
            "tools": [tool_schema()],
            "tool_choice": { "type": "function", "function": { "name": "record_verdict" } },
        });

        let url = format!("{}/chat/completions", self.base_url);
        let mut req = self
            .http
            .post(&url)
            .header("content-type", "application/json")
            .json(&body);
        if let Some(k) = &self.api_key {
            req = req.bearer_auth(k);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| AdjudicatorError::Transport(e.to_string()))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AdjudicatorError::Api(format!("HTTP {status}: {text}")));
        }
        let parsed: ChatResponse = resp
            .json()
            .await
            .map_err(|e| AdjudicatorError::InvalidResponse(e.to_string()))?;

        let choice = parsed
            .choices
            .into_iter()
            .next()
            .ok_or_else(|| AdjudicatorError::InvalidResponse("no choices".into()))?;

        let tool_args_json = extract_tool_args(&choice.message)
            .or_else(|| extract_inline_json(choice.message.content.as_deref()))
            .ok_or_else(|| {
                AdjudicatorError::InvalidResponse(
                    "no record_verdict tool call and no inline JSON".into(),
                )
            })?;

        let verdict: ToolInput = serde_json::from_str(&tool_args_json)
            .map_err(|e| AdjudicatorError::InvalidResponse(format!("verdict json: {e}")))?;

        let usage = parsed.usage.unwrap_or_default();
        Ok(Some(Stage2Result {
            model: self.model.clone(),
            verdict: verdict.verdict,
            confidence: verdict.confidence.clamp(0.0, 1.0),
            reasoning: verdict.reasoning,
            indicators: verdict.indicators,
            recommended_action: verdict.recommended_action,
            tokens_in: usage.prompt_tokens,
            tokens_out: usage.completion_tokens,
        }))
    }
}

fn tool_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "function",
        "function": {
            "name": "record_verdict",
            "description": "Record the final adjudication for this package.",
            "parameters": {
                "type": "object",
                "required": ["verdict", "confidence", "reasoning", "indicators", "recommended_action"],
                "properties": {
                    "verdict": {
                        "type": "string",
                        "enum": ["clean", "suspicious", "malicious"],
                    },
                    "confidence": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                    "reasoning": { "type": "string" },
                    "indicators": { "type": "array", "items": { "type": "string" } },
                    "recommended_action": {
                        "type": "string",
                        "enum": ["allow", "warn", "block"],
                    },
                },
            },
        }
    })
}

fn extract_tool_args(msg: &ChatMessage) -> Option<String> {
    let tc = msg.tool_calls.as_ref()?;
    let call = tc.iter().find(|c| c.function.name == "record_verdict")?;
    Some(call.function.arguments.clone())
}

/// Fallback for local models that emit `{...}` in `content` instead
/// of calling the tool. Picks the first balanced top-level object.
fn extract_inline_json(content: Option<&str>) -> Option<String> {
    let s = content?;
    let bytes = s.as_bytes();
    let start = bytes.iter().position(|&b| b == b'{')?;
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escape = false;
    for (i, &b) in bytes.iter().enumerate().skip(start) {
        if in_string {
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(s[start..=i].to_string());
                }
            }
            _ => {}
        }
    }
    None
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
struct ChatResponse {
    choices: Vec<ChatChoice>,
    #[serde(default)]
    usage: Option<Usage>,
}

#[derive(Debug, Deserialize)]
struct ChatChoice {
    message: ChatMessage,
}

#[derive(Debug, Deserialize)]
struct ChatMessage {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tool_calls: Option<Vec<ToolCall>>,
}

#[derive(Debug, Deserialize)]
struct ToolCall {
    function: ToolCallFunction,
}

#[derive(Debug, Deserialize)]
struct ToolCallFunction {
    name: String,
    arguments: String,
}

#[derive(Debug, Default, Deserialize)]
struct Usage {
    #[serde(default)]
    prompt_tokens: u32,
    #[serde(default)]
    completion_tokens: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_first_balanced_object() {
        let s = "prelude {\"a\": {\"b\": 1}} trailing {\"x\":2}";
        assert_eq!(
            extract_inline_json(Some(s)).as_deref(),
            Some(r#"{"a": {"b": 1}}"#)
        );
    }

    #[test]
    fn handles_strings_with_braces() {
        let s = r#"text {"msg": "has } brace", "n": 1}"#;
        assert_eq!(
            extract_inline_json(Some(s)).as_deref(),
            Some(r#"{"msg": "has } brace", "n": 1}"#)
        );
    }

    #[test]
    fn handles_escaped_quotes() {
        let s = r#"{"a": "x\"y", "b": 1}"#;
        assert_eq!(extract_inline_json(Some(s)).as_deref(), Some(s));
    }

    #[test]
    fn returns_none_on_unbalanced() {
        assert_eq!(extract_inline_json(Some("{unbalanced")), None);
        assert_eq!(extract_inline_json(Some("no braces here")), None);
    }
}
