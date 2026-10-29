//! Client for a local OpenAI-compatible LLM server (Ollama, vLLM, llama.cpp, LM Studio, ...).
//!
//! AnonWarp has no Warp server, so every AI feature that used to go through it talks to this
//! instead. Configuration comes from the environment so it can point anywhere on the LAN:
//!
//! - `ANONWARP_LLM_BASE_URL` — OpenAI-compatible base URL including `/v1`
//!   (default `http://localhost:11434/v1`, Ollama's default).
//! - `ANONWARP_LLM_MODEL` — model name sent in requests (default `llama3.1`).
//! - `ANONWARP_LLM_API_KEY` — optional bearer token (vLLM `--api-key`, proxies).

use anyhow::{Context as _, Result, anyhow};
use futures::{Stream, StreamExt as _};
use serde::{Deserialize, Serialize};

const DEFAULT_BASE_URL: &str = "http://localhost:11434/v1";
const DEFAULT_MODEL: &str = "llama3.1";

#[derive(Clone, Debug)]
pub struct LocalLlmConfig {
    pub base_url: String,
    pub model: String,
    pub api_key: Option<String>,
}

impl LocalLlmConfig {
    pub fn from_env() -> Self {
        let get = |key: &str| std::env::var(key).ok().filter(|v| !v.trim().is_empty());
        Self {
            base_url: get("ANONWARP_LLM_BASE_URL")
                .unwrap_or_else(|| DEFAULT_BASE_URL.to_owned())
                .trim_end_matches('/')
                .to_owned(),
            model: get("ANONWARP_LLM_MODEL").unwrap_or_else(|| DEFAULT_MODEL.to_owned()),
            api_key: get("ANONWARP_LLM_API_KEY"),
        }
    }

    fn chat_url(&self) -> String {
        format!("{}/chat/completions", self.base_url)
    }

    fn models_url(&self) -> String {
        format!("{}/models", self.base_url)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

impl ChatMessage {
    pub fn new(role: &str, content: impl Into<String>) -> Self {
        Self {
            role: role.to_owned(),
            content: content.into(),
        }
    }
    pub fn system(content: impl Into<String>) -> Self {
        Self::new("system", content)
    }
    pub fn user(content: impl Into<String>) -> Self {
        Self::new("user", content)
    }
    pub fn assistant(content: impl Into<String>) -> Self {
        Self::new("assistant", content)
    }
}

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: &'a [ChatMessage],
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<ChatChoice>,
}

#[derive(Deserialize)]
struct ChatChoice {
    #[serde(default)]
    message: Option<ChatMessageOut>,
    #[serde(default)]
    delta: Option<ChatMessageOut>,
}

#[derive(Deserialize)]
struct ChatMessageOut {
    #[serde(default)]
    content: Option<String>,
}

#[derive(Deserialize)]
struct ModelList {
    data: Vec<ModelEntry>,
}

#[derive(Deserialize)]
struct ModelEntry {
    id: String,
}

fn client() -> &'static http_client::Client {
    static CLIENT: std::sync::OnceLock<http_client::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(http_client::Client::new_external)
}

fn with_auth<'a>(
    builder: http_client::RequestBuilder<'a>,
    config: &LocalLlmConfig,
) -> http_client::RequestBuilder<'a> {
    match &config.api_key {
        Some(key) => builder.bearer_auth(key),
        None => builder,
    }
}

/// One non-streaming chat completion; returns the assistant text.
pub async fn chat_completion(
    config: &LocalLlmConfig,
    messages: &[ChatMessage],
    temperature: Option<f32>,
) -> Result<String> {
    let body = ChatRequest {
        model: &config.model,
        messages,
        stream: false,
        temperature,
    };
    let response = with_auth(client().post(config.chat_url()).json(&body), config)
        .send()
        .await
        .with_context(|| format!("local LLM request to {} failed", config.chat_url()))?
        .error_for_status()
        .context("local LLM returned an error status")?;
    let parsed: ChatResponse = response.json().await.context("invalid local LLM response")?;
    parsed
        .choices
        .into_iter()
        .next()
        .and_then(|c| c.message)
        .and_then(|m| m.content)
        .ok_or_else(|| anyhow!("local LLM response had no message content"))
}

/// Streaming chat completion; yields content deltas as they arrive.
///
/// Native only: the SSE stream type is `!Send` on wasm.
#[cfg(not(target_family = "wasm"))]
pub fn chat_completion_stream(
    config: &LocalLlmConfig,
    messages: &[ChatMessage],
) -> impl Stream<Item = Result<String>> + Send + 'static + use<> {
    let body = ChatRequest {
        model: &config.model,
        messages,
        stream: true,
        temperature: None,
    };
    let events = with_auth(client().post(config.chat_url()).json(&body), config).eventsource();
    events.filter_map(|event| async move {
        match event {
            Ok(reqwest_eventsource::Event::Open) => None,
            Ok(reqwest_eventsource::Event::Message(message)) => {
                if message.data.trim() == "[DONE]" {
                    return None;
                }
                match serde_json::from_str::<ChatResponse>(&message.data) {
                    Ok(chunk) => chunk
                        .choices
                        .into_iter()
                        .next()
                        .and_then(|c| c.delta)
                        .and_then(|d| d.content)
                        .filter(|text| !text.is_empty())
                        .map(Ok),
                    Err(err) => Some(Err(anyhow!("invalid local LLM stream chunk: {err}"))),
                }
            }
            // The server closing the stream after `[DONE]` is the normal end.
            Err(reqwest_eventsource::Error::StreamEnded) => None,
            Err(err) => Some(Err(anyhow!("local LLM stream failed: {err}"))),
        }
    })
}

/// Model ids the server reports at `GET {base_url}/models`.
pub async fn list_models(config: &LocalLlmConfig) -> Result<Vec<String>> {
    let response = with_auth(client().get(config.models_url()), config)
        .send()
        .await
        .with_context(|| format!("local LLM request to {} failed", config.models_url()))?
        .error_for_status()
        .context("local LLM returned an error status")?;
    let list: ModelList = response.json().await.context("invalid model list")?;
    Ok(list.data.into_iter().map(|m| m.id).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_and_trailing_slash() {
        let config = LocalLlmConfig {
            base_url: "http://gpu-box:8000/v1".to_owned(),
            model: "m".to_owned(),
            api_key: None,
        };
        assert_eq!(config.chat_url(), "http://gpu-box:8000/v1/chat/completions");
        assert_eq!(config.models_url(), "http://gpu-box:8000/v1/models");
    }

    #[test]
    fn parses_stream_delta_and_full_message() {
        let delta: ChatResponse =
            serde_json::from_str(r#"{"choices":[{"delta":{"content":"hi"}}]}"#).unwrap();
        assert_eq!(delta.choices[0].delta.as_ref().unwrap().content.as_deref(), Some("hi"));
        let full: ChatResponse =
            serde_json::from_str(r#"{"choices":[{"message":{"role":"assistant","content":"yo"}}]}"#)
                .unwrap();
        assert_eq!(full.choices[0].message.as_ref().unwrap().content.as_deref(), Some("yo"));
    }
}
