//! Local-LLM implementations of the small AI features the Warp server normally provides
//! (command search, workflow metadata, Warp AI dialogue, model lists).
//!
//! Prompt building and response parsing are pure functions so they can be unit tested without a
//! network. The network entry points are thin wrappers around [`crate::ai::local_llm`].

use std::collections::HashMap;

use chrono::{Duration, Utc};
use serde::Deserialize;
use warp_graphql::scalars::time::ServerTimestamp;

use crate::ai::llms::{
    AvailableLLMs, LLMContextWindow, LLMInfo, LLMProvider, LLMUsageMetadata, ModelsByFeature,
};
use crate::ai::local_llm::{self, ChatMessage, LocalLlmConfig};
use crate::ai::request_usage_model::{RequestLimitInfo, RequestLimitRefreshDuration};
use crate::ai_assistant::execution_context::WarpAiExecutionContext;
use crate::ai_assistant::utils::TranscriptPart;
use crate::ai_assistant::AIGeneratedCommand;
use crate::drive::workflows::ai_assist::{GeneratedArgument, GeneratedCommandMetadata};

// ---------------------------------------------------------------------------------------------
// JSON extraction
// ---------------------------------------------------------------------------------------------

/// Pulls the first JSON object or array out of free-form model output: strips markdown code
/// fences and tolerates prose before/after the JSON. Returns the JSON substring.
pub(crate) fn extract_json(text: &str) -> Option<&str> {
    let start = text.find(['{', '['])?;
    let bytes = text.as_bytes();
    let (open, close) = if bytes[start] == b'{' {
        (b'{', b'}')
    } else {
        (b'[', b']')
    };
    let (mut depth, mut in_str, mut escaped) = (0usize, false, false);
    for (i, &b) in bytes.iter().enumerate().skip(start) {
        if in_str {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_str = false;
            }
            continue;
        }
        match b {
            b'"' => in_str = true,
            b if b == open => depth += 1,
            b if b == close => {
                depth -= 1;
                if depth == 0 {
                    return Some(&text[start..=i]);
                }
            }
            _ => {}
        }
    }
    None
}

fn parse_json<T: for<'de> Deserialize<'de>>(text: &str) -> Option<T> {
    serde_json::from_str(extract_json(text)?).ok()
}

// ---------------------------------------------------------------------------------------------
// Natural language -> commands
// ---------------------------------------------------------------------------------------------

/// Number of candidate commands requested (matches the server's typical response).
pub(crate) const COMMAND_SUGGESTION_COUNT: usize = 3;

fn environment_line(ctx: &Option<WarpAiExecutionContext>) -> String {
    match ctx {
        Some(ctx) => {
            let os = ctx
                .os
                .distribution
                .as_deref()
                .or(ctx.os.category.as_deref())
                .unwrap_or("unknown OS");
            match &ctx.shell_version {
                Some(v) => format!("The user is on {os} using the {} shell (version {v}).", ctx.shell_name),
                None => format!("The user is on {os} using the {} shell.", ctx.shell_name),
            }
        }
        None => "The user is on a Unix-like system using a POSIX shell.".to_owned(),
    }
}

pub(crate) fn build_command_messages(
    prompt: &str,
    ctx: &Option<WarpAiExecutionContext>,
) -> Vec<ChatMessage> {
    let system = format!(
        "You translate natural-language requests into shell commands for a terminal. {env}\n\
         Respond with ONLY a JSON object, no prose and no code fences, of this exact shape:\n\
         {{\"commands\":[{{\"command\":\"<shell command>\",\"description\":\"<short imperative title, under 60 chars>\",\
         \"parameters\":[{{\"id\":\"<name>\",\"description\":\"<what to fill in>\"}}]}}]}}\n\
         Return between 1 and {n} distinct candidate commands, best first. Use {{{{name}}}} placeholders in \
         the command for values the user must supply, and list each placeholder in \"parameters\" (use an \
         empty list if there are none). Never include explanations outside the JSON.",
        env = environment_line(ctx),
        n = COMMAND_SUGGESTION_COUNT,
    );
    vec![ChatMessage::system(system), ChatMessage::user(prompt)]
}

#[derive(Deserialize)]
struct RawCommands {
    commands: Vec<RawCommand>,
}

#[derive(Deserialize)]
struct RawCommand {
    command: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    parameters: Vec<RawCommandParam>,
}

#[derive(Deserialize)]
struct RawCommandParam {
    #[serde(alias = "name")]
    id: String,
    #[serde(default)]
    description: String,
}

/// Parses model output into commands. Accepts `{"commands":[...]}`, a bare array, or a single
/// command object. Returns `None` if nothing usable was found.
pub(crate) fn parse_commands(text: &str) -> Option<Vec<AIGeneratedCommand>> {
    let json = extract_json(text)?;
    let raw: Vec<RawCommand> = if let Ok(c) = serde_json::from_str::<RawCommands>(json) {
        c.commands
    } else if let Ok(v) = serde_json::from_str::<Vec<RawCommand>>(json) {
        v
    } else if let Ok(c) = serde_json::from_str::<RawCommand>(json) {
        vec![c]
    } else {
        return None;
    };
    let commands: Vec<_> = raw
        .into_iter()
        .filter(|c| !c.command.trim().is_empty())
        .take(COMMAND_SUGGESTION_COUNT)
        .map(|c| {
            let description = if c.description.trim().is_empty() {
                c.command.clone()
            } else {
                c.description
            };
            AIGeneratedCommand::new(
                c.command,
                description,
                c.parameters.into_iter().map(|p| (p.id, p.description)).collect(),
            )
        })
        .collect();
    (!commands.is_empty()).then_some(commands)
}

// ---------------------------------------------------------------------------------------------
// Command -> workflow metadata
// ---------------------------------------------------------------------------------------------

pub(crate) fn build_metadata_messages(command: &str) -> Vec<ChatMessage> {
    let system = "You write metadata for saved terminal workflows. Given a shell command, respond with ONLY a \
        JSON object, no prose and no code fences, of this exact shape:\n\
        {\"title\":\"<short title, under 60 chars>\",\"description\":\"<one or two sentences>\",\
        \"parameterized_command\":\"<the command with literal values that a user would change replaced by {{name}} placeholders>\",\
        \"parameters\":[{\"name\":\"<placeholder name>\",\"description\":\"<what to fill in>\",\"value\":\"<the original literal value>\"}]}\n\
        Only parameterize values that are genuinely variable (paths, names, hosts, ports). If nothing needs \
        parameterizing, return the command unchanged and an empty parameters list.";
    vec![ChatMessage::system(system), ChatMessage::user(command)]
}

#[derive(Deserialize)]
struct RawMetadata {
    #[serde(default)]
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default, alias = "command")]
    parameterized_command: String,
    #[serde(default)]
    parameters: Vec<RawMetadataParam>,
}

#[derive(Deserialize)]
struct RawMetadataParam {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    value: String,
}

/// Parses model output into workflow metadata. `original` is used when the model omitted the
/// parameterized command. Returns `None` when there is neither a title nor a description.
pub(crate) fn parse_metadata(text: &str, original: &str) -> Option<GeneratedCommandMetadata> {
    let raw: RawMetadata = parse_json(text)?;
    if raw.title.trim().is_empty() && raw.description.trim().is_empty() {
        return None;
    }
    let command = if raw.parameterized_command.trim().is_empty() {
        original.to_owned()
    } else {
        raw.parameterized_command
    };
    Some(GeneratedCommandMetadata {
        command,
        title: raw.title,
        description: raw.description,
        arguments: raw
            .parameters
            .into_iter()
            .map(|p| GeneratedArgument {
                name: p.name,
                description: p.description,
                default_value: p.value,
            })
            .collect(),
    })
}

// ---------------------------------------------------------------------------------------------
// Dialogue
// ---------------------------------------------------------------------------------------------

pub(crate) fn build_dialogue_messages(
    transcript: &[(String, String)],
    prompt: &str,
    ctx: &Option<WarpAiExecutionContext>,
) -> Vec<ChatMessage> {
    let system = format!(
        "You are a helpful terminal assistant embedded in a terminal emulator. {} Answer concisely in \
         Markdown. Put shell commands in fenced code blocks.",
        environment_line(ctx)
    );
    let mut messages = vec![ChatMessage::system(system)];
    for (user, assistant) in transcript {
        messages.push(ChatMessage::user(user.clone()));
        messages.push(ChatMessage::assistant(assistant.clone()));
    }
    messages.push(ChatMessage::user(prompt));
    messages
}

pub(crate) fn transcript_pairs(transcript: &[TranscriptPart]) -> Vec<(String, String)> {
    transcript
        .iter()
        .map(|p| {
            (
                p.raw_user_prompt().to_owned(),
                p.raw_assistant_answer().to_owned(),
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Models and limits
// ---------------------------------------------------------------------------------------------

fn llm_info(name: &str) -> LLMInfo {
    LLMInfo {
        display_name: name.to_owned(),
        base_model_name: name.to_owned(),
        id: name.to_owned().into(),
        reasoning_level: None,
        usage_metadata: LLMUsageMetadata {
            request_multiplier: 1,
            credit_multiplier: None,
        },
        description: Some("Local model".to_owned()),
        disable_reason: None,
        vision_supported: false,
        spec: None,
        provider: LLMProvider::Unknown,
        host_configs: HashMap::new(),
        discount_percentage: None,
        context_window: LLMContextWindow::default(),
    }
}

/// Builds the per-feature model lists from the server's model names. The configured model is
/// the default and is always present (inserted first if the server did not report it).
pub(crate) fn models_by_feature(configured: &str, reported: Vec<String>) -> ModelsByFeature {
    let mut names: Vec<String> = Vec::new();
    for n in std::iter::once(configured.to_owned()).chain(reported) {
        if !n.is_empty() && !names.contains(&n) {
            names.push(n);
        }
    }
    let available = || {
        AvailableLLMs::new(
            configured.to_owned().into(),
            names.iter().map(|n| llm_info(n)),
            None,
        )
        .expect("names always contains the configured model")
    };
    ModelsByFeature {
        agent_mode: available(),
        coding: available(),
        cli_agent: Some(available()),
        computer_use: Some(available()),
    }
}

pub(crate) async fn fetch_models() -> ModelsByFeature {
    let config = LocalLlmConfig::from_env();
    let reported = match local_llm::list_models(&config).await {
        Ok(m) => m,
        Err(e) => {
            log::debug!(target: "anonwarp::stub", "could not list local models: {e:#}");
            Vec::new()
        }
    };
    models_by_feature(&config.model, reported)
}

/// Request limits that never trigger credit/upgrade messaging.
pub(crate) fn unlimited_request_limit_info() -> RequestLimitInfo {
    RequestLimitInfo {
        limit: 999_999,
        num_requests_used_since_refresh: 0,
        included_usage_cents: None,
        usage_cents_used_since_last_refresh: None,
        next_refresh_time: ServerTimestamp::new(Utc::now() + Duration::days(30)),
        is_unlimited: true,
        request_limit_refresh_duration: RequestLimitRefreshDuration::Monthly,
        is_unlimited_voice: true,
        voice_request_limit: 999_999,
        voice_requests_used_since_last_refresh: 0,
        ..RequestLimitInfo::default()
    }
}

// ---------------------------------------------------------------------------------------------
// Network entry points
// ---------------------------------------------------------------------------------------------

pub(crate) async fn complete(messages: Vec<ChatMessage>, temperature: f32) -> anyhow::Result<String> {
    local_llm::chat_completion(&LocalLlmConfig::from_env(), &messages, Some(temperature)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_json_from_fences_and_prose() {
        let t = "Sure! Here you go:\n```json\n{\"a\": \"}{\", \"b\": [1,2]}\n```\nHope that helps";
        assert_eq!(extract_json(t), Some("{\"a\": \"}{\", \"b\": [1,2]}"));
        assert_eq!(extract_json("no json here"), None);
        assert_eq!(extract_json("{unterminated"), None);
    }

    #[test]
    fn parses_commands_in_several_shapes() {
        let wrapped = r#"```json
{"commands":[{"command":"ls -la {{dir}}","description":"List files","parameters":[{"id":"dir","description":"directory"}]},
{"command":"  ","description":"empty"},{"command":"du -sh *"}]}
```"#;
        let cmds = parse_commands(wrapped).unwrap();
        assert_eq!(cmds.len(), 2);
        assert!(parse_commands(r#"[{"command":"pwd","description":"Print dir"}]"#).is_some());
        assert!(parse_commands(r#"Here: {"command":"pwd"}"#).is_some());
        assert!(parse_commands("I cannot do that").is_none());
        assert!(parse_commands(r#"{"commands":[]}"#).is_none());
    }

    #[test]
    fn caps_command_count() {
        let many = r#"{"commands":[{"command":"a"},{"command":"b"},{"command":"c"},{"command":"d"}]}"#;
        assert_eq!(parse_commands(many).unwrap().len(), COMMAND_SUGGESTION_COUNT);
    }

    #[test]
    fn parses_metadata() {
        let t = r#"{"title":"Serve dir","description":"Starts a server.","parameterized_command":"python3 -m http.server {{port}}","parameters":[{"name":"port","description":"Port","value":"8000"}]}"#;
        let m = parse_metadata(t, "python3 -m http.server 8000").unwrap();
        assert_eq!(m.command, "python3 -m http.server {{port}}");
        assert_eq!(m.arguments.len(), 1);
        assert_eq!(m.arguments[0].default_value, "8000");
        let m = parse_metadata(r#"{"title":"T","description":"D"}"#, "echo hi").unwrap();
        assert_eq!(m.command, "echo hi");
        assert!(parse_metadata(r#"{"title":"","description":""}"#, "x").is_none());
        assert!(parse_metadata("garbage", "x").is_none());
    }

    #[test]
    fn prompts_are_well_formed() {
        let m = build_command_messages("list files", &None);
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].role, "system");
        assert!(m[0].content.contains("\"commands\""));
        assert_eq!(m[1].content, "list files");
        let m = build_metadata_messages("ls");
        assert!(m[0].content.contains("parameterized_command"));
        let d = build_dialogue_messages(&[("q".into(), "a".into())], "next", &None);
        assert_eq!(
            d.iter().map(|m| m.role.as_str()).collect::<Vec<_>>(),
            ["system", "user", "assistant", "user"]
        );
    }

    #[test]
    fn model_lists_always_contain_configured_default() {
        let m = models_by_feature("qwen", vec!["llama".into(), "qwen".into()]);
        assert!(m.cli_agent.is_some() && m.computer_use.is_some());
        let m = models_by_feature("qwen", vec![]);
        assert_eq!(m.agent_mode, m.coding);
    }

    #[test]
    fn limits_are_unlimited() {
        assert!(unlimited_request_limit_info().is_unlimited);
    }
}
