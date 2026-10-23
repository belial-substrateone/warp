//! Offline [`AIClient`]: no AI features are reachable without the Warp server, so every call
//! returns an empty/benign value or an "unsupported offline" error.

use std::collections::HashMap;
#[cfg(not(target_family = "wasm"))]
use std::path::Path;

use ai::api_keys::ChatGPTConnectionStatus;
use ai::index::full_source_code_embedding::store_client::IntermediateNode;
use ai::index::full_source_code_embedding::{
    self, ContentHash, EmbeddingConfig, NodeHash, RepoMetadata,
};
use async_trait::async_trait;
#[cfg(not(target_family = "wasm"))]
use bytes::Bytes;
use chrono::{DateTime, Utc};
use warp_graphql::ai::AgentTaskState;
use warp_graphql::queries::get_conversation_usage::ConversationUsage;
use warp_graphql::queries::get_scheduled_agent_history::ScheduledAgentHistory;
use warp_multi_agent_api::ConversationData;

use super::ai_local as local;
use super::{StubUnsupported, stub_call, unsupported};
use crate::ai::agent::api::ServerConversationToken;
use crate::ai::agent::conversation::{AIAgentConversationFormat, ServerAIConversationMetadata};
use crate::ai::ambient_agents::AmbientAgentTaskId;
use crate::ai::generate_code_review_content::api::{
    GenerateCodeReviewContentRequest, GenerateCodeReviewContentResponse,
};
use crate::ai::harness_availability::HarnessAvailability;
use crate::ai::llms::ModelsByFeature;
use crate::ai::{AICreditAvailability, RequestUsageInfo};
use crate::ai_assistant::execution_context::WarpAiExecutionContext;
use crate::ai_assistant::requests::GenerateDialogueResult;
use crate::ai_assistant::utils::TranscriptPart;
use crate::ai_assistant::{AIGeneratedCommand, GenerateCommandsFromNaturalLanguageError};
use crate::drive::workflows::ai_assist::{GeneratedCommandMetadata, GeneratedCommandMetadataError};
use crate::server::server_api::ai::*;
use crate::server::team_scope::RequestTeamScope;
use crate::terminal::model::block::SerializedBlock;
use crate::ai::ambient_agents::AmbientAgentTask;

/// AI client that never contacts the network.
#[derive(Default, Clone, Copy)]
pub struct StubAiClient;

#[cfg_attr(not(target_family = "wasm"), async_trait)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
impl AIClient for StubAiClient {
    // --- Natural-language generation (needs a server model; unavailable offline) ---

    async fn generate_commands_from_natural_language(
        &self,
        prompt: String,
        ai_execution_context: Option<WarpAiExecutionContext>,
    ) -> Result<Vec<AIGeneratedCommand>, GenerateCommandsFromNaturalLanguageError> {
        stub_call!("ai.generate_commands_from_natural_language");
        let messages = local::build_command_messages(&prompt, &ai_execution_context);
        let text = local::complete(messages, 0.2).await.map_err(|e| {
            log::warn!(target: "anonwarp::stub", "local LLM command generation failed: {e:#}");
            GenerateCommandsFromNaturalLanguageError::AiProviderError
        })?;
        local::parse_commands(&text).ok_or_else(|| {
            log::warn!(target: "anonwarp::stub", "unparseable command suggestions: {text}");
            GenerateCommandsFromNaturalLanguageError::Other
        })
    }

    async fn generate_dialogue_answer(
        &self,
        transcript: Vec<TranscriptPart>,
        prompt: String,
        ai_execution_context: Option<WarpAiExecutionContext>,
    ) -> anyhow::Result<GenerateDialogueResult> {
        stub_call!("ai.generate_dialogue_answer");
        let messages = local::build_dialogue_messages(
            &local::transcript_pairs(&transcript),
            &prompt,
            &ai_execution_context,
        );
        let answer = local::complete(messages, 0.5).await?;
        Ok(GenerateDialogueResult::Success {
            answer,
            truncated: false,
            request_limit_info: local::unlimited_request_limit_info(),
            transcript_summarized: false,
        })
    }

    async fn generate_metadata_for_command(
        &self,
        command: String,
    ) -> Result<GeneratedCommandMetadata, GeneratedCommandMetadataError> {
        stub_call!("ai.generate_metadata_for_command");
        let text = local::complete(local::build_metadata_messages(&command), 0.2)
            .await
            .map_err(|e| {
                log::warn!(target: "anonwarp::stub", "local LLM metadata generation failed: {e:#}");
                GeneratedCommandMetadataError::AiProviderError
            })?;
        local::parse_metadata(&text, &command).ok_or_else(|| {
            log::warn!(target: "anonwarp::stub", "unparseable command metadata: {text}");
            GeneratedCommandMetadataError::BadCommand
        })
    }

    // --- Usage, credits, and account linking ---

    async fn get_request_limit_info(&self) -> Result<RequestUsageInfo, anyhow::Error> {
        stub_call!("ai.get_request_limit_info");
        Ok(RequestUsageInfo {
            request_limit_info: local::unlimited_request_limit_info(),
            bonus_grants: Vec::new(),
        })
    }

    async fn get_ai_credit_availability(&self) -> Result<AICreditAvailability, anyhow::Error> {
        stub_call!("ai.get_ai_credit_availability");
        // Available, so the UI lets the user submit prompts; the offline agent path answers
        // with a canned "not configured" reply (see ai/agent/api/offline.rs).
        Ok(AICreditAvailability::available_with_source(None))
    }

    async fn get_chatgpt_connection(&self) -> Result<ChatGPTConnectionStatus, anyhow::Error> {
        stub_call!("ai.get_chatgpt_connection");
        Ok(ChatGPTConnectionStatus::NotConnected)
    }

    async fn disconnect_chatgpt(&self) -> Result<(), anyhow::Error> {
        stub_call!("ai.disconnect_chatgpt");
        Ok(())
    }

    async fn start_chatgpt_link(&self, _continue_url: String) -> Result<String, anyhow::Error> {
        stub_call!("ai.start_chatgpt_link");
        unsupported!("ai.start_chatgpt_link")
    }

    async fn get_conversation_usage_history(
        &self,
        _days: Option<i32>,
        _limit: Option<i32>,
        _last_updated_end_timestamp: Option<warp_graphql::scalars::Time>,
    ) -> Result<Vec<ConversationUsage>, anyhow::Error> {
        stub_call!("ai.get_conversation_usage_history");
        Ok(Vec::new())
    }

    // --- Models and harnesses ---

    async fn get_feature_model_choices(&self) -> Result<ModelsByFeature, anyhow::Error> {
        stub_call!("ai.get_feature_model_choices");
        Ok(local::fetch_models().await)
    }

    async fn get_available_harnesses(&self) -> Result<Vec<HarnessAvailability>, anyhow::Error> {
        stub_call!("ai.get_available_harnesses");
        Ok(Vec::new())
    }

    async fn list_connected_self_hosted_workers(
        &self,
        _team_scope: RequestTeamScope,
    ) -> Result<ListConnectedSelfHostedWorkersResponse, anyhow::Error> {
        stub_call!("ai.list_connected_self_hosted_workers");
        Ok(ListConnectedSelfHostedWorkersResponse {
            workers: Vec::new(),
        })
    }

    async fn get_free_available_models(
        &self,
        _referrer: Option<String>,
    ) -> Result<ModelsByFeature, anyhow::Error> {
        stub_call!("ai.get_free_available_models");
        Ok(local::fetch_models().await)
    }

    // --- Codebase indexing ---

    async fn update_merkle_tree(
        &self,
        _embedding_config: EmbeddingConfig,
        _nodes: Vec<IntermediateNode>,
    ) -> anyhow::Result<HashMap<NodeHash, bool>> {
        stub_call!("ai.update_merkle_tree");
        Ok(HashMap::new())
    }

    async fn generate_code_embeddings(
        &self,
        _embedding_config: EmbeddingConfig,
        _fragments: Vec<full_source_code_embedding::Fragment>,
        _root_hash: NodeHash,
        _repo_metadata: RepoMetadata,
    ) -> anyhow::Result<HashMap<ContentHash, bool>> {
        stub_call!("ai.generate_code_embeddings");
        Ok(HashMap::new())
    }

    async fn provide_negative_feedback_response_for_ai_conversation(
        &self,
        _conversation_id: String,
        _request_ids: Vec<String>,
    ) -> anyhow::Result<i32, anyhow::Error> {
        stub_call!("ai.provide_negative_feedback_response_for_ai_conversation");
        Ok(0)
    }

    // --- Cloud agent tasks and runs ---

    async fn create_agent_task(
        &self,
        _prompt: String,
        _environment_uid: Option<String>,
        _parent_run_id: Option<String>,
        _config: Option<AgentConfigSnapshot>,
        _metadata: HashMap<String, String>,
        _team_scope: RequestTeamScope,
    ) -> anyhow::Result<AmbientAgentTaskId, anyhow::Error> {
        stub_call!("ai.create_agent_task");
        unsupported!("ai.create_agent_task")
    }

    async fn update_agent_task(
        &self,
        _task_id: AmbientAgentTaskId,
        _task_state: Option<AgentTaskState>,
        _session_id: Option<session_sharing_protocol::common::SessionId>,
        _conversation_id: Option<String>,
        _status_message: Option<TaskStatusUpdate>,
        _session_debug_until: Option<DateTime<Utc>>,
        _debug_agent_active: Option<bool>,
    ) -> anyhow::Result<(), anyhow::Error> {
        stub_call!("ai.update_agent_task");
        Ok(())
    }

    async fn spawn_agent(
        &self,
        _request: SpawnAgentRequest,
        _team_scope: RequestTeamScope,
    ) -> anyhow::Result<SpawnAgentResponse, anyhow::Error> {
        stub_call!("ai.spawn_agent");
        unsupported!("ai.spawn_agent")
    }

    async fn upload_local_handoff_snapshot(
        &self,
        _request: UploadLocalHandoffSnapshotRequest,
    ) -> anyhow::Result<UploadLocalHandoffSnapshotResponse, anyhow::Error> {
        stub_call!("ai.upload_local_handoff_snapshot");
        unsupported!("ai.upload_local_handoff_snapshot")
    }

    async fn fork_conversation(
        &self,
        _conversation_id: String,
        _title: Option<String>,
    ) -> anyhow::Result<ForkConversationResponse, anyhow::Error> {
        stub_call!("ai.fork_conversation");
        unsupported!("ai.fork_conversation")
    }

    async fn rename_conversation(
        &self,
        _conversation_id: String,
        _title: String,
    ) -> anyhow::Result<RenameConversationResponse, anyhow::Error> {
        stub_call!("ai.rename_conversation");
        unsupported!("ai.rename_conversation")
    }

    async fn list_ambient_agent_tasks(
        &self,
        _limit: i32,
        _filter: TaskListFilter,
        _request_team_scope: Option<RequestTeamScope>,
    ) -> anyhow::Result<Vec<AmbientAgentTask>, anyhow::Error> {
        stub_call!("ai.list_ambient_agent_tasks");
        Ok(Vec::new())
    }

    async fn list_agent_runs_raw(
        &self,
        _limit: i32,
        _filter: TaskListFilter,
        _request_team_scope: Option<RequestTeamScope>,
    ) -> anyhow::Result<serde_json::Value, anyhow::Error> {
        stub_call!("ai.list_agent_runs_raw");
        Ok(serde_json::json!({ "runs": [] }))
    }

    async fn get_ambient_agent_task(
        &self,
        _task_id: &AmbientAgentTaskId,
    ) -> anyhow::Result<AmbientAgentTask, anyhow::Error> {
        stub_call!("ai.get_ambient_agent_task");
        unsupported!("ai.get_ambient_agent_task")
    }

    async fn get_agent_run_raw(
        &self,
        _task_id: &AmbientAgentTaskId,
    ) -> anyhow::Result<serde_json::Value, anyhow::Error> {
        stub_call!("ai.get_agent_run_raw");
        unsupported!("ai.get_agent_run_raw")
    }

    #[cfg(not(target_family = "wasm"))]
    async fn download_run_transcript(
        &self,
        _run_id: &AmbientAgentTaskId,
    ) -> anyhow::Result<Bytes, anyhow::Error> {
        stub_call!("ai.download_run_transcript");
        unsupported!("ai.download_run_transcript")
    }

    #[cfg(not(target_family = "wasm"))]
    async fn download_run_transcript_to_path(
        &self,
        _run_id: &AmbientAgentTaskId,
        _destination: &Path,
    ) -> anyhow::Result<(), anyhow::Error> {
        stub_call!("ai.download_run_transcript_to_path");
        unsupported!("ai.download_run_transcript_to_path")
    }

    #[cfg(not(target_family = "wasm"))]
    async fn download_conversation_transcript(
        &self,
        _conversation_id: &str,
    ) -> anyhow::Result<Bytes, anyhow::Error> {
        stub_call!("ai.download_conversation_transcript");
        unsupported!("ai.download_conversation_transcript")
    }

    #[cfg(not(target_family = "wasm"))]
    async fn download_conversation_transcript_to_path(
        &self,
        _conversation_id: &str,
        _destination: &Path,
    ) -> anyhow::Result<(), anyhow::Error> {
        stub_call!("ai.download_conversation_transcript_to_path");
        unsupported!("ai.download_conversation_transcript_to_path")
    }

    async fn submit_run_followup(
        &self,
        _run_id: &AmbientAgentTaskId,
        _request: RunFollowupRequest,
    ) -> anyhow::Result<(), anyhow::Error> {
        stub_call!("ai.submit_run_followup");
        unsupported!("ai.submit_run_followup")
    }

    async fn get_scheduled_agent_history(
        &self,
        _schedule_id: &str,
    ) -> anyhow::Result<ScheduledAgentHistory, anyhow::Error> {
        stub_call!("ai.get_scheduled_agent_history");
        Ok(ScheduledAgentHistory {
            last_ran: None,
            next_run: None,
        })
    }

    // --- Server-side conversations ---

    async fn get_ai_conversation(
        &self,
        _server_conversation_token: ServerConversationToken,
    ) -> anyhow::Result<(ConversationData, ServerAIConversationMetadata), anyhow::Error> {
        stub_call!("ai.get_ai_conversation");
        unsupported!("ai.get_ai_conversation")
    }

    async fn list_ai_conversation_metadata(
        &self,
        _conversation_ids: Option<Vec<String>>,
    ) -> anyhow::Result<Vec<ServerAIConversationMetadata>> {
        stub_call!("ai.list_ai_conversation_metadata");
        Ok(Vec::new())
    }

    async fn get_ai_conversation_format(
        &self,
        _server_conversation_token: ServerConversationToken,
    ) -> anyhow::Result<AIAgentConversationFormat, anyhow::Error> {
        stub_call!("ai.get_ai_conversation_format");
        unsupported!("ai.get_ai_conversation_format")
    }

    async fn get_block_snapshot(
        &self,
        _server_conversation_token: ServerConversationToken,
    ) -> anyhow::Result<SerializedBlock, anyhow::Error> {
        stub_call!("ai.get_block_snapshot");
        unsupported!("ai.get_block_snapshot")
    }

    async fn delete_ai_conversation(
        &self,
        _server_conversation_token: String,
    ) -> anyhow::Result<(), anyhow::Error> {
        stub_call!("ai.delete_ai_conversation");
        Ok(())
    }

    // --- Skills and agent identities ---

    async fn list_skills(
        &self,
        _repo: Option<String>,
        _team_scope: RequestTeamScope,
    ) -> anyhow::Result<Vec<AgentSkillItem>, anyhow::Error> {
        stub_call!("ai.list_skills");
        Ok(Vec::new())
    }

    async fn list_agents(
        &self,
        _team_scope: RequestTeamScope,
    ) -> anyhow::Result<Vec<AgentResponse>, anyhow::Error> {
        stub_call!("ai.list_agents");
        Ok(Vec::new())
    }

    async fn list_agents_raw(
        &self,
        _team_scope: RequestTeamScope,
    ) -> anyhow::Result<serde_json::Value, anyhow::Error> {
        stub_call!("ai.list_agents_raw");
        Ok(serde_json::json!({ "agents": [] }))
    }

    async fn get_agent(&self, _uid: &str) -> anyhow::Result<AgentResponse, anyhow::Error> {
        stub_call!("ai.get_agent");
        unsupported!("ai.get_agent")
    }

    async fn get_agent_raw(&self, _uid: &str) -> anyhow::Result<serde_json::Value, anyhow::Error> {
        stub_call!("ai.get_agent_raw");
        unsupported!("ai.get_agent_raw")
    }

    async fn create_agent(
        &self,
        _request: CreateAgentRequest,
        _team_scope: RequestTeamScope,
    ) -> anyhow::Result<AgentResponse, anyhow::Error> {
        stub_call!("ai.create_agent");
        unsupported!("ai.create_agent")
    }

    async fn create_agent_raw(
        &self,
        _request: CreateAgentRequest,
        _team_scope: RequestTeamScope,
    ) -> anyhow::Result<serde_json::Value, anyhow::Error> {
        stub_call!("ai.create_agent_raw");
        unsupported!("ai.create_agent_raw")
    }

    async fn update_agent(
        &self,
        _uid: &str,
        _request: UpdateAgentRequest,
    ) -> anyhow::Result<AgentResponse, anyhow::Error> {
        stub_call!("ai.update_agent");
        unsupported!("ai.update_agent")
    }

    async fn update_agent_raw(
        &self,
        _uid: &str,
        _request: UpdateAgentRequest,
    ) -> anyhow::Result<serde_json::Value, anyhow::Error> {
        stub_call!("ai.update_agent_raw");
        unsupported!("ai.update_agent_raw")
    }

    async fn delete_agent(&self, _uid: &str) -> anyhow::Result<(), anyhow::Error> {
        stub_call!("ai.delete_agent");
        Ok(())
    }

    // --- Memory stores ---

    async fn list_memory_stores(
        &self,
        _team_scope: RequestTeamScope,
    ) -> anyhow::Result<Vec<MemoryStoreItem>, anyhow::Error> {
        stub_call!("ai.list_memory_stores");
        Ok(Vec::new())
    }

    async fn list_memory_store_memories(
        &self,
        _store_uid: &str,
    ) -> anyhow::Result<Vec<MemoryItem>, anyhow::Error> {
        stub_call!("ai.list_memory_store_memories");
        Ok(Vec::new())
    }

    async fn create_memory_store_memory(
        &self,
        _store_uid: &str,
        _request: CreateMemoryRequest,
    ) -> anyhow::Result<CreateMemoryResponse, anyhow::Error> {
        stub_call!("ai.create_memory_store_memory");
        unsupported!("ai.create_memory_store_memory")
    }

    async fn update_memory_store_memory(
        &self,
        _store_uid: &str,
        _memory_uid: &str,
        _request: UpdateMemoryRequest,
    ) -> anyhow::Result<UpdateMemoryResponse, anyhow::Error> {
        stub_call!("ai.update_memory_store_memory");
        unsupported!("ai.update_memory_store_memory")
    }

    async fn delete_memory_store_memory(
        &self,
        _store_uid: &str,
        _memory_uid: &str,
    ) -> anyhow::Result<(), anyhow::Error> {
        stub_call!("ai.delete_memory_store_memory");
        Ok(())
    }

    async fn get_memory_store(
        &self,
        _store_uid: &str,
    ) -> anyhow::Result<MemoryStoreItem, anyhow::Error> {
        stub_call!("ai.get_memory_store");
        unsupported!("ai.get_memory_store")
    }

    async fn update_memory_store(
        &self,
        _store_uid: &str,
        _request: UpdateMemoryStoreRequest,
    ) -> anyhow::Result<MemoryStoreItem, anyhow::Error> {
        stub_call!("ai.update_memory_store");
        unsupported!("ai.update_memory_store")
    }

    async fn list_memory_store_agents(
        &self,
        _store_uid: &str,
    ) -> anyhow::Result<Vec<AgentAttachmentItem>, anyhow::Error> {
        stub_call!("ai.list_memory_store_agents");
        Ok(Vec::new())
    }

    async fn list_memory_versions(
        &self,
        _store_uid: &str,
        _memory_uid: &str,
    ) -> anyhow::Result<Vec<MemoryVersionItem>, anyhow::Error> {
        stub_call!("ai.list_memory_versions");
        Ok(Vec::new())
    }

    // --- Task lifecycle, credentials, attachments, artifacts ---

    async fn cancel_ambient_agent_task(
        &self,
        _task_id: &AmbientAgentTaskId,
    ) -> anyhow::Result<(), anyhow::Error> {
        stub_call!("ai.cancel_ambient_agent_task");
        Ok(())
    }

    async fn get_task_git_credentials(
        &self,
        _task_id: String,
        _workload_token: String,
        _accepts_partial_refresh: bool,
        _use_factory_repositories: bool,
    ) -> Result<TaskGitCredentialsResponse, TaskGitCredentialsError> {
        stub_call!("ai.get_task_git_credentials");
        Err(TaskGitCredentialsError::Request(anyhow::Error::new(
            StubUnsupported("ai.get_task_git_credentials"),
        )))
    }

    async fn setup_failure_debug_authorization(
        &self,
        _task_id: AmbientAgentTaskId,
        _workload_token: String,
        _participant_firebase_uid: String,
    ) -> anyhow::Result<bool, anyhow::Error> {
        stub_call!("ai.setup_failure_debug_authorization");
        Ok(false)
    }

    async fn get_task_attachments(
        &self,
        _task_id: String,
    ) -> anyhow::Result<Vec<TaskAttachment>, anyhow::Error> {
        stub_call!("ai.get_task_attachments");
        Ok(Vec::new())
    }

    async fn create_file_artifact_upload_target(
        &self,
        _request: CreateFileArtifactUploadRequest,
    ) -> anyhow::Result<CreateFileArtifactUploadResponse, anyhow::Error> {
        stub_call!("ai.create_file_artifact_upload_target");
        unsupported!("ai.create_file_artifact_upload_target")
    }

    async fn confirm_file_artifact_upload(
        &self,
        _artifact_uid: String,
        _checksum: String,
    ) -> anyhow::Result<FileArtifactRecord, anyhow::Error> {
        stub_call!("ai.confirm_file_artifact_upload");
        unsupported!("ai.confirm_file_artifact_upload")
    }

    async fn get_artifact_download(
        &self,
        _artifact_uid: &str,
    ) -> anyhow::Result<ArtifactDownloadResponse, anyhow::Error> {
        stub_call!("ai.get_artifact_download");
        unsupported!("ai.get_artifact_download")
    }

    async fn download_stored_screenshot(
        &self,
        _conversation_id: &str,
        _screenshot_uid: &str,
    ) -> anyhow::Result<bytes::Bytes, anyhow::Error> {
        stub_call!("ai.download_stored_screenshot");
        unsupported!("ai.download_stored_screenshot")
    }

    async fn prepare_attachments_for_upload(
        &self,
        _task_id: &AmbientAgentTaskId,
        _files: &[AttachmentFileInfo],
    ) -> anyhow::Result<PrepareAttachmentUploadsResponse, anyhow::Error> {
        stub_call!("ai.prepare_attachments_for_upload");
        unsupported!("ai.prepare_attachments_for_upload")
    }

    async fn download_task_attachments(
        &self,
        _task_id: &AmbientAgentTaskId,
        _attachment_ids: &[String],
    ) -> anyhow::Result<DownloadAttachmentsResponse, anyhow::Error> {
        stub_call!("ai.download_task_attachments");
        unsupported!("ai.download_task_attachments")
    }

    async fn get_handoff_snapshot_attachments(
        &self,
        _task_id: &AmbientAgentTaskId,
    ) -> anyhow::Result<Vec<TaskAttachment>, anyhow::Error> {
        stub_call!("ai.get_handoff_snapshot_attachments");
        Ok(Vec::new())
    }

    // --- Orchestrations V2 messaging ---

    async fn send_agent_message(
        &self,
        _request: SendAgentMessageRequest,
    ) -> anyhow::Result<SendAgentMessageResponse, anyhow::Error> {
        stub_call!("ai.send_agent_message");
        unsupported!("ai.send_agent_message")
    }

    async fn list_agent_messages(
        &self,
        _run_id: &str,
        _request: ListAgentMessagesRequest,
    ) -> anyhow::Result<Vec<AgentMessageHeader>, anyhow::Error> {
        stub_call!("ai.list_agent_messages");
        Ok(Vec::new())
    }

    async fn update_event_sequence_on_server(
        &self,
        _run_id: &str,
        _sequence: i64,
    ) -> anyhow::Result<(), anyhow::Error> {
        stub_call!("ai.update_event_sequence_on_server");
        Ok(())
    }

    async fn report_agent_event(
        &self,
        _run_id: &str,
        _request: ReportAgentEventRequest,
    ) -> anyhow::Result<ReportAgentEventResponse, anyhow::Error> {
        stub_call!("ai.report_agent_event");
        unsupported!("ai.report_agent_event")
    }

    async fn post_agent_run_client_event(
        &self,
        _run_id: &AmbientAgentTaskId,
        _request: AgentRunClientEventRequest,
    ) -> anyhow::Result<(), anyhow::Error> {
        stub_call!("ai.post_agent_run_client_event");
        Ok(())
    }

    async fn post_agent_run_environment_snapshot(
        &self,
        _run_id: &AmbientAgentTaskId,
        _request: AgentRunEnvironmentSnapshotRequest,
    ) -> anyhow::Result<(), anyhow::Error> {
        stub_call!("ai.post_agent_run_environment_snapshot");
        Ok(())
    }

    async fn mark_message_delivered(&self, _message_id: &str) -> anyhow::Result<(), anyhow::Error> {
        stub_call!("ai.mark_message_delivered");
        Ok(())
    }

    async fn read_agent_message(
        &self,
        _message_id: &str,
    ) -> anyhow::Result<ReadAgentMessageResponse, anyhow::Error> {
        stub_call!("ai.read_agent_message");
        unsupported!("ai.read_agent_message")
    }

    async fn get_public_conversation(
        &self,
        _conversation_id: &str,
    ) -> anyhow::Result<serde_json::Value, anyhow::Error> {
        stub_call!("ai.get_public_conversation");
        unsupported!("ai.get_public_conversation")
    }

    async fn get_run_conversation(
        &self,
        _run_id: &str,
    ) -> anyhow::Result<serde_json::Value, anyhow::Error> {
        stub_call!("ai.get_run_conversation");
        unsupported!("ai.get_run_conversation")
    }

    async fn generate_code_review_content(
        &self,
        _request: GenerateCodeReviewContentRequest,
    ) -> Result<GenerateCodeReviewContentResponse, anyhow::Error> {
        stub_call!("ai.generate_code_review_content");
        unsupported!("ai.generate_code_review_content")
    }
}
