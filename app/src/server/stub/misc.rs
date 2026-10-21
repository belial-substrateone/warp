//! Offline stand-ins for the small server client traits (blocks, referrals, integrations,
//! managed MCP, factory, harness support, prewarmed sandboxes, TUI onboarding, managed secrets).

use std::collections::HashMap;
use std::sync::OnceLock;

use anyhow::Result;
use async_trait::async_trait;
use warp_cli::agent::Harness;
use warp_graphql::ai::AgentHarness;
use warp_graphql::managed_secrets::{ManagedSecret, ManagedSecretType};
use warp_graphql::mutations::create_managed_mcp_client_config::CreateManagedMcpClientConfigOutput;
use warp_graphql::mutations::create_simple_integration::CreateSimpleIntegrationOutput;
use warp_graphql::mutations::upsert_runner::UpsertRunnerInput;
use warp_graphql::queries::get_integrations_using_environment::GetIntegrationsUsingEnvironmentOutput;
use warp_graphql::queries::get_oauth_connect_tx_status::OauthConnectTxStatus;
use warp_graphql::queries::get_runners::{Runner, RunnerSortBy};
use warp_graphql::queries::get_simple_integrations::SimpleIntegrationsOutput;
use warp_graphql::queries::suggest_cloud_environment_image::SuggestCloudEnvironmentImageResult;
use warp_graphql::queries::user_github_info::UserGithubInfoResult;
use warp_graphql::queries::user_repo_auth_status::UserRepoAuthStatusOutput;

use super::{stub_call, unsupported};
use crate::ai::agent::api::ServerConversationToken;
use crate::ai::artifacts::Artifact;
use crate::ai::generate_block_title::api::{GenerateBlockTitleRequest, GenerateBlockTitleResponse};
use crate::server::block::{Block, DisplaySetting};
use crate::server::server_api::block::BlockClient;
use crate::server::server_api::factory::{FactoryClient, UpsertedRunner};
use crate::server::server_api::harness_support::{
    CommitSnapshotRequest, CommitSnapshotResponse, HarnessSupportClient, ReportArtifactResponse,
    ResolvePromptRequest, ResolvedHarnessPrompt, SnapshotUploadRequest, UploadTarget,
};
use crate::server::server_api::integrations::IntegrationsClient;
use crate::server::server_api::managed_mcp::ManagedMcpClient;
use crate::server::server_api::managed_secrets::{ManagedSecretConfigs, ManagedSecretsClient};
use crate::server::server_api::prewarmed_sandbox::{
    PrewarmedSandboxClient, PrewarmedSandboxConfiguration, PrewarmedSandboxControlStream,
    PrewarmedSandboxState,
};
use crate::server::server_api::referral::{ReferralInfo, ReferralsClient};
#[cfg(feature = "tui")]
use crate::server::server_api::tui_onboarding::{TuiOnboardingClient, TuiOnboardingMarkersSnapshot};
use crate::server::team_scope::RequestTeamScope;
use warp_managed_secrets::client::{
    IdentityTokenOptions, ManagedSecretValue, SecretOwner, TaskIdentityToken,
};

// ---------------------------------------------------------------------------------------------
// Blocks
// ---------------------------------------------------------------------------------------------

#[derive(Default, Clone, Copy)]
pub struct StubBlockClient;

#[cfg_attr(not(target_family = "wasm"), async_trait)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
impl BlockClient for StubBlockClient {
    async fn unshare_block(&self, _block_id: String) -> Result<(), anyhow::Error> {
        stub_call!("block.unshare_block");
        unsupported!("unshare_block")
    }

    async fn save_block(
        &self,
        _block: &Block,
        _title: Option<String>,
        _show_prompt: bool,
        _display_setting: DisplaySetting,
    ) -> Result<String, anyhow::Error> {
        stub_call!("block.save_block");
        unsupported!("save_block")
    }

    async fn blocks_owned_by_user(&self) -> Result<Vec<Block>, anyhow::Error> {
        stub_call!("block.blocks_owned_by_user");
        Ok(Vec::new())
    }

    async fn generate_shared_block_title(
        &self,
        _request: GenerateBlockTitleRequest,
    ) -> Result<GenerateBlockTitleResponse, anyhow::Error> {
        stub_call!("block.generate_shared_block_title");
        unsupported!("generate_shared_block_title")
    }
}

// ---------------------------------------------------------------------------------------------
// Referrals
// ---------------------------------------------------------------------------------------------

#[derive(Default, Clone, Copy)]
pub struct StubReferralsClient;

#[cfg_attr(not(target_family = "wasm"), async_trait)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
impl ReferralsClient for StubReferralsClient {
    async fn get_referral_info(&self) -> Result<ReferralInfo> {
        stub_call!("referrals.get_referral_info");
        unsupported!("get_referral_info")
    }

    async fn send_invite(&self, _emails: Vec<String>) -> Result<Vec<String>> {
        stub_call!("referrals.send_invite");
        unsupported!("send_invite")
    }
}

// ---------------------------------------------------------------------------------------------
// Integrations
// ---------------------------------------------------------------------------------------------

#[derive(Default, Clone, Copy)]
pub struct StubIntegrationsClient;

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl IntegrationsClient for StubIntegrationsClient {
    async fn check_user_repo_auth_status(
        &self,
        _repos: Vec<(String, String)>,
    ) -> Result<UserRepoAuthStatusOutput> {
        stub_call!("integrations.check_user_repo_auth_status");
        unsupported!("check_user_repo_auth_status")
    }

    async fn create_or_update_simple_integration(
        &self,
        _integration_type: String,
        _is_update: bool,
        _environment_uid: Option<String>,
        _base_prompt: Option<String>,
        _model_id: Option<String>,
        _mcp_servers_json: Option<String>,
        _remove_mcp_server_names: Option<Vec<String>>,
        _worker_host: Option<String>,
        _enabled: bool,
    ) -> Result<CreateSimpleIntegrationOutput> {
        stub_call!("integrations.create_or_update_simple_integration");
        unsupported!("create_or_update_simple_integration")
    }

    async fn list_simple_integrations(
        &self,
        _providers: Vec<String>,
    ) -> Result<SimpleIntegrationsOutput> {
        stub_call!("integrations.list_simple_integrations");
        unsupported!("list_simple_integrations")
    }

    async fn poll_oauth_connect_status(&self, _tx_id: String) -> Result<OauthConnectTxStatus> {
        stub_call!("integrations.poll_oauth_connect_status");
        unsupported!("poll_oauth_connect_status")
    }

    async fn get_integrations_using_environment(
        &self,
        _environment_id: String,
    ) -> Result<GetIntegrationsUsingEnvironmentOutput> {
        stub_call!("integrations.get_integrations_using_environment");
        unsupported!("get_integrations_using_environment")
    }

    async fn get_user_github_info(&self) -> Result<UserGithubInfoResult> {
        stub_call!("integrations.get_user_github_info");
        unsupported!("get_user_github_info")
    }

    async fn suggest_cloud_environment_image(
        &self,
        _repos: Vec<(String, String)>,
    ) -> Result<SuggestCloudEnvironmentImageResult> {
        stub_call!("integrations.suggest_cloud_environment_image");
        unsupported!("suggest_cloud_environment_image")
    }
}

// ---------------------------------------------------------------------------------------------
// Managed MCP
// ---------------------------------------------------------------------------------------------

#[derive(Default, Clone, Copy)]
pub struct StubManagedMcpClient;

#[cfg_attr(not(target_family = "wasm"), async_trait)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
impl ManagedMcpClient for StubManagedMcpClient {
    async fn create_managed_mcp_client_config(
        &self,
        _uid: String,
    ) -> Result<CreateManagedMcpClientConfigOutput> {
        stub_call!("managed_mcp.create_managed_mcp_client_config");
        unsupported!("create_managed_mcp_client_config")
    }
}

// ---------------------------------------------------------------------------------------------
// Factory (runners)
// ---------------------------------------------------------------------------------------------

#[derive(Default, Clone, Copy)]
pub struct StubFactoryClient;

#[cfg_attr(not(target_family = "wasm"), async_trait)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
impl FactoryClient for StubFactoryClient {
    async fn get_runners(
        &self,
        _sort_by: Option<RunnerSortBy>,
        _team_scope: Option<RequestTeamScope>,
    ) -> Result<Vec<Runner>> {
        stub_call!("factory.get_runners");
        Ok(Vec::new())
    }

    async fn upsert_runner(
        &self,
        _input: UpsertRunnerInput,
        _team_scope: Option<RequestTeamScope>,
    ) -> Result<UpsertedRunner> {
        stub_call!("factory.upsert_runner");
        unsupported!("upsert_runner")
    }

    async fn delete_runner(&self, _uid: String) -> Result<String> {
        stub_call!("factory.delete_runner");
        unsupported!("delete_runner")
    }
}

// ---------------------------------------------------------------------------------------------
// Harness support
// ---------------------------------------------------------------------------------------------

#[derive(Default, Clone, Copy)]
pub struct StubHarnessSupportClient;

#[cfg_attr(not(target_family = "wasm"), async_trait)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
impl HarnessSupportClient for StubHarnessSupportClient {
    async fn create_external_conversation(
        &self,
        _format: &str,
        _harness: Harness,
    ) -> Result<ServerConversationToken> {
        stub_call!("harness_support.create_external_conversation");
        unsupported!("create_external_conversation")
    }

    async fn upload_conversation_data(
        &self,
        _conversation_id: &ServerConversationToken,
        _conversation_data: &[u8],
    ) -> Result<()> {
        stub_call!("harness_support.upload_conversation_data");
        unsupported!("upload_conversation_data")
    }

    async fn get_transcript_upload_target(
        &self,
        _conversation_id: &ServerConversationToken,
    ) -> Result<UploadTarget> {
        stub_call!("harness_support.get_transcript_upload_target");
        unsupported!("get_transcript_upload_target")
    }

    async fn get_block_snapshot_upload_target(
        &self,
        _conversation_id: &ServerConversationToken,
    ) -> Result<UploadTarget> {
        stub_call!("harness_support.get_block_snapshot_upload_target");
        unsupported!("get_block_snapshot_upload_target")
    }

    async fn resolve_prompt(
        &self,
        _request: ResolvePromptRequest,
    ) -> Result<ResolvedHarnessPrompt> {
        stub_call!("harness_support.resolve_prompt");
        unsupported!("resolve_prompt")
    }

    async fn report_artifact(&self, _artifact: &Artifact) -> Result<ReportArtifactResponse> {
        stub_call!("harness_support.report_artifact");
        unsupported!("report_artifact")
    }

    async fn notify_user(&self, _message: &str) -> Result<()> {
        stub_call!("harness_support.notify_user");
        Ok(())
    }

    async fn finish_task(&self, _success: bool, _summary: &str) -> Result<()> {
        stub_call!("harness_support.finish_task");
        Ok(())
    }

    async fn report_clean_shutdown(&self) -> Result<()> {
        stub_call!("harness_support.report_clean_shutdown");
        Ok(())
    }

    async fn report_error_shutdown(
        &self,
        _error_category: String,
        _error_message: String,
        _exit_code: Option<u8>,
    ) -> Result<()> {
        stub_call!("harness_support.report_error_shutdown");
        Ok(())
    }

    async fn get_snapshot_upload_targets(
        &self,
        _request: &SnapshotUploadRequest,
    ) -> Result<Vec<UploadTarget>> {
        stub_call!("harness_support.get_snapshot_upload_targets");
        unsupported!("get_snapshot_upload_targets")
    }

    async fn commit_snapshot(
        &self,
        _request: &CommitSnapshotRequest,
    ) -> Result<CommitSnapshotResponse> {
        stub_call!("harness_support.commit_snapshot");
        unsupported!("commit_snapshot")
    }

    async fn fetch_transcript(&self) -> Result<bytes::Bytes> {
        stub_call!("harness_support.fetch_transcript");
        unsupported!("fetch_transcript")
    }

    fn external_http_client(&self) -> &http_client::Client {
        stub_call!("harness_support.external_http_client");
        static CLIENT: OnceLock<http_client::Client> = OnceLock::new();
        CLIENT.get_or_init(http_client::Client::new_external)
    }
}

// ---------------------------------------------------------------------------------------------
// Prewarmed sandbox
// ---------------------------------------------------------------------------------------------

#[derive(Default, Clone, Copy)]
pub struct StubPrewarmedSandboxClient;

#[cfg_attr(not(target_family = "wasm"), async_trait)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
impl PrewarmedSandboxClient for StubPrewarmedSandboxClient {
    async fn fetch_configuration(
        &self,
        _sandbox_id: &str,
    ) -> Result<PrewarmedSandboxConfiguration> {
        stub_call!("prewarmed_sandbox.fetch_configuration");
        unsupported!("fetch_configuration")
    }

    async fn report_status(
        &self,
        _sandbox_id: &str,
        _generation: &str,
        _state: PrewarmedSandboxState,
    ) -> Result<()> {
        stub_call!("prewarmed_sandbox.report_status");
        Ok(())
    }

    async fn connect_control_stream(
        &self,
        _sandbox_id: &str,
        _generation: &str,
    ) -> Result<PrewarmedSandboxControlStream> {
        stub_call!("prewarmed_sandbox.connect_control_stream");
        unsupported!("connect_control_stream")
    }
}

// ---------------------------------------------------------------------------------------------
// TUI onboarding
// ---------------------------------------------------------------------------------------------

#[cfg(feature = "tui")]
#[derive(Default, Clone, Copy)]
pub struct StubTuiOnboardingClient;

#[cfg(feature = "tui")]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
impl TuiOnboardingClient for StubTuiOnboardingClient {
    async fn get_tui_onboarding_markers(&self) -> Result<TuiOnboardingMarkersSnapshot> {
        stub_call!("tui_onboarding.get_tui_onboarding_markers");
        Ok(TuiOnboardingMarkersSnapshot {
            first_zero_state_shown: false,
            first_credit_gate_shown: false,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Managed secrets (backs `AppManagedSecretsClient = dyn ManagedSecretsClient<RequestScope =
// RequestTeamScope>`)
// ---------------------------------------------------------------------------------------------

#[derive(Default, Clone, Copy)]
pub struct StubManagedSecretsClient;

#[cfg_attr(not(target_family = "wasm"), async_trait)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
impl ManagedSecretsClient for StubManagedSecretsClient {
    type RequestScope = RequestTeamScope;

    async fn get_managed_secret_configs(
        &self,
        _request_scope: &Self::RequestScope,
    ) -> Result<ManagedSecretConfigs> {
        stub_call!("managed_secrets.get_managed_secret_configs");
        Ok(ManagedSecretConfigs {
            user_secrets: None,
            team_secrets: HashMap::new(),
        })
    }

    async fn create_managed_secret(
        &self,
        _request_scope: &Self::RequestScope,
        _owner: SecretOwner,
        _name: String,
        _secret_type: ManagedSecretType,
        _encrypted_value: String,
        _description: Option<String>,
    ) -> Result<ManagedSecret> {
        stub_call!("managed_secrets.create_managed_secret");
        unsupported!("create_managed_secret")
    }

    async fn delete_managed_secret(
        &self,
        _request_scope: &Self::RequestScope,
        _owner: SecretOwner,
        _name: String,
    ) -> Result<()> {
        stub_call!("managed_secrets.delete_managed_secret");
        unsupported!("delete_managed_secret")
    }

    async fn update_managed_secret(
        &self,
        _request_scope: &Self::RequestScope,
        _owner: SecretOwner,
        _name: String,
        _encrypted_value: Option<String>,
        _description: Option<String>,
    ) -> Result<ManagedSecret> {
        stub_call!("managed_secrets.update_managed_secret");
        unsupported!("update_managed_secret")
    }

    async fn list_secrets(
        &self,
        _request_scope: Option<&Self::RequestScope>,
    ) -> Result<Vec<ManagedSecret>> {
        stub_call!("managed_secrets.list_secrets");
        Ok(Vec::new())
    }

    async fn list_harness_auth_secrets(
        &self,
        _request_scope: &Self::RequestScope,
        _harness: AgentHarness,
    ) -> Result<Vec<ManagedSecret>> {
        stub_call!("managed_secrets.list_harness_auth_secrets");
        Ok(Vec::new())
    }

    async fn get_task_secrets(
        &self,
        _task_id: String,
        _workload_token: String,
    ) -> Result<HashMap<String, ManagedSecretValue>> {
        stub_call!("managed_secrets.get_task_secrets");
        Ok(HashMap::new())
    }

    async fn issue_task_identity_token(
        &self,
        _request_scope: Option<&Self::RequestScope>,
        _options: IdentityTokenOptions,
    ) -> Result<TaskIdentityToken> {
        stub_call!("managed_secrets.issue_task_identity_token");
        unsupported!("issue_task_identity_token")
    }
}
