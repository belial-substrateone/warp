//! Offline [`TeamClient`] stub: the user belongs to no teams and cannot create or join any.

use anyhow::Result;
use async_trait::async_trait;

use super::{stub_call, unsupported};
use crate::auth::UserUid;
use crate::cloud_object::CloudObjectEventEntrypoint;
use crate::server::ids::ServerId;
use crate::server::server_api::team::TeamClient;
use crate::workspaces::team::{DiscoveryOptions, MembershipRole};
use crate::workspaces::user_workspaces::{
    CreateTeamResponse, WorkspacesMetadataResponse, WorkspacesMetadataWithPricing,
};
use crate::workspaces::workspace::{UserTier, WorkspaceUid};

#[derive(Default, Clone, Copy)]
pub struct StubTeamClient;

#[cfg_attr(not(target_family = "wasm"), async_trait)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
impl TeamClient for StubTeamClient {
    async fn workspaces_metadata(&self) -> Result<WorkspacesMetadataWithPricing> {
        stub_call!("team.workspaces_metadata");
        Ok(WorkspacesMetadataWithPricing {
            metadata: WorkspacesMetadataResponse {
                workspaces: Vec::new(),
                joinable_teams: Vec::new(),
                experiments: None,
                ai_credit_availability: None,
                user_tier: UserTier::default(),
            },
            pricing_info: None,
        })
    }

    async fn add_invite_link_domain_restriction(
        &self,
        _team_uid: ServerId,
        _domain: String,
    ) -> Result<WorkspacesMetadataWithPricing> {
        stub_call!("team.add_invite_link_domain_restriction");
        unsupported!("add_invite_link_domain_restriction")
    }

    async fn delete_invite_link_domain_restriction(
        &self,
        _team_uid: ServerId,
        _domain_uid: ServerId,
    ) -> Result<WorkspacesMetadataWithPricing> {
        stub_call!("team.delete_invite_link_domain_restriction");
        unsupported!("delete_invite_link_domain_restriction")
    }

    async fn create_team(
        &self,
        _name: String,
        _entrypoint: CloudObjectEventEntrypoint,
        _discoverable: Option<bool>,
    ) -> Result<CreateTeamResponse> {
        stub_call!("team.create_team");
        unsupported!("create_team")
    }

    async fn remove_user_from_team(
        &self,
        _user_uid: UserUid,
        _team_uid: ServerId,
        _entrypoint: CloudObjectEventEntrypoint,
    ) -> Result<WorkspacesMetadataWithPricing> {
        stub_call!("team.remove_user_from_team");
        unsupported!("remove_user_from_team")
    }

    async fn leave_team(
        &self,
        _user_uid: UserUid,
        _team_uid: ServerId,
        _entrypoint: CloudObjectEventEntrypoint,
    ) -> Result<WorkspacesMetadataWithPricing> {
        stub_call!("team.leave_team");
        unsupported!("leave_team")
    }

    async fn join_team_with_team_discovery(
        &self,
        _team_uid: ServerId,
    ) -> Result<WorkspacesMetadataWithPricing> {
        stub_call!("team.join_team_with_team_discovery");
        unsupported!("join_team_with_team_discovery")
    }

    async fn join_team_in_workspace(
        &self,
        _team_uid: ServerId,
    ) -> Result<WorkspacesMetadataWithPricing> {
        stub_call!("team.join_team_in_workspace");
        unsupported!("join_team_in_workspace")
    }

    async fn join_workspace_from_discovery(
        &self,
        _workspace_uid: WorkspaceUid,
        _team_uid: Option<ServerId>,
    ) -> Result<WorkspacesMetadataWithPricing> {
        stub_call!("team.join_workspace_from_discovery");
        unsupported!("join_workspace_from_discovery")
    }

    async fn send_team_invite_email(
        &self,
        _team_uid: ServerId,
        _email: String,
    ) -> Result<WorkspacesMetadataWithPricing> {
        stub_call!("team.send_team_invite_email");
        unsupported!("send_team_invite_email")
    }

    async fn delete_team_invite(
        &self,
        _team_uid: ServerId,
        _email: String,
    ) -> Result<WorkspacesMetadataWithPricing> {
        stub_call!("team.delete_team_invite");
        unsupported!("delete_team_invite")
    }

    async fn get_discovery_options(&self) -> Result<DiscoveryOptions> {
        stub_call!("team.get_discovery_options");
        Ok(DiscoveryOptions::default())
    }

    async fn rename_team(
        &self,
        _new_name: String,
        _team_uid: ServerId,
    ) -> Result<WorkspacesMetadataWithPricing> {
        stub_call!("team.rename_team");
        unsupported!("rename_team")
    }

    async fn reset_invite_links(
        &self,
        _team_uid: ServerId,
    ) -> Result<WorkspacesMetadataWithPricing> {
        stub_call!("team.reset_invite_links");
        unsupported!("reset_invite_links")
    }

    async fn set_is_invite_link_enabled(
        &self,
        _team_uid: ServerId,
        _new_value: bool,
    ) -> Result<WorkspacesMetadataWithPricing> {
        stub_call!("team.set_is_invite_link_enabled");
        unsupported!("set_is_invite_link_enabled")
    }

    async fn set_team_discoverability(
        &self,
        _team_uid: ServerId,
        _discoverable: bool,
    ) -> Result<WorkspacesMetadataWithPricing> {
        stub_call!("team.set_team_discoverability");
        unsupported!("set_team_discoverability")
    }

    async fn transfer_team_ownership(
        &self,
        _new_owner_email: String,
    ) -> Result<WorkspacesMetadataWithPricing> {
        stub_call!("team.transfer_team_ownership");
        unsupported!("transfer_team_ownership")
    }

    async fn set_team_member_role(
        &self,
        _user_uid: UserUid,
        _team_uid: ServerId,
        _role: MembershipRole,
    ) -> Result<WorkspacesMetadataWithPricing> {
        stub_call!("team.set_team_member_role");
        unsupported!("set_team_member_role")
    }
}
