//! Offline [`WorkspaceClient`] stub: the user has no workspaces and nothing to bill.

use anyhow::Result;
use async_trait::async_trait;

use super::{stub_call, unsupported};
use crate::auth::UserUid;
use crate::cloud_object::CloudObjectEventEntrypoint;
use crate::server::ids::ServerId;
use crate::server::server_api::workspace::{PurchaseAddonCreditsOutcome, WorkspaceClient};
use crate::workspaces::user_workspaces::{
    WorkspacesMetadataResponse, WorkspacesMetadataWithPricing,
};
use crate::workspaces::workspace::{AiOverages, WorkspaceUid};

#[derive(Default, Clone, Copy)]
pub struct StubWorkspaceClient;

#[cfg_attr(not(target_family = "wasm"), async_trait)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
impl WorkspaceClient for StubWorkspaceClient {
    async fn generate_stripe_billing_portal_link(&self, _team_uid: ServerId) -> Result<String> {
        stub_call!("workspace.generate_stripe_billing_portal_link");
        unsupported!("generate_stripe_billing_portal_link")
    }

    async fn remove_user_from_workspace(
        &self,
        _user_uid: UserUid,
        _workspace_uid: WorkspaceUid,
        _entrypoint: CloudObjectEventEntrypoint,
    ) -> Result<WorkspacesMetadataWithPricing> {
        stub_call!("workspace.remove_user_from_workspace");
        unsupported!("remove_user_from_workspace")
    }

    async fn update_usage_based_pricing_settings(
        &self,
        _team_uid: ServerId,
        _usage_based_pricing_enabled: bool,
        _max_monthly_spend_cents: Option<u32>,
    ) -> Result<WorkspacesMetadataResponse> {
        stub_call!("workspace.update_usage_based_pricing_settings");
        unsupported!("update_usage_based_pricing_settings")
    }

    async fn refresh_ai_overages(&self) -> Result<AiOverages> {
        stub_call!("workspace.refresh_ai_overages");
        Ok(AiOverages {
            current_monthly_request_cost_cents: 0,
            current_monthly_requests_used: 0,
            current_period_end: chrono::Utc::now(),
        })
    }

    async fn purchase_addon_credits(
        &self,
        _team_uid: Option<ServerId>,
        _credits: i32,
    ) -> Result<PurchaseAddonCreditsOutcome> {
        stub_call!("workspace.purchase_addon_credits");
        unsupported!("purchase_addon_credits")
    }

    async fn update_addon_credits_settings(
        &self,
        _team_uid: ServerId,
        _auto_reload_enabled: Option<bool>,
        _max_monthly_spend_cents: Option<i32>,
        _selected_auto_reload_credit_denomination: Option<i32>,
    ) -> Result<WorkspacesMetadataResponse> {
        stub_call!("workspace.update_addon_credits_settings");
        unsupported!("update_addon_credits_settings")
    }
}
