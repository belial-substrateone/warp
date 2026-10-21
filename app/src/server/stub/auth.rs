//! Offline [`AuthClient`]: the app behaves as a signed-out user with no server session.

use std::result::Result as StdResult;

use anyhow::Result;
use async_trait::async_trait;
use cloud_objects::ids::ServerId;
use instant::Duration;
use warp_graphql::mutations::create_anonymous_user::{AnonymousUserType, CreateAnonymousUserResult};
use warp_graphql::mutations::expire_api_key::ExpireApiKeyResult;
use warp_graphql::mutations::generate_api_key::GenerateApiKeyResult;
use warp_graphql::mutations::mint_custom_token::MintCustomTokenResult;
use warp_graphql::mutations::update_user_settings::UpdateUserSettingsInput;
use warp_graphql::queries::api_keys::ApiKeyProperties;
use warp_graphql::queries::get_user::UserOutput as GqlUserOutput;
use warp_server_auth::credentials::{AuthToken, FirebaseToken, LoginToken};
use warp_server_client::auth::{AgentIdentity, MintCustomTokenError};
use warp_server_client::ids::ApiKeyUid;

use super::{stub_call, unsupported};
use crate::server::server_api::auth::{
    AuthClient, FetchUserResult, SyncedUserSettings, UserAuthenticationError,
};

/// Stub [`AuthClient`] that never talks to a server.
#[derive(Default, Clone, Copy)]
pub struct StubAuthClient;

#[cfg_attr(not(target_family = "wasm"), async_trait)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
impl AuthClient for StubAuthClient {
    async fn create_anonymous_user(
        &self,
        _referral_code: Option<String>,
        _anonymous_user_type: AnonymousUserType,
    ) -> Result<CreateAnonymousUserResult> {
        stub_call!("auth.create_anonymous_user");
        unsupported!("create_anonymous_user")
    }

    async fn get_or_refresh_access_token(&self) -> Result<AuthToken> {
        stub_call!("auth.get_or_refresh_access_token");
        // No Authorization header; nothing is ever sent to a server anyway.
        Ok(AuthToken::NoAuth)
    }

    async fn fetch_user(
        &self,
        _token: LoginToken,
        _for_refresh: bool,
    ) -> StdResult<FetchUserResult, UserAuthenticationError> {
        stub_call!("auth.fetch_user");
        Err(UserAuthenticationError::Unexpected(anyhow::Error::new(
            super::StubUnsupported("fetch_user"),
        )))
    }

    async fn fetch_new_custom_token(&self) -> Result<MintCustomTokenResult> {
        stub_call!("auth.fetch_new_custom_token");
        unsupported!("fetch_new_custom_token")
    }

    fn on_custom_token_fetched(
        &self,
        _response: Result<MintCustomTokenResult>,
    ) -> StdResult<String, MintCustomTokenError> {
        stub_call!("auth.on_custom_token_fetched");
        Err(MintCustomTokenError::Unknown)
    }

    async fn fetch_user_properties<'a>(
        &self,
        _auth_token: Option<&'a str>,
    ) -> Result<GqlUserOutput> {
        stub_call!("auth.fetch_user_properties");
        unsupported!("fetch_user_properties")
    }

    async fn get_user_settings(&self) -> Result<Option<SyncedUserSettings>> {
        stub_call!("auth.get_user_settings");
        Ok(None)
    }

    async fn set_is_telemetry_enabled(&self, _value: bool) -> Result<()> {
        stub_call!("auth.set_is_telemetry_enabled");
        Ok(())
    }

    async fn set_is_crash_reporting_enabled(&self, _value: bool) -> Result<()> {
        stub_call!("auth.set_is_crash_reporting_enabled");
        Ok(())
    }

    async fn set_is_cloud_conversation_storage_enabled(&self, _value: bool) -> Result<()> {
        stub_call!("auth.set_is_cloud_conversation_storage_enabled");
        Ok(())
    }

    async fn update_user_settings(&self, _input: UpdateUserSettingsInput) -> Result<()> {
        stub_call!("auth.update_user_settings");
        Ok(())
    }

    async fn set_user_is_onboarded(&self) -> Result<bool> {
        stub_call!("auth.set_user_is_onboarded");
        Ok(true)
    }

    async fn request_device_code(
        &self,
    ) -> StdResult<oauth2::StandardDeviceAuthorizationResponse, UserAuthenticationError> {
        stub_call!("auth.request_device_code");
        Err(UserAuthenticationError::Unexpected(anyhow::Error::new(
            super::StubUnsupported("request_device_code"),
        )))
    }

    async fn exchange_device_access_token(
        &self,
        _details: &oauth2::StandardDeviceAuthorizationResponse,
        _timeout: Duration,
    ) -> StdResult<FirebaseToken, UserAuthenticationError> {
        stub_call!("auth.exchange_device_access_token");
        Err(UserAuthenticationError::Unexpected(anyhow::Error::new(
            super::StubUnsupported("exchange_device_access_token"),
        )))
    }

    async fn list_api_keys(&self, _team_uid: Option<ServerId>) -> Result<Vec<ApiKeyProperties>> {
        stub_call!("auth.list_api_keys");
        Ok(Vec::new())
    }

    async fn create_api_key(
        &self,
        _name: String,
        _team_id: Option<cynic::Id>,
        _agent_uid: Option<cynic::Id>,
        _expires_at: Option<warp_graphql::scalars::Time>,
    ) -> Result<GenerateApiKeyResult> {
        stub_call!("auth.create_api_key");
        unsupported!("create_api_key")
    }

    async fn expire_api_key(&self, _key_uid: &ApiKeyUid) -> Result<ExpireApiKeyResult> {
        stub_call!("auth.expire_api_key");
        unsupported!("expire_api_key")
    }

    async fn list_agent_identities(
        &self,
        _team_uid: Option<ServerId>,
    ) -> Result<Vec<AgentIdentity>> {
        stub_call!("auth.list_agent_identities");
        Ok(Vec::new())
    }
}
