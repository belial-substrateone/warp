//! Offline [`ObjectClient`] stub: Warp Drive is permanently empty and read-only.

use std::collections::HashMap;

use anyhow::Result;
use async_channel::Sender;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use cloud_object_client::{
    GetCloudObjectResponse, InitialLoadResponse, ObjectActionHistory, ObjectActionType,
    ObjectDeleteResult, ObjectMetadataUpdateResult, ObjectPermissionUpdateResult,
    ObjectPermissionsUpdateData, ObjectUpdateMessage,
};
use warp_graphql::object_permissions::AccessLevel;

use super::{stub_call, unsupported};
use crate::cloud_object::{
    BulkCreateCloudObjectResult, BulkCreateGenericStringObjectsRequest, CreateCloudObjectResult,
    CreateObjectRequest, GenericStringObjectFormat, GenericStringObjectUniqueKey, ObjectType,
    ObjectsToUpdate, Owner, Revision, ServerFolder, ServerMetadata, ServerNotebook, ServerObject,
    ServerPermissions, ServerWorkflow, UpdateCloudObjectResult,
};
use crate::drive::folders::FolderId;
use crate::drive::sharing::SharingAccessLevel;
use crate::cloud_object::model::generic_string_model::GenericStringObjectId;
use crate::notebooks::NotebookId;
use crate::server::ids::ServerId;
use crate::server::server_api::object::{GuestIdentifier, ObjectClient};
use crate::server::sync_queue::SerializedModel;
use crate::workflows::WorkflowId;

const OFFLINE_MSG: &str = "Warp Drive is not available in AnonWarp's offline mode";

#[derive(Default, Clone, Copy)]
pub struct StubObjectClient;

#[cfg_attr(not(target_family = "wasm"), async_trait)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
impl ObjectClient for StubObjectClient {
    async fn create_workflow(
        &self,
        _request: CreateObjectRequest,
    ) -> Result<CreateCloudObjectResult> {
        stub_call!("objects.create_workflow");
        Ok(CreateCloudObjectResult::UserFacingError(OFFLINE_MSG.to_string()))
    }

    async fn update_workflow(
        &self,
        _workflow_id: WorkflowId,
        _data: SerializedModel,
        _revision: Option<Revision>,
    ) -> Result<UpdateCloudObjectResult<ServerWorkflow>> {
        stub_call!("objects.update_workflow");
        unsupported!("update_workflow")
    }

    async fn bulk_create_generic_string_objects(
        &self,
        _owner: Owner,
        _objects: &[BulkCreateGenericStringObjectsRequest],
    ) -> Result<BulkCreateCloudObjectResult> {
        stub_call!("objects.bulk_create_generic_string_objects");
        unsupported!("bulk_create_generic_string_objects")
    }

    async fn create_generic_string_object(
        &self,
        _format: GenericStringObjectFormat,
        _uniqueness_key: Option<GenericStringObjectUniqueKey>,
        _request: CreateObjectRequest,
    ) -> Result<CreateCloudObjectResult> {
        stub_call!("objects.create_generic_string_object");
        Ok(CreateCloudObjectResult::UserFacingError(OFFLINE_MSG.to_string()))
    }

    async fn create_notebook(
        &self,
        _request: CreateObjectRequest,
    ) -> Result<CreateCloudObjectResult> {
        stub_call!("objects.create_notebook");
        Ok(CreateCloudObjectResult::UserFacingError(OFFLINE_MSG.to_string()))
    }

    async fn update_notebook(
        &self,
        _notebook_id: NotebookId,
        _title: Option<String>,
        _data: Option<SerializedModel>,
        _revision: Option<Revision>,
    ) -> Result<UpdateCloudObjectResult<ServerNotebook>> {
        stub_call!("objects.update_notebook");
        unsupported!("update_notebook")
    }

    async fn create_folder(
        &self,
        _request: CreateObjectRequest,
    ) -> Result<CreateCloudObjectResult> {
        stub_call!("objects.create_folder");
        Ok(CreateCloudObjectResult::UserFacingError(OFFLINE_MSG.to_string()))
    }

    async fn update_folder(
        &self,
        _folder_id: FolderId,
        _name: SerializedModel,
    ) -> Result<UpdateCloudObjectResult<ServerFolder>> {
        stub_call!("objects.update_folder");
        unsupported!("update_folder")
    }

    async fn update_generic_string_object(
        &self,
        _object_id: GenericStringObjectId,
        _model: SerializedModel,
        _revision: Option<Revision>,
    ) -> Result<UpdateCloudObjectResult<Box<dyn ServerObject>>> {
        stub_call!("objects.update_generic_string_object");
        unsupported!("update_generic_string_object")
    }

    async fn grab_notebook_edit_access(&self, _notebook_id: NotebookId) -> Result<ServerMetadata> {
        stub_call!("objects.grab_notebook_edit_access");
        unsupported!("grab_notebook_edit_access")
    }

    async fn give_up_notebook_edit_access(
        &self,
        _notebook_id: NotebookId,
    ) -> Result<ServerMetadata> {
        stub_call!("objects.give_up_notebook_edit_access");
        unsupported!("give_up_notebook_edit_access")
    }

    async fn get_warp_drive_updates(
        &self,
        _message_sender: Sender<ObjectUpdateMessage>,
        _stream_ready_sender: Sender<()>,
    ) -> Result<()> {
        stub_call!("objects.get_warp_drive_updates");
        // There is no stream offline. Never resolve, so the listener neither reconnects in a
        // loop nor reports an error (the future is dropped when the listener is).
        std::future::pending::<()>().await;
        Ok(())
    }

    async fn fetch_changed_objects(
        &self,
        _objects_to_update: ObjectsToUpdate,
        _force_refresh: bool,
    ) -> Result<InitialLoadResponse> {
        stub_call!("objects.fetch_changed_objects");
        Ok(InitialLoadResponse::default())
    }

    async fn fetch_single_cloud_object(&self, _id: ServerId) -> Result<GetCloudObjectResponse> {
        stub_call!("objects.fetch_single_cloud_object");
        unsupported!("fetch_single_cloud_object")
    }

    async fn transfer_notebook_owner(
        &self,
        _notebook_id: NotebookId,
        _owner: Owner,
    ) -> Result<bool> {
        stub_call!("objects.transfer_notebook_owner");
        Ok(false)
    }

    async fn transfer_workflow_owner(
        &self,
        _workflow_id: WorkflowId,
        _owner: Owner,
    ) -> Result<bool> {
        stub_call!("objects.transfer_workflow_owner");
        Ok(false)
    }

    async fn transfer_generic_string_object_owner(
        &self,
        _workflow_id: GenericStringObjectId,
        _owner: Owner,
    ) -> Result<bool> {
        stub_call!("objects.transfer_generic_string_object_owner");
        Ok(false)
    }

    async fn trash_object(&self, _id: ServerId) -> Result<bool> {
        stub_call!("objects.trash_object");
        Ok(false)
    }

    async fn untrash_object(&self, _id: ServerId) -> Result<ObjectMetadataUpdateResult> {
        stub_call!("objects.untrash_object");
        Ok(ObjectMetadataUpdateResult::Failure)
    }

    async fn delete_object(&self, _id: ServerId) -> Result<ObjectDeleteResult> {
        stub_call!("objects.delete_object");
        Ok(ObjectDeleteResult::Failure)
    }

    async fn empty_trash(&self, _owner: Owner) -> Result<ObjectDeleteResult> {
        stub_call!("objects.empty_trash");
        Ok(ObjectDeleteResult::Failure)
    }

    async fn move_object(
        &self,
        _id: ServerId,
        _folder_id: Option<FolderId>,
        _owner: Owner,
        _object_type: ObjectType,
    ) -> Result<bool> {
        stub_call!("objects.move_object");
        Ok(false)
    }

    async fn record_object_action(
        &self,
        _id: ServerId,
        _action_type: ObjectActionType,
        _timestamp: DateTime<Utc>,
        _data: Option<String>,
    ) -> Result<ObjectActionHistory> {
        stub_call!("objects.record_object_action");
        unsupported!("record_object_action")
    }

    async fn leave_object(&self, _id: ServerId) -> Result<ObjectDeleteResult> {
        stub_call!("objects.leave_object");
        Ok(ObjectDeleteResult::Failure)
    }

    async fn set_object_link_permissions(
        &self,
        _object_id: ServerId,
        _access_level: SharingAccessLevel,
    ) -> Result<ObjectPermissionUpdateResult> {
        stub_call!("objects.set_object_link_permissions");
        Ok(ObjectPermissionUpdateResult::Failure)
    }

    async fn remove_object_link_permissions(
        &self,
        _object_id: ServerId,
    ) -> Result<ObjectPermissionUpdateResult> {
        stub_call!("objects.remove_object_link_permissions");
        Ok(ObjectPermissionUpdateResult::Failure)
    }

    async fn add_object_guests(
        &self,
        _object_id: ServerId,
        _guest_emails: Vec<String>,
        _access_level: AccessLevel,
    ) -> Result<ObjectPermissionsUpdateData> {
        stub_call!("objects.add_object_guests");
        unsupported!("add_object_guests")
    }

    async fn update_object_guests(
        &self,
        _object_id: ServerId,
        _guest_emails: Vec<String>,
        _access_level: AccessLevel,
    ) -> Result<ServerPermissions> {
        stub_call!("objects.update_object_guests");
        unsupported!("update_object_guests")
    }

    async fn remove_object_guest(
        &self,
        _object_id: ServerId,
        _guest: GuestIdentifier,
    ) -> Result<ServerPermissions> {
        stub_call!("objects.remove_object_guest");
        unsupported!("remove_object_guest")
    }

    async fn fetch_environment_last_task_run_timestamps(
        &self,
    ) -> Result<HashMap<String, DateTime<Utc>>> {
        stub_call!("objects.fetch_environment_last_task_run_timestamps");
        Ok(HashMap::new())
    }
}
