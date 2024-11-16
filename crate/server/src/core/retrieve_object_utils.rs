use cosmian_kmip::kmip::{kmip_types::StateEnumeration, KmipOperation};
use cosmian_kms_server_database::{ExtraStoreParams, ObjectWithMetadata};
use tracing::trace;

use crate::{core::KMS, error::KmsError, result::KResult};

//TODO This function should probably not be a free standing function KMS side,
// and should be refactored as part of Database,

/// Retrieve a single object for a given operation type
/// or the Get operation if not found.
///
/// This function will retrieve from the HSM is the UID
///
/// This function assumes that if the user can `Get` the object,
/// then it can also do any other operation with it.
pub(crate) async fn retrieve_object_for_operation(
    uid_or_tags: &str,
    operation_type: KmipOperation,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraStoreParams>,
) -> KResult<ObjectWithMetadata> {
    trace!(
        "get_key: key_uid_or_tags: {uid_or_tags:?}, user: {user}, operation_type: \
         {operation_type:?}"
    );

    for owm in kms
        .database
        .retrieve_objects(uid_or_tags, params)
        .await?
        .values()
    {
        if !(owm.state() == StateEnumeration::Active || operation_type == KmipOperation::Export) {
            continue
        }

        if user != owm.owner() {
            let permissions = kms
                .database
                .list_user_operations_on_object(owm.id(), user, false, params)
                .await?;
            if !(permissions.contains(&operation_type) || permissions.contains(&KmipOperation::Get))
            {
                continue
            }
        }
        return Ok(owm.to_owned())
    }

    Err(KmsError::InvalidRequest(format!(
        "too many objects found for identifier {uid_or_tags}",
    )))
}
