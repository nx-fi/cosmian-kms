use cosmian_kmip::kmip::{kmip_types::StateEnumeration, KmipOperation};
use cosmian_kms_server_database::{ExtraStoreParams, ObjectWithMetadata};
use tracing::trace;

use crate::{core::KMS, error::KmsError, result::KResult};

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

    // //TODO: we could improve the retrieve() DB calls to support a list of Any(operation..)
    // // https://github.com/Cosmian/kms/issues/93
    // Ok(
    //     match _retrieve_object(uid_or_tags, operation_type, kms, user, params).await {
    //         Ok(key) => key,
    //         Err(_) => {
    //             // see if we can Get: in that case the user can always re-import the object and own it
    //             _retrieve_object(uid_or_tags, KmipOperation::Get, kms, user, params).await?
    //         }
    //     },
    // )
}

// /// Retrieve a single object - inner
// async fn _retrieve_object(
//     uid_or_tags: &str,
//     operation_type: KmipOperation,
//     kms: &KMS,
//     user: &str,
//     params: Option<&ExtraStoreParams>,
// ) -> KResult<ObjectWithMetadata> {
//     trace!(
//         "get_key: key_uid_or_tags: {uid_or_tags:?}, user: {user}, operation_type: \
//          {operation_type:?}"
//     );
//
//     // An HSM Create request will have a uid in the form of "ham::<slot_id>"
//     if uid_or_tags.starts_with("hsm::") {
//         return get_hsm_object(uid_or_tags, operation_type, kms, user).await;
//     }
//
//     // Getting a database object
//     let mut owm_s: Vec<ObjectWithMetadata> = kms
//         .database
//         .retrieve(uid_or_tags, user, operation_type, params)
//         .await?
//         .into_values()
//         .filter(|owm| {
//             owm.state() == StateEnumeration::Active || operation_type == KmipOperation::Export
//         })
//         .collect();
//     // there can only be one object
//     let owm = owm_s.pop().ok_or_else(|| {
//         KmsError::ItemNotFound(format!(
//             "no active or exportable object found for identifier {uid_or_tags}"
//         ))
//     })?;
//     if !owm_s.is_empty() {
//         return Err(KmsError::InvalidRequest(format!(
//             "too many objects found for identifier {uid_or_tags}",
//         )))
//     }
//     Ok(owm)
// }
