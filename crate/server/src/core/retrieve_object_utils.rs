use cosmian_kmip::kmip::kmip_types::StateEnumeration;
use cosmian_kms_client::access::ObjectOperationType;
use tracing::trace;

use crate::{
    core::{
        extra_database_params::ExtraDatabaseParams, object_with_metadata::ObjectWithMetadata, KMS,
    },
    error::KmsError,
    result::KResult,
};

/// Retrieve a single object for a given operation type
/// or the Get operation if not found.
///
/// This function assumes that if the user can `Get` the object,
/// then it can also do any other operation with it.
pub(crate) async fn retrieve_object_for_operation(
    uid_or_tags: &str,
    operation_type: ObjectOperationType,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<ObjectWithMetadata> {
    //TODO: we could improve the retrieve() DB calls to support a list of Any(operation..)
    // https://github.com/Cosmian/kms/issues/93
    Ok(
        match _retrieve_object(uid_or_tags, operation_type, kms, user, params).await {
            Ok(key) => key,
            Err(_) => {
                // see if we can Get: in that case the user can always re-import the object and own it
                _retrieve_object(uid_or_tags, ObjectOperationType::Get, kms, user, params).await?
            }
        },
    )
}

/// Retrieve a single object - inner
async fn _retrieve_object(
    uid_or_tags: &str,
    operation_type: ObjectOperationType,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<ObjectWithMetadata> {
    trace!(
        "get_key: key_uid_or_tags: {uid_or_tags:?}, user: {user}, operation_type: \
         {operation_type:?}"
    );

    // An HSM Create request will have a uid in the form of "ham::<slot_id>"
    if uid_or_tags.starts_with("hsm::") {
        return get_hsm_object(uid_or_tags, operation_type, kms, user).await;
    }

    // Getting a database object
    let mut owm_s: Vec<ObjectWithMetadata> = kms
        .db
        .retrieve(uid_or_tags, user, operation_type, params)
        .await?
        .into_values()
        .filter(|owm| {
            owm.state() == StateEnumeration::Active || operation_type == ObjectOperationType::Export
        })
        .collect();
    // there can only be one object
    let owm = owm_s.pop().ok_or_else(|| {
        KmsError::ItemNotFound(format!(
            "no active or exportable object found for identifier {uid_or_tags}"
        ))
    })?;
    if !owm_s.is_empty() {
        return Err(KmsError::InvalidRequest(format!(
            "too many objects found for identifier {uid_or_tags}",
        )))
    }
    Ok(owm)
}

async fn get_hsm_object(
    uid: &str,
    _operation_type: ObjectOperationType,
    kms: &KMS,
    user: &str,
) -> KResult<ObjectWithMetadata> {
    let hsm = if let Some(hsm) = &kms.hsm {
        if user != kms.params.hsm_admin {
            return Err(KmsError::InvalidRequest(
                "Only the HSM Admin can retrieve HSM objects".to_owned(),
            ));
        }
        hsm
    } else {
        return Err(KmsError::NotSupported(
            "This server does not support HSM operations".to_owned(),
        ))
    };
    // try converting the rest of the uid into a slot_id and key id
    let (slot_id, key_id) = uid
        .trim_start_matches("hsm::")
        .split_once("::")
        .ok_or_else(|| {
            KmsError::InvalidRequest(
                "An HSM create request must have a uid in the form of 'hsm::<slot_id>::<key_id>'"
                    .to_owned(),
            )
        })?;
    let slot_id = slot_id.parse::<usize>().map_err(|e| {
        KmsError::InvalidRequest(format!("The slot_id must be a valid unsigned integer: {e}"))
    })?;
    let key_id = key_id.parse::<usize>().map_err(|e| {
        KmsError::InvalidRequest(format!("The key_id must be a valid unsigned integer: {e}"))
    })?;
    let _hsm_object = hsm.export(slot_id, key_id).await?;
    // Convert the HSM object into an ObjectWithMetadata
    // let owm = match hsm_object.object_type() {
    //     HsmObjectType::Aes => {
    //         let object = Object::SymmetricKey {
    //             key_block: KeyBlock {
    //                 key_format_type: KeyFormatType::Raw,
    //                 key_compression_type: None,
    //                 key_value: KeyValue {},
    //                 cryptographic_algorithm: None,
    //                 cryptographic_length: None,
    //                 key_wrapping_data: None,
    //             },
    //         };
    //         ObjectWithMetadata::new(object, pwmer, state, permissions, attributes)
    //     }
    //     HsmObjectType::RsaPrivate => {
    //         ObjectWithMetadata::new(object, pwmer, state, permissions, attributes)
    //     }
    //     HsmObjectType::RsaPublic => {
    //         ObjectWithMetadata::new(object, pwmer, state, permissions, attributes)
    //     }
    // };
    //
    // Ok(owm)
    todo!()
}
