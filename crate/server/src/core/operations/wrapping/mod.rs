use cosmian_kmip::kmip::{kmip_objects::Object, kmip_types::StateEnumeration};
use cosmian_kms_utils::access::{ExtraDatabaseParams, ObjectOperationType};
use tracing::trace;
pub(crate) use unwrap::unwrap_key;
pub(crate) use wrap::wrap_key;

use crate::{core::KMS, kms_bail, result::KResult};

mod unwrap;
mod wrap;

async fn get_key(
    key_uid_or_tags: &str,
    operation_type: ObjectOperationType,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Object> {
    //TODO: we could improve the retrieve() DB calls to support a list of Any(operation..)
    Ok(
        match _get_key(key_uid_or_tags, operation_type, kms, user, params).await {
            Ok(key) => key,
            Err(_) => {
                // see if we can Get it which is also acceptable in this case
                _get_key(key_uid_or_tags, ObjectOperationType::Get, kms, user, params).await?
            }
        },
    )
}

/// check if unwrapping key exists and retrieve it
async fn _get_key(
    key_uid_or_tags: &str,
    operation_type: ObjectOperationType,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Object> {
    trace!(
        "get_key: key_uid_or_tags: {key_uid_or_tags:?}, user: {user}, operation_type: \
         {operation_type:?}"
    );
    let mut objects: Vec<Object> = kms
        .db
        .retrieve(key_uid_or_tags, user, operation_type, params)
        .await?
        .into_iter()
        .filter(|(_uid, owm)| owm.state == StateEnumeration::Active)
        .map(|(_uid, own)| own.object)
        .collect();
    match objects.len() {
        0 => kms_bail!("unable to fetch the key with uid or tags: {key_uid_or_tags}. No key found"),
        1 => Ok(objects.remove(0)),
        _ => kms_bail!(
            "unable to fetch the key with uid or tags: {key_uid_or_tags}. Too many keys matching \
             the passed tags"
        ),
    }
}
