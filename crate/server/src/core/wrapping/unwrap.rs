use cosmian_kmip::{
    crypto::wrap::{recover_wrapped_key, unwrap_key_block, update_key_block_with_unwrapped_key},
    kmip::{
        kmip_data_structures::KeyBlock,
        kmip_objects::ObjectType,
        kmip_types::{CryptographicUsageMask, LinkType, StateEnumeration},
        KmipOperation,
    },
};
use cosmian_kms_server_database::ExtraStoreParams;
use tracing::debug;

use crate::{
    core::{uid_utils::has_prefix, KMS},
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

/// Unwrap a key
/// This function is used to unwrap a key before storing it in the database
///
/// # Arguments
/// * `object_key_block`    - the key block of the object to unwrap
/// * `kms`                 - the KMS
/// * `user`                - the user accessing the unwrapping key
/// * `params`              - the extra database parameters
///
/// # Returns
/// * `KResult<()>`         - the result of the operation
pub(crate) async fn unwrap_key(
    object_key_block: &mut KeyBlock,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraStoreParams>,
) -> KResult<()> {
    let key_wrapping_data = object_key_block.key_wrapping_data.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest("unwrap_key: key wrapping data is missing".to_owned())
    })?;

    let unwrapping_key_uid = key_wrapping_data
        .encryption_key_information
        .as_ref()
        .ok_or_else(|| {
            KmsError::InvalidRequest("unwrap_key: encryption key information is missing".to_owned())
        })?
        .unique_identifier
        .to_string();

    if let Some(prefix) = has_prefix(&unwrapping_key_uid) {
        debug!(
            "...unwrapping the key block with key uid: {unwrapping_key_uid} using an encryption \
             oracle, user: {user}"
        );
        unwrap_using_encryption_oracle(
            object_key_block,
            kms,
            user,
            params,
            &unwrapping_key_uid,
            prefix,
        )
        .await?;
    } else {
        debug!(
            "...unwrapping the key block with key uid: {unwrapping_key_uid} using the KMS, user: \
             {user}"
        );
        unwrap_using_kms(object_key_block, kms, user, params, &unwrapping_key_uid).await?;
    }
    debug!(
        "Key successfully unwrapped with wrapping key: {}",
        unwrapping_key_uid
    );

    Ok(())
}

async fn unwrap_using_kms(
    object_key_block: &mut KeyBlock,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraStoreParams>,
    unwrapping_key_uid: &String,
) -> KResult<()> {
    // fetch the wrapping key
    let unwrapping_key = kms
        .database
        .retrieve_object(unwrapping_key_uid, params)
        .await
        .context("wrap using KMS")?;
    let unwrapping_key = unwrapping_key.ok_or_else(|| {
        KmsError::NotSupported(format!(
            "The wrapping key {unwrapping_key_uid} does not exist or is not accessible"
        ))
    })?;
    // in the case the key is a PublicKey or Certificate, we need to fetch the corresponding private key
    let object_type = unwrapping_key.object().object_type();
    let unwrapping_key = match object_type {
        ObjectType::PrivateKey | ObjectType::SymmetricKey => unwrapping_key,
        ObjectType::PublicKey | ObjectType::Certificate => {
            //seek if we have a link to a private key
            let attributes = match object_type {
                ObjectType::PublicKey | ObjectType::Certificate => unwrapping_key.attributes(),
                _ => kms_bail!("unwrap_key: unsupported object type: {object_type}"),
            };
            let private_key_uid = attributes.get_link(LinkType::PrivateKeyLink);
            let sk_id = if let Some(private_key_uid) = private_key_uid {
                private_key_uid.to_string()
            } else if let Some(stripped) = unwrapping_key_uid.strip_suffix("_pk") {
                stripped.to_owned()
            } else {
                kms_bail!(
                    "unwrap_key: no corresponding private key link found for the public key \
                     {unwrapping_key_uid}"
                );
            };
            let unwrapping_key = kms
                .database
                .retrieve_object(&sk_id, params)
                .await
                .context("wrap using KMS")?;
            unwrapping_key.ok_or_else(|| {
                KmsError::NotSupported(format!(
                    "The unwrapping private key {sk_id} does not exist or is not accessible for \
                     the public key {unwrapping_key_uid}"
                ))
            })?
        }
        _ => kms_bail!("unwrap_key: unsupported object type: {}", object_type),
    };
    // check active state
    if unwrapping_key.state() != StateEnumeration::Active {
        return Err(KmsError::NotSupported(format!(
            "The unwrapping key {unwrapping_key_uid} is not active"
        )));
    }
    // check authorized usage
    let attributes = unwrapping_key
        .object()
        .attributes()
        .cloned()
        .unwrap_or_default();
    if !attributes.is_usage_authorized_for(CryptographicUsageMask::UnwrapKey)? {
        return Err(KmsError::NotSupported(format!(
            "The key: {unwrapping_key_uid}, is not meant to unwrap keys"
        )));
    }
    // check user permissions
    if unwrapping_key.owner() != user {
        let ops = kms
            .database
            .list_user_operations_on_object(unwrapping_key.id(), user, false, params)
            .await?;
        if !ops
            .iter()
            .any(|p| [KmipOperation::Decrypt, KmipOperation::Get].contains(p))
        {
            return Err(KmsError::NotSupported(format!(
                "The user {user} does not have the permission to unwrap with the key \
                 {unwrapping_key_uid}"
            )));
        }
    }
    // ok => unwrap
    unwrap_key_block(object_key_block, unwrapping_key.object())?;
    Ok(())
}

/// Wrap a key with a wrapping key using an encryption oracle
async fn unwrap_using_encryption_oracle(
    object_key_block: &mut KeyBlock,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraStoreParams>,
    unwrapping_key_uid: &str,
    prefix: &str,
) -> KResult<()> {
    // Extract authenticated additional data on attributes if exist
    let aad = object_key_block.attributes_mut()?.remove_aad();
    // fetch the key wrapping data
    let key_wrapping_data = object_key_block.key_wrapping_data.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest("unwrap_key: key wrapping data is missing".to_owned())
    })?;
    // recover the wrapped key
    let wrapped_key = recover_wrapped_key(object_key_block, key_wrapping_data)?;
    // determine the private key if a public key is passed
    let unwrapping_key_uid = unwrapping_key_uid
        .strip_suffix("_pk")
        .map_or_else(|| unwrapping_key_uid.to_owned(), ToString::to_string);
    //check permissions
    if !kms
        .database
        .is_object_owned_by(&unwrapping_key_uid, user, params)
        .await?
    {
        let ops = kms
            .database
            .list_user_operations_on_object(&unwrapping_key_uid, user, false, params)
            .await?;
        if !ops
            .iter()
            .any(|p| [KmipOperation::Decrypt, KmipOperation::Get].contains(p))
        {
            return Err(KmsError::NotSupported(format!(
                "The user {user} does not have the permission to unwrap the using the key \
                 {unwrapping_key_uid}"
            )));
        }
    }
    //decrypt the wrapped key
    let lock = kms.encryption_oracles.read().await;
    let encryption_oracle = lock.get(prefix).ok_or_else(|| {
        KmsError::InvalidRequest(format!(
            "Encrypt: unknown encryption oracle prefix: {prefix}"
        ))
    })?;
    let plaintext = encryption_oracle
        .decrypt(
            &unwrapping_key_uid,
            &wrapped_key.key_bytes,
            None,
            aad.as_deref(),
        )
        .await?;
    //update the key block with the unwrapped key
    update_key_block_with_unwrapped_key(
        object_key_block,
        &wrapped_key.attributes,
        wrapped_key.encoding,
        &plaintext,
    )?;
    Ok(())
}
