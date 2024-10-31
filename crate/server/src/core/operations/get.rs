use cosmian_hsm_traits::{Hsm, HsmKeyAlgorithm};
use cosmian_kmip::kmip::{
    kmip_objects::ObjectType,
    kmip_operations::{Create, CreateResponse, Export, ExportResponse, Get, GetResponse},
    kmip_types::{Attributes, CryptographicAlgorithm, UniqueIdentifier},
};
use cosmian_kms_client::access::ObjectOperationType;
use proteccio_pkcs11_loader::Proteccio;
use tracing::{debug, trace};

use crate::{
    core::{extra_database_params::ExtraDatabaseParams, operations::export_get, KMS},
    error::KmsError,
    result::KResult,
};

/// Get an object
///
/// If the request contains a `KeyWrappingData`, the key will be wrapped
/// If the request contains a `KeyWrapType`, the key will be unwrapped
/// If both are present, the key will be wrapped
/// If none are present, the key will be returned as is
pub(crate) async fn get(
    kms: &KMS,
    request: Get,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<GetResponse> {
    trace!("Get: {}", serde_json::to_string(&request)?);

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    // An HSM Create request will have a uid in the form of "ham::<slot_id>"
    if let Some(uid) = request.unique_identifier.as_ref().map(|x| x.to_string()) {
        if uid.starts_with("hsm::") {
            return if let Some(hsm) = &kms.hsm {
                if user != kms.params.super_admin_username {
                    return Err(KmsError::InvalidRequest(
                        "Only the Super Admin can create HSM objects".to_owned(),
                    ));
                }
                get_hsm_key(request, hsm, &uid).await.map(|r| r.into())
            } else {
                Err(KmsError::NotSupported(
                    "This server does not support HSM operations".to_owned(),
                ))
            }
        }
    }

    let response = export_get(kms, request, ObjectOperationType::Get, user, params)
        .await
        .map(Into::into)?;
    Ok(response)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
async fn get_hsm_key(
    request: impl Into<Export>,
    hsm: &Proteccio,
    uid: &str,
) -> KResult<ExportResponse> {
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
    let slot_id = slot_id.parse::<u64>().map_err(|_| {
        KmsError::InvalidRequest("The slot_id must be a valid unsigned integer".to_owned())
    })?;
    let key_id = key_id.parse::<u64>().map_err(|_| {
        KmsError::InvalidRequest("The key_id must be a valid unsigned integer".to_owned())
    })?;
    let id = hsm
        .retrieve(
            slot_id,
            HsmKeyAlgorithm::AES,
            *key_length as usize,
            label.as_str(),
        )
        .await?;

    match &request.object_type {
        ObjectType::SymmetricKey => {
            let algorithm = request
                .attributes
                .cryptographic_algorithm
                .as_ref()
                .ok_or_else(|| {
                    KmsError::InvalidRequest(
                        "Symmetric key must have a cryptographic algorithm specified".to_owned(),
                    )
                })?;
            if *algorithm != CryptographicAlgorithm::AES {
                return Err(KmsError::InvalidRequest(
                    "Only AES symmetric keys can be created on the HSM in this server".to_owned(),
                ));
            }
            let key_length = request
                .attributes
                .cryptographic_length
                .as_ref()
                .ok_or_else(|| {
                    KmsError::InvalidRequest(
                        "Symmetric key must have a cryptographic length specified".to_owned(),
                    )
                })?;
            // recover tags
            let tags = &request.attributes.get_tags();
            Attributes::check_user_tags(&tags)?;
            let label = if tags.is_empty() {
                String::new()
            } else {
                serde_json::to_string(&tags)?
            };
            let id = hsm
                .create_key(
                    slot_id,
                    HsmKeyAlgorithm::AES,
                    *key_length as usize,
                    label.as_str(),
                )
                .await?;
            let uid = format!("hsm::{slot_id}::{id}");
            debug!(
                "Created HSM Key of type {:?} with id {uid}",
                &request.object_type,
            );
            Ok(CreateResponse {
                object_type: request.object_type,
                unique_identifier: UniqueIdentifier::TextString(uid),
            })
        }
        _ => Err(KmsError::InvalidRequest(
            "Only HSM Symmetric keys can be created in this server".to_owned(),
        )),
    }
}
