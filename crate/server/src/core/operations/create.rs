#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use cosmian_hsm_traits::{Hsm, HsmKeyAlgorithm};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use cosmian_kmip::kmip::kmip_types::{Attributes, CryptographicAlgorithm};
use cosmian_kmip::kmip::{
    kmip_objects::ObjectType,
    kmip_operations::{Create, CreateResponse},
    kmip_types::UniqueIdentifier,
};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use proteccio_pkcs11_loader::Proteccio;
use tracing::{debug, trace};

use crate::{
    core::{extra_database_params::ExtraDatabaseParams, KMS},
    error::KmsError,
    kms_bail,
    result::KResult,
};

pub(crate) async fn create(
    kms: &KMS,
    request: Create,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<CreateResponse> {
    trace!("Create: {}", serde_json::to_string(&request)?);
    if request.protection_storage_masks.is_some() {
        kms_bail!(KmsError::UnsupportedPlaceholder)
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    // An HSM Create request will have a uid in the form of "ham::<slot_id>"
    if let Some(uid) = request
        .attributes
        .unique_identifier
        .as_ref()
        .map(|x| x.to_string())
    {
        if uid.starts_with("hsm::") {
            return if let Some(hsm) = &kms.hsm {
                if owner != kms.params.super_admin_username {
                    return Err(KmsError::InvalidRequest(
                        "Only the Super Admin can create HSM objects".to_owned(),
                    ));
                }
                create_hsm_key(&request, hsm, &uid).await
            } else {
                Err(KmsError::NotSupported(
                    "This server does not support HSM operations".to_owned(),
                ))
            }
        }
    }

    create_kms_key(kms, &request, owner, params).await
}

async fn create_kms_key(
    kms: &KMS,
    request: &Create,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<CreateResponse> {
    let (unique_identifier, object, tags) = match &request.object_type {
        ObjectType::SymmetricKey => KMS::create_symmetric_key_and_tags(request)?,
        ObjectType::PrivateKey => {
            kms.create_private_key_and_tags(request, owner, params)
                .await?
        }
        _ => {
            kms_bail!(KmsError::NotSupported(format!(
                "This server does not yet support creation of: {}",
                request.object_type
            )))
        }
    };
    let uid = kms
        .db
        .create(
            unique_identifier,
            owner,
            &object,
            object.attributes()?,
            &tags,
            params,
        )
        .await?;
    debug!(
        "Created KMS Object of type {:?} with id {uid}",
        &object.object_type(),
    );
    Ok(CreateResponse {
        object_type: request.object_type,
        unique_identifier: UniqueIdentifier::TextString(uid),
    })
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
async fn create_hsm_key(request: &Create, hsm: &Proteccio, uid: &str) -> KResult<CreateResponse> {
    // try converting the rest of the uid into a slot_id
    let slot_id = uid
        .trim_start_matches("hsm::")
        .parse::<usize>()
        .map_err(|e| {
            KmsError::InvalidRequest(format!(
                "An HSM create request must have a uid in the form of 'hsm::<slot_id>': {e}"
            ))
        })?;
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
