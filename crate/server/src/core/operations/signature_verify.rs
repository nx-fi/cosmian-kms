use alloy::{
    primitives::{Address, FixedBytes, PrimitiveSignature},
    signers::{
        k256::ecdsa::VerifyingKey,
        local::{LocalSigner, PrivateKeySigner},
        SignerSync,
    },
};
use cosmian_kmip::{
    crypto::secret::Secret,
    kmip::{
        kmip_data_structures::KeyMaterial,
        kmip_objects::{Object, ObjectType},
        kmip_operations::{ErrorReason, SignatureVerify, SignatureVerifyResponse},
        kmip_types::{
            CryptographicUsageMask, KeyFormatType, RecommendedCurve, StateEnumeration,
            UniqueIdentifier, ValidityIndicator,
        },
    },
    kmip_bail, KmipError,
};
use cosmian_kms_client::access::ObjectOperationType;
use tracing::trace;

use crate::{
    core::{extra_database_params::ExtraDatabaseParams, operations::unwrap_key, KMS},
    database::object_with_metadata::ObjectWithMetadata,
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

const EMPTY_SLICE: &[u8] = &[];

pub(crate) async fn signature_verify(
    kms: &KMS,
    request: SignatureVerify,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<SignatureVerifyResponse> {
    trace!("Signature Verify: {}", serde_json::to_string(&request)?);

    let owm = get_key(kms, &request, user, params).await?;

    match &owm.object {
        Object::PublicKey { .. } => {
            if request.digested_data.is_some() {
                verify_signature_with_public_key(&owm, &request)
            } else if request.data.is_some() {
                // TODO: implement sign_data_with_private_key
                // sign_data_with_private_key(&owm, &request)
                kms_bail!(KmsError::InvalidRequest(
                    "sign: digest must be provided".to_owned()
                ));
            } else {
                kms_bail!(KmsError::InvalidRequest(
                    "sign: either data or digested_data must be provided".to_owned()
                ));
            }
        }
        other => kms_bail!(KmsError::NotSupported(format!(
            "sign: sign with keys of type: {} is not supported",
            other.object_type()
        ))),
    }
}

async fn get_key(
    kms: &KMS,
    request: &SignatureVerify,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<ObjectWithMetadata> {
    // there must be an identifier
    let uid_or_tags = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("SignatureVerify: the unique identifier or tags must be a string")?
        .to_owned();
    trace!("operations::signature_verify: key uid_or_tags: {uid_or_tags}");

    // retrieve from tags or use passed identifier
    let mut owm_s = kms
        .db
        .retrieve(
            &uid_or_tags,
            user,
            ObjectOperationType::SignatureVerify,
            params,
        )
        .await?
        .into_values()
        .filter(|owm| {
            let object_type = owm.object.object_type();
            owm.state == StateEnumeration::Active && object_type == ObjectType::PrivateKey
        })
        .collect::<Vec<ObjectWithMetadata>>();

    trace!(
        "operations::signature_verify: key owm_s: number of results: {}",
        owm_s.len()
    );
    // there can only be one key
    let mut owm = owm_s
        .pop()
        .ok_or_else(|| KmsError::KmipError(ErrorReason::Item_Not_Found, uid_or_tags.clone()))?;

    if !owm_s.is_empty() {
        return Err(KmsError::InvalidRequest(format!(
            "get: too many objects for key {uid_or_tags}",
        )));
    }

    // the key must be active
    if owm.state != StateEnumeration::Active {
        kms_bail!(KmsError::InconsistentOperation(
            "signature_verify: the server cannot if the key is not active".to_owned()
        ));
    }

    // unwrap if wrapped
    if owm.object.key_wrapping_data().is_some() {
        let key_block = owm.object.key_block_mut()?;
        unwrap_key(key_block, kms, &owm.owner, params).await?;
    }
    Ok(owm)
}

fn verify_signature_with_public_key(
    owm: &ObjectWithMetadata,
    request: &SignatureVerify,
) -> KResult<SignatureVerifyResponse> {
    let pubkey = public_key_to_raw(&owm.object)?;
    let signature = request
        .signature
        .as_ref()
        .context("SignatureVerify: signature is missing")?;
    let signature = PrimitiveSignature::try_from(signature.as_slice())
        .context("SignatureVerify: signature data error")?;
    let data = request
        .data
        .as_ref()
        .context("SignatureVerify: data is missing")?;
    let valid = signature
        .recover_from_prehash(
            &FixedBytes::<32>::try_from(data.as_slice())
                .context("SignatureVerify: data length error")?,
        )
        .context("SignatureVerify: signature recovery error")?
        == VerifyingKey::from_sec1_bytes(pubkey.as_slice())
            .context("SignatureVerify: key recovery error")?;
    let valid: ValidityIndicator = if valid {
        ValidityIndicator::Valid
    } else {
        ValidityIndicator::Invalid
    };

    Ok(SignatureVerifyResponse {
        unique_identifier: UniqueIdentifier::TextString(owm.id.clone()),
        validity_indicator: valid,
        recovered_data: None,
        correlation_value: request.correlation_value.clone(),
    })
}

fn public_key_to_raw(public_key: &Object) -> Result<Vec<u8>, KmipError> {
    let key_block = match public_key {
        Object::PublicKey { key_block } => key_block,
        x => kmip_bail!("Invalid Object: {}. KMIP Public Key expected", x),
    };
    let pubkey: Vec<u8> = match key_block.key_format_type {
        KeyFormatType::TransparentECPublicKey => match &key_block.key_value.key_material {
            KeyMaterial::TransparentECPublicKey {
                q_string,
                recommended_curve,
            } => match recommended_curve {
                RecommendedCurve::SECP256K1 => q_string.clone(),
                other => kmip_bail!(
                    "Unsupported curve for Transparent EC public key: {:?}",
                    other
                ),
            },
            x => kmip_bail!(
                "KMIP key to openssl: invalid Transparent EC public key material: {}: \
                 TransparentECPublicKey expected",
                x
            ),
        },
        f => kmip_bail!(
            "Unsupported key format type: {:?}, for a Transparent EC public key",
            f
        ),
    };
    Ok(pubkey)
}
