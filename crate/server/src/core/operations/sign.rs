use std::{cmp::min, collections::HashSet, default::Default};

use alloy::{
    primitives::FixedBytes,
    signers::{
        local::{LocalSigner, PrivateKeySigner},
        SignerSync,
    },
};
use cosmian_kmip::{
    crypto::secret::Secret,
    kmip::{
        extra::{x509_extensions, VENDOR_ATTR_X509_EXTENSION, VENDOR_ID_COSMIAN},
        kmip_data_structures::KeyMaterial,
        kmip_objects::{Object, ObjectType},
        kmip_operations::{ErrorReason, Sign, SignResponse},
        kmip_types::{
            Attributes, CertificateAttributes, CertificateRequestType, CryptographicAlgorithm,
            CryptographicParameters, CryptographicUsageMask, KeyFormatType, LinkType,
            LinkedObjectIdentifier, RecommendedCurve, StateEnumeration, UniqueIdentifier,
        },
    },
    kmip_bail,
    openssl::{
        kmip_certificate_to_openssl, kmip_private_key_to_openssl, kmip_public_key_to_openssl,
        openssl_certificate_to_kmip,
    },
    pad_be_bytes, KmipError,
};
#[cfg(feature = "fips")]
use cosmian_kmip::{
    crypto::{
        elliptic_curves::{
            FIPS_PRIVATE_ECC_MASK_ECDH, FIPS_PRIVATE_ECC_MASK_SIGN,
            FIPS_PRIVATE_ECC_MASK_SIGN_ECDH, FIPS_PUBLIC_ECC_MASK_ECDH, FIPS_PUBLIC_ECC_MASK_SIGN,
            FIPS_PUBLIC_ECC_MASK_SIGN_ECDH,
        },
        rsa::{FIPS_PRIVATE_RSA_MASK, FIPS_PUBLIC_RSA_MASK},
    },
    kmip::kmip_types::{CryptographicAlgorithm, CryptographicUsageMask},
};
use cosmian_kms_client::access::ObjectOperationType;
use openssl::{
    ec::EcKey,
    hash::MessageDigest,
    pkey::{Id, PKey, Public},
    sign::Signer,
    x509::X509,
};
use tracing::{debug, trace};
use zeroize::Zeroizing;

use crate::{
    core::{extra_database_params::ExtraDatabaseParams, operations::unwrap_key, KMS},
    database::object_with_metadata::ObjectWithMetadata,
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
    routes::kmip::kmip,
};

const EMPTY_SLICE: &[u8] = &[];

pub(crate) async fn sign(
    kms: &KMS,
    request: Sign,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<SignResponse> {
    trace!("Sign: {}", serde_json::to_string(&request)?);

    let owm = get_key(kms, &request, user, params).await?;

    // Make sure that the key used to decrypt can be used to decrypt.
    if !owm
        .object
        .attributes()?
        .is_usage_authorized_for(CryptographicUsageMask::Sign)?
    {
        return Err(KmsError::KmipError(
            ErrorReason::Incompatible_Cryptographic_Usage_Mask,
            "CryptographicUsageMask not authorized for Sign".to_owned(),
        ))
    }

    match &owm.object {
        Object::PrivateKey { .. } => {
            if request.digested_data.is_some() {
                sign_digest_with_private_key(&owm, &request)
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
    request: &Sign,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<ObjectWithMetadata> {
    // there must be an identifier
    let uid_or_tags = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("Sign: the unique identifier or tags must be a string")?
        .to_owned();
    trace!("operations::sign: key uid_or_tags: {uid_or_tags}");

    // retrieve from tags or use passed identifier
    let mut owm_s = kms
        .db
        .retrieve(&uid_or_tags, user, ObjectOperationType::Sign, params)
        .await?
        .into_values()
        .filter(|owm| {
            let object_type = owm.object.object_type();
            owm.state == StateEnumeration::Active && object_type == ObjectType::PrivateKey
        })
        .collect::<Vec<ObjectWithMetadata>>();

    trace!(
        "operations::sign: key owm_s: number of results: {}",
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
            "sign: the server cannot if the key is not active".to_owned()
        ));
    }

    // unwrap if wrapped
    if owm.object.key_wrapping_data().is_some() {
        let key_block = owm.object.key_block_mut()?;
        unwrap_key(key_block, kms, &owm.owner, params).await?;
    }
    Ok(owm)
}

fn sign_digest_with_private_key(owm: &ObjectWithMetadata, request: &Sign) -> KResult<SignResponse> {
    let private_key = private_key_to_raw(&owm.object)?;
    let signer: PrivateKeySigner = LocalSigner::from_slice(&private_key)
        .unwrap_or_else(|_| kmip_bail!("sign: could not create a signer from the private key"));

    let signature = signer.sign_hash_sync(
        request
            .digested_data
            .as_ref()
            .context("sign: digested_data must be provided"),
    );

    Ok(SignResponse {
        unique_identifier: Some(UniqueIdentifier::from(owm.object.unique_identifier())),
        signature: Some(signature.into()),
        correlation_value: None,
    })
}

fn private_key_to_raw(private_key: &Object) -> Result<Secret<32>, KmipError> {
    let key_block = match private_key {
        Object::PrivateKey { key_block } => key_block,
        x => kmip_bail!("Invalid Object: {}. KMIP Private Key expected", x),
    };
    let pk: Secret<32> = match key_block.key_format_type {
        KeyFormatType::ECPrivateKey => {
            let mut key_bytes = key_block.key_bytes()?;
            Secret::from_zeroizing_vector(&mut key_bytes)?
        }
        KeyFormatType::TransparentECPrivateKey => match &key_block.key_value.key_material {
            KeyMaterial::TransparentECPrivateKey {
                d,
                recommended_curve,
            } => match recommended_curve {
                RecommendedCurve::SECP256K1 => d.into(),
                other => kmip_bail!(
                    "Unsupported curve for Transparent EC private key: {:?}",
                    other
                ),
            },
            x => kmip_bail!(
                "KMIP key to openssl: invalid Transparent EC private key material: {}: \
                 TransparentECPrivateKey expected",
                x
            ),
        },
        f => kmip_bail!(
            "Unsupported key format type: {:?}, for a Transparent EC private key",
            f
        ),
    };
    Ok(pk)
}
