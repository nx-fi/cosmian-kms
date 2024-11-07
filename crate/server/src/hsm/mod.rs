use std::{collections::HashSet, default::Default};

use cosmian_hsm_traits::{HsmObject, KeyMaterial, HSM};
use cosmian_kmip::{
    crypto::secret::SafeBigUint,
    kmip::{
        kmip_data_structures::{KeyBlock, KeyMaterial as KmipKeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType},
        kmip_types::{
            Attributes, CryptographicAlgorithm, CryptographicUsageMask, KeyFormatType,
            StateEnumeration,
        },
    },
};
use cosmian_kms_client::access::KmipOperation;
use num_bigint_dig::BigUint;
use KmipKeyMaterial::TransparentRSAPublicKey;

use crate::{
    core::{object_with_metadata::ObjectWithMetadata, KMS},
    error::KmsError,
    result::KResult,
};

pub(crate) async fn get_hsm_object(
    uid: &str,
    _operation_type: KmipOperation,
    kms: &KMS,
    user: &str,
) -> KResult<ObjectWithMetadata> {
    let hsm = ensure_hsm_admin(kms, user)?;
    // try converting the rest of the uid into a slot_id and key id
    let (slot_id, key_id) = parse_uid(uid)?;
    let hsm_object = hsm.export(slot_id, key_id).await?;
    // Convert the HSM object into an ObjectWithMetadata
    let owm = to_object_with_metadate(&hsm_object, uid, user)?;
    Ok(owm)
}

/// Parse the `uid` into a `slot_id` and `key_id`
fn parse_uid(uid: &str) -> Result<(usize, usize), KmsError> {
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
    Ok((slot_id, key_id))
}

/// Ensure that the HSM is instantiated and that the user is the HSM admin
fn ensure_hsm_admin<'a>(kms: &'a KMS, user: &str) -> KResult<&'a (dyn HSM + Sync + Send)> {
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
    Ok(&**hsm)
}

fn to_object_with_metadate(
    hsm_object: &HsmObject,
    uid: &str,
    user: &str,
) -> KResult<ObjectWithMetadata> {
    match hsm_object.key_material() {
        KeyMaterial::AesKey(bytes) => {
            let length: i32 = i32::try_from(bytes.len())? * 8;
            let mut attributes = Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                cryptographic_length: Some(length),
                object_type: Some(ObjectType::SymmetricKey),
                // TODO: query these flags from the HSM
                cryptographic_usage_mask: Some(
                    CryptographicUsageMask::Encrypt
                        | CryptographicUsageMask::Decrypt
                        | CryptographicUsageMask::WrapKey
                        | CryptographicUsageMask::UnwrapKey,
                ),
                ..Attributes::default()
            };
            let mut tags: HashSet<String> =
                serde_json::from_str(hsm_object.label()).unwrap_or_else(|_| HashSet::new());
            tags.insert("_kk".to_owned());
            attributes.set_tags(tags)?;
            let kmip_key_material = KmipKeyMaterial::TransparentSymmetricKey { key: bytes.clone() };
            let object = Object::SymmetricKey {
                key_block: KeyBlock {
                    key_format_type: KeyFormatType::Raw,
                    key_compression_type: None,
                    key_value: KeyValue {
                        key_material: kmip_key_material,
                        attributes: Some(attributes.clone()),
                    },
                    cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                    cryptographic_length: Some(i32::try_from(bytes.len())? * 8),
                    key_wrapping_data: None,
                },
            };
            Ok(ObjectWithMetadata::new(
                uid.to_owned(),
                object,
                user.to_owned(),
                StateEnumeration::Active,
                attributes,
            ))
        }
        KeyMaterial::RsaPrivateKey(km) => {
            let mut attributes = Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                cryptographic_length: Some(i32::try_from(km.modulus.len())? * 8),
                object_type: Some(ObjectType::PrivateKey),
                // TODO: query these flags from the HSM
                cryptographic_usage_mask: Some(
                    CryptographicUsageMask::Decrypt
                        | CryptographicUsageMask::UnwrapKey
                        | CryptographicUsageMask::Sign,
                ),
                ..Attributes::default()
            };
            let mut tags: HashSet<String> =
                serde_json::from_str(hsm_object.label()).unwrap_or_else(|_| HashSet::new());
            tags.insert("_sk".to_owned());
            attributes.set_tags(tags)?;
            let kmip_key_material = KmipKeyMaterial::TransparentRSAPrivateKey {
                modulus: Box::new(BigUint::from_bytes_be(km.modulus.as_slice())),
                private_exponent: Some(Box::new(SafeBigUint::from_bytes_be(
                    km.private_exponent.as_slice(),
                ))),
                public_exponent: Some(Box::new(BigUint::from_bytes_be(
                    km.public_exponent.as_slice(),
                ))),
                p: Some(Box::new(SafeBigUint::from_bytes_be(km.prime_1.as_slice()))),
                q: Some(Box::new(SafeBigUint::from_bytes_be(km.prime_2.as_slice()))),
                prime_exponent_p: Some(Box::new(SafeBigUint::from_bytes_be(
                    km.exponent_1.as_slice(),
                ))),
                prime_exponent_q: Some(Box::new(SafeBigUint::from_bytes_be(
                    km.exponent_2.as_slice(),
                ))),
                crt_coefficient: Some(Box::new(SafeBigUint::from_bytes_be(
                    km.coefficient.as_slice(),
                ))),
            };
            let object = Object::PrivateKey {
                key_block: KeyBlock {
                    key_format_type: KeyFormatType::TransparentRSAPrivateKey,
                    key_compression_type: None,
                    key_value: KeyValue {
                        key_material: kmip_key_material,
                        attributes: Some(attributes.clone()),
                    },
                    cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                    cryptographic_length: Some(i32::try_from(km.modulus.len())? * 8),
                    key_wrapping_data: None,
                },
            };
            Ok(ObjectWithMetadata::new(
                uid.to_owned(),
                object,
                user.to_owned(),
                StateEnumeration::Active,
                attributes,
            ))
        }
        KeyMaterial::RsaPublicKey(km) => {
            let mut attributes = Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                cryptographic_length: Some(i32::try_from(km.modulus.len())? * 8),
                object_type: Some(ObjectType::PrivateKey),
                // TODO: query these flags from the HSM
                cryptographic_usage_mask: Some(
                    CryptographicUsageMask::Encrypt
                        | CryptographicUsageMask::WrapKey
                        | CryptographicUsageMask::Verify,
                ),
                ..Attributes::default()
            };
            let mut tags: HashSet<String> =
                serde_json::from_str(hsm_object.label()).unwrap_or_else(|_| HashSet::new());
            tags.insert("_sk".to_owned());
            attributes.set_tags(tags)?;
            let kmip_key_material = TransparentRSAPublicKey {
                modulus: Box::new(BigUint::from_bytes_be(km.modulus.as_slice())),
                public_exponent: Box::new(BigUint::from_bytes_be(km.public_exponent.as_slice())),
            };
            let object = Object::PublicKey {
                key_block: KeyBlock {
                    key_format_type: KeyFormatType::TransparentRSAPublicKey,
                    key_compression_type: None,
                    key_value: KeyValue {
                        key_material: kmip_key_material,
                        attributes: Some(attributes.clone()),
                    },
                    cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                    cryptographic_length: Some(i32::try_from(km.modulus.len())? * 8),
                    key_wrapping_data: None,
                },
            };
            Ok(ObjectWithMetadata::new(
                uid.to_owned(),
                object,
                user.to_owned(),
                StateEnumeration::Active,
                attributes,
            ))
        }
    }
}
