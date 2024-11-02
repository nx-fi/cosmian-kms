use std::collections::HashSet;
use num_bigint_dig::BigUint;
use cosmian_hsm_traits::KeyMaterial;
use cosmian_kmip::kmip::{
    kmip_data_structures::{KeyBlock, KeyFormatType, KeyMaterial as KmipKeyMaterial, KeyValue},
    kmip_objects::{Object, ObjectType},
    kmip_types::{Attributes, CryptographicAlgorithm, CryptographicUsageMask, StateEnumeration},
};
use cosmian_kms_client::access::ObjectOperationType;

use crate::{
    core::{object_with_metadata::ObjectWithMetadata, KMS},
    error::KmsError,
    result::KResult,
};

pub(crate) async fn get_hsm_object(
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
    let hsm_object = hsm.export(slot_id, key_id).await?;
    // Convert the HSM object into an ObjectWithMetadata
    let owm = match hsm_object.key_material() {
        KeyMaterial::AesKey(bytes) => {
            let mut attributes = Attributes::default();
            attributes.cryptographic_algorithm = Some(CryptographicAlgorithm::AES);
            attributes.cryptographic_length = Some(bytes.len() as i32 * 8);
            attributes.object_type = Some(ObjectType::SymmetricKey);
            // TODO: query these flags from the HSM
            attributes.cryptographic_usage_mask = Some(
                CryptographicUsageMask::Encrypt
                    | CryptographicUsageMask::Decrypt
                    | CryptographicUsageMask::WrapKey
                    | CryptographicUsageMask::UnwrapKey,
            );
            let mut tags: HashSet<String> =
                serde_json::from_str(hsm_object.label()).unwrap_or_else(|_| HashSet::new());
            tags.insert("_kk".to_string());
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
                    cryptographic_length: Some(bytes.len() as i32 * 8),
                    key_wrapping_data: None,
                },
            };
            ObjectWithMetadata::new(
                uid.to_owned(),
                object,
                kms.params.hsm_admin.to_owned(),
                StateEnumeration::Active,
                HashSet::from([ObjectOperationType::Get]),
                attributes,
            )
        }
        KeyMaterial::RsaPrivateKey(km) => {
            let mut attributes = Attributes::default();
            attributes.cryptographic_algorithm = Some(CryptographicAlgorithm::RSA);
            attributes.cryptographic_length = Some(km.modulus.len() as i32 * 8);
            attributes.object_type = Some(ObjectType::PrivateKey);
            // TODO: query these flags from the HSM
            attributes.cryptographic_usage_mask = Some(
                CryptographicUsageMask::Decrypt
                    | CryptographicUsageMask::UnwrapKey
                    | CryptographicUsageMask::Sign,
            );
            let mut tags: HashSet<String> =
                serde_json::from_str(hsm_object.label()).unwrap_or_else(|_| HashSet::new());
            tags.insert("_sk".to_string());
            attributes.set_tags(tags)?;
            let kmip_key_material = KmipKeyMaterial::TransparentRSAPrivateKey {
                modulus: Box::new(BigUint::from_bytes_be(km.modulus.as_slice())),
                private_exponent: None,
                public_exponent: None,
                p: None,
                q: None,
                prime_exponent_p: None,
                prime_exponent_q: None,
                crt_coefficient: None,
            }
            ObjectWithMetadata::new(
                uid.to_owned(),
                object,
                kms.params.hsm_admin.to_owned(),
                StateEnumeration::Active,
                HashSet::from([ObjectOperationType::Get]),
                attributes,
            )
        }
        KeyMaterial::RsaPublicKey(_) => {}
    };

    Ok(owm)
}

fn label_to_tags(label: &str) -> HashSet<String> {
    serde_json::from_str(&label).unwrap_or_else(|_| HashSet::new())
}
