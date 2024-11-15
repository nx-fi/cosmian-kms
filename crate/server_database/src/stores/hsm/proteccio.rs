use std::{collections::HashSet, path::PathBuf};

use async_trait::async_trait;
use cosmian_hsm_traits::{HsmKeyAlgorithm, HsmKeypairAlgorithm, HsmObject, KeyMaterial, HSM};
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
use num_bigint_dig::BigUint;
use tracing::debug;
use KmipKeyMaterial::TransparentRSAPublicKey;

use super::super::store_traits::ObjectsStore;
use crate::{db_bail, AtomicOperation, DbError, DbResult, ExtraStoreParams, ObjectWithMetadata};

pub struct HsmStore {
    hsm: Box<dyn HSM + Send + Sync>,
    hsm_admin: String,
}

impl HsmStore {
    pub fn new(hsm: Box<dyn HSM + Send + Sync>, hsm_admin: String) -> Self {
        Self { hsm, hsm_admin }
    }
}

#[async_trait(?Send)]
impl ObjectsStore for HsmStore {
    fn filename(&self, _group_id: u128) -> Option<PathBuf> {
        None
    }

    async fn migrate(&self, _params: Option<&ExtraStoreParams>) -> DbResult<()> {
        Ok(())
    }

    // Only single keys are created using this call,
    // keypair creation goes through the atomic operations
    async fn create(
        &self,
        uid: Option<String>,
        owner: &str,
        object: &Object,
        attributes: &Attributes,
        tags: &HashSet<String>,
        _params: Option<&ExtraStoreParams>,
    ) -> DbResult<String> {
        if owner != self.hsm_admin {
            return Err(DbError::InvalidRequest(
                "Only the HSM Admin can create HSM objects".to_owned(),
            ));
        }
        // try converting the rest of the uid into a slot_id
        let slot_id = uid
            .ok_or_else(|| {
                DbError::InvalidRequest(
                    "An HSM create request must have a uid in the form of 'hsm::<slot_id>'"
                        .to_string(),
                )
            })?
            .trim_start_matches("hsm::")
            .parse::<usize>()
            .map_err(|e| {
                DbError::InvalidRequest(format!(
                    "The uid of an HSM create request must be in the form of 'hsm::<slot_id>': {e}"
                ))
            })?;
        let label = if tags.is_empty() {
            String::new()
        } else {
            serde_json::to_string(&tags)?
        };
        if object.object_type() != ObjectType::SymmetricKey {
            return Err(DbError::InvalidRequest(
                "Only symmetric keys can be created on the HSM in this server".to_owned(),
            ));
        }
        let algorithm = attributes.cryptographic_algorithm.as_ref().ok_or_else(|| {
            DbError::InvalidRequest(
                "Create: HSM keys must have a cryptographic algorithm specified".to_owned(),
            )
        })?;
        if *algorithm != CryptographicAlgorithm::AES {
            return Err(DbError::InvalidRequest(
                "Only AES symmetric keys can be created on the HSM in this server".to_owned(),
            ));
        }
        let key_length = attributes.cryptographic_length.as_ref().ok_or_else(|| {
            DbError::InvalidRequest(
                "Symmetric key must have a cryptographic length specified".to_owned(),
            )
        })?;
        let id = self
            .hsm
            .create_key(
                slot_id,
                HsmKeyAlgorithm::AES,
                usize::try_from(*key_length)?,
                tags.contains("exportable"),
                label.as_str(),
            )
            .await?;
        let uid = format!("hsm::{slot_id}::{id}");
        debug!("Created HSM AES Key of length {key_length} with id {uid}",);
        Ok(uid)
    }

    async fn retrieve(
        &self,
        uid: &str,
        _params: Option<&ExtraStoreParams>,
    ) -> DbResult<Option<ObjectWithMetadata>> {
        // try converting the rest of the uid into a slot_id and key id
        let (slot_id, key_id) = parse_uid(uid)?;
        Ok(
            if let Some(hsm_object) = self.hsm.export(slot_id, key_id).await? {
                // Convert the HSM object into an ObjectWithMetadata
                let owm = to_object_with_metadate(&hsm_object, uid, self.hsm_admin.as_str())?;
                Some(owm)
            } else {
                None
            },
        )
    }

    async fn retrieve_tags(
        &self,
        uid: &str,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<HashSet<String>> {
        todo!()
    }

    async fn update_object(
        &self,
        uid: &str,
        object: &Object,
        attributes: &Attributes,
        tags: Option<&HashSet<String>>,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<()> {
        todo!()
    }

    async fn update_state(
        &self,
        uid: &str,
        state: StateEnumeration,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<()> {
        todo!()
    }

    async fn upsert(
        &self,
        uid: &str,
        user: &str,
        object: &Object,
        attributes: &Attributes,
        tags: Option<&HashSet<String>>,
        state: StateEnumeration,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<()> {
        todo!()
    }

    async fn delete(
        &self,
        uid: &str,
        user: &str,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<()> {
        todo!()
    }

    async fn atomic(
        &self,
        user: &str,
        operations: &[AtomicOperation],
        _params: Option<&ExtraStoreParams>,
    ) -> DbResult<Vec<String>> {
        if let Some((uid, object, attributes, tags)) = is_rsa_keypair_creation(operations) {
            if user != self.hsm_admin {
                return Err(DbError::InvalidRequest(
                    "Only the HSM Admin can create HSM keypairs".to_owned(),
                ));
            }
            let slot_id = uid
                .trim_start_matches("hsm::")
                .parse::<usize>()
                .map_err(|e| {
                    DbError::InvalidRequest(format!(
                        "The uid of an HSM create keypair request must be in the form of \
                         'hsm::<slot_id>': {e}"
                    ))
                })?;
            let label = if tags.is_empty() {
                String::new()
            } else {
                serde_json::to_string(&tags)?
            };
            let (sk_id, pk_id) = self
                .hsm
                .create_keypair(
                    slot_id,
                    HsmKeypairAlgorithm::RSA,
                    usize::try_from(attributes.cryptographic_length.unwrap_or(2048))?,
                    tags.contains("exportable"),
                    label.as_str(),
                )
                .await?;
            return Ok(vec![
                format!("hsm::{slot_id}::{sk_id}"),
                format!("hsm::{slot_id}::{pk_id}"),
            ]);
        }

        db_bail!("HSM atomic operations only support RSA keypair creations for now");
    }

    async fn list_uids_for_tags(
        &self,
        tags: &HashSet<String>,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<HashSet<String>> {
        todo!()
    }

    async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<StateEnumeration>,
        user: &str,
        user_must_be_owner: bool,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<Vec<(String, StateEnumeration, Attributes)>> {
        todo!()
    }
}

/// The creation of RSA key pairs is done via 2 atomic operations,
/// one to create the private key and one to generate the public key.
/// All the information we need is contained in the atomic operation
/// to create the private key, so we recover it here
///
/// # Returns
///  - the uid of the private key
/// - the object of the private key
/// - the attributes of the private key
fn is_rsa_keypair_creation(
    operations: &[AtomicOperation],
) -> Option<(String, Object, Attributes, HashSet<String>)> {
    operations
        .iter()
        .filter_map(|op| match op {
            AtomicOperation::Create((uid, object, attributes, tags)) => {
                if object.object_type() != ObjectType::PrivateKey {
                    return None;
                }
                if attributes
                    .cryptographic_algorithm
                    .as_ref()
                    .map(|algorithm| *algorithm == CryptographicAlgorithm::RSA)
                    .unwrap_or(false)
                {
                    return None;
                }
                Some((
                    uid.clone(),
                    object.clone(),
                    attributes.clone(),
                    tags.clone(),
                ))
            }
            _ => None,
        })
        .collect::<Vec<_>>()
        .first()
        .cloned()
}

/// Parse the `uid` into a `slot_id` and `key_id`
fn parse_uid(uid: &str) -> Result<(usize, usize), DbError> {
    let (slot_id, key_id) = uid
        .trim_start_matches("hsm::")
        .split_once("::")
        .ok_or_else(|| {
            DbError::InvalidRequest(
                "An HSM create request must have a uid in the form of 'hsm::<slot_id>::<key_id>'"
                    .to_owned(),
            )
        })?;
    let slot_id = slot_id.parse::<usize>().map_err(|e| {
        DbError::InvalidRequest(format!("The slot_id must be a valid unsigned integer: {e}"))
    })?;
    let key_id = key_id.parse::<usize>().map_err(|e| {
        DbError::InvalidRequest(format!("The key_id must be a valid unsigned integer: {e}"))
    })?;
    Ok((slot_id, key_id))
}

// /// Ensure that the HSM is instantiated and that the user is the HSM admin
// fn ensure_hsm_admin<'a>(kms: &'a KMS, user: &str) -> DbResult<&'a (dyn HSM + Sync + Send)> {
//     let hsm = if let Some(hsm) = &kms.hsm {
//         if user != kms.params.hsm_admin {
//             return Err(DbError::InvalidRequest(
//                 "Only the HSM Admin can retrieve HSM objects".to_owned(),
//             ));
//         }
//         hsm
//     } else {
//         return Err(DbError::NotSupported(
//             "This server does not support HSM operations".to_owned(),
//         ))
//     };
//     Ok(&**hsm)
// }

fn to_object_with_metadate(
    hsm_object: &HsmObject,
    uid: &str,
    user: &str,
) -> DbResult<ObjectWithMetadata> {
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
