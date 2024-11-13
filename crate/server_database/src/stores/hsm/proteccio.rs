use std::{collections::HashSet, path::PathBuf};

use async_trait::async_trait;
use cosmian_hsm_traits::{HsmKeyAlgorithm, HSM};
use cosmian_kmip::kmip::{
    kmip_objects::{Object, ObjectType},
    kmip_types::{Attributes, CryptographicAlgorithm, StateEnumeration},
};
use tracing::debug;

use super::super::store_traits::ObjectsStore;
use crate::{AtomicOperation, DbError, DbResult, ExtraStoreParams, ObjectWithMetadata};

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
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<Option<ObjectWithMetadata>> {
        todo!()
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
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<()> {
        todo!()
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
