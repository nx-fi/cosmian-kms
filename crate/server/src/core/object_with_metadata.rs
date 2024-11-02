use std::{
    collections::HashSet,
    fmt::{self, Display, Formatter},
    sync::Arc,
};

use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_operations::ErrorReason,
    kmip_types::{Attributes, StateEnumeration},
};
use cosmian_kms_client::access::ObjectOperationType;
use log::trace;
use serde_json::Value;
use sqlx::{mysql::MySqlRow, postgres::PgRow, sqlite::SqliteRow, Row};

use crate::{
    core::{extra_database_params::ExtraDatabaseParams, wrapping::unwrap_key, KMS},
    database::{
        cached_database::{CachedUnwrappedObject, UnwrappedCache},
        state_from_string, DBObject,
    },
    error::KmsError,
    result::{KResult, KResultHelper},
};

/// An object with its metadata such as permissions and state
#[derive(Clone)]
pub(crate) struct ObjectWithMetadata {
    id: String,
    // this is the object as registered in the DN. For a key, it may be wrapped or unwrapped
    object: Object,
    owner: String,
    state: StateEnumeration,
    permissions: HashSet<ObjectOperationType>,
    attributes: Attributes,
    /// This is a reference the cache - if any -  holding the unwrapped version of the objects,
    /// if the object is unwrappable;
    unwrapped_cache: Option<Arc<UnwrappedCache>>,
}

impl ObjectWithMetadata {
    pub(crate) const fn new(
        id: String,
        object: Object,
        owner: String,
        state: StateEnumeration,
        permissions: HashSet<ObjectOperationType>,
        attributes: Attributes,
    ) -> Self {
        Self {
            id,
            object,
            owner,
            state,
            permissions,
            attributes,
            unwrapped_cache: None,
        }
    }

    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) const fn object(&self) -> &Object {
        &self.object
    }

    /// Set a new object, clearing the cached unwrapped version
    /// if any
    pub(crate) async fn set_object(&mut self, object: Object) {
        self.object = object;
        self.clear_unwrapped().await;
    }

    /// Return a mutable borrow to the Object
    /// Do not use this to set a new object or make sure you clear
    /// the cached unwrapped object
    pub(crate) fn object_mut(&mut self) -> &mut Object {
        &mut self.object
    }

    pub(crate) fn owner(&self) -> &str {
        &self.owner
    }

    pub(crate) const fn state(&self) -> StateEnumeration {
        self.state
    }

    pub(crate) const fn permissions(&self) -> &HashSet<ObjectOperationType> {
        &self.permissions
    }

    pub(crate) fn permissions_mut(&mut self) -> &mut HashSet<ObjectOperationType> {
        &mut self.permissions
    }

    pub(crate) const fn attributes(&self) -> &Attributes {
        &self.attributes
    }

    pub(crate) fn attributes_mut(&mut self) -> &mut Attributes {
        &mut self.attributes
    }

    /// Will return the unwrapped version of the object.
    /// If the object is wrapped, it wil try to unwrap it
    /// and cache the unwrapped version in the structure.
    /// This call will return None for non-wrappable objects such as Certificates
    pub(crate) async fn unwrapped(
        &self,
        kms: &KMS,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Object> {
        // Is this an unwrapped key?
        if self
            .object
            .key_block()
            .context("Cannot unwrap non key object")?
            .key_wrapping_data
            .is_none()
        {
            // already an unwrapped key
            trace!("Already an unwrapped key");
            return Ok(self.object.clone());
        }

        // check is we have it in cache
        if let Some(unwrapped_cache) = &self.unwrapped_cache {
            if let Some(unwrapped) = unwrapped_cache.read().await.peek(&self.id) {
                trace!("Unwrapped cache hit");
                return unwrapped
                    .as_ref()
                    .map(|u| u.unwrapped_object().to_owned())
                    .map_err(Clone::clone);
            }
        }

        // local async future unwrap the object
        let unwrap_local = async {
            let key_signature = self.object.key_signature()?;
            let mut unwrapped_object = self.object.clone();
            let key_block = unwrapped_object.key_block_mut()?;
            unwrap_key(key_block, kms, user, params).await?;
            Ok(CachedUnwrappedObject::new(key_signature, unwrapped_object))
        };

        // cache miss, try to unwrap
        trace!("Unwrapped cache miss. Trying to unwrap");
        let unwrapped_object = unwrap_local.await;
        //pre-calculating the result avoids a clone on the `CachedUnwrappedObject`
        let result = unwrapped_object
            .as_ref()
            .map(|u| u.unwrapped_object().to_owned())
            .map_err(KmsError::clone);
        // update cache is there is one
        if let Some(unwrapped_cache) = &self.unwrapped_cache {
            unwrapped_cache
                .write()
                .await
                .put(self.id.clone(), unwrapped_object);
        }
        //return the result
        result
    }

    /// Get the unwrapped cache
    /// This is used for testing
    #[cfg(test)]
    pub(crate) fn unwrapped_cache(&self) -> Option<Arc<UnwrappedCache>> {
        self.unwrapped_cache.clone()
    }

    /// Set the unwrapped cache
    pub(crate) fn set_unwrapped_cache(&mut self, unwrapped_cache: Arc<UnwrappedCache>) {
        self.unwrapped_cache = Some(unwrapped_cache);
    }

    /// Clear the Unwrapped value if any, forcing unwrapping again on a call to `unwrapped()`
    pub(crate) async fn clear_unwrapped(&mut self) {
        if let Some(cache) = &mut self.unwrapped_cache {
            cache.write().await.pop(&self.id);
        }
    }

    /// Transform this own to its unwrapped version.
    /// Returns false if this fails
    /// Has no effect on a non wrappable object such as a Certificate
    pub(crate) async fn make_unwrapped(
        &mut self,
        kms: &KMS,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        self.object = self.unwrapped(kms, user, params).await?;
        Ok(())
    }
}

impl Display for ObjectWithMetadata {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ObjectWithMetadata {{ id: {}, object: {}, owner: {}, state: {}, permissions: {:?}, \
             attributes: {:?} }}",
            self.id, self.object, self.owner, self.state, self.permissions, self.attributes
        )
    }
}

impl TryFrom<&PgRow> for ObjectWithMetadata {
    type Error = KmsError;

    fn try_from(row: &PgRow) -> Result<Self, Self::Error> {
        let id = row.get::<String, _>(0);
        let db_object: DBObject = serde_json::from_value(row.get::<Value, _>(1))
            .context("failed deserializing the object")
            .reason(ErrorReason::Internal_Server_Error)?;
        let object = Object::post_fix(db_object.object_type, db_object.object);
        let attributes: Attributes = serde_json::from_value(row.get::<Value, _>(2))
            .context("failed deserializing the Attributes")
            .reason(ErrorReason::Internal_Server_Error)?;
        let owner = row.get::<String, _>(3);
        let state = state_from_string(&row.get::<String, _>(4))?;
        let permissions: HashSet<ObjectOperationType> = match row.try_get::<Value, _>(5) {
            Err(_) => HashSet::new(),
            Ok(v) => serde_json::from_value(v)
                .context("failed deserializing the permissions")
                .reason(ErrorReason::Internal_Server_Error)?,
        };
        Ok(Self::new(id, object, owner, state, permissions, attributes))
    }
}

impl TryFrom<&SqliteRow> for ObjectWithMetadata {
    type Error = KmsError;

    fn try_from(row: &SqliteRow) -> Result<Self, Self::Error> {
        let id = row.get::<String, _>(0);
        let db_object: DBObject = serde_json::from_slice(&row.get::<Vec<u8>, _>(1))
            .context("failed deserializing the object")
            .reason(ErrorReason::Internal_Server_Error)?;
        let object = Object::post_fix(db_object.object_type, db_object.object);
        let raw_attributes = row.get::<Value, _>(2);
        let attributes = serde_json::from_value(raw_attributes)?;
        let owner = row.get::<String, _>(3);
        let state = state_from_string(&row.get::<String, _>(4))?;
        let raw_permissions = row.get::<Vec<u8>, _>(5);
        let permissions: HashSet<ObjectOperationType> = if raw_permissions.is_empty() {
            HashSet::new()
        } else {
            serde_json::from_slice(&raw_permissions)
                .context("failed deserializing the permissions")
                .reason(ErrorReason::Internal_Server_Error)?
        };
        Ok(Self::new(id, object, owner, state, permissions, attributes))
    }
}

impl TryFrom<&MySqlRow> for ObjectWithMetadata {
    type Error = KmsError;

    fn try_from(row: &MySqlRow) -> Result<Self, Self::Error> {
        let id = row.get::<String, _>(0);
        let db_object: DBObject = serde_json::from_value(row.get::<Value, _>(1))
            .context("failed deserializing the object")
            .reason(ErrorReason::Internal_Server_Error)?;
        let object = Object::post_fix(db_object.object_type, db_object.object);
        let attributes: Attributes = serde_json::from_value(row.get::<Value, _>(2))
            .context("failed deserializing the Attributes")
            .reason(ErrorReason::Internal_Server_Error)?;
        let owner = row.get::<String, _>(3);
        let state = state_from_string(&row.get::<String, _>(4))?;
        let permissions: HashSet<ObjectOperationType> = match row.try_get::<Value, _>(5) {
            Err(_) => HashSet::new(),
            Ok(v) => serde_json::from_value(v)
                .context("failed deserializing the permissions")
                .reason(ErrorReason::Internal_Server_Error)?,
        };
        Ok(Self::new(id, object, owner, state, permissions, attributes))
    }
}
