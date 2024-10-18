use std::{
    collections::HashSet,
    fmt::{self, Display, Formatter},
};

use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_operations::ErrorReason,
    kmip_types::{Attributes, StateEnumeration},
};
use cosmian_kms_client::access::ObjectOperationType;
use serde::Serialize;
use serde_json::Value;
use sqlx::{mysql::MySqlRow, postgres::PgRow, sqlite::SqliteRow, Row};

use super::{state_from_string, DBObject};
use crate::{
    core::{extra_database_params::ExtraDatabaseParams, KMS},
    error::KmsError,
    result::{KResult, KResultHelper},
};

/// An object with its metadata such as permissions and state
#[derive(Clone, Serialize)]
pub(crate) struct ObjectWithMetadata {
    id: String,
    // this is the object as registered in the DN. For a key, it may be wrapped or unwrapped
    object: Object,
    owner: String,
    state: StateEnumeration,
    permissions: HashSet<ObjectOperationType>,
    attributes: Attributes,
    // If the key is wrapped, this will be the unwrapped object.
    // A key is usually retrieved to perform some operation.
    // When retrieved, if the key is wrapped an automatic attempt to unwrap it will be performed
    // This will allow having the unwrapped version in cache and avoir the expensive unwrapping
    // operation to be run again.
    // This filed is lazily loaded, so unwrapped() should be called first on the structure
    unwrapped: Option<Object>,
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
            unwrapped: None,
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
    pub(crate) fn set_object(&mut self, object: Object) {
        self.object = object;
        self.unwrapped = None;
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
        &mut self,
        kms: &KMS,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Option<&Object>> {
        if self.unwrapped.is_some() {
            return Ok(self.unwrapped.as_ref())
        }
        if let Ok(key_block) = self.object.key_block() {
            if key_block.key_wrapping_data.is_some() {
                // attempt unwrapping
                let mut unwrapped_object = self.object.clone();
                let key_block = unwrapped_object.key_block_mut()?;
                crate::core::wrapping::unwrap_key(key_block, kms, user, params).await?;
                self.unwrapped = Some(unwrapped_object.clone());
                Ok(self.unwrapped.as_ref())
            } else {
                // the object is unwrapped
                // TODO: this duplicates it and is maybe not worth the memory
                // TODO: it will speed up the next retrieve though
                self.unwrapped = Some(self.object.clone());
                Ok(self.unwrapped.as_ref())
            }
        } else {
            // not a wrappable object
            Ok(None)
        }
    }

    /// Clear the Unwrapped value if any, forcing unwrapping again on a call to `unwrapped()`
    pub(crate) fn clear_unwrapped(&mut self) {
        self.unwrapped = None;
    }

    /// Transform this own to its unwrapped version.
    /// Returns false if this fails
    /// Has not effect on a non wrappable object such as a Certificate
    pub(crate) async fn make_unwrapped(
        &mut self,
        kms: &KMS,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        if let Some(object) = self.unwrapped(kms, user, params).await? {
            self.object = object.clone();
            // the unwrapped property is already set to the unwrapped object
        }
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
        Ok(Self {
            id,
            object,
            owner,
            state,
            permissions,
            attributes,
            // will lazily unwrap if need be
            unwrapped: None,
        })
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
        let perms: HashSet<ObjectOperationType> = if raw_permissions.is_empty() {
            HashSet::new()
        } else {
            serde_json::from_slice(&raw_permissions)
                .context("failed deserializing the permissions")
                .reason(ErrorReason::Internal_Server_Error)?
        };

        Ok(Self {
            id,
            object,
            attributes,
            owner,
            state,
            permissions: perms,
            // will lazily unwrap if need be
            unwrapped: None,
        })
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
        Ok(Self {
            id,
            object,
            owner,
            state,
            permissions,
            attributes,
            // will lazily unwrap if need be
            unwrapped: None,
        })
    }
}
