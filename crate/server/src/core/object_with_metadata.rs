use std::{
    collections::HashSet,
    fmt::{self, Display, Formatter},
};

use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_types::{Attributes, StateEnumeration},
};
use cosmian_kms_client::access::ObjectOperationType;
use tracing::trace;

use crate::{
    core::{extra_database_params::ExtraDatabaseParams, KMS},
    result::{KResult, KResultHelper},
};

/// An object with its metadata such as owner, permissions and state
///
/// This is the main representation of objects through the KMS server.
/// Mpe APIs should use this representation.
#[derive(Clone)]
pub(crate) struct ObjectWithMetadata {
    id: String,
    // this is the object as registered in the DN. For a key, it may be wrapped or unwrapped
    object: Object,
    owner: String,
    state: StateEnumeration,
    permissions: HashSet<ObjectOperationType>,
    attributes: Attributes,
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
        _kms: &KMS,
        _user: &str,
        _params: Option<&ExtraDatabaseParams>,
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

        panic!("this must be re-implemented");

        // // check is we have it in cache
        // if let Some(unwrapped_cache) = &self.unwrapped_cache {
        //     if let Some(unwrapped) = unwrapped_cache.read().await.peek(&self.id) {
        //         trace!("Unwrapped cache hit");
        //         return unwrapped
        //             .as_ref()
        //             .map(|u| u.unwrapped_object().to_owned())
        //             .map_err(Clone::clone);
        //     }
        // }
        //
        // // local async future unwrap the object
        // let unwrap_local = async {
        //     let key_signature = self.object.key_signature()?;
        //     let mut unwrapped_object = self.object.clone();
        //     let key_block = unwrapped_object.key_block_mut()?;
        //     unwrap_key(key_block, kms, user, params).await?;
        //     Ok(CachedUnwrappedObject::new(key_signature, unwrapped_object))
        // };
        //
        // // cache miss, try to unwrap
        // trace!("Unwrapped cache miss. Trying to unwrap");
        // let unwrapped_object = unwrap_local.await;
        // //pre-calculating the result avoids a clone on the `CachedUnwrappedObject`
        // let result = unwrapped_object
        //     .as_ref()
        //     .map(|u| u.unwrapped_object().to_owned())
        //     .map_err(KmsError::clone);
        // // update cache is there is one
        // if let Some(unwrapped_cache) = &self.unwrapped_cache {
        //     unwrapped_cache
        //         .write()
        //         .await
        //         .put(self.id.clone(), unwrapped_object);
        // }
        // //return the result
        // result
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
