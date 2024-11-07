use std::fmt::{self, Display, Formatter};

use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_types::{Attributes, StateEnumeration},
};

use crate::{
    core::{extra_database_params::ExtraStoreParams, KMS},
    result::KResult,
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
    attributes: Attributes,
}

impl ObjectWithMetadata {
    pub(crate) const fn new(
        id: String,
        object: Object,
        owner: String,
        state: StateEnumeration,
        attributes: Attributes,
    ) -> Self {
        Self {
            id,
            object,
            owner,
            state,
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
    pub(crate) fn set_object(&mut self, object: Object) {
        self.object = object;
    }

    /// Return a mutable borrow to the Object
    /// Do not use this to set a new object or make sure you clear
    /// the cached unwrapped object
    pub(crate) fn object_mut(&mut self) -> &mut Object {
        &mut self.object
    }

    #[cfg(test)]
    pub(crate) fn owner(&self) -> &str {
        &self.owner
    }

    pub(crate) const fn state(&self) -> StateEnumeration {
        self.state
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
        params: Option<&ExtraStoreParams>,
    ) -> KResult<Object> {
        kms.store
            .get_unwrapped(self.id(), self.object(), kms, user, params)
            .await
    }

    /// Transform this own to its unwrapped version.
    /// Returns false if this fails
    /// Has no effect on a non wrappable object such as a Certificate
    pub(crate) async fn make_unwrapped(
        &mut self,
        kms: &KMS,
        user: &str,
        params: Option<&ExtraStoreParams>,
    ) -> KResult<()> {
        self.object = self.unwrapped(kms, user, params).await?;
        Ok(())
    }
}

impl Display for ObjectWithMetadata {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ObjectWithMetadata {{ id: {}, object: {}, owner: {}, state: {}, attributes: {:?} }}",
            self.id, self.object, self.owner, self.state, self.attributes
        )
    }
}
