use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

use async_trait::async_trait;
use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_types::{Attributes, StateEnumeration},
};
use cosmian_kms_client::access::{IsWrapped, KmipOperation};

use crate::{
    core::{extra_database_params::ExtraDatabaseParams, object_with_metadata::ObjectWithMetadata},
    result::KResult,
};

/// An atomic operation on the objects database
#[allow(dead_code)]
pub(crate) enum AtomicOperation {
    /// Create (uid, object, attributes, tags) - the state will be active
    Create((String, Object, Attributes, HashSet<String>)),
    /// Upsert (uid, object, attributes, tags, state) - the state be updated
    Upsert(
        (
            String,
            Object,
            Attributes,
            Option<HashSet<String>>,
            StateEnumeration,
        ),
    ),
    /// Update the object (uid, object, attributes, tags) - the state will be not be updated
    UpdateObject((String, Object, Attributes, Option<HashSet<String>>)),
    /// Update the state (uid, state)
    UpdateState((String, StateEnumeration)),
    /// Delete (uid)
    Delete(String),
}

impl AtomicOperation {
    pub(crate) fn get_object_uid(&self) -> &str {
        match self {
            Self::Create((uid, _, _, _))
            | Self::Upsert((uid, _, _, _, _))
            | Self::UpdateObject((uid, _, _, _))
            | Self::UpdateState((uid, _))
            | Self::Delete(uid) => uid,
        }
    }
}

/// Trait that must implement all databases, HSMs, etc. that store objects
#[async_trait(?Send)]
pub(crate) trait ObjectsDatabase {
    /// Return the filename of the database or `None` if not supported
    fn filename(&self, group_id: u128) -> Option<PathBuf>;

    /// Migrate the database to the latest version
    async fn migrate(&self, params: Option<&ExtraDatabaseParams>) -> KResult<()>;

    /// Create the given Object in the database.
    ///
    /// A new UUID will be created if none is supplier.
    /// This method will fail if a `uid` is supplied
    /// and an object with the same id already exists
    async fn create(
        &self,
        uid: Option<String>,
        owner: &str,
        object: &Object,
        attributes: &Attributes,
        tags: &HashSet<String>,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<String>;

    /// Retrieve an object from the database.
    async fn retrieve(
        &self,
        uid: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Option<ObjectWithMetadata>>;

    /// Retrieve the tags of the object with the given `uid`
    async fn retrieve_tags(
        &self,
        uid: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashSet<String>>;

    /// Update an object in the database.
    ///
    /// If tags is `None`, the tags will not be updated.
    async fn update_object(
        &self,
        uid: &str,
        object: &Object,
        attributes: &Attributes,
        tags: Option<&HashSet<String>>,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()>;

    /// Update the state of an object in the database.
    async fn update_state(
        &self,
        uid: &str,
        state: StateEnumeration,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()>;

    /// Upsert (update or create if does not exist)
    ///
    /// If tags is `None`, the tags will not be updated.
    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code)]
    async fn upsert(
        &self,
        uid: &str,
        user: &str,
        object: &Object,
        attributes: &Attributes,
        tags: Option<&HashSet<String>>,
        state: StateEnumeration,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()>;

    /// Delete an object from the database.
    #[allow(dead_code)]
    async fn delete(
        &self,
        uid: &str,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()>;

    /// Perform an atomic set of operation on the database
    /// (typically in a transaction)
    async fn atomic(
        &self,
        user: &str,
        operations: &[AtomicOperation],
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()>;

    /// List the `uid` of all the objects that have the given `tags`
    async fn list_uids_for_tags(
        &self,
        tags: &HashSet<String>,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashSet<String>>;

    /// Return uid, state and attributes of the object identified by its owner,
    /// and possibly by its attributes and/or its `state`
    async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<StateEnumeration>,
        user: &str,
        user_must_be_owner: bool,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<(String, StateEnumeration, Attributes, IsWrapped)>>;
}

/// Trait that the database must implement to store permissions
#[async_trait(?Send)]
pub(crate) trait PermissionsDatabase {
    /// List all the KMIP operations granted to the `user`
    /// on all the objects in the database
    /// (i.e. the objects for which `user` is not the owner)
    /// The result is a list of tuples (uid, owner, state, operations, is_wrapped)
    /// where `operations` is a list of operations that `user` can perform on the object
    async fn list_user_operations_granted(
        &self,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashMap<String, (String, StateEnumeration, HashSet<KmipOperation>)>>;

    /// List all the KMIP operations granted per `user`
    /// This is called by the owner only
    async fn list_object_operations_granted(
        &self,
        uid: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashMap<String, HashSet<KmipOperation>>>;

    /// Grant to `user` the ability to perform the KMIP `operations`
    /// on the object identified by its `uid`
    async fn grant_operations(
        &self,
        uid: &str,
        user: &str,
        operations: HashSet<KmipOperation>,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()>;

    /// Remove to `user` the ability to perform the KMIP `operations`
    /// on the object identified by its `uid`
    async fn remove_operations(
        &self,
        uid: &str,
        user: &str,
        operations: HashSet<KmipOperation>,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()>;

    /// Test if an object identified by its `uid` is currently owned by `owner`
    async fn is_object_owned_by(
        &self,
        uid: &str,
        owner: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<bool>;

    /// List all the KMIP operations that have been granted to a user on an object
    ///
    /// These operations may have been directly granted or via the wildcard user
    /// unless `no_inherited_access` is set to `true`
    async fn list_user_operations_on_object(
        &self,
        uid: &str,
        user: &str,
        no_inherited_access: bool,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashSet<KmipOperation>>;
}
