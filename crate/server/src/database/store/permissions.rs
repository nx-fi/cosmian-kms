use std::collections::{HashMap, HashSet};

use cosmian_kmip::kmip::kmip_types::StateEnumeration;
use cosmian_kms_client::access::ObjectOperationType;

use crate::{
    core::extra_database_params::ExtraDatabaseParams, database::store::Store, result::KResult,
};

/// Methods that manipulate permissions
impl Store {
    /// List all the access rights granted to the `user`
    /// on all the objects in the database
    /// (i.e. the objects for which `user` is not the owner)
    /// The result is a list of tuples (uid, owner, state, operations, `is_wrapped`)
    /// where `operations` is a list of operations that `user` can perform on the object
    pub(crate) async fn list_user_granted_access_rights(
        &self,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashMap<String, (String, StateEnumeration, HashSet<ObjectOperationType>)>> {
        self.permissions
            .list_user_granted_access_rights(user, params)
            .await
    }

    /// List all the accessed granted per `user`
    /// This is called by the owner only
    pub(crate) async fn list_object_accesses_granted(
        &self,
        uid: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashMap<String, HashSet<ObjectOperationType>>> {
        self.permissions
            .list_object_accesses_granted(uid, params)
            .await
    }

    /// Grant the access right to `user` to perform the `operation_type`
    /// on the object identified by its `uid`
    pub(crate) async fn grant_access(
        &self,
        uid: &str,
        user: &str,
        operation_types: HashSet<ObjectOperationType>,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        self.permissions
            .grant_access(uid, user, operation_types, params)
            .await
    }

    /// Remove the access right to `user` to perform the `operation_type`
    /// on the object identified by its `uid`
    pub(crate) async fn remove_access(
        &self,
        uid: &str,
        user: &str,
        operation_types: HashSet<ObjectOperationType>,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        self.permissions
            .remove_access(uid, user, operation_types, params)
            .await
    }

    /// Test if an object identified by its `uid` is currently owned by `owner`
    pub(crate) async fn is_object_owned_by(
        &self,
        uid: &str,
        owner: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<bool> {
        self.permissions
            .is_object_owned_by(uid, owner, params)
            .await
    }

    /// List all the access rights that have been granted to a user on an object
    ///
    /// These access rights may have been directly granted or via the wildcard user
    /// unless `no_inherited_access` is set to `true`
    #[allow(dead_code)]
    pub(crate) async fn list_user_access_rights_on_object(
        &self,
        uid: &str,
        user: &str,
        no_inherited_access: bool,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashSet<ObjectOperationType>> {
        self.permissions
            .list_user_access_rights_on_object(uid, user, no_inherited_access, params)
            .await
    }
}
