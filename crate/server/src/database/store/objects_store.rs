use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{Arc, RwLock},
};

use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_types::{Attributes, StateEnumeration},
};
use cosmian_kms_client::access::{IsWrapped, ObjectOperationType};

use crate::{
    core::{extra_database_params::ExtraDatabaseParams, object_with_metadata::ObjectWithMetadata},
    database::{AtomicOperation, Database},
    error::KmsError,
    result::KResult,
};

pub(crate) struct ObjectsStore {
    /// A map of uid prefixes to Objects Database
    /// The "no-prefix" DB is registered under the empty string
    dbs: RwLock<HashMap<String, Arc<dyn Database + Sync + Send>>>,
}

impl ObjectsStore {
    /// Register an Objects Database for Objects uid starting with <prefix>::
    ///
    /// The un-prefixed objects go to the default database with the None or empty prefix  
    pub fn register_database(
        &self,
        prefix: Option<&str>,
        database: Arc<dyn Database + Sync + Send>,
    ) {
        let mut map = self.dbs.write().expect("failed locking the DBs map");
        map.insert(prefix.map(String::from).unwrap_or(String::new()), database);
    }

    /// Unregister the default objects database or a database for the given prefix
    pub fn unregister_database(&self, prefix: Option<&str>) {
        let mut map = self.dbs.write().expect("failed locking the DBs map");
        map.remove(prefix.unwrap_or(""));
    }

    fn get_database(&self, uid: &str) -> KResult<Arc<dyn Database + Sync + Send>> {
        // split the uid on the first ::
        let splits = uid.split_once("::");
        Ok(match splits {
            Some((prefix, _rest)) => self
                .dbs
                .read()
                .expect("failed locking the DBs map")
                .get(prefix)
                .ok_or_else(|| {
                    KmsError::InvalidRequest(format!(
                        "No object store available for uids prefixed with {prefix}::"
                    ))
                })?
                .clone(),
            None => self
                .dbs
                .read()
                .expect("failed locking the DBs map")
                .get("")
                .ok_or_else(|| {
                    KmsError::InvalidRequest("No default object store available".to_string())
                })?
                .clone(),
        })
    }

    /// Return the filename of the database or `None` if not supported
    fn filename(&self, group_id: u128) -> Option<PathBuf> {
        self.get_database("")
            .ok()
            .and_then(|db| db.filename(group_id))
    }

    /// Migrate all the databases to the latest version
    async fn migrate(&self, params: Option<&ExtraDatabaseParams>) -> KResult<()> {
        let map = self.dbs.write().expect("failed locking the DBs map");
        for (_prefix, db) in map.iter() {
            db.migrate(params).await?;
        }
        Ok(())
    }

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
    ) -> KResult<String> {
        let db = self.get_database(uid.clone().unwrap_or(String::new()).as_str())?;
        db.create(uid, owner, object, attributes, tags, params)
            .await
    }

    /// Retrieve objects from the database.
    ///
    /// The `uid_or_tags` parameter can be either a `uid` or a comma-separated list of tags
    /// in a JSON array.
    ///
    /// The `query_access_grant` allows additional filtering in the `access` table to see
    /// if a `user`, that is not a owner, has the corresponding access granted
    async fn retrieve(
        &self,
        uid_or_tags: &str,
        user: &str,
        query_access_grant: ObjectOperationType,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashMap<String, ObjectWithMetadata>> {
        let db = self.get_database(uid_or_tags)?;
        db.retrieve(uid_or_tags, user, query_access_grant, params)
            .await
    }

    /// Retrieve the tags of the object with the given `uid`
    async fn retrieve_tags(
        &self,
        uid: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashSet<String>> {
        let db = self.get_database(uid)?;
        db.retrieve_tags(uid, params).await
    }

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
    ) -> KResult<()> {
        let db = self.get_database(uid)?;
        db.update_object(uid, object, attributes, tags, params)
            .await
    }

    /// Update the state of an object in the database.
    async fn update_state(
        &self,
        uid: &str,
        state: StateEnumeration,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        let db = self.get_database(uid)?;
        db.update_state(uid, state, params).await
    }

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
    ) -> KResult<()> {
        let db = self.get_database(uid)?;
        db.upsert(uid, user, object, attributes, tags, state, params)
            .await
    }

    /// Delete an object from the database.
    #[allow(dead_code)]
    async fn delete(
        &self,
        uid: &str,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        let db = self.get_database(uid)?;
        db.delete(uid, user, params).await
    }

    /// Return uid, state and attributes of the object identified by its owner,
    /// and possibly by its attributes and/or its `state`
    async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<StateEnumeration>,
        user: &str,
        user_must_be_owner: bool,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<(String, StateEnumeration, Attributes, IsWrapped)>> {
        let map = self.dbs.read().expect("failed locking the DBs map");
        let mut results: Vec<(String, StateEnumeration, Attributes, IsWrapped)> = Vec::new();
        for (_prefix, db) in map.iter() {
            results.extend(
                db.find(
                    researched_attributes,
                    state,
                    user,
                    user_must_be_owner,
                    params,
                )
                .await
                .unwrap_or(vec![]),
            )
        }
        Ok(results)
    }

    /// Perform an atomic set of operation on the database
    /// (typically in a transaction)
    async fn atomic(
        &self,
        user: &str,
        operations: &[AtomicOperation],
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        if operations.is_empty() {
            return Ok(())
        }
        let first_op = &operations[0];
        let uid = match first_op {
            AtomicOperation::Create((uid, _, _, _))
            | AtomicOperation::Upsert((uid, _, _, _, _))
            | AtomicOperation::UpdateObject((uid, _, _, _))
            | AtomicOperation::UpdateState((uid, _))
            | AtomicOperation::Delete((uid)) => uid,
        };
    }
}
