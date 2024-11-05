use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
};

use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_types::{Attributes, StateEnumeration},
};
use cosmian_kms_client::access::{IsWrapped, ObjectOperationType};
use tracing::trace;

use crate::{
    core::{
        extra_database_params::ExtraDatabaseParams, object_with_metadata::ObjectWithMetadata,
        wrapping::unwrap_key, KMS,
    },
    database::{
        store::Store, unwrapped_cache::CachedUnwrappedObject, AtomicOperation, ObjectsDatabase,
    },
    error::KmsError,
    result::{KResult, KResultHelper},
};

/// Methods that manipulate Objects in the database(s)
impl Store {
    #[allow(dead_code)]
    /// Register an Objects Database for Objects uid starting with <prefix>::
    pub(crate) async fn register_database(
        &self,
        prefix: &str,
        database: Arc<dyn ObjectsDatabase + Sync + Send>,
    ) {
        let mut map = self.objects.write().await;
        map.insert(prefix.to_owned(), database);
    }

    #[allow(dead_code)]
    /// Unregister the default objects database or a database for the given prefix
    pub(crate) async fn unregister_database(&self, prefix: Option<&str>) {
        let mut map = self.objects.write().await;
        map.remove(prefix.unwrap_or(""));
    }

    async fn get_database<'a>(
        &'a self,
        uid: &str,
    ) -> KResult<Arc<dyn ObjectsDatabase + Sync + Send>> {
        // split the uid on the first ::
        let splits = uid.split_once("::");
        Ok(match splits {
            Some((prefix, _rest)) => self
                .objects
                .read()
                .await
                .get(prefix)
                .ok_or_else(|| {
                    KmsError::InvalidRequest(format!(
                        "No object store available for UIDs prefixed with {prefix}::"
                    ))
                })?
                .clone(),
            None => self
                .objects
                .read()
                .await
                .get("")
                .ok_or_else(|| {
                    KmsError::InvalidRequest("No default object store available".to_owned())
                })?
                .clone(),
        })
    }

    /// Return the filename of the database or `None` if not supported
    pub(crate) async fn filename(&self, group_id: u128) -> Option<PathBuf> {
        self.get_database("")
            .await
            .ok()
            .and_then(|db| db.filename(group_id))
    }

    #[allow(dead_code)]
    /// Migrate all the databases to the latest version
    pub(crate) async fn migrate(&self, params: Option<&ExtraDatabaseParams>) -> KResult<()> {
        let map = self.objects.write().await;
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
    pub(crate) async fn create(
        &self,
        uid: Option<String>,
        owner: &str,
        object: &Object,
        attributes: &Attributes,
        tags: &HashSet<String>,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<String> {
        let db = self
            .get_database(uid.clone().unwrap_or_default().as_str())
            .await?;
        let uid = db
            .create(uid, owner, object, attributes, tags, params)
            .await?;
        // Clear the cache for the unwrapped key (if any)
        self.unwrapped_cache.validate_cache(&uid, object).await;
        Ok(uid)
    }

    /// Retrieve objects from the database.
    ///
    /// The `uid_or_tags` parameter can be either a `uid` or a comma-separated list of tags
    /// in a JSON array.
    ///
    /// The `permission` allows additional filtering in the `access` table to see
    /// if a `user`, that is not an owner, has the corresponding access granted
    pub(crate) async fn retrieve(
        &self,
        uid_or_tags: &str,
        user: &str,
        permission: ObjectOperationType,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashMap<String, ObjectWithMetadata>> {
        let db = self.get_database(uid_or_tags).await?;
        let objects = db.retrieve(uid_or_tags, user, permission, params).await?;
        // check if we need to invalidate the cache wrapped objects
        for owm in objects.values() {
            self.unwrapped_cache
                .validate_cache(owm.id(), owm.object())
                .await;
        }
        Ok(objects)
    }

    /// Retrieve the tags of the object with the given `uid`
    pub(crate) async fn retrieve_tags(
        &self,
        uid: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashSet<String>> {
        let db = self.get_database(uid).await?;
        db.retrieve_tags(uid, params).await
    }

    /// Update an object in the database.
    ///
    /// If tags is `None`, the tags will not be updated.
    pub(crate) async fn update_object(
        &self,
        uid: &str,
        object: &Object,
        attributes: &Attributes,
        tags: Option<&HashSet<String>>,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        let db = self.get_database(uid).await?;
        db.update_object(uid, object, attributes, tags, params)
            .await?;
        self.unwrapped_cache.validate_cache(uid, object).await;
        Ok(())
    }

    /// Update the state of an object in the database.
    pub(crate) async fn update_state(
        &self,
        uid: &str,
        state: StateEnumeration,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        let db = self.get_database(uid).await?;
        db.update_state(uid, state, params).await
    }

    // /// Upsert (update or create, if the object does not exist)
    // ///
    // /// If tags is `None`, the tags will not be updated.
    // #[allow(clippy::too_many_arguments)]
    // pub(crate) async fn upsert(
    //     &self,
    //     uid: &str,
    //     user: &str,
    //     object: &Object,
    //     attributes: &Attributes,
    //     tags: Option<&HashSet<String>>,
    //     state: StateEnumeration,
    //     params: Option<&ExtraDatabaseParams>,
    // ) -> KResult<()> {
    //     let db = self.get_database(uid).await?;
    //     db.upsert(uid, user, object, attributes, tags, state, params)
    //         .await?;
    //     self.unwrapped_cache.validate_cache(uid, object).await;
    //     Ok(())
    // }

    // /// Delete an object from the database.
    // pub(crate) async fn delete(
    //     &self,
    //     uid: &str,
    //     user: &str,
    //     params: Option<&ExtraDatabaseParams>,
    // ) -> KResult<()> {
    //     let db = self.get_database(uid).await?;
    //     db.delete(uid, user, params).await?;
    //     self.unwrapped_cache.clear_cache(uid).await;
    //     Ok(())
    // }

    #[allow(dead_code)]
    pub(crate) async fn list_uids_for_tags(
        &self,
        tags: &HashSet<String>,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<String>> {
        let map = self.objects.read().await;
        let mut results: Vec<String> = Vec::new();
        for (_prefix, db) in map.iter() {
            results.extend(db.list_uids_for_tags(tags, params).await?);
        }
        Ok(results)
    }

    /// Return uid, state and attributes of the object identified by its owner,
    /// and possibly by its attributes and/or its `state`
    pub(crate) async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<StateEnumeration>,
        user: &str,
        user_must_be_owner: bool,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<(String, StateEnumeration, Attributes, IsWrapped)>> {
        let map = self.objects.read().await;
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
            );
        }
        Ok(results)
    }

    /// Perform an atomic set of operation on the database
    /// (typically in a transaction). This function assumes
    /// that all objects belong to the same database.
    pub(crate) async fn atomic(
        &self,
        user: &str,
        operations: &[AtomicOperation],
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        if operations.is_empty() {
            return Ok(())
        }
        let first_op = &operations[0];
        let first_uid = first_op.get_object_uid();
        let db = self.get_database(first_uid).await?;
        db.atomic(user, operations, params).await?;
        // invalidate of clear cache for all operations
        for op in operations {
            match op {
                AtomicOperation::Create((uid, object, ..))
                | AtomicOperation::UpdateObject((uid, object, ..))
                | AtomicOperation::Upsert((uid, object, ..)) => {
                    self.unwrapped_cache.validate_cache(uid, object).await;
                }
                AtomicOperation::Delete(uid) => {
                    self.unwrapped_cache.clear_cache(uid).await;
                }
                AtomicOperation::UpdateState(_) => {}
            }
        }
        Ok(())
    }

    /// Unwrap the object (if need be) and return the unwrapped object
    /// The unwrapped object is cached in memory
    //TODO refactor unwrap_key() to use the permissions store
    pub(crate) async fn get_unwrapped(
        &self,
        uid: &str,
        object: &Object,
        kms: &KMS,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Object> {
        // Is this an unwrapped key?
        if object
            .key_block()
            .context("Cannot unwrap non key object")?
            .key_wrapping_data
            .is_none()
        {
            // already an unwrapped key
            trace!("Already an unwrapped key");
            return Ok(object.clone());
        }

        // check is we have it in cache
        match self.unwrapped_cache.peek(uid).await {
            Some(Ok(u)) => {
                // Note: In theory the cache should always be in sync...
                if *u.key_signature() == object.key_signature()? {
                    trace!("Unwrapped cache hit");
                    return Ok(u.unwrapped_object().clone());
                }
            }
            Some(Err(e)) => {
                return Err(e);
            }
            None => {
                // try unwrapping
            }
        }

        // local async future unwrap the object
        let unwrap_local = async {
            let key_signature = object.key_signature()?;
            let mut unwrapped_object = object.clone();
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
        self.unwrapped_cache
            .insert(uid.to_owned(), unwrapped_object)
            .await;
        //return the result
        result
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, sync::Arc};

    use cloudproof::reexport::crypto_core::{
        reexport::rand_core::{RngCore, SeedableRng},
        CsRng,
    };
    use cosmian_kmip::{
        crypto::symmetric::create_symmetric_key_kmip_object,
        kmip::kmip_types::CryptographicAlgorithm,
    };
    use cosmian_kms_client::access::ObjectOperationType;
    use cosmian_logger::log_utils::log_init;
    use tempfile::TempDir;
    use uuid::Uuid;

    use crate::{
        database::{sqlite::SqlitePool, store::Store},
        result::KResult,
    };

    #[tokio::test]
    pub(crate) async fn test_lru_cache() -> KResult<()> {
        log_init(option_env!("RUST_LOG"));

        let dir = TempDir::new()?;
        let db_file = dir.path().join("test_sqlite.db");
        if db_file.exists() {
            std::fs::remove_file(&db_file)?;
        }
        let sqlite = Arc::new(SqlitePool::instantiate(&db_file, true).await?);
        let store = Store::new(sqlite.clone(), sqlite);
        let db_params = None;

        let mut rng = CsRng::from_entropy();

        // create a symmetric key with tags
        let mut symmetric_key_bytes = vec![0; 32];
        rng.fill_bytes(&mut symmetric_key_bytes);
        // create symmetric key
        let symmetric_key =
            create_symmetric_key_kmip_object(&symmetric_key_bytes, CryptographicAlgorithm::AES)?;

        // insert into DB
        let owner = "eyJhbGciOiJSUzI1Ni";
        let uid = Uuid::new_v4().to_string();
        let uid_ = store
            .create(
                Some(uid.clone()),
                owner,
                &symmetric_key,
                symmetric_key.attributes()?,
                &HashSet::new(),
                db_params.as_ref(),
            )
            .await?;
        assert_eq!(&uid, &uid_);

        // The key should not be in cache
        assert!(store.unwrapped_cache.get_cache().await.peek(&uid).is_none());

        // fetch the key
        let map = store
            .retrieve(&uid, owner, ObjectOperationType::Get, db_params.as_ref())
            .await?;
        assert_eq!(map.len(), 1);
        assert!(map.contains_key(&uid));
        {
            let cache = store.unwrapped_cache.get_cache();
            // the unwrapped version should not be in the cache
            assert!(cache.await.peek(&uid).is_none());
        }

        Ok(())
    }
}
