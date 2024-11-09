use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
};

use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_types::{Attributes, StateEnumeration},
    KmipOperation,
};

use crate::{
    core::ObjectWithMetadata,
    error::{DbError, DbResult},
    stores::{ExtraStoreParams, ObjectsStore},
    AtomicOperation, Database,
};

/// Enum representing different user filters for object operations.
///
/// This enum is used to specify the conditions under which a user can perform
/// operations on objects in the database.
///
/// Variants:
/// - `None`: No user filter is applied.
/// - `UserMustBeOwner`: The user must be the owner of the object.
/// - `UserCanPerformAnyOperation(HashSet<KmipOperation>)`: The user can perform any of the specified operations.
/// - `UserCanPerformAllOperations(HashSet<KmipOperation>)`: The user can perform all the specified operations.
#[derive(Clone)]
pub enum UserFilter {
    None,
    UserMustBeOwner,
    UserCanPerformAnyOperation(HashSet<KmipOperation>),
    UserCanPerformAllOperations(HashSet<KmipOperation>),
}

/// Enum representing different state filters for object operations.
///
/// This enum is used to specify the conditions based on the state of objects
/// in the database.
///
/// Variants:
/// - `None`: No state filter is applied.
/// - `StateIn(HashSet<StateEnumeration>)`: The object state must be in the specified set of states.
/// - `StateNotIn(HashSet<StateEnumeration>)`: The object state must not be in the specified set of states.
#[derive(Clone)]
pub enum StateFilter {
    None,
    StateIn(HashSet<StateEnumeration>),
    StateNotIn(HashSet<StateEnumeration>),
}

/// Struct representing the database and providing methods to manipulate objects within it.
///
/// The `Database` struct provides various methods to register, unregister, retrieve, create, update,
/// and delete objects in the database. It also supports operations like migration, atomic transactions,
/// and cache management for unwrapped objects.
///
/// # Methods
///
/// - `register_objects_store`: Registers an `ObjectsStore` for objects with a specific prefix.
/// - `unregister_object_store`: Unregisters the default objects store or a store for a given prefix.
/// - `get_object_store`: Retrieves the appropriate object store based on the prefix of the `uid`.
/// - `filename`: Returns the filename of the database or `None` if not supported.
/// - `migrate`: Migrates all the databases to the latest version.
/// - `create`: Creates a new object in the database.
/// - `retrieve_objects`: Retrieves objects from the database based on `uid` or tags.
/// - `retrieve_object`: Retrieves a single object from the database.
/// - `retrieve_tags`: Retrieves the tags of an object with the given `uid`.
/// - `update_object`: Updates the specified object in the database.
/// - `update_state`: Updates the state of an object in the database.
/// - `atomic`: Performs an atomic set of operations on the database.
/// - `get_unwrapped`: Unwraps the object (if needed) and returns the unwrapped object.
impl Database {
    #[allow(dead_code)]
    /// Register an Objects store for Objects `uid` starting with `<prefix>::`.
    ///
    /// This function registers an `ObjectsStore` for objects whose unique identifiers
    /// start with the specified prefix. The prefix is used to route operations to the
    /// appropriate store.
    ///
    /// # Arguments
    ///
    /// * `prefix` - A string slice representing the prefix for the objects' unique identifiers.
    /// * `objects_store` - An `Arc` containing the `ObjectsStore` to be registered.
    ///
    /// # Example
    ///
    /// ```
    /// let store = Arc::new(MyObjectsStore::new());
    /// database.register_objects_store("my_prefix", store).await;
    /// ```
    pub async fn register_objects_store(
        &self,
        prefix: &str,
        objects_store: Arc<dyn ObjectsStore + Sync + Send>,
    ) {
        let mut map = self.objects.write().await;
        map.insert(prefix.to_owned(), objects_store);
    }

    #[allow(dead_code)]
    /// Unregister the default objects store or a store for the given prefix
    pub async fn unregister_object_store(&self, prefix: Option<&str>) {
        let mut map = self.objects.write().await;
        map.remove(prefix.unwrap_or(""));
    }

    /// Return the object store for the given `uid`
    ///
    /// This function retrieves the appropriate object store based on the prefix of the `uid`.
    /// If the `uid` contains a prefix separated by "::", it will look for a store registered with that prefix.
    /// If no prefix is found, it will return the default object store.
    ///
    /// # Arguments
    ///
    /// * `uid` - A string slice representing the unique identifier of the object.
    ///
    /// # Returns
    ///
    /// * `DbResult<Arc<dyn ObjectsStore + Sync + Send>>` - A result containing the object store.
    ///
    /// # Errors
    ///
    /// This function will return an error if no object store is found for the given prefix or if no default object store is available.
    async fn get_object_store<'a>(
        &'a self,
        uid: &str,
    ) -> DbResult<Arc<dyn ObjectsStore + Sync + Send>> {
        // split the uid on the first ::
        let splits = uid.split_once("::");
        Ok(match splits {
            Some((prefix, _rest)) => self
                .objects
                .read()
                .await
                .get(prefix)
                .ok_or_else(|| {
                    DbError::InvalidRequest(format!(
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
                    DbError::InvalidRequest("No default object store available".to_owned())
                })?
                .clone(),
        })
    }

    /// Return the filename of the database or `None` if not supported
    pub async fn filename(&self, group_id: u128) -> Option<PathBuf> {
        self.get_object_store("")
            .await
            .ok()
            .and_then(|db| db.filename(group_id))
    }

    #[allow(dead_code)]
    /// Migrate all the databases to the latest version
    pub async fn migrate(&self, params: Option<&ExtraStoreParams>) -> DbResult<()> {
        let map = self.objects.write().await;
        for (_prefix, db) in map.iter() {
            db.migrate(params).await?;
        }
        Ok(())
    }

    /// Create the given Object in the database.
    ///
    /// # Arguments
    ///
    /// * `uid` - An optional string representing the unique identifier of the object.
    /// * `owner` - A string slice representing the owner of the object.
    /// * `object` - A reference to the `Object` to be created.
    /// * `attributes` - A reference to the `Attributes` of the object.
    /// * `tags` - A reference to a `HashSet` of tags associated with the object.
    /// * `params` - An optional reference to `ExtraStoreParams` for additional parameters.
    ///
    /// # Returns
    ///
    /// * `DbResult<String>` - A result containing the unique identifier of the created object.
    /// Create the given Object in the database.
    ///
    /// A new UUID will be created if none is supplier.
    /// This method will fail if an ` uid ` is supplied
    /// and an object with the same id already exists
    pub async fn create(
        &self,
        uid: Option<String>,
        owner: &str,
        object: &Object,
        attributes: &Attributes,
        tags: &HashSet<String>,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<String> {
        let db = self
            .get_object_store(uid.clone().unwrap_or_default().as_str())
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
    /// The `uid_or_tags` parameter can be either a `uid` or a JSON array of tags.
    ///
    /// The `user_filter` parameter allows filtering based on user permissions.
    ///
    /// The `state_filter` parameter allows filtering based on the state of the objects.
    ///
    /// The `params` parameter allows passing additional parameters for the database query.
    ///
    /// Returns a `DbResult` containing a `HashMap` where the keys are the `uid`s and the values are the `ObjectWithMetadata`.
    ///
    /// # Arguments
    ///
    /// * `uid_or_tags` - A string representing either a `uid` or a JSON array of tags.
    /// * `user` - A string representing the user requesting the objects.
    /// * `user_filter` - A `UserFilter` enum to filter objects based on user permissions.
    /// * `state_filter` - A `StateFilter` enum to filter objects based on their state.
    /// * `params` - An optional reference to `ExtraStoreParams` for additional query parameters.
    ///
    /// # Returns
    ///
    /// * `DbResult<HashMap<String, ObjectWithMetadata>>` - A result containing a map of `uid`s to `ObjectWithMetadata`.
    pub async fn retrieve_objects(
        &self,
        uid_or_tags: &str,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<HashMap<String, ObjectWithMetadata>> {
        let uids = if uid_or_tags.starts_with('[') {
            // tags
            let tags: HashSet<String> = serde_json::from_str(uid_or_tags)?;
            self.list_uids_for_tags(&tags, params).await?
        } else {
            HashSet::from([uid_or_tags.to_owned()])
        };
        let mut results: HashMap<String, ObjectWithMetadata> = HashMap::new();
        for uid in &uids {
            let owm = self.retrieve_object(uid, params).await?;
            if let Some(owm) = owm {
                results.insert(uid.to_owned(), owm);
            }
        }
        Ok(results)
    }

    /// Retrieve a single object from the database.
    ///
    /// This method retrieves an object identified by its `uid` and applies
    /// user and state filters to determine if the object should be returned.
    ///
    /// # Arguments
    ///
    /// * `uid` - A string slice that holds the unique identifier of the object.
    /// * `user` - A string slice representing the user requesting the object.
    /// * `user_filter` - A `UserFilter` enum to filter objects based on user permissions.
    /// * `state_filter` - A `StateFilter` enum to filter objects based on their state.
    /// * `params` - An optional reference to `ExtraStoreParams` for additional query parameters.
    ///
    /// # Returns
    ///
    /// * `DbResult<Option<ObjectWithMetadata>>` - A result containing an optional `ObjectWithMetadata`.
    ///   If the object is found and passes the filters, it is returned wrapped in `Some`.
    ///   If the object is not found or does not pass the filters, `None` is returned.
    pub async fn retrieve_object(
        &self,
        uid: &str,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<Option<ObjectWithMetadata>> {
        // retrieve the object
        let db = self.get_object_store(uid).await?;
        db.retrieve(uid, params).await
    }

    // /// Retrieve objects from the database.
    // ///
    // /// The `uid_or_tags` parameter can be either an ` uid ` or a comma-separated list of tags
    // /// in a JSON array.
    // ///
    // /// The `permission` allows additional filtering in the `access` table to see
    // /// if a `user` that is not an owner has the corresponding access granted
    // pub async fn retrieve(
    //     &self,
    //     uid_or_tags: &str,
    //     user: &str,
    //     permission: KmipOperation,
    //     params: Option<&ExtraStoreParams>,
    // ) -> DbResult<HashMap<String, ObjectWithMetadata>> {
    //     let uids = if uid_or_tags.starts_with('[') {
    //         // tags
    //         let tags: HashSet<String> = serde_json::from_str(uid_or_tags)?;
    //         self.list_uids_for_tags(&tags, params).await?
    //     } else {
    //         vec![uid_or_tags.to_owned()]
    //     };
    //
    //     let mut results: HashMap<String, ObjectWithMetadata> = HashMap::new();
    //     for uid in &uids {
    //         let mut retrieve = self.is_object_owned_by(uid, user, params).await?;
    //         // user is not the owner, check if the user has the permission
    //         if !retrieve {
    //             let operations = self
    //                 .list_user_operations_on_object(uid, user, false, params)
    //                 .await?;
    //             retrieve = operations.contains(&permission);
    //         }
    //         if retrieve {
    //             let db = self.get_object_store(uid).await?;
    //             let owm = db.retrieve(uid, params).await?;
    //             if let Some(owm) = owm {
    //                 // check if we need to invalidate the cache wrapped objects
    //                 self.unwrapped_cache.validate_cache(uid, owm.object()).await;
    //                 results.insert(uid.to_owned(), owm);
    //             }
    //         }
    //     }
    //     Ok(results)
    // }

    /// Retrieve the tags of the object with the given `uid`
    pub async fn retrieve_tags(
        &self,
        uid: &str,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<HashSet<String>> {
        let db = self.get_object_store(uid).await?;
        db.retrieve_tags(uid, params).await
    }

    /// This method updates the specified object identified by its `uid` in the database.
    /// If the `tags` parameter is `None`, the tags will not be updated.
    ///
    /// # Arguments
    ///
    /// * `uid` - A string slice that holds the unique identifier of the object.
    /// * `object` - A reference to the `Object` to be updated.
    /// * `attributes` - A reference to the `Attributes` of the object.
    /// * `tags` - An optional reference to a `HashSet` of tags associated with the object.
    /// * `params` - An optional reference to `ExtraStoreParams` for additional parameters.
    ///
    /// # Returns
    ///
    /// * `DbResult<()>` - A result indicating success or failure of the update operation.
    ///
    /// # Errors
    ///
    /// This function will return an error if the object store for the given `uid` cannot be found
    /// or if the update operation fails.
    pub async fn update_object(
        &self,
        uid: &str,
        object: &Object,
        attributes: &Attributes,
        tags: Option<&HashSet<String>>,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<()> {
        let db = self.get_object_store(uid).await?;
        db.update_object(uid, object, attributes, tags, params)
            .await?;
        self.unwrapped_cache.validate_cache(uid, object).await;
        Ok(())
    }

    /// Update the state of an object in the database.
    pub async fn update_state(
        &self,
        uid: &str,
        state: StateEnumeration,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<()> {
        let db = self.get_object_store(uid).await?;
        db.update_state(uid, state, params).await
    }

    // /// Upsert (update or create, if the object does not exist)
    // ///
    // /// If tags is `None`, the tags will not be updated.
    // #[allow(clippy::too_many_arguments)]
    // pub async fn upsert(
    //     &self,
    //     uid: &str,
    //     user: &str,
    //     object: &Object,
    //     attributes: &Attributes,
    //     tags: Option<&HashSet<String>>,
    //     state: StateEnumeration,
    //     params: Option<&ExtraDatabaseParams>,
    // ) -> DbResult<()> {
    //     let db = self.get_database(uid).await?;
    //     db.upsert(uid, user, object, attributes, tags, state, params)
    //         .await?;
    //     self.unwrapped_cache.validate_cache(uid, object).await;
    //     Ok(())
    // }

    // /// Delete an object from the database.
    // pub async fn delete(
    //     &self,
    //     uid: &str,
    //     user: &str,
    //     params: Option<&ExtraDatabaseParams>,
    // ) -> DbResult<()> {
    //     let db = self.get_database(uid).await?;
    //     db.delete(uid, user, params).await?;
    //     self.unwrapped_cache.clear_cache(uid).await;
    //     Ok(())
    // }

    pub async fn list_uids_for_tags(
        &self,
        tags: &HashSet<String>,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<HashSet<String>> {
        let db_map = self.objects.read().await;
        let mut results = HashSet::new();
        for (_prefix, db) in db_map.iter() {
            results.extend(db.list_uids_for_tags(tags, params).await?);
        }
        Ok(results)
    }

    /// Return uid, state and attributes of the object identified by its owner,
    /// and possibly by its attributes and/or its `state`
    pub async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<StateEnumeration>,
        user: &str,
        user_must_be_owner: bool,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<Vec<(String, StateEnumeration, Attributes)>> {
        let map = self.objects.read().await;
        let mut results: Vec<(String, StateEnumeration, Attributes)> = Vec::new();
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

    /// Perform an atomic set of operations on the database.
    ///
    /// This function executes a series of operations (typically in a transaction) atomically.
    /// It assumes that all objects involved in the operations belong to the same database.
    ///
    /// # Arguments
    ///
    /// * `user` - A string slice representing the user performing the operations.
    /// * `operations` - A slice of `AtomicOperation` representing the operations to be performed.
    /// * `params` - An optional reference to `ExtraStoreParams` for additional parameters.
    ///
    /// # Returns
    ///
    /// * `DbResult<()>` - A result indicating success or failure of the atomic operation.
    ///
    /// # Errors
    ///
    /// This function will return an error if any of the operations fail or if the database
    /// cannot be accessed.
    pub async fn atomic(
        &self,
        user: &str,
        operations: &[AtomicOperation],
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<()> {
        if operations.is_empty() {
            return Ok(())
        }
        let first_op = &operations[0];
        let first_uid = first_op.get_object_uid();
        let db = self.get_object_store(first_uid).await?;
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
}
