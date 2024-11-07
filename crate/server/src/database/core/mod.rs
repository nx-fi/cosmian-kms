use std::{collections::HashMap, sync::Arc};

use tokio::sync::RwLock;
mod objects;
mod permissions;

use crate::database::{
    stores::{ObjectsStore, PermissionsStore},
    unwrapped_cache::UnwrappedCache,
};

pub(crate) struct Database {
    /// A map of uid prefixes to Objects Database
    /// The "no-prefix" DB is registered under the empty string
    objects: RwLock<HashMap<String, Arc<dyn ObjectsStore + Sync + Send>>>,
    /// The Unwrapped cache keeps the unwrapped version of keys in memory
    /// This cache avoid calls to HSMs for each operation
    unwrapped_cache: UnwrappedCache,
    /// The permissions store is used to check if a user has the right to perform an operation
    //TODO use this store to check permissions in retrive, update, delete, etc.
    permissions: Arc<dyn PermissionsStore + Sync + Send>,
}

impl Database {
    /// Create a new Objects Store
    ///  - `default_database` is the default database for objects without a prefix
    pub(crate) fn new(
        default_objects_database: Arc<dyn ObjectsStore + Sync + Send>,
        permissions_database: Arc<dyn PermissionsStore + Sync + Send>,
    ) -> Self {
        Self {
            objects: RwLock::new(HashMap::from([(String::new(), default_objects_database)])),
            unwrapped_cache: UnwrappedCache::new(),
            permissions: permissions_database,
        }
    }
}
