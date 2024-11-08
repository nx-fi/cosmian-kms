//! This module contains the core database functionalities, including object management,
//! permission checks, and caching mechanisms for unwrapped keys.

use std::{collections::HashMap, sync::Arc};

use cloudproof::reexport::crypto_core::FixedSizeCBytes;
use cosmian_kmip::crypto::secret::Secret;
use tokio::sync::RwLock;

mod objects;
pub use objects::{StateFilter, UserFilter};
mod permissions;

mod db_params;
pub use db_params::DbParams;

use crate::{
    stores::{
        CachedSqlCipher, MySqlPool, ObjectsStore, PermissionsStore, PgPool, RedisWithFindex,
        SqlitePool, REDIS_WITH_FINDEX_MASTER_KEY_LENGTH,
    },
    unwrapped_cache::UnwrappedCache,
    DbResult,
};

/// The `Database` struct represents the core database functionalities, including object management,
/// permission checks, and caching mechanisms for unwrapped keys.
pub struct Database {
    /// A map of uid prefixes to Object Store
    /// The "no-prefix" DB is registered under the empty string
    objects: RwLock<HashMap<String, Arc<dyn ObjectsStore + Sync + Send>>>,
    /// The Unwrapped cache keeps the unwrapped version of keys in memory.
    /// This cache avoids calls to HSMs for each operation
    unwrapped_cache: UnwrappedCache,
    /// The permissions store is used to check if a user has the right to perform an operation
    //TODO use this store to check permissions in retrive, update, delete, etc.
    permissions: Arc<dyn PermissionsStore + Sync + Send>,
}

impl Database {
    pub async fn instantiate(db_params: &DbParams, clear_db_on_start: bool) -> DbResult<Self> {
        Ok(match db_params {
            DbParams::Sqlite(db_path) => {
                let db = Arc::new(
                    SqlitePool::instantiate(&db_path.join("kms.db"), clear_db_on_start).await?,
                );
                Database::new(db.clone(), db)
            }
            DbParams::SqliteEnc(db_path) => {
                let db = Arc::new(CachedSqlCipher::instantiate(&*db_path, clear_db_on_start)?);
                Database::new(db.clone(), db)
            }
            DbParams::Postgres(url) => {
                let db = Arc::new(PgPool::instantiate(url.as_str(), clear_db_on_start).await?);
                Database::new(db.clone(), db)
            }
            DbParams::Mysql(url) => {
                let db = Arc::new(MySqlPool::instantiate(url.as_str(), clear_db_on_start).await?);
                Database::new(db.clone(), db)
            }
            DbParams::RedisFindex(url, master_key, label) => {
                // There is no reason to keep a copy of the key in the shared config
                // So we are going to create a "zeroizable" copy which will be passed to Redis with Findex
                // and zeroize the one in the shared config
                let new_master_key =
                    Secret::<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>::from_unprotected_bytes(
                        &mut master_key.to_bytes(),
                    );
                // `master_key` implements ZeroizeOnDrop so there is no need
                // to manually zeroize.
                let db = Arc::new(
                    RedisWithFindex::instantiate(url.as_str(), new_master_key, &*label).await?,
                );
                Database::new(db.clone(), db)
            }
        })
    }

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
