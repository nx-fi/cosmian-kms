mod store_traits;

use cosmian_kmip::kmip::kmip_objects::{Object, ObjectType};
use lazy_static::lazy_static;
use rawsql::Loader;
use serde::{Deserialize, Serialize};
pub use store_traits::{AtomicOperation, ObjectsStore, PermissionsStore};

mod cached_sqlcipher;
pub use cached_sqlcipher::CachedSqlCipher;

mod cached_sqlite_struct;

mod locate_query;
mod mysql;
pub(crate) use mysql::MySqlPool;
mod pgsql;
pub(crate) use pgsql::PgPool;
#[cfg(not(test))]
mod redis;
pub(crate) use redis::RedisWithFindex;
pub use redis::{redis_master_key_from_password, REDIS_WITH_FINDEX_MASTER_KEY_LENGTH};
mod extra_store_params;
#[cfg(test)]
pub(crate) mod redis;
mod sqlite;

pub use extra_store_params::ExtraStoreParams;
pub(crate) use sqlite::SqlitePool;

const PGSQL_FILE_QUERIES: &str = include_str!("query.sql");
const MYSQL_FILE_QUERIES: &str = include_str!("query_mysql.sql");
const SQLITE_FILE_QUERIES: &str = include_str!("query.sql");

lazy_static! {
    static ref PGSQL_QUERIES: Loader =
        Loader::get_queries_from(PGSQL_FILE_QUERIES).expect("Can't parse the SQL file");
    static ref MYSQL_QUERIES: Loader =
        Loader::get_queries_from(MYSQL_FILE_QUERIES).expect("Can't parse the SQL file");
    static ref SQLITE_QUERIES: Loader =
        Loader::get_queries_from(SQLITE_FILE_QUERIES).expect("Can't parse the SQL file");
}

#[derive(Clone)]
/// When using JSON serialization, the Object is untagged
/// and loses its type information, so we have to keep
/// the `ObjectType`. See `Object` and `post_fix()` for details
#[derive(Serialize, Deserialize)]
pub(crate) struct DBObject {
    pub(crate) object_type: ObjectType,
    pub(crate) object: Object,
}
