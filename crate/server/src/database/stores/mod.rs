mod store_traits;
pub(crate) use store_traits::{AtomicOperation, ObjectsStore, PermissionsStore};

mod cached_sqlcipher;
pub(crate) use cached_sqlcipher::CachedSqlCipher;
mod cached_sqlite_struct;

mod locate_query;
mod mysql;
pub(crate) use mysql::MySqlPool;
mod pgsql;
pub(crate) use pgsql::PgPool;
#[cfg(not(test))]
mod redis;
pub(crate) use redis::{RedisWithFindex, REDIS_WITH_FINDEX_MASTER_KEY_LENGTH};
#[cfg(test)]
pub(crate) mod redis;
mod sqlite;
pub(crate) use sqlite::SqlitePool;
