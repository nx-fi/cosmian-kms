use std::{
    collections::{HashMap, HashSet},
    num::NonZeroUsize,
    path::PathBuf,
};

use async_trait::async_trait;
use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_types::{Attributes, StateEnumeration},
};
use cosmian_kms_client::access::{IsWrapped, ObjectOperationType};
use log::trace;
use lru::LruCache;
use tokio::sync::RwLock;

use crate::{
    core::extra_database_params::ExtraDatabaseParams,
    database::{object_with_metadata::ObjectWithMetadata, AtomicOperation, Database},
    error::KmsError,
    result::KResult,
};

pub(crate) struct CachedDatabase {
    db: Box<dyn Database + Sync + Send>,
    // id -> user -> OWM
    cache: RwLock<LruCache<String, RwLock<LruCache<String, ObjectWithMetadata>>>>,
}

impl CachedDatabase {
    pub(crate) fn new(db: Box<dyn Database + Sync + Send>) -> KResult<Self> {
        Ok(Self {
            db,
            cache: RwLock::new(LruCache::new(NonZeroUsize::new(100).ok_or_else(|| {
                KmsError::ServerError("Failed instantiating the LRU Cache".to_owned())
            })?)),
        })
    }
}

#[async_trait(?Send)]
impl Database for CachedDatabase {
    fn filename(&self, group_id: u128) -> Option<PathBuf> {
        self.db.filename(group_id)
    }

    async fn migrate(&self, params: Option<&ExtraDatabaseParams>) -> KResult<()> {
        self.db.migrate(params).await
    }

    async fn create(
        &self,
        uid: Option<String>,
        owner: &str,
        object: &Object,
        attributes: &Attributes,
        tags: &HashSet<String>,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<String> {
        self.db
            .create(uid, owner, object, attributes, tags, params)
            .await
    }

    async fn retrieve(
        &self,
        uid_or_tags: &str,
        user: &str,
        query_access_grant: ObjectOperationType,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashMap<String, ObjectWithMetadata>> {
        if let Some(user_cache) = self.cache.read().await.peek(uid_or_tags) {
            if let Some(owm) = user_cache.read().await.peek(user) {
                if (user == owm.owner()) || owm.permissions().contains(&query_access_grant) {
                    trace!("LRU Cache hit for object {}", uid_or_tags);
                    return Ok(HashMap::from([(uid_or_tags.to_owned(), owm.clone())]));
                }
            }
        }
        trace!("LRU Cache miss for object {}", uid_or_tags);
        let objects = self
            .db
            .retrieve(uid_or_tags, user, query_access_grant, params)
            .await?;
        for (uid, owm) in &objects {
            let mut main_cache = self.cache.write().await;
            if let Some(user_cache) = main_cache.get(user) {
                user_cache.write().await.put(user.to_owned(), owm.clone());
            } else {
                let mut user_cache = LruCache::new(NonZeroUsize::new(100).ok_or_else(|| {
                    KmsError::ServerError("Failed instantiating the LRU Cache".to_owned())
                })?);
                user_cache.put(user.to_owned(), owm.to_owned());
                main_cache.put(uid.to_string(), RwLock::new(user_cache));
            }
        }
        Ok(objects)
    }

    async fn retrieve_tags(
        &self,
        uid: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashSet<String>> {
        self.db.retrieve_tags(uid, params).await
    }

    async fn update_object(
        &self,
        uid: &str,
        object: &Object,
        attributes: &Attributes,
        tags: Option<&HashSet<String>>,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        self.db
            .update_object(uid, object, attributes, tags, params)
            .await?;
        self.cache.write().await.pop(uid);
        Ok(())
    }

    async fn update_state(
        &self,
        uid: &str,
        state: StateEnumeration,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        self.db.update_state(uid, state, params).await?;
        self.cache.write().await.pop(uid);
        Ok(())
    }

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
        self.db
            .upsert(uid, user, object, attributes, tags, state, params)
            .await?;
        self.cache.write().await.pop(uid);
        Ok(())
    }

    async fn delete(
        &self,
        uid: &str,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        self.db.delete(uid, user, params).await?;
        self.cache.write().await.pop(uid);
        Ok(())
    }

    async fn list_user_granted_access_rights(
        &self,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashMap<String, (String, StateEnumeration, HashSet<ObjectOperationType>)>> {
        self.db.list_user_granted_access_rights(user, params).await
    }

    async fn list_object_accesses_granted(
        &self,
        uid: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashMap<String, HashSet<ObjectOperationType>>> {
        self.db.list_object_accesses_granted(uid, params).await
    }

    async fn grant_access(
        &self,
        uid: &str,
        user: &str,
        operation_types: HashSet<ObjectOperationType>,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        self.db
            .grant_access(uid, user, operation_types, params)
            .await?;
        let mut main_cache = self.cache.write().await;
        if let Some(user_cache) = main_cache.get(uid) {
            user_cache.write().await.pop(user);
        }
        Ok(())
    }

    async fn remove_access(
        &self,
        uid: &str,
        user: &str,
        operation_types: HashSet<ObjectOperationType>,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        self.db
            .remove_access(uid, user, operation_types, params)
            .await?;
        let mut main_cache = self.cache.write().await;
        if let Some(user_cache) = main_cache.get(uid) {
            user_cache.write().await.pop(user);
        }
        Ok(())
    }

    async fn is_object_owned_by(
        &self,
        uid: &str,
        owner: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<bool> {
        self.db.is_object_owned_by(uid, owner, params).await
    }

    async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<StateEnumeration>,
        user: &str,
        user_must_be_owner: bool,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<(String, StateEnumeration, Attributes, IsWrapped)>> {
        self.db
            .find(
                researched_attributes,
                state,
                user,
                user_must_be_owner,
                params,
            )
            .await
    }

    async fn list_user_access_rights_on_object(
        &self,
        uid: &str,
        user: &str,
        no_inherited_access: bool,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashSet<ObjectOperationType>> {
        self.db
            .list_user_access_rights_on_object(uid, user, no_inherited_access, params)
            .await
    }

    async fn atomic(
        &self,
        user: &str,
        operations: &[AtomicOperation],
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        self.db.atomic(user, operations, params).await?;
        for operation in operations {
            let uid = match operation {
                AtomicOperation::Create((id, _, _, _))
                | AtomicOperation::Upsert((id, _, _, _, _))
                | AtomicOperation::UpdateObject((id, _, _, _))
                | AtomicOperation::UpdateState((id, _))
                | AtomicOperation::Delete(id) => id,
            };
            self.cache.write().await.pop(uid);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use std::collections::HashSet;

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
        database::{cached_database::CachedDatabase, sqlite::SqlitePool, Database},
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
        let sqlite = SqlitePool::instantiate(&db_file, true).await?;
        let db = Box::new(CachedDatabase::new(Box::new(sqlite))?);
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
        let uid_ = db
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
        assert!(db.cache.read().await.peek(&uid).is_none());

        // fetch the key
        let map = db
            .retrieve(&uid, owner, ObjectOperationType::Get, db_params.as_ref())
            .await?;
        assert_eq!(map.len(), 1);
        assert!(map.contains_key(&uid));
        let owm = map
            .get(&uid)
            .expect("this cannot happen due to previous assert");

        // the key should now be in the cache
        assert!(db.cache.read().await.peek(&uid).is_some());

        // update the key
        db.update_object(
            &uid,
            owm.object(),
            owm.attributes(),
            None,
            db_params.as_ref(),
        )
        .await?;

        // the key should not be in cache anymore
        assert!(db.cache.read().await.peek(&uid).is_none());

        Ok(())
    }
}
