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
use tracing::info;

use crate::{
    core::extra_database_params::ExtraDatabaseParams,
    database::{object_with_metadata::ObjectWithMetadata, AtomicOperation, Database},
    error::KmsError,
    result::KResult,
};

/// This is the object kept in the Main LRU cache
///
/// The difference with `ObjectWithMetadata` is that it contains a cache of permissions
/// per user.
pub(crate) struct CachedObjectWithMetadata {
    owm: ObjectWithMetadata,
    permissions_cache: RwLock<LruCache<String, HashSet<ObjectOperationType>>>,
}

impl CachedObjectWithMetadata {
    pub(crate) async fn to_object_with_metadata(&self, user: &str) -> Option<ObjectWithMetadata> {
        self.permissions_cache.read().await.peek(user).map_or_else(
            || None,
            |permissions| {
                let mut owm = self.owm.clone();
                owm.permissions_mut().clone_from(permissions);
                Some(owm)
            },
        )
    }

    pub(crate) fn from_object_with_metadata(owm: &ObjectWithMetadata, user: &str) -> KResult<Self> {
        // set permissions for the user on the cache
        let mut permissions_cache = LruCache::new(NonZeroUsize::new(100).ok_or_else(|| {
            KmsError::ServerError("Failed instantiating the permissions LRU Cache".to_owned())
        })?);
        permissions_cache.put(user.to_owned(), owm.permissions().clone());
        // remove permissions on the owm
        let mut owm = owm.clone();
        *owm.permissions_mut() = HashSet::new();
        Ok(Self {
            owm,
            permissions_cache: RwLock::new(permissions_cache),
        })
    }
}

pub(crate) struct CachedDatabase {
    db: Box<dyn Database + Sync + Send>,
    cache: RwLock<LruCache<String, CachedObjectWithMetadata>>,
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
        {
            let main_cache = self.cache.read().await;
            if let Some(cowm) = main_cache.peek(uid_or_tags) {
                if let Some(owm) = cowm.to_object_with_metadata(user).await {
                    if (user == owm.owner()) || owm.permissions().contains(&query_access_grant) {
                        trace!("LRU Cache hit for object: {uid_or_tags}, for user: {user}");
                        return Ok(HashMap::from([(uid_or_tags.to_owned(), owm)]));
                    }
                }
            }
            // main_cache should be dropped
        }
        trace!("LRU Cache miss for object: {uid_or_tags}, for user: {user}");
        let objects = self
            .db
            .retrieve(uid_or_tags, user, query_access_grant, params)
            .await?;
        info!("objects: {}", objects.len());
        if !objects.is_empty() {
            // update the permissions cache
            let mut main_cache = self.cache.write().await;
            info!("main_cache: {}", main_cache.len());
            for (uid, owm) in &objects {
                if let Some(cowm) = main_cache.get(user) {
                    cowm.permissions_cache
                        .write()
                        .await
                        .put(user.to_owned(), owm.permissions().clone());
                } else {
                    let cowm = CachedObjectWithMetadata::from_object_with_metadata(owm, user)?;
                    main_cache.put(uid.to_string(), cowm);
                }
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
        if let Some(cowm) = main_cache.get(uid) {
            cowm.permissions_cache.write().await.pop(user);
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
        if let Some(cowm) = main_cache.get(uid) {
            cowm.permissions_cache.write().await.pop(user);
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
        core::extra_database_params::ExtraDatabaseParams,
        database::{
            cached_database::CachedDatabase, object_with_metadata::ObjectWithMetadata,
            sqlite::SqlitePool, Database,
        },
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
        let owm = fetch_and_assert(&db, &db_params, owner, &uid).await?;

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

        // fetch and assert
        fetch_and_assert(&db, &db_params, owner, &uid).await?;

        // grant a permission to the user bob
        db.grant_access(
            &uid,
            "bob",
            HashSet::from([ObjectOperationType::Get]),
            db_params.as_ref(),
        )
        .await?;
        {
            // the key should be in the cache but not for Bob
            let cache = db.cache.read().await;
            let cowm = cache.peek(&uid).expect("the key should be in the cache");
            assert!(cowm.permissions_cache.read().await.peek("bob").is_none());
            assert!(cowm.permissions_cache.read().await.peek(owner).is_some());
        }

        // fetch the key for bob
        fetch_and_assert(&db, &db_params, "bob", &uid).await?;

        // add another permission to Bob
        db.grant_access(
            &uid,
            "bob",
            HashSet::from([ObjectOperationType::Destroy]),
            db_params.as_ref(),
        )
        .await?;

        // the key should be in the cache but not for Bob anymore
        {
            let cache = db.cache.read().await;
            let cowm = cache.peek(&uid).expect("the key should be in the cache");
            assert!(cowm.permissions_cache.read().await.peek("bob").is_none());
            assert!(cowm.permissions_cache.read().await.peek(owner).is_some());
        }

        Ok(())
    }

    async fn fetch_and_assert(
        db: &CachedDatabase,
        db_params: &Option<ExtraDatabaseParams>,
        user: &str,
        uid: &str,
    ) -> KResult<ObjectWithMetadata> {
        let map = db
            .retrieve(uid, user, ObjectOperationType::Get, db_params.as_ref())
            .await?;
        assert_eq!(map.len(), 1);
        assert!(map.contains_key(uid));
        let owm = map
            .get(uid)
            .expect("this cannot happen due to previous assert");

        // the key should now be in the cache
        let cache = db.cache.read().await;
        let cowm = cache.peek(uid);
        assert!(cowm.is_some());
        let cowm = cowm.expect("this cannot happen due to previous assert");
        let owm_ = cowm.to_object_with_metadata(user).await;
        assert!(owm_.is_some());

        Ok(owm.to_owned())
    }
}
