use std::{
    collections::{HashMap, HashSet},
    num::NonZeroUsize,
    path::PathBuf,
    sync::Arc,
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
    core::{extra_database_params::ExtraDatabaseParams, object_with_metadata::ObjectWithMetadata},
    database::{AtomicOperation, Database},
    error::KmsError,
    result::KResult,
};

/// This is the object kept in the Main LRU cache
/// It contains the unwrapped object and the key signature
pub(crate) struct CachedUnwrappedObject {
    key_signature: [u8; 32],
    unwrapped_object: Object,
}

impl CachedUnwrappedObject {
    pub(crate) fn new(key_signature: [u8; 32], unwrapped_object: Object) -> Self {
        Self {
            key_signature,
            unwrapped_object,
        }
    }

    pub(crate) fn key_signature(&self) -> &[u8; 32] {
        &self.key_signature
    }

    pub(crate) fn unwrapped_object(&self) -> &Object {
        &self.unwrapped_object
    }
}

/// The cache of unwrapped objects
/// The key is the uid of the object
/// The value is the unwrapped object
/// The value is a `Err(KmsError)` if the object cannot be unwrapped
pub(crate) type UnwrappedCache = RwLock<LruCache<String, KResult<CachedUnwrappedObject>>>;

/// A local cache of the unwrapped value of a key
/// which may be very expensive to compute, particularly
/// if the unwrapping key is stored in a remote HSM.
pub(crate) struct CachedDatabase {
    db: Box<dyn Database + Sync + Send>,
    // uid -> unwrapped value
    cache: Arc<UnwrappedCache>,
}

impl CachedDatabase {
    pub(crate) fn new(db: Box<dyn Database + Sync + Send>) -> KResult<Self> {
        Ok(Self {
            db,
            cache: Arc::new(RwLock::new(LruCache::new(
                NonZeroUsize::new(100).ok_or_else(|| {
                    KmsError::ServerError("Failed instantiating the LRU Cache".to_owned())
                })?,
            ))),
        })
    }

    /// Validate the cache for a given object
    /// If the key signature is different, the cache is invalidated
    /// and the value is removed.
    async fn validate_cache(&self, uid: &str, object: &Object) {
        if let Ok(key_signature) = object.key_signature() {
            let mut cache = self.cache.write().await;
            // invalidate the value in cache if the signature is different
            if let Some(cached_object) = cache.peek(uid) {
                if let Ok(cached_object) = cached_object {
                    if *cached_object.key_signature() != key_signature {
                        trace!("Invalidating the cache for {}", uid);
                        cache.pop(uid);
                    }
                }
            }
        }
    }

    /// Clear a value from the cache
    pub(crate) async fn clear_cache(&self, uid: &str) {
        self.cache.write().await.pop(uid);
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
        let mut objects = self
            .db
            .retrieve(uid_or_tags, user, query_access_grant, params)
            .await?;
        // check if we need to invalidate the cache wrapped objects
        for (_, owm) in objects.iter_mut() {
            self.validate_cache(owm.id(), owm.object()).await;
            owm.set_unwrapped_cache(self.cache.clone());
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
        self.validate_cache(uid, object).await;
        Ok(())
    }

    async fn update_state(
        &self,
        uid: &str,
        state: StateEnumeration,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        self.db.update_state(uid, state, params).await?;
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
        self.validate_cache(uid, object).await;
        Ok(())
    }

    async fn delete(
        &self,
        uid: &str,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        self.db.delete(uid, user, params).await?;
        self.clear_cache(uid).await;
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
            .await
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
            .await
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
            // not great, but hard to do better
            self.clear_cache(uid).await;
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

        {
            let cache = db.cache.read().await;
            // the unwrapped version should not be in the cache
            assert!(cache.peek(&uid).is_none());
            // however the object metadata should have the unwrapped_cache set
            assert!(owm.unwrapped_cache().is_some());
        }

        Ok(())
    }
}
