use std::num::NonZeroUsize;

use cosmian_kmip::kmip::kmip_objects::Object;
use lru::LruCache;
use tokio::sync::RwLock;
#[cfg(test)]
use tokio::sync::RwLockReadGuard;
use tracing::trace;

use crate::DbResult;

/// This is the object kept in the Main LRU cache
/// It contains the unwrapped object and the key signature
#[derive(Clone)]
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
pub(crate) struct UnwrappedCache {
    cache: RwLock<LruCache<String, DbResult<CachedUnwrappedObject>>>,
}

impl UnwrappedCache {
    pub(crate) fn new() -> Self {
        #[allow(unsafe_code)]
        let max = unsafe { NonZeroUsize::new_unchecked(100) };
        Self {
            cache: RwLock::new(LruCache::new(max)),
        }
    }

    /// Validate the cache for a given object
    /// If the key signature is different, the cache is invalidated
    /// and the value is removed.
    pub(crate) async fn validate_cache(&self, uid: &str, object: &Object) {
        if let Ok(key_signature) = object.key_signature() {
            let mut cache = self.cache.write().await;
            // invalidate the value in cache if the signature is different
            match cache.peek(uid) {
                Some(Ok(cached_object)) => {
                    if *cached_object.key_signature() != key_signature {
                        trace!("Invalidating the cache for {}", uid);
                        cache.pop(uid);
                    }
                }
                Some(Err(_)) => {
                    // Note: this forces invalidation every time
                    // but trying to unwrap a key that fails to unwrap
                    // should be an exceptional case
                    trace!("Invalidating the cache for {}", uid);
                    cache.pop(uid);
                }
                None => {}
            }
        }
    }

    /// Clear a value from the cache
    pub(crate) async fn clear_cache(&self, uid: &str) {
        self.cache.write().await.pop(uid);
    }

    /// Peek into the cache
    pub(crate) async fn peek(&self, uid: &str) -> Option<DbResult<CachedUnwrappedObject>> {
        self.cache.read().await.peek(uid).cloned()
    }

    /// Insert into the cache
    pub(crate) async fn insert(
        &self,
        uid: String,
        unwrapped_object: DbResult<CachedUnwrappedObject>,
    ) {
        self.cache.write().await.put(uid, unwrapped_object);
    }

    #[cfg(test)]
    pub(crate) async fn get_cache(
        &self,
    ) -> RwLockReadGuard<'_, LruCache<String, DbResult<CachedUnwrappedObject>>> {
        self.cache.read().await
    }
}
