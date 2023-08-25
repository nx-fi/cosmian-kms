use std::{collections::HashSet, sync::Arc};

use async_trait::async_trait;
use cloudproof::reexport::{
    crypto_core::{
        reexport::rand_core::{RngCore, SeedableRng},
        CsRng, RandomFixedSizeCBytes, SymmetricKey,
    },
    findex::{
        implementations::redis::{FindexRedis, FindexRedisError, RemovedLocationsFinder},
        Location,
    },
};
use cosmian_kmip::kmip::kmip_types::{CryptographicAlgorithm, StateEnumeration};
use cosmian_kms_utils::{access::ObjectOperationType, crypto::symmetric::create_symmetric_key};
use redis::aio::ConnectionManager;
use tracing::trace;

use crate::{
    database::{
        redis::{
            objects_db::{ObjectsDB, RedisDbObject},
            permissions::PermissionsDB,
        },
        tests::get_redis_url,
    },
    log_utils::log_init,
    result::KResult,
};

struct DummyDB {}
#[async_trait]
impl RemovedLocationsFinder for DummyDB {
    async fn find_removed_locations(
        &self,
        _locations: HashSet<Location>,
    ) -> Result<HashSet<Location>, FindexRedisError> {
        Ok(HashSet::new())
    }
}

async fn clear_all(mgr: &mut ConnectionManager) -> KResult<()> {
    redis::cmd("FLUSHDB").query_async(mgr).await?;
    Ok(())
}

pub async fn test_objects_db() -> KResult<()> {
    log_init("test_objects_db=trace");
    trace!("test_objects_db");

    let client = redis::Client::open(get_redis_url())?;
    let mgr = ConnectionManager::new(client).await?;

    let o_db = ObjectsDB::new(mgr.clone()).await?;

    // single upsert - get - delete
    let uid = "test_objects_db";

    let mut rng = CsRng::from_entropy();
    let mut symmetric_key = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key);
    let object = create_symmetric_key(&symmetric_key, CryptographicAlgorithm::AES);

    // clean up
    o_db.clear_all().await?;

    // check that the object is not there
    assert!(o_db.object_get(uid).await.is_err());

    o_db.object_upsert(
        uid,
        &RedisDbObject::new(
            object.clone(),
            "owner".to_string(),
            StateEnumeration::Active,
            HashSet::new(),
        ),
    )
    .await?;
    let redis_db_object = o_db.object_get(uid).await?;
    assert_eq!(
        object.key_block()?.key_bytes()?,
        redis_db_object.object.key_block()?.key_bytes()?
    );
    assert_eq!(redis_db_object.owner, "owner");
    assert_eq!(redis_db_object.state, StateEnumeration::Active);

    o_db.object_delete(uid).await?;
    assert!(o_db.object_get(uid).await.is_err());

    Ok(())
}

pub async fn test_permissions_db() -> KResult<()> {
    // generate the findex key
    let mut rng = CsRng::from_entropy();
    let findex_key = SymmetricKey::new(&mut rng);

    // the findex label
    let label = b"label";

    let client = redis::Client::open(get_redis_url())?;
    let mut mgr = ConnectionManager::new(client).await?;
    // clear the DB
    clear_all(&mut mgr).await?;
    // create the findex
    let findex =
        Arc::new(FindexRedis::connect_with_manager(mgr.clone(), Arc::new(DummyDB {})).await?);
    let permissions_db = PermissionsDB::new(findex, label).await?;

    // let us add the permission Encrypt on object O1 for user U1
    permissions_db
        .add(&findex_key, "O1", "U1", ObjectOperationType::Encrypt)
        .await?;

    // verify that the permission is present
    let permissions = permissions_db.get(&findex_key, "O1", "U1").await?;
    assert_eq!(permissions.len(), 1);
    assert!(permissions.contains(&ObjectOperationType::Encrypt));

    // find the permissions for user U1
    let permissions = permissions_db
        .list_user_permissions(&findex_key, "U1")
        .await?;
    assert_eq!(permissions.len(), 1);
    assert!(permissions.contains_key("O1"));
    assert_eq!(
        permissions.get("O1").unwrap(),
        &HashSet::from([ObjectOperationType::Encrypt])
    );

    //find the permission for the object O1
    let permissions = permissions_db
        .list_object_permissions(&findex_key, "O1")
        .await?;
    assert_eq!(permissions.len(), 1);
    assert!(permissions.contains_key("U1"));
    assert_eq!(
        permissions.get("U1").unwrap(),
        &HashSet::from([ObjectOperationType::Encrypt])
    );

    // add the permission Decrypt to user U1 for object O1
    permissions_db
        .add(&findex_key, "O1", "U1", ObjectOperationType::Decrypt)
        .await?;

    // assert the permission is present
    let permissions = permissions_db.get(&findex_key, "O1", "U1").await?;
    assert_eq!(permissions.len(), 2);
    assert!(permissions.contains(&ObjectOperationType::Encrypt));
    assert!(permissions.contains(&ObjectOperationType::Decrypt));

    // find the permissions for user U1
    let permissions = permissions_db
        .list_user_permissions(&findex_key, "U1")
        .await?;
    assert_eq!(permissions.len(), 1);
    assert!(permissions.contains_key("O1"));
    assert_eq!(
        permissions.get("O1").unwrap(),
        &HashSet::from([ObjectOperationType::Encrypt, ObjectOperationType::Decrypt])
    );

    //find the permission for the object O1
    let permissions = permissions_db
        .list_object_permissions(&findex_key, "O1")
        .await?;
    assert_eq!(permissions.len(), 1);
    assert!(permissions.contains_key("U1"));
    assert_eq!(
        permissions.get("U1").unwrap(),
        &HashSet::from([ObjectOperationType::Encrypt, ObjectOperationType::Decrypt])
    );

    // the situation now is that we have
    // O1 -> U1 -> Encrypt, Decrypt

    // let us add the permission Encrypt on object O1 for user U2
    permissions_db
        .add(&findex_key, "O1", "U2", ObjectOperationType::Encrypt)
        .await?;
    // assert the permission is present
    let permissions = permissions_db.get(&findex_key, "O1", "U2").await?;
    assert_eq!(permissions.len(), 1);
    assert!(permissions.contains(&ObjectOperationType::Encrypt));

    // find the permissions for user U2
    let permissions = permissions_db
        .list_user_permissions(&findex_key, "U2")
        .await?;
    assert_eq!(permissions.len(), 1);
    assert!(permissions.contains_key("O1"));
    assert_eq!(
        permissions.get("O1").unwrap(),
        &HashSet::from([ObjectOperationType::Encrypt])
    );

    //find the permission for the object O1
    let permissions = permissions_db
        .list_object_permissions(&findex_key, "O1")
        .await?;
    assert_eq!(permissions.len(), 2);
    assert!(permissions.contains_key("U1"));
    assert_eq!(
        permissions.get("U1").unwrap(),
        &HashSet::from([ObjectOperationType::Encrypt, ObjectOperationType::Decrypt])
    );
    assert!(permissions.contains_key("U2"));
    assert_eq!(
        permissions.get("U2").unwrap(),
        &HashSet::from([ObjectOperationType::Encrypt])
    );

    // the situation now is that we have
    // O1 -> U1 -> Encrypt, Decrypt
    // O1 -> U2 -> Encrypt

    // let us add the permission Encrypt on object O2 for user U2
    permissions_db
        .add(&findex_key, "O2", "U2", ObjectOperationType::Encrypt)
        .await?;
    // assert the permission is present
    let permissions = permissions_db.get(&findex_key, "O2", "U2").await?;
    assert_eq!(permissions.len(), 1);
    assert!(permissions.contains(&ObjectOperationType::Encrypt));

    // find the permissions for user U2
    let permissions = permissions_db
        .list_user_permissions(&findex_key, "U2")
        .await?;
    assert_eq!(permissions.len(), 2);
    assert!(permissions.contains_key("O1"));
    assert_eq!(
        permissions.get("O1").unwrap(),
        &HashSet::from([ObjectOperationType::Encrypt])
    );
    assert!(permissions.contains_key("O2"));
    assert_eq!(
        permissions.get("O2").unwrap(),
        &HashSet::from([ObjectOperationType::Encrypt])
    );

    //find the permission for the object O2
    let permissions = permissions_db
        .list_object_permissions(&findex_key, "O2")
        .await?;
    assert_eq!(permissions.len(), 1);
    assert!(permissions.contains_key("U2"));
    assert_eq!(
        permissions.get("U2").unwrap(),
        &HashSet::from([ObjectOperationType::Encrypt])
    );

    // the situation now is that we have
    // O1 -> U1 -> Encrypt, Decrypt
    // O1 -> U2 -> Encrypt
    // O2 -> U2 -> Encrypt

    // let us remove the permission Decrypt on object O1 for user U1
    permissions_db
        .remove(&findex_key, "O1", "U1", ObjectOperationType::Decrypt)
        .await?;
    // assert the permission Encrypt is present and Decrypt is not
    let permissions = permissions_db.get(&findex_key, "O1", "U1").await?;
    assert_eq!(permissions.len(), 1);
    assert!(permissions.contains(&ObjectOperationType::Encrypt));

    // find the permissions for user U1
    let permissions = permissions_db
        .list_user_permissions(&findex_key, "U1")
        .await?;
    assert_eq!(permissions.len(), 1);
    assert!(permissions.contains_key("O1"));
    assert_eq!(
        permissions.get("O1").unwrap(),
        &HashSet::from([ObjectOperationType::Encrypt])
    );

    //find the permission for the object O1
    let permissions = permissions_db
        .list_object_permissions(&findex_key, "O1")
        .await?;
    assert_eq!(permissions.len(), 2);
    assert!(permissions.contains_key("U1"));
    assert_eq!(
        permissions.get("U1").unwrap(),
        &HashSet::from([ObjectOperationType::Encrypt])
    );
    assert!(permissions.contains_key("U2"));
    assert_eq!(
        permissions.get("U2").unwrap(),
        &HashSet::from([ObjectOperationType::Encrypt])
    );

    // let us remove the permission Encrypt on object O1 for user U1
    permissions_db
        .remove(&findex_key, "O1", "U1", ObjectOperationType::Encrypt)
        .await?;
    // assert the permission is not present
    let permissions = permissions_db.get(&findex_key, "O1", "U1").await?;
    assert_eq!(permissions.len(), 0);

    // find the permissions for user U1
    let permissions = permissions_db
        .list_user_permissions(&findex_key, "U1")
        .await?;
    assert_eq!(permissions.len(), 0);

    //find the permission for the object O1
    let permissions = permissions_db
        .list_object_permissions(&findex_key, "O1")
        .await?;
    assert_eq!(permissions.len(), 1);
    assert!(permissions.contains_key("U2"));
    assert_eq!(
        permissions.get("U2").unwrap(),
        &HashSet::from([ObjectOperationType::Encrypt])
    );

    // let us remove the permission Encrypt on object O1 for user U2
    permissions_db
        .remove(&findex_key, "O1", "U2", ObjectOperationType::Encrypt)
        .await?;
    // assert the permission is not present
    let permissions = permissions_db.get(&findex_key, "O1", "U2").await?;
    assert_eq!(permissions.len(), 0);

    // find the permissions for user U2
    let permissions = permissions_db
        .list_user_permissions(&findex_key, "U2")
        .await?;
    assert_eq!(permissions.len(), 1);
    assert!(permissions.contains_key("O2"));
    assert_eq!(
        permissions.get("O2").unwrap(),
        &HashSet::from([ObjectOperationType::Encrypt])
    );

    //find the permission for the object O1
    let permissions = permissions_db
        .list_object_permissions(&findex_key, "O1")
        .await?;
    assert_eq!(permissions.len(), 0);

    Ok(())
}

pub async fn test_corner_case() -> KResult<()> {
    // generate the findex key
    let mut rng = CsRng::from_entropy();
    let findex_key = SymmetricKey::new(&mut rng);

    // the findex label
    let label = b"label";

    let client = redis::Client::open(get_redis_url())?;
    let mut mgr = ConnectionManager::new(client).await?;
    // clear the DB
    clear_all(&mut mgr).await?;
    // create the findex
    let findex =
        Arc::new(FindexRedis::connect_with_manager(mgr.clone(), Arc::new(DummyDB {})).await?);
    let permissions_db = PermissionsDB::new(findex, label).await?;

    // remove a permission that does not exist
    permissions_db
        .remove(&findex_key, "O1", "U1", ObjectOperationType::Encrypt)
        .await?;

    // test that it does not exist
    let permissions = permissions_db.get(&findex_key, "O1", "U1").await?;
    assert_eq!(permissions.len(), 0);

    // test there are no permissions for user U1
    let permissions = permissions_db
        .list_user_permissions(&findex_key, "U1")
        .await?;
    assert_eq!(permissions.len(), 0);

    // test there are no permissions for object O1
    let permissions = permissions_db
        .list_object_permissions(&findex_key, "O1")
        .await?;
    assert_eq!(permissions.len(), 0);

    //add the permission Encrypt on object O1 for user U1
    permissions_db
        .add(&findex_key, "O1", "U1", ObjectOperationType::Encrypt)
        .await?;

    // test there is one permission for user U1
    let permissions = permissions_db
        .list_user_permissions(&findex_key, "U1")
        .await?;
    assert_eq!(permissions.len(), 1);
    assert!(permissions.contains_key("O1"));
    assert_eq!(
        permissions.get("O1").unwrap(),
        &HashSet::from([ObjectOperationType::Encrypt])
    );

    // test there is one permission for object O1
    let permissions = permissions_db
        .list_object_permissions(&findex_key, "O1")
        .await?;
    assert_eq!(permissions.len(), 1);
    assert!(permissions.contains_key("U1"));
    assert_eq!(
        permissions.get("U1").unwrap(),
        &HashSet::from([ObjectOperationType::Encrypt])
    );

    // remove the permission again
    permissions_db
        .remove(&findex_key, "O1", "U1", ObjectOperationType::Encrypt)
        .await?;

    // test there are no permissions for user U1
    let permissions = permissions_db
        .list_user_permissions(&findex_key, "U1")
        .await?;
    assert_eq!(permissions.len(), 0);

    // test there are no permissions for object O1
    let permissions = permissions_db
        .list_object_permissions(&findex_key, "O1")
        .await?;
    assert_eq!(permissions.len(), 0);

    Ok(())
}
