use std::collections::HashSet;

use cloudproof::reexport::crypto_core::{
    reexport::rand_core::{RngCore, SeedableRng},
    CsRng,
};
use cosmian_kmip::{
    crypto::symmetric::create_symmetric_key_kmip_object,
    kmip::kmip_types::{CryptographicAlgorithm, StateEnumeration},
};
use uuid::Uuid;

use crate::{
    core::extra_database_params::ExtraDatabaseParams,
    database::{ObjectsDatabase, PermissionsDatabase},
    result::KResult,
};

pub(crate) async fn list_uids_for_tags_test<DB: ObjectsDatabase + PermissionsDatabase>(
    db_and_params: &(DB, Option<ExtraDatabaseParams>),
) -> KResult<()> {
    cosmian_logger::log_utils::log_init(None);
    let db = &db_and_params.0;
    let db_params = db_and_params.1.as_ref();

    let mut rng = CsRng::from_entropy();
    let owner = Uuid::new_v4().to_string();

    // Create a first symmetric key with tag "tag1"
    let mut symmetric_key_bytes = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key_bytes);
    let symmetric_key =
        create_symmetric_key_kmip_object(&symmetric_key_bytes, CryptographicAlgorithm::AES)?;

    let uid1 = Uuid::new_v4().to_string();

    db.upsert(
        &uid1,
        owner.as_str(),
        &symmetric_key,
        symmetric_key.attributes()?,
        Some(&HashSet::from(["tag1".to_owned()])),
        StateEnumeration::Active,
        db_params,
    )
    .await?;

    // Create a first symmetric key with tag "tag1" and tag "tag2"
    let mut symmetric_key_bytes = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key_bytes);
    let symmetric_key =
        create_symmetric_key_kmip_object(&symmetric_key_bytes, CryptographicAlgorithm::AES)?;

    let uid2 = Uuid::new_v4().to_string();

    db.upsert(
        &uid2,
        owner.as_str(),
        &symmetric_key,
        symmetric_key.attributes()?,
        Some(&HashSet::from(["tag1".to_owned(), "tag2".to_owned()])),
        StateEnumeration::Active,
        db_params,
    )
    .await?;

    // List yids for tag "tag1"
    let uids = db
        .list_uids_for_tags(
            &HashSet::from(["tag1".to_owned(), "_kk".to_owned()]),
            db_params,
        )
        .await?;
    assert_eq!(uids.len(), 1);
    assert!(uids.contains(&uid1));

    Ok(())
}
