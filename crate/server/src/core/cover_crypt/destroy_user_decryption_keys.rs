use std::collections::HashSet;

use cosmian_kmip::kmip::kmip_types::UniqueIdentifier;
use cosmian_kms_server_database::ExtraStoreParams;

use super::locate_user_decryption_keys;
use crate::{
    core::{operations::recursively_destroy_key, KMS},
    result::KResult,
};

/// Revoke all the user decryption keys associated with the master private key
pub(crate) async fn destroy_user_decryption_keys(
    master_private_key_id: &str,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraStoreParams>,
    // keys that should be skipped
    ids_to_skip: HashSet<String>,
) -> KResult<()> {
    if let Some(ids) =
        locate_user_decryption_keys(kms, master_private_key_id, None, None, owner, params).await?
    {
        for id in ids.into_iter().filter(|id| !ids_to_skip.contains(id)) {
            recursively_destroy_key(
                &UniqueIdentifier::TextString(id),
                kms,
                owner,
                params,
                ids_to_skip.clone(),
            )
            .await?;
        }
    }
    Ok(())
}
