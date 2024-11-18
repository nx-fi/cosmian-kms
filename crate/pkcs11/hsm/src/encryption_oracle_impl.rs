use cosmian_kms_plugins::{
    CryptographicAlgorithm, EncryptionOracle, KeyMetadata, PluginError, PluginResult,
};

use crate::HSM;

struct HsmEncryptionOracle {
    hsm: Box<dyn HSM + Send + Sync>,
    hsm_admin: String,
}

impl HsmEncryptionOracle {
    pub fn new(hsm: Box<dyn HSM + Send + Sync>, hsm_admin: String) -> Self {
        HsmEncryptionOracle { hsm, hsm_admin }
    }
}

impl EncryptionOracle for HsmEncryptionOracle {
    fn encrypt(
        &self,
        key_id: &str,
        data: &[u8],
        cryptographic_algorithm: Option<CryptographicAlgorithm>,
        authenticated_encryption_additional_data: Option<Vec<u8>>,
    ) -> PluginResult<Vec<u8>> {
        let (slot_id, key_id) = parse_uid(key_id)?;
        self.hsm.encrypt(
            key_id,
            cryptographic_algorithm,
            authenticated_encryption_additional_data,
            data,
        )
    }

    fn decrypt(
        &self,
        key_id: &str,
        data: &[u8],
        cryptographic_algorithm: Option<CryptographicAlgorithm>,
        authenticated_encryption_additional_data: Option<Vec<u8>>,
    ) -> PluginResult<Vec<u8>> {
        todo!()
    }

    fn get_key_metadata(&self, key_id: &str) -> PluginResult<KeyMetadata> {
        todo!()
    }
}

/// Parse the `uid` into a `slot_id` and `key_id`
fn parse_uid(uid: &str) -> PluginResult<(usize, usize)> {
    let (slot_id, key_id) = uid
        .trim_start_matches("hsm::")
        .split_once("::")
        .ok_or_else(|| {
            PluginError::InvalidRequest(
                "An HSM create request must have a uid in the form of 'hsm::<slot_id>::<key_id>'"
                    .to_owned(),
            )
        })?;
    let slot_id = slot_id.parse::<usize>().map_err(|e| {
        PluginError::InvalidRequest(format!("The slot_id must be a valid unsigned integer: {e}"))
    })?;
    let key_id = key_id.parse::<usize>().map_err(|e| {
        PluginError::InvalidRequest(format!("The key_id must be a valid unsigned integer: {e}"))
    })?;
    Ok((slot_id, key_id))
}
