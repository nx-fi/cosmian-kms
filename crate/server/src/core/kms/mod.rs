mod kmip;
mod others;
mod permissions;

use std::collections::HashMap;

use cosmian_kms_plugins::EncryptionOracle;
use cosmian_kms_server_database::Database;
use futures::lock::Mutex;

use crate::{config::ServerParams, error::KmsError, result::KResult};

/// A Simple Key Management System that partially implements KMIP 2.1:
/// `https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=kmip`
pub struct KMS {
    pub(crate) params: ServerParams,
    /// The database is made of two parts:
    /// - The objects' store that stores the cryptographic objects.
    ///    The Object store may be backed by multiple databases or HSMs
    ///    and store the cryptographic objects and their attributes.
    ///    Objects are spread across the underlying stores based on their ID prefix.
    /// - The permissions store that stores the permissions granted to users on the objects.
    pub(crate) database: Database,

    /// Encryption Oracles are used to encrypt/decrypt data using keys with specific prefixes.
    /// A typical use case is delegating encryption/decryption to an HSM.
    /// This is a map of key prefixes to encryption oracles.
    pub(crate) encryption_oracles: Mutex<HashMap<String, Box<dyn EncryptionOracle + Sync + Send>>>,
}

/// Implement the KMIP Server operations and dispatches the actual actions
/// to the implementation module or ciphers for encryption/decryption
impl KMS {}

impl KMS {
    pub(crate) async fn instantiate(server_params: ServerParams) -> KResult<Self> {
        let database = Database::instantiate(
            server_params.db_params.as_ref().ok_or_else(|| {
                KmsError::InvalidRequest("The database parameters are not specified".to_owned())
            })?,
            server_params.clear_db_on_start,
        )
        .await?;

        Ok(Self {
            params: server_params,
            database,
            encryption_oracles: Mutex::new(HashMap::new()),
        })
    }
}
