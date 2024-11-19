mod kmip;
mod others;
mod permissions;

use std::collections::HashMap;

use cosmian_kms_plugins::EncryptionOracle;
use cosmian_kms_server_database::Database;
use futures::lock::Mutex;

use crate::{config::ServerParams, error::KmsError, kms_bail, result::KResult};

/// A Key Management System that partially implements KMIP 2.1:
/// `https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=kmip`
/// and other operations that are not part of KMIP such as Google CSE or Microsoft DKE.
pub struct KMS {
    /// The server parameters built from the configuration file or command line arguments.
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

impl KMS {
    /// Instantiate a new KMS instance with the given server parameters.
    /// # Arguments
    /// * `server_params` - The server parameters built from the configuration file or command line arguments.
    /// # Returns
    /// A new KMS instance.
    pub(crate) async fn instantiate(server_params: ServerParams) -> KResult<Self> {
        let database = Database::instantiate(
            server_params.db_params.as_ref().ok_or_else(|| {
                KmsError::InvalidRequest("The database parameters are not specified".to_owned())
            })?,
            server_params.clear_db_on_start,
        )
        .await?;

        // Encryption Oracles are used to encrypt/decrypt data using keys with specific prefixes.
        let encryption_oracles = if server_params.slot_passwords.is_empty() {
            HashMap::new()
        } else {
            if server_params
                .hsm_model
                .as_ref()
                .map(String::from)
                .unwrap_or_default()
                != "proteccio"
            {
                kms_bail!("The only supported HSM model is Proteccio for now")
            }
            #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
            kms_bail!("Fatal: Proteccio HSM is only supported on Linux x86_64");
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            {
                //TODO this will need to be de-hardcoded at some stage. Nothing prevents the underlying code
                // to be used with multiple HSMs or other encryption oracles
                let mut encryption_oracles = HashMap::new();
                encryption_oracles.insert(
                    "hsm".to_owned(),
                    Box::new(HsmStore::new(Box::new(Proteccio::instantiate(
                        server_params.slot_passwords.clone(),
                        server_params.hsm_admin.clone(),
                    )))),
                );
                encryption_oracles
            }
        };

        Ok(Self {
            params: server_params,
            database,
            encryption_oracles: Mutex::new(encryption_oracles),
        })
    }
}
