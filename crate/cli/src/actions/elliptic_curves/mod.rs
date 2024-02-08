#[cfg(not(feature = "fips"))]
mod decrypt;
#[cfg(not(feature = "fips"))]
mod encrypt;
mod keys;

use clap::Parser;
use cosmian_kms_client::KmsRestClient;

use self::keys::KeysCommands;
#[cfg(not(feature = "fips"))]
use self::{decrypt::DecryptAction, encrypt::EncryptAction};
use crate::error::CliError;

/// Manage elliptic curve keys. Encrypt and decrypt data using ECIES.
#[derive(Parser)]
pub enum EllipticCurveCommands {
    #[command(subcommand)]
    Keys(KeysCommands),
    #[cfg(not(feature = "fips"))]
    Encrypt(EncryptAction),
    #[cfg(not(feature = "fips"))]
    Decrypt(DecryptAction),
}

impl EllipticCurveCommands {
    pub async fn process(&self, kms_rest_client: &KmsRestClient) -> Result<(), CliError> {
        match self {
            Self::Keys(command) => command.process(kms_rest_client).await?,
            #[cfg(not(feature = "fips"))]
            Self::Encrypt(action) => action.run(kms_rest_client).await?,
            #[cfg(not(feature = "fips"))]
            Self::Decrypt(action) => action.run(kms_rest_client).await?,
        };
        Ok(())
    }
}
