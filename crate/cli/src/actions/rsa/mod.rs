mod decrypt;
mod encrypt;
mod keys;

use clap::Parser;
use cosmian_kms_client::KmsRestClient;

use self::{decrypt::DecryptAction, encrypt::EncryptAction, keys::KeysCommands};
use crate::error::CliError;

/// Manage RSA keys.
#[derive(Parser)]
pub enum RsaCommands {
    #[command(subcommand)]
    Keys(KeysCommands),
    Encrypt(EncryptAction),
    Decrypt(DecryptAction),
}

impl RsaCommands {
    pub async fn process(&self, kms_rest_client: &KmsRestClient) -> Result<(), CliError> {
        match self {
            Self::Keys(command) => command.process(kms_rest_client).await?,
            Self::Encrypt(action) => action.run(kms_rest_client).await?,
            Self::Decrypt(action) => action.run(kms_rest_client).await?,
        };
        Ok(())
    }
}