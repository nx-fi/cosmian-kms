use clap::StructOpt;
use cosmian_kms_client::KmipRestClient;

use super::{
    decrypt::DecryptAction,
    encrypt::EncryptAction,
    keys::{
        DestroyUserKeyAction, NewMasterKeyPairAction, NewUserKeyAction, RevokeUserKeyAction,
        RotateAttributeAction,
    },
};

/// Uses Attribute-Based encryption.
#[derive(StructOpt, Debug)]
pub enum AbeAction {
    Init(NewMasterKeyPairAction),
    Rotate(RotateAttributeAction),

    New(NewUserKeyAction),
    Revoke(RevokeUserKeyAction),
    Destroy(DestroyUserKeyAction),

    Encrypt(EncryptAction),
    Decrypt(DecryptAction),
}

impl AbeAction {
    pub async fn process(&self, client_connector: &KmipRestClient) -> eyre::Result<()> {
        match self {
            AbeAction::Init(action) => action.run(client_connector).await?,
            AbeAction::Rotate(action) => action.run(client_connector).await?,
            AbeAction::New(action) => action.run(client_connector).await?,
            // For the time being, Revoke an user decryption key is not possible. We dismiss the action in the cli.
            // Uncomment the followings to activate that command.
            AbeAction::Revoke(_) => eyre::bail!("Revokation is not supported yet"), // action.run(client_connector).await?,
            AbeAction::Destroy(action) => action.run(client_connector).await?,
            AbeAction::Encrypt(action) => action.run(client_connector).await?,
            AbeAction::Decrypt(action) => action.run(client_connector).await?,
        };

        Ok(())
    }
}
