use clap::Parser;
use cosmian_kms_client::KmsRestClient;

use crate::{actions::shared::utils::revoke, error::CliError};

/// Revoke a symmetric key.
///
/// When a key is revoked, it can only be exported by the owner of the key,
/// using the --allow-revoked flag on the export function.
#[derive(Parser, Debug)]
pub struct RevokeKeyAction {
    /// The unique identifier of the key to revoke
    #[clap(required = true)]
    key_id: String,

    /// The reason for the revocation as a string
    #[clap(required = true)]
    revocation_reason: String,
}

impl RevokeKeyAction {
    pub async fn run(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        revoke(client_connector, &self.key_id, &self.revocation_reason).await
    }
}
