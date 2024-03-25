use clap::Parser;
use cosmian_kms_client::KmsClient;

use crate::{actions::shared::utils::destroy, cli_bail, error::CliError};

/// Destroy a public or private key.
///
/// The key must have been revoked first.
///
/// When a key is destroyed, it can only be exported by the owner of the key,
/// and without its key material
///
/// Destroying a public or private key will destroy the whole key pair
/// when the two keys are stored in the KMS.
#[derive(Parser, Debug)]
pub struct DestroyKeyAction {
    /// The key unique identifier of the key to destroy
    /// If not specified, tags should be specified
    #[clap(long = "key-id", short = 'k', group = "key-tags")]
    key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    tags: Option<Vec<String>>,
}

impl DestroyKeyAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> Result<(), CliError> {
        let id = if let Some(key_id) = &self.key_id {
            key_id.clone()
        } else if let Some(tags) = &self.tags {
            serde_json::to_string(&tags)?
        } else {
            cli_bail!("Either --key-id or one or more --tag must be specified")
        };

        destroy(kms_rest_client, &id).await
    }
}
