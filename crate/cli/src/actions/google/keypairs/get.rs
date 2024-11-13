use clap::Parser;
use cosmian_kms_client::reexport::cosmian_kms_config::KmsClientConfig;

use super::KEY_PAIRS_ENDPOINT;
use crate::{actions::google::gmail_client::GmailClient, error::result::CliResult};

/// Retrieves an existing client-side encryption key pair.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct GetKeyPairsAction {
    /// The identifier of the key pair to retrieve
    #[clap(required = true)]
    key_pairs_id: String,

    /// The requester's primary email address
    #[clap(long, short = 'u', required = true)]
    user_id: String,
}

impl GetKeyPairsAction {
    pub async fn run(&self, conf: &KmsClientConfig) -> CliResult<()> {
        let endpoint = [KEY_PAIRS_ENDPOINT, &self.key_pairs_id].concat();
        let gmail_client = GmailClient::new(conf, &self.user_id);
        let response = gmail_client.await?.get(&endpoint).await?;
        GmailClient::handle_response(response).await
    }
}
