use clap::Parser;
use cosmian_kms_client::reexport::cosmian_kms_config::KmsClientConfig;

use super::IDENTITIES_ENDPOINT;
use crate::{actions::google::gmail_client::GmailClient, error::result::CliResult};

/// Lists the client-side encrypted identities for an authenticated user.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct ListIdentitiesAction {
    /// The requester's primary email address.
    #[clap(required = true)]
    user_id: String,
}

impl ListIdentitiesAction {
    pub async fn run(&self, conf: &KmsClientConfig) -> CliResult<()> {
        let gmail_client = GmailClient::new(conf, &self.user_id);
        let response = gmail_client.await?.get(IDENTITIES_ENDPOINT).await?;
        GmailClient::handle_response(response).await
    }
}
