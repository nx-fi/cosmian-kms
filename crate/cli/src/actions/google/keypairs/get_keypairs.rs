use std::path::PathBuf;

use clap::Parser;

use crate::{
    error::{CliError}, actions::google::{gmail_client::{GmailClient, RequestError}, GoogleApiError},
};

/// Retrieves an existing client-side encryption key pair.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct GetKeypairsAction {
    /// The identifier of the key pair to retrieve
    #[clap(required = true)]
    keypairs_id: String,

    /// The requester's primary email address
    #[clap(
        long = "user-id",
        short = 'u',
        required = true
    )]
    user_id: String
}

impl GetKeypairsAction {
    pub async fn run(&self, conf_path: &PathBuf) -> Result<(), CliError> {
        let gmail_client = GmailClient::new(conf_path, &self.user_id);
        let endpoint =  "/settings/cse/keypairs/".to_owned() + &self.keypairs_id;
        let response = gmail_client.await?.get(&endpoint).await?;
        let status_code = response.status();
        if status_code.is_success() {
            println!("{}", response.text().await.unwrap());
            Ok(())
        }
        else {
            let json_body = response.json::<RequestError>().await.map_err(GoogleApiError::ReqwestError)?;
            Err(CliError::GmailApiError(json_body.error.message.to_string()))
        }
    }
}
