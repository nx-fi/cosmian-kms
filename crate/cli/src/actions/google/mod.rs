use std::path::PathBuf;

use clap::Parser;

use self::{identities::IdentitiesCommands, keypairs::KeypairsCommands};
use crate::error::result::CliResult;

mod gmail_client;
mod identities;
mod keypairs;
pub(crate) use gmail_client::GoogleApiError;

/// Manage google elements. Handle keypairs and identities from Gmail API.
#[derive(Parser)]
pub enum GoogleCommands {
    #[command(subcommand)]
    Keypairs(KeypairsCommands),
    #[command(subcommand)]
    Identities(IdentitiesCommands),
}

impl GoogleCommands {
    /// Process the Google command by delegating the execution to the appropriate subcommand.
    ///
    /// # Arguments
    ///
    /// * `conf_path` - The path to the configuration file.
    ///
    /// # Errors
    ///
    /// Returns a `CliResult` indicating the success or failure of the command.
    ///
    pub async fn process(&self, conf_path: &PathBuf) -> CliResult<()> {
        match self {
            Self::Keypairs(command) => command.process(conf_path).await?,
            Self::Identities(command) => command.process(conf_path).await?,
        };
        Ok(())
    }
}
