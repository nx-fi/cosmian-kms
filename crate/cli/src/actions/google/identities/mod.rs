use clap::Subcommand;
use cosmian_kms_client::reexport::cosmian_kms_config::KmsClientConfig;

use self::{
    delete_identities::DeleteIdentitiesAction, get_identities::GetIdentitiesAction,
    insert_identities::InsertIdentitiesAction, list_identities::ListIdentitiesAction,
    patch_identities::PatchIdentitiesAction,
};
use crate::error::result::CliResult;

mod delete_identities;
mod get_identities;
mod insert_identities;
mod list_identities;
mod patch_identities;

pub(crate) const IDENTITIES_ENDPOINT: &str = "/settings/cse/identities/";

/// Insert, get, list, patch and delete identities from Gmail API.
#[derive(Subcommand)]
pub enum IdentitiesCommands {
    Get(GetIdentitiesAction),
    List(ListIdentitiesAction),
    Insert(InsertIdentitiesAction),
    Delete(DeleteIdentitiesAction),
    Patch(PatchIdentitiesAction),
}

impl IdentitiesCommands {
    pub async fn process(&self, conf: &KmsClientConfig) -> CliResult<()> {
        match self {
            Self::Get(action) => action.run(conf).await,
            Self::List(action) => action.run(conf).await,
            Self::Insert(action) => action.run(conf).await,
            Self::Delete(action) => action.run(conf).await,
            Self::Patch(action) => action.run(conf).await,
        }
    }
}
