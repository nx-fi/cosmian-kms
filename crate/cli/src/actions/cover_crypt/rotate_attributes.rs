use clap::Parser;
use cloudproof::reexport::cover_crypt::abe_policy::Attribute;
use cosmian_kms_client::KmsRestClient;
use cosmian_kms_utils::crypto::cover_crypt::{
    attributes::EditPolicyAction, kmip_requests::build_rekey_keypair_request,
};

use crate::{
    cli_bail,
    error::{result::CliResultHelper, CliError},
};

/// Rotate attributes and rekey the master and user keys.
///
/// Data encrypted with the rotated attributes
/// cannot be decrypted by user decryption keys unless they have been re-keyed.
///
/// Active user decryption keys are automatically re-keyed.
/// Revoked or destroyed user decryption keys are not re-keyed.
///
/// User keys that have not been rekeyed can still decrypt data encrypted
/// with the old attribute values.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct RotateAttributesAction {
    /// The policy attributes to rotate.
    /// Example: `department::marketing level::confidential`
    #[clap(required = true)]
    attributes: Vec<String>,

    /// The private master key unique identifier stored in the KMS
    /// If not specified, tags should be specified
    #[clap(long = "key-id", short = 'k', group = "key-tags")]
    secret_key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    tags: Option<Vec<String>>,
}

impl RotateAttributesAction {
    pub async fn run(&self, kms_rest_client: &KmsRestClient) -> Result<(), CliError> {
        // Parse the attributes
        let ats = self
            .attributes
            .iter()
            .map(|s| Attribute::try_from(s.as_str()).map_err(Into::into))
            .collect::<Result<Vec<Attribute>, CliError>>()?;

        let id = if let Some(key_id) = &self.secret_key_id {
            key_id.clone()
        } else if let Some(tags) = &self.tags {
            serde_json::to_string(&tags)?
        } else {
            cli_bail!("Either --key-id or one or more --tag must be specified")
        };

        // Create the kmip query
        let rotate_query =
            build_rekey_keypair_request(&id, EditPolicyAction::RotateAttributes(ats))?;

        // Query the KMS with your kmip data
        let rotate_response = kms_rest_client
            .rekey_keypair(rotate_query)
            .await
            .with_context(|| "failed rotating the master keys")?;

        println!(
            "The master private key {} and master public key {} were rotated for attributes {:?}",
            &rotate_response.private_key_unique_identifier,
            &rotate_response.public_key_unique_identifier,
            &self.attributes
        );
        Ok(())
    }
}
