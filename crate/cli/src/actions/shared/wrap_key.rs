use std::path::PathBuf;

use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use cosmian_kms_client::{
    cosmian_kmip::{
        crypto::{
            password_derivation::derive_key_from_password,
            symmetric::create_symmetric_key_kmip_object, wrap::wrap_key_block,
        },
        kmip::{
            kmip_data_structures::KeyWrappingSpecification, kmip_types::CryptographicAlgorithm,
        },
    },
    export_object, read_object_from_json_ttlv_file, write_kmip_object_to_file, ExportObjectParams,
    KmsClient,
};

use crate::{
    actions::{console, shared::SYMMETRIC_WRAPPING_KEY_SIZE},
    cli_bail,
    error::result::{CliResult, CliResultHelper},
};

/// Locally wrap a key in KMIP JSON TTLV format.
///
/// The key can be wrapped using either:
///  - a password derived into a symmetric key using Argon2
///  - symmetric key bytes in base64
///  - a key in the KMS (which will be exported first)
///  - a key in a KMIP JSON TTLV file
///
/// For the latter 2 cases, the key may be a symmetric key,
/// and RFC 5649 will be used, or a curve 25519 public key
/// and ECIES will be used.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct WrapKeyAction {
    /// The KMIP JSON TTLV input key file to wrap
    #[clap(required = true)]
    key_file_in: PathBuf,

    /// The KMIP JSON output file. When not specified the input file is overwritten.
    #[clap(required = false)]
    key_file_out: Option<PathBuf>,

    /// A password to wrap the imported key.
    /// This password will be derived into a AES-256 symmetric key. For security reasons, a fresh salt is internally handled and generated by `ckms` and this final AES symmetric key will be displayed only once.
    #[clap(long = "wrap-password", short = 'p', required = false, group = "wrap")]
    wrap_password: Option<String>,

    /// A symmetric key as a base 64 string to wrap the imported key.
    #[clap(long = "wrap-key-b64", short = 'k', required = false, group = "wrap")]
    wrap_key_b64: Option<String>,

    /// The id of a wrapping key in the KMS that will be exported and used to wrap the key.
    #[clap(long = "wrap-key-id", short = 'i', required = false, group = "wrap")]
    wrap_key_id: Option<String>,

    /// A wrapping key in a KMIP JSON TTLV file used to wrap the key.
    #[clap(long = "wrap-key-file", short = 'f', required = false, group = "wrap")]
    wrap_key_file: Option<PathBuf>,
}

impl WrapKeyAction {
    /// Run the wrap key action.
    ///
    /// # Errors
    ///
    /// This function can return an error if:
    ///
    /// - The key file cannot be read.
    /// - The key is already wrapped and cannot be wrapped again.
    /// - The wrap key cannot be decoded from base64.
    /// - The wrap password cannot be derived into a symmetric key.
    /// - The wrap key cannot be exported from the KMS.
    /// - The wrap key file cannot be read.
    /// - The key block cannot be wrapped with the wrapping key.
    /// - The wrapped key object cannot be written to the output file.
    /// - The console output cannot be written.
    #[allow(clippy::print_stdout)]
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        // read the key file
        let mut object = read_object_from_json_ttlv_file(&self.key_file_in)?;

        // cannot wrap an already wrapped key
        if object.key_wrapping_data().is_some() {
            cli_bail!("cannot wrap an already wrapped key");
        }

        // cache the object type
        let object_type = object.object_type();

        // if the key must be wrapped, prepare the wrapping key
        let wrapping_key = if let Some(b64) = &self.wrap_key_b64 {
            let key_bytes = general_purpose::STANDARD
                .decode(b64)
                .with_context(|| "failed decoding the wrap key")?;
            create_symmetric_key_kmip_object(&key_bytes, CryptographicAlgorithm::AES)?
        } else if let Some(password) = &self.wrap_password {
            let key_bytes = derive_key_from_password::<SYMMETRIC_WRAPPING_KEY_SIZE>(
                &[0_u8; 16],
                password.as_bytes(),
            )?;

            let symmetric_key_object =
                create_symmetric_key_kmip_object(key_bytes.as_ref(), CryptographicAlgorithm::AES)?;

            // Print the wrapping key for user.
            println!(
                "Wrapping key: {}. This is the only time that this wrapping key will be printed.",
                general_purpose::STANDARD.encode(&*key_bytes)
            );
            symmetric_key_object
        } else if let Some(key_id) = &self.wrap_key_id {
            export_object(kms_rest_client, key_id, ExportObjectParams::default())
                .await?
                .1
        } else if let Some(key_file) = &self.wrap_key_file {
            read_object_from_json_ttlv_file(key_file)?
        } else {
            cli_bail!("one of the wrapping options must be specified");
        };

        wrap_key_block(
            object.key_block_mut()?,
            &wrapping_key,
            &KeyWrappingSpecification::default(),
        )?;

        // set the output file path to the input file path if not specified
        let output_file = self
            .key_file_out
            .as_ref()
            .unwrap_or(&self.key_file_in)
            .clone();

        write_kmip_object_to_file(&object, &output_file)?;

        let stdout = format!(
            "The key of type {:?} in file {:?} was wrapped in file: {:?}",
            object_type, self.key_file_in, &output_file
        );
        console::Stdout::new(&stdout).write()?;

        Ok(())
    }
}
