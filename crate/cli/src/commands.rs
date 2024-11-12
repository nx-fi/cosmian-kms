use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand};
use cosmian_kms_client::{reexport::cosmian_kms_config::KmsClientConfig, KmsClient};
use cosmian_logger::log_init;
use tracing::{error, info};

#[cfg(not(feature = "fips"))]
use crate::actions::cover_crypt::CovercryptCommands;
use crate::{
    actions::{
        access::AccessAction, attributes::AttributesCommands, certificates::CertificatesCommands,
        elliptic_curves::EllipticCurveCommands, google::GoogleCommands, login::LoginAction,
        logout::LogoutAction, markdown::MarkdownAction, new_database::NewDatabaseAction,
        rsa::RsaCommands, shared::LocateObjectsAction, symmetric::SymmetricCommands,
        version::ServerVersionAction,
    },
    error::{result::CliResult, CliError},
};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: KmsActions,

    /// Configuration file location
    ///
    /// This is an alternative to the env variable `KMS_CLI_CONF`.
    /// Takes precedence over `KMS_CLI_CONF` env variable.
    #[arg(short, long)]
    conf: Option<PathBuf>,

    /// The URL of the KMS
    #[arg(long, action)]
    pub(crate) url: Option<String>,

    /// Allow to connect using a self-signed cert or untrusted cert chain
    ///
    /// `accept_invalid_certs` is useful if the CLI needs to connect to an HTTPS KMS server
    /// running an invalid or insecure SSL certificate
    #[arg(long)]
    pub(crate) accept_invalid_certs: Option<bool>,

    /// Output the JSON KMIP request and response.
    /// This is useful to understand JSON POST requests and responses
    /// required to programmatically call the KMS on the `/kmip/2_1` endpoint
    #[arg(long, default_value = "false")]
    pub(crate) json: bool,
}

#[derive(Subcommand)]
pub enum KmsActions {
    #[command(subcommand)]
    AccessRights(AccessAction),
    #[cfg(not(feature = "fips"))]
    #[command(subcommand)]
    Cc(CovercryptCommands),
    #[command(subcommand)]
    Certificates(CertificatesCommands),
    #[command(subcommand)]
    Ec(EllipticCurveCommands),
    #[command(subcommand)]
    Attributes(AttributesCommands),
    Locate(LocateObjectsAction),
    NewDatabase(NewDatabaseAction),
    #[command(subcommand)]
    Rsa(RsaCommands),
    ServerVersion(ServerVersionAction),
    #[command(subcommand)]
    Sym(SymmetricCommands),
    Login(LoginAction),
    Logout(LogoutAction),

    /// Action to auto-generate doc in Markdown format
    /// Run `cargo run --bin ckms -- markdown documentation/docs/cli/main_commands.md`
    #[clap(hide = true)]
    Markdown(MarkdownAction),

    #[command(subcommand)]
    Google(GoogleCommands),
}

/// Process the command line arguments
/// # Errors
/// - If the configuration file is not found or invalid
pub async fn kms_process(
    command: KmsActions,
    conf_path_arg: Option<PathBuf>,
    url: Option<String>,
    accept_invalid_certs: Option<bool>,
    json: bool,
) -> CliResult<()> {
    let conf_path = KmsClientConfig::location(conf_path_arg)?;
    match command {
        KmsActions::Login(action) => action.process(&conf_path).await,
        KmsActions::Logout(action) => action.process(&conf_path),

        command => {
            let mut conf = KmsClientConfig::load(&conf_path)?;
            if url.is_some() {
                info!("Override URL from configuration file with: {:?}", url);
                conf.http_config.server_url = url.unwrap_or_default();
            }
            if accept_invalid_certs.is_some() {
                info!(
                    "Override accept_invalid_certs from configuration file with: {:?}",
                    accept_invalid_certs
                );
                conf.http_config.accept_invalid_certs = accept_invalid_certs.unwrap_or_default();
            }
            if json {
                info!("Override json from configuration file with: {:?}", json);
                conf.print_json = Some(json);
            }
            let kms_rest_client = KmsClient::new(conf)?;

            match command {
                KmsActions::Locate(action) => action.process(&kms_rest_client).await,
                #[cfg(not(feature = "fips"))]
                KmsActions::Cc(action) => action.process(&kms_rest_client).await,
                KmsActions::Ec(action) => action.process(&kms_rest_client).await,
                KmsActions::Rsa(action) => action.process(&kms_rest_client).await,
                KmsActions::Sym(action) => action.process(&kms_rest_client).await,
                KmsActions::AccessRights(action) => action.process(&kms_rest_client).await,
                KmsActions::Certificates(action) => action.process(&kms_rest_client).await,
                KmsActions::NewDatabase(action) => action.process(&kms_rest_client).await,
                KmsActions::ServerVersion(action) => action.process(&kms_rest_client).await,
                KmsActions::Attributes(action) => action.process(&kms_rest_client).await,
                KmsActions::Google(action) => action.process(&conf_path, &kms_rest_client).await,
                _ => {
                    error!("unexpected command");
                    Err(CliError::Default("unexpected command".to_string()))
                }
            }
        }
    }
}
/// Main entry point for the CLI
/// # Errors
/// - If the configuration file is not found or invalid
pub async fn ckms_main() -> CliResult<()> {
    log_init(None);
    let opts = Cli::parse();

    if let KmsActions::Markdown(action) = opts.command {
        let command = <Cli as CommandFactory>::command();
        action.process(&command)?;
        return Ok(())
    }

    kms_process(
        opts.command,
        opts.conf,
        opts.url,
        opts.accept_invalid_certs,
        opts.json,
    )
    .await?;

    Ok(())
}
