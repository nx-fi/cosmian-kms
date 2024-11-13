use std::path::PathBuf;

use clap::{Parser, Subcommand};
use cosmian_kms_client::{reexport::cosmian_kms_config::KmsClientConfig, KmsClient};
use cosmian_logger::log_init;
use tracing::info;

#[cfg(not(feature = "fips"))]
use crate::actions::cover_crypt::CovercryptCommands;
use crate::{
    actions::{
        access::AccessAction, attributes::AttributesCommands, certificates::CertificatesCommands,
        elliptic_curves::EllipticCurveCommands, google::GoogleCommands, login::LoginAction,
        logout::LogoutAction, new_database::NewDatabaseAction, rsa::RsaCommands,
        shared::LocateObjectsAction, symmetric::SymmetricCommands, version::ServerVersionAction,
    },
    error::result::CliResult,
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
    Login(LoginAction),
    Logout(LogoutAction),

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
    #[command(subcommand)]
    Google(GoogleCommands),
}

/// Process the command line arguments
/// # Errors
/// - If the configuration file is not found or invalid
pub async fn kms_process(command: KmsActions, kms_rest_client: KmsClient) -> CliResult<()> {
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
        KmsActions::Google(action) => action.process(&kms_rest_client).await,
        KmsActions::Login(action) => action.process(&kms_rest_client.conf).await,
        KmsActions::Logout(action) => action.process(&kms_rest_client.conf),
    }
}

/// Main entry point for the CLI
/// # Errors
/// - If the configuration file is not found or invalid
#[allow(clippy::cognitive_complexity)]
pub async fn ckms_main() -> CliResult<()> {
    log_init(None);
    let opts = Cli::parse();

    let mut conf = KmsClientConfig::load(&KmsClientConfig::location(opts.conf)?)?;

    // Override configuration file with command line options
    if opts.url.is_some() {
        info!("Override URL from configuration file with: {:?}", opts.url);
        conf.http_config.server_url = opts.url.unwrap_or_default();
    }
    if opts.accept_invalid_certs.is_some() {
        info!(
            "Override accept_invalid_certs from configuration file with: {:?}",
            opts.accept_invalid_certs
        );
        conf.http_config.accept_invalid_certs = opts.accept_invalid_certs.unwrap_or_default();
    }
    if opts.json {
        info!(
            "Override json from configuration file with: {:?}",
            opts.json
        );
        conf.print_json = Some(opts.json);
    }

    // Instantiate the KMS client
    let kms_rest_client = KmsClient::new(conf)?;

    kms_process(opts.command, kms_rest_client).await?;

    Ok(())
}
