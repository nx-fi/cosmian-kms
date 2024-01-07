use std::process;

use clap::{CommandFactory, Parser, Subcommand};
use cosmian_kms_cli::{
    actions::{
        access::AccessAction,
        certificates::CertificatesCommands,
        cover_crypt::CovercryptCommands,
        elliptic_curves::EllipticCurveCommands,
        login::LoginAction,
        logout::LogoutAction,
        markdown::MarkdownAction,
        new_database::NewDatabaseAction,
        rsa::RsaCommands,
        shared::{GetAttributesAction, LocateObjectsAction},
        symmetric::SymmetricCommands,
        version::ServerVersionAction,
    },
    config::CliConf,
    error::CliError,
};
use cosmian_logger::log_utils::log_init;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: CliCommands,
}

#[derive(Subcommand)]
enum CliCommands {
    #[command(subcommand)]
    AccessRights(AccessAction),
    #[command(subcommand)]
    Cc(CovercryptCommands),
    #[command(subcommand)]
    Certificates(CertificatesCommands),
    #[command(subcommand)]
    Ec(EllipticCurveCommands),
    GetAttributes(GetAttributesAction),
    Locate(LocateObjectsAction),
    NewDatabase(NewDatabaseAction),
    #[command(subcommand)]
    Rsa(RsaCommands),
    ServerVersion(ServerVersionAction),
    #[command(subcommand)]
    Sym(SymmetricCommands),
    Login(LoginAction),
    Logout(LogoutAction),
    #[clap(hide = true)]
    Markdown(MarkdownAction),
}

#[tokio::main]
async fn main() {
    if let Some(err) = main_().await.err() {
        eprintln!("ERROR: {err}");
        process::exit(1);
    }
}

async fn main_() -> Result<(), CliError> {
    log_init("");

    let opts = Cli::parse();
    let conf = CliConf::load()?;

    if let CliCommands::Markdown(action) = opts.command {
        let command = <Cli as CommandFactory>::command();
        action.process(&command).await?;
        return Ok(())
    }

    let kms_rest_client = conf.initialize_kms_client()?;

    match opts.command {
        CliCommands::Locate(action) => action.process(&kms_rest_client).await?,
        CliCommands::Cc(action) => action.process(&kms_rest_client).await?,
        CliCommands::Ec(action) => action.process(&kms_rest_client).await?,
        CliCommands::Rsa(action) => action.process(&kms_rest_client).await?,
        CliCommands::Sym(action) => action.process(&kms_rest_client).await?,
        CliCommands::AccessRights(action) => action.process(&kms_rest_client).await?,
        CliCommands::Certificates(action) => action.process(&kms_rest_client).await?,
        CliCommands::NewDatabase(action) => action.process(&kms_rest_client).await?,
        CliCommands::ServerVersion(action) => action.process(&kms_rest_client).await?,
        CliCommands::GetAttributes(action) => action.process(&kms_rest_client).await?,
        CliCommands::Login(action) => action.process().await?,
        CliCommands::Logout(action) => action.process().await?,
        _ => {
            println!("Error: unexpected command");
        }
    };

    Ok(())
}
