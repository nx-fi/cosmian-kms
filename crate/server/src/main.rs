use cosmian_kms_server::{
    config::{init_config, Config},
    start_kms_server,
};
use dotenvy::dotenv;
use tracing::info;
#[cfg(feature = "timeout")]
use tracing::warn;

#[cfg(feature = "timeout")]
mod expiry;

use clap::Parser;

#[actix_web::main]
async fn main() -> eyre::Result<()> {
    if option_env!("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    if option_env!("RUST_LOG").is_none() {
        std::env::set_var(
            "RUST_LOG",
            "debug, actix_web=debug,hyper=info,reqwest=info,sqlx::query=error,mysql=debug",
        );
    }

    // Load variable from a .env file
    dotenv().ok();

    env_logger::init();

    // Instanciate a config object using the env variables and the args of the binary
    let conf = Config::parse();
    init_config(&conf).await?;

    #[cfg(feature = "timeout")]
    {
        warn!("This is a demo version, the server will stop in 3 months");
        let demo = actix_rt::spawn(expiry::demo_timeout());
        futures::future::select(Box::pin(start_kms_server()), demo).await;
    }

    info!("Enabled features:");
    #[cfg(feature = "auth")]
    info!("- Auth");
    #[cfg(feature = "https")]
    info!("- Https");
    #[cfg(feature = "enclave")]
    info!("- Enclave");
    #[cfg(feature = "timeout")]
    info!("- Timeout");
    #[cfg(feature = "insecure")]
    info!("- Insecure");

    // Start the KMS
    start_kms_server().await?;

    Ok(())
}
