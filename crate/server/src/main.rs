use cosmian_kms_server::{
    config::{init_config, Config},
    start_server,
};
use twelf::Layer;

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

    env_logger::init();

    let matches = clap::Command::new("kms_server")
        .args(&Config::clap_args())
        .get_matches();
    let conf = Config::with_layers(&[Layer::Env(Some("KMS_".to_string())), Layer::Clap(matches)])?;

    init_config(&conf).await?;

    start_server().await
}