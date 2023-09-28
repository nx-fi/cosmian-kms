use crate::{
    error::CliError,
    tests::{symmetric::create_key::create_symmetric_key, utils::start_test_server_with_options},
};

#[tokio::test]
pub async fn test_create_symmetric_key_with_jwe() -> Result<(), CliError> {
    // init the test server
    // since we are going to rewrite the conf, use a different port
    let ctx = start_test_server_with_options(19997, true, false, false, true, false).await;

    create_symmetric_key(&ctx.owner_cli_conf_path, None, None, None, &["test_jwe"])?;

    Ok(())
}