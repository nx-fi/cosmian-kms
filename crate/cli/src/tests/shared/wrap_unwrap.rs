use std::{
    path::{Path, PathBuf},
    process::Command,
};

use assert_cmd::prelude::CommandCargoExt;
use base64::{engine::general_purpose, Engine as _};
use cloudproof::reexport::crypto_core::{
    reexport::rand_core::{RngCore, SeedableRng},
    CsRng,
};
use cosmian_kmip::kmip::kmip_types::{EncodingOption, WrappingMethod};
use tempfile::TempDir;

use crate::{
    actions::shared::utils::read_key_from_file,
    config::KMS_CLI_CONF_ENV,
    error::CliError,
    tests::{
        cover_crypt::master_key_pair::create_cc_master_key_pair,
        elliptic_curve::create_key_pair::create_ec_key_pair,
        shared::export::export,
        symmetric::create_key::create_symmetric_key,
        utils::{init_test_server, TestsContext, ONCE},
        PROG_NAME,
    },
};

#[allow(clippy::too_many_arguments)]
pub fn wrap(
    cli_conf_path: &str,
    sub_command: &str,
    key_file_in: &Path,
    key_file_out: Option<&PathBuf>,
    wrap_password: Option<String>,
    wrap_key_b64: Option<String>,
    wrap_key_id: Option<String>,
    wrap_key_file: Option<PathBuf>,
) -> Result<(), CliError> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    let mut args: Vec<String> = vec![
        "keys".to_owned(),
        "wrap".to_owned(),
        key_file_in.to_str().unwrap().to_owned(),
    ];

    if let Some(key_file_out) = key_file_out {
        args.push(key_file_out.to_str().unwrap().to_owned());
    }
    if let Some(wrap_password) = wrap_password {
        args.push("-p".to_owned());
        args.push(wrap_password);
    } else if let Some(wrap_key_b64) = wrap_key_b64 {
        args.push("-k".to_owned());
        args.push(wrap_key_b64);
    } else if let Some(wrap_key_id) = wrap_key_id {
        args.push("-i".to_owned());
        args.push(wrap_key_id);
    } else if let Some(wrap_key_file) = wrap_key_file {
        args.push("-f".to_owned());
        args.push(wrap_key_file.to_str().unwrap().to_owned());
    }
    cmd.arg(sub_command).args(args);
    let output = cmd.output()?;
    if output.status.success() {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[allow(clippy::too_many_arguments)]
pub fn unwrap(
    cli_conf_path: &str,
    sub_command: &str,
    key_file_in: &Path,
    key_file_out: Option<&PathBuf>,
    unwrap_password: Option<String>,
    unwrap_key_b64: Option<String>,
    unwrap_key_id: Option<String>,
    unwrap_key_file: Option<PathBuf>,
) -> Result<(), CliError> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    let mut args: Vec<String> = vec![
        "keys".to_owned(),
        "unwrap".to_owned(),
        key_file_in.to_str().unwrap().to_owned(),
    ];

    if let Some(key_file_out) = key_file_out {
        args.push(key_file_out.to_str().unwrap().to_owned());
    }
    if let Some(unwrap_password) = unwrap_password {
        args.push("-p".to_owned());
        args.push(unwrap_password);
    } else if let Some(unwrap_key_b64) = unwrap_key_b64 {
        args.push("-k".to_owned());
        args.push(unwrap_key_b64);
    } else if let Some(unwrap_key_id) = unwrap_key_id {
        args.push("-i".to_owned());
        args.push(unwrap_key_id);
    } else if let Some(unwrap_key_file) = unwrap_key_file {
        args.push("-f".to_owned());
        args.push(unwrap_key_file.to_str().unwrap().to_owned());
    }
    cmd.arg(sub_command).args(args);
    let output = cmd.output()?;
    if output.status.success() {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
pub async fn test_password_wrap_import() -> Result<(), CliError> {
    let ctx = ONCE.get_or_init(init_test_server).await;

    // CC
    let (private_key_id, _public_key_id) = create_cc_master_key_pair(
        &ctx.owner_cli_conf_path,
        "--policy-specifications",
        "test_data/policy_specifications.json",
        &[],
    )?;
    password_wrap_import_test(ctx, "cc", &private_key_id)?;

    // EC
    let (private_key_id, _public_key_id) = create_ec_key_pair(&ctx.owner_cli_conf_path, &[])?;
    password_wrap_import_test(ctx, "ec", &private_key_id)?;

    // syn
    let key_id = create_symmetric_key(&ctx.owner_cli_conf_path, None, None, None, &[])?;
    password_wrap_import_test(ctx, "sym", &key_id)?;

    Ok(())
}

pub fn password_wrap_import_test(
    ctx: &TestsContext,
    sub_command: &str,
    private_key_id: &str,
) -> Result<(), CliError> {
    let temp_dir = TempDir::new()?;

    // Export
    let key_file = temp_dir.path().join("master_private.key");
    export(
        &ctx.owner_cli_conf_path,
        sub_command,
        private_key_id,
        key_file.to_str().unwrap(),
        false,
        false,
        None,
        false,
    )?;

    let object = read_key_from_file(&key_file)?;
    let key_bytes = object.key_block()?.key_bytes()?;

    //wrap and unwrap using a password
    {
        wrap(
            &ctx.owner_cli_conf_path,
            sub_command,
            &key_file,
            None,
            Some("password".to_owned()),
            None,
            None,
            None,
        )?;
        let wrapped_object = read_key_from_file(&key_file)?;
        assert!(wrapped_object.key_wrapping_data().is_some());
        assert_eq!(
            wrapped_object.key_wrapping_data().unwrap().wrapping_method,
            WrappingMethod::Encrypt
        );
        assert_eq!(
            wrapped_object.key_wrapping_data().unwrap().encoding_option,
            Some(EncodingOption::NoEncoding)
        );
        assert_ne!(wrapped_object.key_block()?.key_bytes()?, key_bytes);
        unwrap(
            &ctx.owner_cli_conf_path,
            sub_command,
            &key_file,
            None,
            Some("password".to_owned()),
            None,
            None,
            None,
        )?;
        let unwrapped_object = read_key_from_file(&key_file)?;
        assert!(unwrapped_object.key_wrapping_data().is_none());
        assert_eq!(unwrapped_object.key_block()?.key_bytes()?, key_bytes);
    }

    //wrap and unwrap using a base64 key
    {
        let mut rng = CsRng::from_entropy();
        let mut key = vec![0u8; 32];
        rng.fill_bytes(&mut key);
        let key_b64 = general_purpose::STANDARD.encode(&key);
        wrap(
            &ctx.owner_cli_conf_path,
            sub_command,
            &key_file,
            None,
            None,
            Some(key_b64.clone()),
            None,
            None,
        )?;
        let wrapped_object = read_key_from_file(&key_file)?;
        assert!(wrapped_object.key_wrapping_data().is_some());
        assert_eq!(
            wrapped_object.key_wrapping_data().unwrap().wrapping_method,
            WrappingMethod::Encrypt
        );
        assert_eq!(
            wrapped_object.key_wrapping_data().unwrap().encoding_option,
            Some(EncodingOption::NoEncoding)
        );
        assert_ne!(wrapped_object.key_block()?.key_bytes()?, key_bytes);
        unwrap(
            &ctx.owner_cli_conf_path,
            sub_command,
            &key_file,
            None,
            None,
            Some(key_b64),
            None,
            None,
        )?;
        let unwrapped_object = read_key_from_file(&key_file)?;
        assert!(unwrapped_object.key_wrapping_data().is_none());
        assert_eq!(unwrapped_object.key_block()?.key_bytes()?, key_bytes);
    }

    // other wrap unwrap scenarios are covered by tests in utils/wrap_unwrap

    Ok(())
}
