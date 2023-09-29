use std::process::Command;

use assert_cmd::prelude::*;

use crate::{
    actions::certificates::CertificateInputFormat,
    config::KMS_CLI_CONF_ENV,
    error::CliError,
    tests::{
        utils::{extract_uids::extract_imported_key_id, start_default_test_kms_server, ONCE},
        PROG_NAME,
    },
};

#[allow(clippy::too_many_arguments)]
pub fn import(
    cli_conf_path: &str,
    sub_command: &str,
    key_file: &str,
    format: CertificateInputFormat,
    key_id: Option<String>,
    tags: Option<&[&str]>,
    unwrap: bool,
    replace_existing: bool,
) -> Result<String, CliError> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    let mut args: Vec<String> = vec!["import".to_owned(), key_file.to_owned()];
    if let Some(key_id) = key_id {
        args.push(key_id);
    }
    if unwrap {
        args.push("-u".to_owned());
    }
    if replace_existing {
        args.push("-r".to_owned());
    }
    // Format arg
    args.push("-f".to_owned());
    match format {
        CertificateInputFormat::TTLV => args.push("ttlv".to_owned()),
        CertificateInputFormat::PEM => args.push("pem".to_owned()),
        CertificateInputFormat::CHAIN => args.push("chain".to_owned()),
        CertificateInputFormat::CCADB => args.push("ccadb".to_owned()),
        CertificateInputFormat::PKCS12 => {
            args.push("pkcs12".to_owned());
            args.push("--pkcs12-password".to_owned());
            args.push("secret".to_string());
        }
    };
    if let Some(tags) = tags {
        for tag in tags {
            args.push("--tag".to_owned());
            args.push((*tag).to_string());
        }
    }

    cmd.arg(sub_command).args(args);
    let output = cmd.output()?;
    println!("output: {output:?}");
    if output.status.success() {
        let import_output = std::str::from_utf8(&output.stdout)?;
        let imported_key_id = extract_imported_key_id(import_output)
            .ok_or_else(|| CliError::Default("failed extracting the imported key id".to_owned()))?
            .to_owned();
        return Ok(imported_key_id)
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
pub async fn test_certificate_import_different_format() -> Result<(), CliError> {
    // Create a test server
    let ctx = ONCE.get_or_init(start_default_test_kms_server).await;

    // import as TTLV JSON
    import(
        &ctx.owner_cli_conf_path,
        "certificates",
        "test_data/certificates/exported_certificate_ttlv.json",
        CertificateInputFormat::TTLV,
        None,
        None,
        false,
        false,
    )?;

    // import as PEM
    import(
        &ctx.owner_cli_conf_path,
        "certificates",
        "test_data/certificates/ca.crt",
        CertificateInputFormat::PEM,
        None,
        Some(&["import_cert"]),
        false,
        false,
    )?;

    // import a chain
    import(
        &ctx.owner_cli_conf_path,
        "certificates",
        "test_data/certificates/mozilla_IncludedRootsPEM.txt",
        CertificateInputFormat::CHAIN,
        None,
        Some(&["import_chain"]),
        false,
        false,
    )?;

    // import a PKCS12
    import(
        &ctx.owner_cli_conf_path,
        "certificates",
        "test_data/certificates/kms/output.p12",
        CertificateInputFormat::PKCS12,
        None,
        Some(&["import_pkcs12"]),
        false,
        false,
    )?;

    Ok(())
}
