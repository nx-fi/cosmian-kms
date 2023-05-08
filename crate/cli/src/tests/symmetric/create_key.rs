use std::process::Command;

use assert_cmd::prelude::*;
use base64::{engine::general_purpose, Engine as _};
use cloudproof::reexport::crypto_core::{
    reexport::rand_core::{RngCore, SeedableRng},
    CsRng,
};

use super::SUB_COMMAND;
use crate::{
    config::KMS_CLI_CONF_ENV,
    error::CliError,
    tests::{
        test_utils::{init_test_server, ONCE},
        utils::extract_uids::extract_uid,
        CONF_PATH, PROG_NAME,
    },
};

pub async fn create_symmetric_key(
    number_of_bits: Option<usize>,
    wrap_key_b64: Option<&str>,
    algorithm: Option<&str>,
) -> Result<String, CliError> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(SUB_COMMAND).args(vec!["keys", "create"]);
    if let Some(number_of_bits) = number_of_bits {
        cmd.args(vec!["--number-of-bits", &number_of_bits.to_string()]);
    }
    if let Some(wrap_key_b64) = wrap_key_b64 {
        cmd.args(vec!["--bytes-b64", wrap_key_b64]);
    }
    if let Some(algorithm) = algorithm {
        cmd.args(vec!["--algorithm", algorithm]);
    }
    let output = cmd.output()?;
    if output.status.success() {
        let output = std::str::from_utf8(&output.stdout)?;

        let unique_identifier = extract_uid(output, "The symmetric key was created with id")
            .ok_or_else(|| {
                CliError::Default("failed extracting the unique identifier".to_owned())
            })?;
        return Ok(unique_identifier.to_string())
    }

    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
pub async fn test_create_symmetric_key() -> Result<(), CliError> {
    ONCE.get_or_init(init_test_server).await;
    let mut rng = CsRng::from_entropy();
    let mut key = vec![0u8; 32];

    // AES
    {
        // AES 256 bit key
        create_symmetric_key(None, None, None).await?;
        // AES 128 bit key
        create_symmetric_key(Some(128), None, None).await?;
        //  AES 256 bit key from a base64 encoded key
        rng.fill_bytes(&mut key);
        let key_b64 = general_purpose::STANDARD.encode(&key);
        create_symmetric_key(None, Some(&key_b64), None).await?;
    }

    // AChaCha20
    {
        // ChaCha20 256 bit key
        create_symmetric_key(None, None, Some("chacha20")).await?;
        // ChaCha20 128 bit key
        create_symmetric_key(Some(128), None, Some("chacha20")).await?;
        //  ChaCha20 256 bit key from a base64 encoded key
        let mut rng = CsRng::from_entropy();
        let mut key = vec![0u8; 32];
        rng.fill_bytes(&mut key);
        let key_b64 = general_purpose::STANDARD.encode(&key);
        create_symmetric_key(None, Some(&key_b64), Some("chacha20")).await?;
    }

    // Sha3
    {
        // ChaCha20 256 bit salt
        create_symmetric_key(None, None, Some("sha3")).await?;
        // ChaCha20 salts
        create_symmetric_key(Some(224), None, Some("sha3")).await?;
        create_symmetric_key(Some(256), None, Some("sha3")).await?;
        create_symmetric_key(Some(384), None, Some("sha3")).await?;
        create_symmetric_key(Some(512), None, Some("sha3")).await?;
        //  ChaCha20 256 bit salt from a base64 encoded salt
        let mut rng = CsRng::from_entropy();
        let mut salt = vec![0u8; 32];
        rng.fill_bytes(&mut salt);
        let key_b64 = general_purpose::STANDARD.encode(&salt);
        create_symmetric_key(None, Some(&key_b64), Some("sha3")).await?;
    }
    Ok(())
}
