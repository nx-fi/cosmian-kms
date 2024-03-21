use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Output, Stdio},
    sync::mpsc,
    thread::{self, JoinHandle},
    time::Duration,
};

use actix_server::ServerHandle;
use assert_cmd::prelude::{CommandCargoExt, OutputAssertExt};
use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use cosmian_kms_client::cosmian_kmip::crypto::{secret::Secret, symmetric::AES_256_GCM_KEY_LENGTH};
use cosmian_kms_server::{
    config::{ClapConfig, DBConfig, HttpConfig, HttpParams, JwtAuthConfig, ServerParams},
    core::extra_database_params::ExtraDatabaseParams,
    kms_server::start_kms_server,
};
use tokio::sync::OnceCell;
use tracing::trace;

use super::extract_uids::extract_database_secret;
use crate::{
    actions::shared::utils::write_json_object_to_file,
    cli_bail,
    config::{CliConf, KMS_CLI_CONF_ENV},
    error::CliError,
    tests::PROG_NAME,
};

// Test auth0 Config
const AUTH0_JWT_ISSUER_URI: &str = "https://kms-cosmian.eu.auth0.com/";
const AUTH0_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjVVU1FrSVlULW9QMWZrcjQtNnRrciJ9.eyJuaWNrbmFtZSI6InRlY2giLCJuYW1lIjoidGVjaEBjb3NtaWFuLmNvbSIsInBpY3R1cmUiOiJodHRwczovL3MuZ3JhdmF0YXIuY29tL2F2YXRhci81MmZiMzFjOGNjYWQzNDU4MTIzZDRmYWQxNDA4NTRjZj9zPTQ4MCZyPXBnJmQ9aHR0cHMlM0ElMkYlMkZjZG4uYXV0aDAuY29tJTJGYXZhdGFycyUyRnRlLnBuZyIsInVwZGF0ZWRfYXQiOiIyMDIzLTA1LTMwVDA5OjMxOjExLjM4NloiLCJlbWFpbCI6InRlY2hAY29zbWlhbi5jb20iLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImlzcyI6Imh0dHBzOi8va21zLWNvc21pYW4uZXUuYXV0aDAuY29tLyIsImF1ZCI6IkszaXhldXhuVDVrM0Roa0tocWhiMXpYbjlFNjJGRXdJIiwiaWF0IjoxNjg1NDM5MDc0LCJleHAiOjE2ODU0NzUwNzQsInN1YiI6ImF1dGgwfDYzZDNkM2VhOTNmZjE2NDJjNzdkZjkyOCIsInNpZCI6ImJnVUNuTTNBRjVxMlpaVHFxMTZwclBCMi11Z0NNaUNPIiwibm9uY2UiOiJVRUZWTlZWeVluWTVUbHBwWjJScGNqSmtVMEZ4TmxkUFEwc3dTVGMwWHpaV2RVVmtkVnBEVGxSMldnPT0ifQ.HmU9fFwZ-JjJVlSy_PTei3ys0upeWQbWWiESmKBtRSClGnAXJNCpwuP4Jw7fgKn-8IBf-PYmP1_54u2Rw3RcJFVl7EblVoGMghYxVq5hViGpd00st3VwZmyCwOUz2CE5RBnBAoES4C8xA3zWg6oau0xjFQbC3jNU20eyFYMDewXA8UXCHQrEiQ56ylqSbyqlBbQIWbmOO4m5w2WDkx0bVyyJ893JfIJr_NANEQMJITYo8Mp_iHCyKp7llsfgCt07xN8ZqnsrMsJ15zC1n50bHGrTQisxURS1dpuFXF1hfrxhzogxYMX8CEISjsFgROjPY84GRMmvpYZfyaJbDDql3A";

pub fn get_auth0_jwt_config() -> JwtAuthConfig {
    JwtAuthConfig {
        jwt_issuer_uri: Some(AUTH0_JWT_ISSUER_URI.to_owned()),
        jwks_uri: None,
        jwt_audience: None,
    }
}

/// Recover output logs from a command call `cmd` and re-inject it into stdio
pub(crate) fn recover_cmd_logs(cmd: &mut Command) -> Output {
    let output = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    std::io::stdout()
        .write_all(format!("\r\x1b[K{}", String::from_utf8_lossy(&output.stdout)).as_bytes())
        .unwrap();
    std::io::stderr()
        .write_all(format!("\r\x1b[K{}", String::from_utf8_lossy(&output.stderr)).as_bytes())
        .unwrap();
    output
}

/// In order to run most tests in parallel,
/// we use that to avoid to try to start N KMS servers (one per test)
/// with a default configuration.
/// Otherwise we get: "Address already in use (os error 98)"
/// for N-1 tests.
pub static ONCE: OnceCell<TestsContext> = OnceCell::const_new();

pub struct TestsContext {
    pub owner_cli_conf_path: String,
    pub user_cli_conf_path: String,
    pub owner_cli_conf: CliConf,
    pub server_handle: ServerHandle,
    pub thread_handle: JoinHandle<Result<(), CliError>>,
}

impl TestsContext {
    pub async fn stop_server(self) {
        self.server_handle.stop(false).await;
        self.thread_handle.join().unwrap().unwrap();
        println!("Server stopped\n");
    }
}

/// Start a test KMS server in a thread with the default options:
/// JWT authentication and encrypted database, no TLS
pub async fn start_default_test_kms_server() -> TestsContext {
    start_test_server_with_options(9990, false, true, true).await
}

/// Start a KMS server in a thread with the given options
pub async fn start_test_server_with_options(
    port: u16,
    use_jwt_token: bool,
    use_https: bool,
    use_client_cert: bool,
) -> TestsContext {
    let server_params = generate_server_params(port, use_jwt_token, use_https, use_client_cert)
        .await
        .unwrap();

    // Create a (object owner) conf
    let (owner_cli_conf_path, mut owner_cli_conf) = generate_owner_conf(&server_params).unwrap();

    println!(
        "Starting KMS test server at URL: {} with server params {:?}",
        owner_cli_conf.kms_server_url, &server_params
    );

    let (server_handle, thread_handle) =
        start_test_kms_server(server_params).expect("Can't start KMS server");

    // wait for the server to be up
    wait_for_server_to_start(&owner_cli_conf_path)
        .await
        .expect("server timeout");

    // Configure a database and create the kms json file
    let database_secret =
        create_new_database(&owner_cli_conf_path).expect("failed configuring a database");

    // Rewrite the conf with the correct database secret
    owner_cli_conf.kms_database_secret = Some(database_secret);
    write_json_object_to_file(&owner_cli_conf, &owner_cli_conf_path)
        .expect("Can't write owner CLI conf path");

    // generate a user conf
    let user_cli_conf_path =
        generate_user_conf(port, &owner_cli_conf).expect("Can't generate user conf");

    TestsContext {
        owner_cli_conf_path,
        user_cli_conf_path,
        owner_cli_conf,
        server_handle,
        thread_handle,
    }
}

/// Start a test KMS server with the given config in a separate thread
fn start_test_kms_server(
    server_params: ServerParams,
) -> Result<(ServerHandle, JoinHandle<Result<(), CliError>>), CliError> {
    let (tx, rx) = mpsc::channel::<ServerHandle>();

    let thread_handle = thread::spawn(move || {
        // allow others `spawn` to happen within the KMS Server future
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(start_kms_server(server_params, Some(tx)))
            .map_err(|e| CliError::ServerError(e.to_string()))
    });
    trace!("Waiting for test KMS server to start...");
    let server_handle = rx
        .recv_timeout(Duration::from_secs(25))
        .expect("Can't get test KMS server handle after 25 seconds");
    trace!("... got handle ...");
    Ok((server_handle, thread_handle))
}

/// Create a new database and return the database secret
pub fn fetch_version(cli_conf_path: &str) -> Result<String, CliError> {
    // Configure a database and create the kms json file
    let mut cmd = Command::cargo_bin(PROG_NAME).expect("Can't execute the server-version command");
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.arg("server-version");

    let success = cmd.assert().success();
    let output = success.get_output();
    let version: &str = std::str::from_utf8(&output.stdout).expect("Can't recover command output");

    Ok(version.to_owned())
}

/// Wait for the server to start by reading the version
async fn wait_for_server_to_start(cli_conf_path: &str) -> Result<(), CliError> {
    // Depending on the running environment, the server could take a bit of time to start
    // We try to query it with a dummy request until be sure it is started.
    let mut retry = true;
    let mut timeout = 5;
    let mut waiting = 1;
    while retry {
        print!("...checking if the server is up...");
        let result = fetch_version(cli_conf_path);

        if result.is_err() {
            timeout -= 1;
            retry = timeout >= 0;
            if retry {
                println!("The server is not up yet, retrying in {waiting}s... ({result:?}) ",);
                thread::sleep(std::time::Duration::from_secs(waiting));
                waiting *= 2;
            } else {
                println!("The server is still not up, stop trying");
                cli_bail!("Can't start the kms server to run tests");
            }
        } else {
            println!("UP!");
            retry = false;
        }
    }
    Ok(())
}

/// Create a new database and return the database secret
pub fn create_new_database(cli_conf_path: &str) -> Result<String, CliError> {
    // Configure a database and create the kms json file
    let mut cmd = Command::cargo_bin(PROG_NAME).expect("Can't execute new database command");
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.arg("new-database");

    let success = cmd.assert().success();
    let output = success.get_output();
    let stdout: &str = std::str::from_utf8(&output.stdout).expect("Can't recover command output");

    // Get the secret
    let database_secret =
        extract_database_secret(stdout).expect("Can't extract database secret from cmd output");

    Ok(database_secret.to_owned())
}

async fn generate_server_params(
    port: u16,
    use_jwt_token: bool,
    use_https: bool,
    use_client_cert: bool,
) -> Result<ServerParams, CliError> {
    // Configure the serveur
    let clap_config = ClapConfig {
        auth: if use_jwt_token {
            get_auth0_jwt_config()
        } else {
            JwtAuthConfig::default()
        },
        db: DBConfig {
            database_type: Some("sqlite-enc".to_string()),
            clear_database: true,
            ..Default::default()
        },
        http: if use_https {
            if use_client_cert {
                HttpConfig {
                    port,
                    https_p12_file: Some(PathBuf::from(
                        "test_data/certificates/kmserver.acme.com.p12",
                    )),
                    https_p12_password: Some("password".to_string()),
                    authority_cert_file: Some(PathBuf::from("test_data/certificates/ca.crt")),
                    ..Default::default()
                }
            } else {
                HttpConfig {
                    port,
                    https_p12_file: Some(PathBuf::from(
                        "test_data/certificates/kmserver.acme.com.p12",
                    )),
                    https_p12_password: Some("password".to_string()),
                    ..Default::default()
                }
            }
        } else {
            HttpConfig {
                port,
                ..Default::default()
            }
        },
        ..Default::default()
    };
    ServerParams::try_from(&clap_config)
        .await
        .map_err(|e| CliError::Default(format!("failed initializing the server config: {e}")))
}

fn generate_owner_conf(server_params: &ServerParams) -> Result<(String, CliConf), CliError> {
    // Create a conf
    let owner_cli_conf_path = format!("/tmp/owner_kms_{}.json", server_params.port);

    // Generate a CLI Conf.
    // We will update it later by appending the database secret
    let owner_cli_conf = CliConf {
        kms_server_url: if matches!(server_params.http_params, HttpParams::Https(_)) {
            format!("https://0.0.0.0:{}", server_params.port)
        } else {
            format!("http://0.0.0.0:{}", server_params.port)
        },
        accept_invalid_certs: true,
        kms_access_token: if server_params.jwt_issuer_uri.is_some() {
            Some(AUTH0_TOKEN.to_string())
        } else {
            None
        },
        ssl_client_pkcs12_path: if server_params.client_cert.is_some() {
            #[cfg(not(target_os = "macos"))]
            let p = "test_data/certificates/owner.client.acme.com.p12".to_string();
            #[cfg(target_os = "macos")]
            let p = "test_data/certificates/owner.client.acme.com.old.format.p12".to_string();
            Some(p)
        } else {
            None
        },
        ssl_client_pkcs12_password: if server_params.client_cert.is_some() {
            Some("password".to_string())
        } else {
            None
        },
        // We use the private key since the private key is the public key with additional information.
        ..Default::default()
    };
    // write the conf to a file
    write_json_object_to_file(&owner_cli_conf, &owner_cli_conf_path)
        .expect("Can't write owner CLI conf path");

    Ok((owner_cli_conf_path, owner_cli_conf))
}

/// Generate a user configuration for user.client@acme.com and return the file path
fn generate_user_conf(port: u16, owner_cli_conf: &CliConf) -> Result<String, CliError> {
    let mut user_conf = owner_cli_conf.clone();
    user_conf.ssl_client_pkcs12_path = {
        #[cfg(not(target_os = "macos"))]
        let p = "test_data/certificates/user.client.acme.com.p12".to_string();
        #[cfg(target_os = "macos")]
        let p = "test_data/certificates/user.client.acme.com.old.format.p12".to_string();
        Some(p)
    };
    user_conf.ssl_client_pkcs12_password = Some("password".to_string());

    // write the user conf
    let user_conf_path = format!("/tmp/user_kms_{port}.json");
    write_json_object_to_file(&user_conf, &user_conf_path)?;

    // return the path
    Ok(user_conf_path)
}

/// Generate an invalid configuration by changin the database secret  and return the file path
pub(crate) fn generate_invalid_conf(correct_conf: &CliConf) -> String {
    // Create a new database key
    let db_key = Secret::<AES_256_GCM_KEY_LENGTH>::new_random()
        .expect("Failed to generate rand bytes for generate_invalid_conf");

    let mut invalid_conf = correct_conf.clone();
    // and a temp file
    let invalid_conf_path = "/tmp/invalid_conf.json".to_string();
    // Generate a wrong token with valid group id
    let secrets = b64
        .decode(
            correct_conf
                .kms_database_secret
                .as_ref()
                .expect("missing database secret")
                .clone(),
        )
        .expect("Can't decode token");
    let mut secrets =
        serde_json::from_slice::<ExtraDatabaseParams>(&secrets).expect("Can't deserialized token");
    secrets.key = db_key; // bad secret
    let token = b64.encode(serde_json::to_string(&secrets).expect("Can't encode token"));
    invalid_conf.kms_database_secret = Some(token);
    write_json_object_to_file(&invalid_conf, &invalid_conf_path)
        .expect("Can't write CONF_PATH_BAD_KEY");
    invalid_conf_path
}
