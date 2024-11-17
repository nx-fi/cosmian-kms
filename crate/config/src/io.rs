use std::path::PathBuf;

use cosmian_config_utils::{location, ConfigUtils};

use crate::{
    config::{KMS_CLI_CONF_DEFAULT_SYSTEM_PATH, KMS_CLI_CONF_PATH},
    error::KmsConfigError,
    KmsClientConfig, KMS_CLI_CONF_ENV,
};

/// This method is used to configure the KMS CLI by reading a JSON configuration file.
///
/// The method looks for a JSON configuration file with the following structure:
///
/// ```json
/// {
///    "http_config": {
///     "accept_invalid_certs": false,
///     "server_url": "http://127.0.0.1:9998",
///     "access_token": "AA...AAA",
///     "database_secret": "BB...BBB",
///     "ssl_client_pkcs12_path": "/path/to/client.p12",
///     "ssl_client_pkcs12_password": "password"
///     }
/// }
/// ```
/// The path to the configuration file is specified through the `KMS_CLI_CONF` environment variable.
/// If the environment variable is not set, a default path is used.
/// If the configuration file does not exist at the path, a new file is created with default values.
///
/// This function returns a KMS client configured according to the settings specified in the configuration file.
impl KmsClientConfig {
    pub fn location(conf: Option<PathBuf>) -> Result<PathBuf, KmsConfigError> {
        Ok(location(
            conf,
            KMS_CLI_CONF_ENV,
            KMS_CLI_CONF_PATH,
            KMS_CLI_CONF_DEFAULT_SYSTEM_PATH,
        )?)
    }
}

impl ConfigUtils for KmsClientConfig {}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        path::{Path, PathBuf},
    };

    use cosmian_config_utils::{get_default_conf_path, ConfigUtils};
    use cosmian_logger::log_init;

    use super::{KmsClientConfig, KMS_CLI_CONF_ENV};
    use crate::io::KMS_CLI_CONF_PATH;

    #[test]
    pub(crate) fn test_save() {
        let conf_path = Path::new("/tmp/kms.json").to_path_buf();
        log_init(None);
        let conf = KmsClientConfig {
            conf_path: Some(conf_path.clone()),
            ..Default::default()
        };
        conf.save(&conf_path).unwrap();

        let loaded_config = KmsClientConfig::load(&conf_path).unwrap();
        assert_eq!(loaded_config.conf_path, conf.conf_path);
    }

    #[test]
    pub(crate) fn test_load() {
        log_init(None);
        // valid conf
        unsafe {
            env::set_var(KMS_CLI_CONF_ENV, "../../test_data/configs/kms.json");
        }
        let conf_path = KmsClientConfig::location(None).unwrap();
        assert!(KmsClientConfig::load(&conf_path).is_ok());

        // another valid conf
        unsafe {
            env::set_var(KMS_CLI_CONF_ENV, "../../test_data/configs/kms_partial.json");
        }
        let conf_path = KmsClientConfig::location(None).unwrap();
        assert!(KmsClientConfig::load(&conf_path).is_ok());

        // Default conf file
        unsafe {
            env::remove_var(KMS_CLI_CONF_ENV);
        }
        let _ = fs::remove_file(get_default_conf_path(KMS_CLI_CONF_PATH).unwrap());
        let conf_path = KmsClientConfig::location(None).unwrap();
        assert!(KmsClientConfig::load(&conf_path).is_ok());
        assert!(get_default_conf_path(KMS_CLI_CONF_PATH).unwrap().exists());

        // invalid conf
        unsafe {
            env::set_var(KMS_CLI_CONF_ENV, "../../test_data/configs/kms.bad");
        }
        let conf_path = KmsClientConfig::location(None).unwrap();
        let e = KmsClientConfig::load(&conf_path).err().unwrap().to_string();
        assert!(e.contains("missing field `server_url`"));

        // with a file
        unsafe {
            env::remove_var(KMS_CLI_CONF_ENV);
        }
        let conf_path =
            KmsClientConfig::location(Some(PathBuf::from("../../test_data/configs/kms.json")))
                .unwrap();
        assert!(KmsClientConfig::load(&conf_path).is_ok());
    }
}
