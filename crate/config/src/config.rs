use std::path::{Path, PathBuf};

use cosmian_http_client::HttpClientConfig;
use serde::{Deserialize, Serialize};

pub const KMS_CLI_CONF_ENV: &str = "KMS_CLI_CONF";
pub(crate) const KMS_CLI_CONF_DEFAULT_SYSTEM_PATH: &str = "/etc/cosmian/kms.json";
pub(crate) const KMS_CLI_CONF_PATH: &str = ".cosmian/kms.json";

/// The configuration that is used by the google command
/// to perform actions over Gmail API.
#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone)]
pub struct GmailApiConf {
    #[serde(rename = "type")]
    pub account_type: String,
    pub project_id: String,
    pub private_key_id: String,
    pub private_key: String,
    pub client_email: String,
    pub client_id: String,
    pub auth_uri: String,
    pub token_uri: String,
    pub auth_provider_x509_cert_url: String,
    pub client_x509_cert_url: String,
    pub universe_domain: String,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone)]
pub struct KmsClientConfig {
    pub conf_path: PathBuf,
    pub http_config: HttpClientConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gmail_api_conf: Option<GmailApiConf>,
    /// will output the JSON KMIP request and response
    #[serde(skip_serializing_if = "Option::is_none")]
    pub print_json: Option<bool>,
}

impl Default for KmsClientConfig {
    fn default() -> Self {
        Self {
            http_config: HttpClientConfig {
                server_url: "http://0.0.0.0:9998".to_owned(),
                ..HttpClientConfig::default()
            },
            conf_path: Path::new(KMS_CLI_CONF_PATH).to_path_buf(),
            gmail_api_conf: None,
            print_json: None,
        }
    }
}
