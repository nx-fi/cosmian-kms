use std::{fmt::Display, path::PathBuf};

use clap::Args;

#[derive(Args, Clone)]
pub struct HttpConfig {
    /// The KMS server port
    #[clap(long, env = "KMS_PORT", default_value = "9998")]
    pub port: u16,

    /// The KMS server (and bootstrap server) hostname
    #[clap(long, env = "KMS_HOSTNAME", default_value = "0.0.0.0")]
    pub hostname: String,

    /// The KMS server optional PKCS#12 Certificates and Key file. If provided, this will start the server in HTTPS mode.
    ///
    /// The PKCS#12 can be securely provided via the bootstrap server. Check the documentation.
    #[clap(long, env = "KMS_HTTPS_P12_FILE")]
    pub https_p12_file: Option<PathBuf>,

    /// The password to open the PKCS#12 Certificates and Key file
    ///
    /// The PKCS#12 password can be securely provided via the bootstrap server. Check the documentation.
    #[clap(long, env = "KMS_HTTPS_P12_PASSWORD", default_value = "")]
    pub https_p12_password: String,

    /// The server optional authority X509 certificate in PEM format used to validate the client certificate presented for authentication.
    /// If provided, this will require clients to present a certificate signed by this authority for authentication.
    /// The server must run in TLS mode for this to be used.
    #[clap(long, env = "KMS_AUTHORITY_CERT_FILE")]
    pub authority_cert_file: Option<PathBuf>,
}

impl Display for HttpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.https_p12_file.is_some() {
            write!(f, "https://{}:{}, ", self.hostname, self.port)?;
            write!(f, "Pkcs12 file: {:?}, ", self.https_p12_file.as_ref())?;
            write!(
                f,
                "password: {}, ",
                self.https_p12_password.replace('.', "*")
            )?;
            write!(
                f,
                "authority cert file: {:?}",
                self.authority_cert_file.as_ref()
            )
        } else {
            write!(f, "http://{}:{}", self.hostname, self.port)
        }
    }
}

impl std::fmt::Debug for HttpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}", &self))
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            port: 9998,
            hostname: "0.0.0.0".to_string(),
            https_p12_file: None,
            https_p12_password: String::new(),
            authority_cert_file: None,
        }
    }
}