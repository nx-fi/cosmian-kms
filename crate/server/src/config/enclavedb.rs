use std::{fs, path::Path};

use clap::Args;
use tracing::info;

use super::workspace::WorkspaceConfig;
use crate::core::enclavedb::EnclaveDB;

#[derive(Debug, Args)]
pub struct EnclaveDBConfig {
    /// The url of the database
    #[clap(long, env = "KMS_EDGELESS_HOST")]
    edgeless_host: String,

    /// The port to use when connecting through MYSQL
    #[clap(long, env = "KMS_EDGELESS_SQL_PORT")]
    edgeless_sql_port: u16,

    /// The port to use when connecting through HTTP
    #[clap(long, env = "KMS_EDGELESS_HTTP_PORT")]
    edgeless_http_port: u16,
}

impl Default for EnclaveDBConfig {
    fn default() -> Self {
        EnclaveDBConfig {
            edgeless_host: "localhost".to_string(),
            edgeless_sql_port: 3306,
            edgeless_http_port: 8080,
        }
    }
}

impl EnclaveDBConfig {
    pub fn init(&self, workspace: &WorkspaceConfig) -> eyre::Result<EnclaveDB> {
        let private_path = workspace.tmp_path.join("edglessdb");

        if !Path::new(&private_path).exists() {
            info!("Creating {:?}...", private_path);
            fs::create_dir_all(&private_path)?;
        }

        let public_path = workspace.shared_path.join("edglessdb");

        if !Path::new(&public_path).exists() {
            info!("Creating {:?}...", public_path);
            fs::create_dir_all(&public_path)?;
        }

        Ok(EnclaveDB::new(
            private_path,
            public_path,
            self.edgeless_host.to_owned(),
            self.edgeless_sql_port,
            self.edgeless_http_port,
        ))
    }
}
