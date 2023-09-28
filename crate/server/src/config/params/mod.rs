mod db_params;
mod enclave_params;
mod http_params;
mod server_params;

pub use db_params::DbParams;
pub use enclave_params::EnclaveParams;
pub use http_params::HttpParams;
pub use server_params::ServerParams;

use super::command_line::BootstrapServerConfig;

pub type BootstrapServerParams = BootstrapServerConfig;