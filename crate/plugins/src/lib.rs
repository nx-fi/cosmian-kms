mod encryption_oracle;
mod error;

pub use encryption_oracle::{CryptographicAlgorithm, EncryptionOracle, KeyMetadata};
pub use error::{PluginError, PluginResult};
