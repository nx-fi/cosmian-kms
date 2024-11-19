mod encryption_oracle;
mod error;
mod hsm;

use clap::Parser;
pub use encryption_oracle::{CryptographicAlgorithm, EncryptionOracle, KeyMetadata};
pub use error::{PluginError, PluginResult};
pub use hsm::{
    HsmKeyAlgorithm, HsmKeypairAlgorithm, HsmObject, HsmObjectFilter, KeyMaterial,
    RsaPrivateKeyMaterial, RsaPublicKeyMaterial, HSM,
};

/// Supported cryptographic object types
/// in plugins
#[derive(Debug, Eq, PartialEq)]
pub enum KeyType {
    AesKey,
    RsaPrivateKey,
    RsaPublicKey,
}
