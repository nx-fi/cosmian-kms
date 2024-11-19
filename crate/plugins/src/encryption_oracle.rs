//! # Encryption Oracle
//! The encryption oracle interface should be implemented by plugins that provide encryption and
//! decryption capabilities for a given key prefix.
//! Once implemented, an encryption oracle must be registered on the KMS instance for that prefix.
//! HSMs that implement the `HSM` interface have a blanket implementation of this interface called
//! `HsmEncryptionOracle`.
use async_trait::async_trait;

use crate::{error::PluginResult, KeyType};

#[derive(Debug)]
pub struct KeyMetadata {
    pub key_type: KeyType,
    pub key_length_in_bits: usize,
    pub sensitive: bool,
    pub label: Option<String>,
}

#[derive(Debug)]
pub enum CryptographicAlgorithm {
    AesGcm,
    RsaPkcsV15,
    RsaOaep,
}

#[async_trait(?Send)]
pub trait EncryptionOracle {
    /// Encrypt data
    /// # Arguments
    /// * `key_id` - the ID of the key to use for encryption
    /// * `data` - the data to encrypt
    /// * `cryptographic_algorithm` - the cryptographic algorithm to use for encryption
    /// * `authenticated_encryption_additional_data` - the additional data to use for authenticated encryption
    /// # Returns
    /// * `Vec<u8>` - the encrypted data
    async fn encrypt(
        &self,
        key_id: &str,
        data: &[u8],
        cryptographic_algorithm: Option<CryptographicAlgorithm>,
        authenticated_encryption_additional_data: Option<Vec<u8>>,
    ) -> PluginResult<Vec<u8>>;

    /// Decrypt data
    /// # Arguments
    /// * `key_id` - the ID of the key to use for decryption
    /// * `data` - the data to decrypt
    /// * `cryptographic_algorithm` - the cryptographic algorithm to use for decryption
    /// * `authenticated_encryption_additional_data` - the additional data to use for authenticated decryption
    /// # Returns
    /// * `Vec<u8>` - the decrypted data
    async fn decrypt(
        &self,
        key_id: &str,
        data: &[u8],
        cryptographic_algorithm: Option<CryptographicAlgorithm>,
        authenticated_encryption_additional_data: Option<Vec<u8>>,
    ) -> PluginResult<Vec<u8>>;

    /// Get the key type
    /// On HSMs, this should be a single call to the HSM.
    /// # Arguments
    /// * `key_id` - the ID of the key
    /// # Returns
    /// * `KeyType` - the type of the key
    async fn get_key_type(&self, key_id: &str) -> PluginResult<KeyType>;

    /// Get the metadata of a key
    /// On HSMs, this should be a double call to the HSM.
    /// # Arguments
    /// * `key_id` - the ID of the key
    /// # Returns
    /// * `KeyMetadata` - the metadata of the key
    async fn get_key_metadata(&self, key_id: &str) -> PluginResult<KeyMetadata>;
}
