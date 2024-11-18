pub struct KeyMetadata {
    pub key_algorithm: CryptographicAlgorithm,
    pub key_length_in_bits: usize,
    pub sensitive: bool,
    pub label: Option<String>,
}

pub enum CryptographicAlgorithm {
    AesGcm,
    RsaPkcsV15,
    RsaOaep,
}

pub trait EncryptionOracle {
    /// Encrypt data
    /// # Arguments
    /// * `key_id` - the ID of the key to use for encryption
    /// * `data` - the data to encrypt
    /// * `cryptographic_algorithm` - the cryptographic algorithm to use for encryption
    /// * `authenticated_encryption_additional_data` - the additional data to use for authenticated encryption
    /// # Returns
    /// * `Vec<u8>` - the encrypted data
    fn encrypt(
        &self,
        key_id: &str,
        data: &[u8],
        cryptographic_algorithm: Option<CryptographicAlgorithm>,
        authenticated_encryption_additional_data: Option<Vec<u8>>,
    ) -> Vec<u8>;

    /// Decrypt data
    /// # Arguments
    /// * `key_id` - the ID of the key to use for decryption
    /// * `data` - the data to decrypt
    /// * `cryptographic_algorithm` - the cryptographic algorithm to use for decryption
    /// * `authenticated_encryption_additional_data` - the additional data to use for authenticated decryption
    /// # Returns
    /// * `Vec<u8>` - the decrypted data
    fn decrypt(
        &self,
        key_id: &str,
        data: &[u8],
        cryptographic_algorithm: Option<CryptographicAlgorithm>,
        authenticated_encryption_additional_data: Option<Vec<u8>>,
    ) -> Vec<u8>;

    /// Get the metadata of a key
    /// # Arguments
    /// * `key_id` - the ID of the key
    /// # Returns
    /// * `KeyMetadata` - the metadata of the key
    fn get_key_metadata(&self, key_id: &str) -> KeyMetadata;
}
