//! # HSM
mod encryption_oracle_impl;
mod error;

use async_trait::async_trait;
use zeroize::Zeroizing;

pub use crate::error::{HsmError, HsmResult};

/// Supported key algorithms
pub enum HsmKeyAlgorithm {
    AES,
}

/// Supported key pair algorithms
pub enum HsmKeypairAlgorithm {
    RSA,
}

/// Supported object filters on find
pub enum HsmObjectFilter {
    Any,
    AesKey,
    RsaKey,
    RsaPrivateKey,
    RsaPublicKey,
}

/// Supported object types in the HSM
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum HsmObjectType {
    Aes,
    RsaPrivate,
    RsaPublic,
}

/// RSA private key value representation
/// All values are in big-endian format
#[derive(Debug)]
pub struct RsaPrivateKeyMaterial {
    pub modulus: Vec<u8>,
    pub public_exponent: Vec<u8>,
    pub private_exponent: Zeroizing<Vec<u8>>,
    pub prime_1: Zeroizing<Vec<u8>>,
    pub prime_2: Zeroizing<Vec<u8>>,
    pub exponent_1: Zeroizing<Vec<u8>>,
    pub exponent_2: Zeroizing<Vec<u8>>,
    pub coefficient: Zeroizing<Vec<u8>>,
}

/// RSA public key value representation
/// All values are in big-endian format
#[derive(Debug)]
pub struct RsaPublicKeyMaterial {
    pub modulus: Vec<u8>,
    pub public_exponent: Vec<u8>,
}

/// Key material representation
#[derive(Debug)]
pub enum KeyMaterial {
    AesKey(Zeroizing<Vec<u8>>),
    RsaPrivateKey(RsaPrivateKeyMaterial),
    RsaPublicKey(RsaPublicKeyMaterial),
}

/// HSM object representation
#[derive(Debug)]
pub struct HsmObject {
    key_material: KeyMaterial,
    label: String,
}

/// Supported encryption algorithms
#[derive(Debug)]
pub enum EncryptionAlgorithm {
    AesGcm,
    RsaPkcsV15,
    RsaOaep,
}

impl HsmObject {
    pub fn new(key_material: KeyMaterial, label: String) -> Self {
        HsmObject {
            key_material,
            label,
        }
    }

    pub fn key_material(&self) -> &KeyMaterial {
        &self.key_material
    }

    pub fn label(&self) -> &str {
        &self.label
    }
}

/// HSM trait
/// This trait defines the operations that can be performed on an HSM.
/// The HSM is assumed to be a PKCS#11 compliant device.
#[async_trait(?Send)]
pub trait HSM {
    /// Create the given key in the HSM.
    /// The key ID will be generated by the HSM and returned.
    ///
    /// The key will not be exportable from the HSM if the sensitive flag is set to true.
    /// # Arguments
    /// * `slot_id` - the slot ID of the HSM
    /// * `algorithm` - the key algorithm to use
    /// * `key_length_in_bits` - the length of the key in bits
    /// * `sensitive` - whether the key should be exportable
    /// * `label` - the label to assign to the key
    /// # Returns
    /// * `HsmResult<usize>` - the ID of the key
    async fn create_key(
        &self,
        slot_id: usize,
        algorithm: HsmKeyAlgorithm,
        key_length_in_bits: usize,
        sensitive: bool,
        label: &str,
    ) -> HsmResult<usize>;

    /// Create the given key pair in the HSM.
    /// The private key ID and Public key ID will be generated by the HSM
    /// and returned in that order.
    ///
    /// The key pair will not be exportable from the HSM if the sensitive flag is set to true.
    /// # Arguments
    /// * `slot_id` - the slot ID of the HSM
    /// * `algorithm` - the key pair algorithm to use
    /// * `key_length_in_bits` - the length of the key in bits
    /// * `sensitive` - whether the key pair should be exportable
    /// * `label` - the label to assign to the key pair
    /// # Returns
    /// * `HsmResult<(usize, usize)>` - the IDs of the private and public keys
    async fn create_keypair(
        &self,
        slot_id: usize,
        algorithm: HsmKeypairAlgorithm,
        key_length_in_bits: usize,
        sensitive: bool,
        label: &str,
    ) -> HsmResult<(usize, usize)>;

    /// Export objects from the HSN.
    ///
    /// To be exportable, the object must have been created with the sensitive flag set to false.
    /// # Arguments
    /// * `slot_id` - the slot ID of the HSM
    /// * `object_id` - the ID of the object to export
    /// # Returns
    /// * `HsmResult<Option<HsmObject>>` - the exported object
    async fn export(&self, slot_id: usize, object_id: usize) -> HsmResult<Option<HsmObject>>;

    /// Delete an object from the HSM.
    /// # Arguments
    /// * `slot_id` - the slot ID of the HSM
    /// * `object_id` - the ID of the object to delete
    /// # Returns
    /// * `HsmResult<()>` - the result of the operation
    async fn delete(&self, slot_id: usize, object_id: usize) -> HsmResult<()>;

    /// Find objects in the HSM.
    /// # Arguments
    /// * `slot_id` - the slot ID of the HSM
    /// * `object_filter` - the filter to apply to the objects
    /// # Returns
    /// * `HsmResult<Vec<usize>>` - the IDs of the objects found
    async fn find(&self, slot_id: usize, object_filter: HsmObjectFilter) -> HsmResult<Vec<usize>>;

    /// Encrypt data using the given key in the HSM.
    /// # Arguments
    /// * `slot_id` - the slot ID of the HSM
    /// * `key_id` - the ID of the key to use for encryption
    /// * `algorithm` - the encryption algorithm to use
    /// * `data` - the data to encrypt
    /// # Returns
    /// * `HsmResult<Vec<u8>>` - the encrypted data
    async fn encrypt(
        &self,
        slot_id: usize,
        key_id: usize,
        algorithm: Option<EncryptionAlgorithm>,
        data: &[u8],
    ) -> HsmResult<Vec<u8>>;

    /// Decrypt data using the given key in the HSM.
    /// # Arguments
    /// * `slot_id` - the slot ID of the HSM
    /// * `key_id` - the ID of the key to use for decryption
    /// * `algorithm` - the encryption algorithm to use
    /// * `data` - the data to decrypt
    /// # Returns
    /// * `HsmResult<Vec<u8>>` - the decrypted data
    async fn decrypt(
        &self,
        slot_id: usize,
        key_id: usize,
        algorithm: Option<EncryptionAlgorithm>,
        data: &[u8],
    ) -> HsmResult<Vec<u8>>;
}
