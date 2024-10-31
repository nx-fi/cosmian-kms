mod error;

use async_trait::async_trait;
use zeroize::Zeroizing;

pub use crate::error::{HsmError, HsmResult};

pub enum HsmKeyAlgorithm {
    AES,
}

pub enum HsmKeypairAlgorithm {
    RSA,
}

pub enum HsmObjectFilter {
    Any,
    AesKey,
    RsaKey,
    RsaPrivateKey,
    RsaPublicKey,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum HsmObjectType {
    Aes,
    RsaPrivate,
    RsaPublic,
}

#[derive(Debug)]
pub struct HsmObject {
    object_type: HsmObjectType,
    value: Zeroizing<Vec<u8>>,
    key_len_in_bits: usize,
    label: String,
}

impl HsmObject {
    pub fn new(
        object_type: HsmObjectType,
        value: &[u8],
        key_len_in_bits: usize,
        label: String,
    ) -> Self {
        HsmObject {
            object_type,
            value: Zeroizing::new(value.to_vec()),
            key_len_in_bits,
            label,
        }
    }

    pub fn object_type(&self) -> HsmObjectType {
        self.object_type
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }

    pub fn key_len_in_bits(&self) -> usize {
        self.key_len_in_bits
    }

    pub fn label(&self) -> &str {
        &self.label
    }
}

#[async_trait(?Send)]
pub trait Hsm {
    /// Create the given key in the HSM.
    /// The key ID will be generated by the HSM and returned.
    /// If the key is sensitive, it will not be exportable.
    ///
    /// The key will be extractable.
    async fn create_key(
        &self,
        slot_id: usize,
        algorithm: HsmKeyAlgorithm,
        key_length_in_bits: usize,
        sensitive: bool,
        label: &str,
    ) -> HsmResult<usize>;

    /// Create the given key pair in the HSM.
    /// The private key ID and Public key will be generated by the HSM
    /// and returned in that order.
    ///
    /// The keypair will be extractable.
    async fn create_keypair(
        &self,
        slot_id: usize,
        algorithm: HsmKeypairAlgorithm,
        key_length_in_bits: usize,
        label: &str,
    ) -> HsmResult<(usize, usize)>;

    /// Retrieve objects from the HSN.
    async fn retrieve(&self, slot_id: usize, object_id: usize) -> HsmResult<HsmObject>;

    /// Delete an object from the HSM.
    async fn delete(&self, slot_id: usize, object_id: usize) -> HsmResult<()>;

    /// Find objects in the HSM.
    async fn find(&self, slot_id: usize, object_filter: HsmObjectFilter) -> HsmResult<Vec<String>>;
}
