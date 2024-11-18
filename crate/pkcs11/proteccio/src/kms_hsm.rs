use async_trait::async_trait;
use cosmian_hsm_traits::{
    EncryptionAlgorithm, HsmError, HsmKeyAlgorithm, HsmKeypairAlgorithm, HsmObject,
    HsmObjectFilter, HsmResult, HSM,
};
use pkcs11_sys::CK_OBJECT_HANDLE;

use crate::{AesKeySize, Proteccio, RsaKeySize};

#[async_trait(?Send)]
impl HSM for Proteccio {
    async fn create_key(
        &self,
        slot_id: usize,
        algorithm: HsmKeyAlgorithm,
        key_length_in_bits: usize,
        sensitive: bool,
        label: &str,
    ) -> HsmResult<usize> {
        let slot = self.get_slot(slot_id)?;
        let session = slot.open_session(true)?;

        match algorithm {
            HsmKeyAlgorithm::AES => {
                let key_size = match key_length_in_bits {
                    128 => AesKeySize::Aes128,
                    256 => AesKeySize::Aes256,
                    x => {
                        return Err(HsmError::Default(format!(
                            "Invalid key length: {x} bits, for and HSM AES key"
                        )))
                    }
                };
                let id = session.generate_aes_key(key_size, label, sensitive)?;
                Ok(id as usize)
            } // _ => Err(HsmError::Default(
              //     "Only AES or RSA keys can be created on the Proteccio HSM".to_string(),
              // )),
        }
    }

    async fn create_keypair(
        &self,
        slot_id: usize,
        algorithm: HsmKeypairAlgorithm,
        key_length_in_bits: usize,
        sensitive: bool,
        label: &str,
    ) -> HsmResult<(usize, usize)> {
        let slot = self.get_slot(slot_id)?;
        let session = slot.open_session(true)?;

        let key_length_in_bits = match key_length_in_bits {
            1024 => RsaKeySize::Rsa1024,
            2048 => RsaKeySize::Rsa2048,
            3072 => RsaKeySize::Rsa3072,
            4096 => RsaKeySize::Rsa4096,
            x => {
                return Err(HsmError::Default(format!(
                    "Invalid key length: {x} bits, for and HSM RSA key (valid values are 1024, \
                     2048, 3072, 4096)"
                )))
            }
        };

        match algorithm {
            HsmKeypairAlgorithm::RSA => {
                let (sk, pk) =
                    session.generate_rsa_key_pair(key_length_in_bits, label, sensitive)?;
                Ok((sk as usize, pk as usize))
            } // _ => Err(HsmError::Default(
              //     "Only AES or RSA keys can be created on the Proteccio HSM".to_string(),
              // )),
        }
    }

    async fn export(&self, slot_id: usize, object_id: usize) -> HsmResult<Option<HsmObject>> {
        let slot = self.get_slot(slot_id)?;
        let session = slot.open_session(true)?;
        let object = session.export_key(object_id as CK_OBJECT_HANDLE)?;
        Ok(object)
    }

    async fn delete(&self, slot_id: usize, object_id: usize) -> HsmResult<()> {
        let slot = self.get_slot(slot_id)?;
        let session = slot.open_session(true)?;
        session.destroy_object(object_id as CK_OBJECT_HANDLE)?;
        Ok(())
    }

    async fn find(&self, slot_id: usize, object_type: HsmObjectFilter) -> HsmResult<Vec<usize>> {
        let slot = self.get_slot(slot_id)?;
        let session = slot.open_session(true)?;
        let objects = session.list_objects(object_type)?;
        Ok(objects.into_iter().map(|id| id as usize).collect())
    }

    async fn encrypt(
        &self,
        slot_id: usize,
        key_id: usize,
        algorithm: EncryptionAlgorithm,
        data: &[u8],
    ) -> HsmResult<Vec<u8>> {
        let slot = self.get_slot(slot_id)?;
        let session = slot.open_session(true)?;
        let ciphertext = session.encrypt(key_id as CK_OBJECT_HANDLE, algorithm.into(), data)?;
        Ok(ciphertext)
    }

    async fn decrypt(
        &self,
        slot_id: usize,
        key_id: usize,
        algorithm: EncryptionAlgorithm,
        data: &[u8],
    ) -> HsmResult<Vec<u8>> {
        let slot = self.get_slot(slot_id)?;
        let session = slot.open_session(true)?;
        let plaintext = session.decrypt(key_id as CK_OBJECT_HANDLE, algorithm.into(), data)?;
        Ok(plaintext)
    }
}
