use async_trait::async_trait;
use cosmian_hsm_traits::{
    Hsm, HsmError, HsmKeyAlgorithm, HsmKeypairAlgorithm, HsmObject, HsmObjectFilter, HsmResult,
};

use crate::{AesKeySize, Proteccio, RsaKeySize};

#[async_trait(?Send)]
impl Hsm for Proteccio {
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
                let (sk, pk) = session.generate_rsa_key_pair(key_length_in_bits, label)?;
                Ok((sk as usize, pk as usize))
            } // _ => Err(HsmError::Default(
              //     "Only AES or RSA keys can be created on the Proteccio HSM".to_string(),
              // )),
        }
    }

    async fn retrieve(&self, _slot_id: usize, _object_id: usize) -> HsmResult<HsmObject> {
        todo!()
    }

    async fn delete(&self, _slot_id: usize, _object_id: usize) -> HsmResult<()> {
        todo!()
    }

    async fn find(&self, _slot_id: usize, _object_type: HsmObjectFilter) -> HsmResult<Vec<String>> {
        todo!()
    }
}
