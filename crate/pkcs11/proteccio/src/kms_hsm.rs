use async_trait::async_trait;
use cosmian_hsm_traits::{
    reexports::kmip::Object, Hsm, HsmAlgorithm, HsmError, HsmObject, HsmResult,
};

use crate::{AesKeySize, Proteccio};

#[async_trait(?Send)]
impl Hsm for Proteccio {
    async fn create(
        &self,
        slot_id: usize,
        algorithm: HsmAlgorithm,
        key_length_in_bits: usize,
        label: &str,
    ) -> HsmResult<usize> {
        let slot = self.get_slot(slot_id)?;
        let session = slot.open_session(true)?;

        match algorithm {
            HsmAlgorithm::AES => {
                let key_size = match key_length_in_bits {
                    128 => AesKeySize::Aes128,
                    256 => AesKeySize::Aes256,
                    x => {
                        return Err(HsmError::Default(format!(
                            "Invalid key length: {x} bits, for and HSM AES key"
                        )))
                    }
                };
                let id = session.generate_aes_key(key_size, label)?;
                Ok(id)
            }
            _ => Err(HsmError::Default(
                "Only AES or RSA keys can be created on the Proteccio HSM".to_string(),
            )),
        }
    }

    async fn retrieve(&self, _slot_id: usize, _object_id: usize) -> HsmResult<Object> {
        todo!()
    }

    async fn delete(&self, _slot_id: usize, _object_id: usize) -> HsmResult<()> {
        todo!()
    }

    async fn find(&self, _slot_id: usize, _object_type: HsmObject) -> HsmResult<Vec<String>> {
        todo!()
    }
}
