mod aes;
mod rsa;

use std::{ptr, sync::Arc};

pub use aes::AesKeySize;
use pkcs11_sys::*;
pub use rsa::RsaKeySize;

use crate::{aes_mechanism, generate_random_nonce, rsa_mechanism, PError, PResult};

pub enum ObjectType {
    Any,
    AesKey,
    RsaKey,
    RsaPrivateKey,
    RsaPublicKey,
}

pub enum EncryptionAlgorithm {
    AesGcm,
    RsaPkcsv15,
    RsaOaep,
}

pub struct Session {
    hsm: Arc<crate::proteccio::HsmLib>,
    session_handle: CK_SESSION_HANDLE,
    is_logged_in: bool,
}

impl Session {
    pub fn new(
        hsm: Arc<crate::proteccio::HsmLib>,
        session_handle: CK_SESSION_HANDLE,
        is_logged_in: bool,
    ) -> Self {
        Session {
            hsm,
            session_handle,
            is_logged_in,
        }
    }

    pub fn close(&self) -> PResult<()> {
        unsafe {
            if self.is_logged_in {
                let rv = self.hsm.C_Logout.ok_or_else(|| {
                    PError::Default("C_Logout not available on library".to_string())
                })?(self.session_handle);
                if rv != CKR_OK {
                    return Err(PError::Default("Failed logging out".to_string()));
                }
            }
            let rv = self.hsm.C_CloseSession.ok_or_else(|| {
                PError::Default("C_CloseSession not available on library".to_string())
            })?(self.session_handle);
            if rv != CKR_OK {
                return Err(PError::Default("Failed closing a session".to_string()));
            }
            Ok(())
        }
    }

    pub fn generate_random(&self, len: usize) -> PResult<Vec<u8>> {
        unsafe {
            let mut values = vec![0u8; len];
            let values_ptr: *mut u8 = values.as_mut_ptr();
            let rv = self.hsm.C_GenerateRandom.ok_or_else(|| {
                PError::Default("C_GenerateRandom not available on library".to_string())
            })?(self.session_handle, values_ptr, len as u64);
            if rv != CKR_OK {
                return Err(PError::Default("Failed generating random data".to_string()));
            }
            Ok(values)
        }
    }

    pub fn list_objects(&self, object_type: ObjectType) -> PResult<Vec<u64>> {
        let mut object_handles: Vec<u64> = Vec::new();
        let mut template: Vec<CK_ATTRIBUTE> = Vec::new();
        match object_type {
            ObjectType::Any => {}
            ObjectType::AesKey => {
                template.extend([
                    CK_ATTRIBUTE {
                        type_: CKA_CLASS,
                        pValue: &CKO_SECRET_KEY as *const _ as *mut _,
                        ulValueLen: size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
                    },
                    CK_ATTRIBUTE {
                        type_: CKA_KEY_TYPE,
                        pValue: &CKK_AES as *const _ as *mut _,
                        ulValueLen: size_of::<CK_KEY_TYPE>() as CK_ULONG,
                    },
                ]);
            }
            ObjectType::RsaKey => template.extend([CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: &CKK_RSA as *const _ as *mut _,
                ulValueLen: size_of::<CK_KEY_TYPE>() as CK_ULONG,
            }]),
            ObjectType::RsaPrivateKey => template.extend([
                CK_ATTRIBUTE {
                    type_: CKA_CLASS,
                    pValue: &CKO_PRIVATE_KEY as *const _ as *mut _,
                    ulValueLen: size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_KEY_TYPE,
                    pValue: &CKK_RSA as *const _ as *mut _,
                    ulValueLen: size_of::<CK_KEY_TYPE>() as CK_ULONG,
                },
            ]),
            ObjectType::RsaPublicKey => template.extend([
                CK_ATTRIBUTE {
                    type_: CKA_CLASS,
                    pValue: &CKO_PUBLIC_KEY as *const _ as *mut _,
                    ulValueLen: size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_KEY_TYPE,
                    pValue: &CKK_RSA as *const _ as *mut _,
                    ulValueLen: size_of::<CK_KEY_TYPE>() as CK_ULONG,
                },
            ]),
        }

        unsafe {
            let rv = self.hsm.C_FindObjectsInit.ok_or_else(|| {
                PError::Default("C_FindObjectsInit not available on library".to_string())
            })?(
                self.session_handle,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
            );
            if rv != CKR_OK {
                return Err(PError::Default(
                    "Failed to initialize object search".to_string(),
                ));
            }

            let mut object_handle: CK_OBJECT_HANDLE = 0;
            let mut object_count: CK_ULONG = 0;
            loop {
                let rv = self.hsm.C_FindObjects.ok_or_else(|| {
                    PError::Default("C_FindObjects not available on library".to_string())
                })?(
                    self.session_handle,
                    &mut object_handle,
                    1,
                    &mut object_count,
                );
                if rv != CKR_OK {
                    return Err(PError::Default("Failed to find objects".to_string()));
                }
                if object_count == 0 {
                    break;
                }
                object_handles.push(object_handle as u64);
            }

            let rv = self.hsm.C_FindObjectsFinal.ok_or_else(|| {
                PError::Default("C_FindObjectsFinal not available on library".to_string())
            })?(self.session_handle);
            if rv != CKR_OK {
                return Err(PError::Default(
                    "Failed to finalize object search".to_string(),
                ));
            }
        }
        Ok(object_handles)
    }

    pub fn destroy_object(&self, object_handle: u64) -> PResult<()> {
        unsafe {
            let rv = self.hsm.C_DestroyObject.ok_or_else(|| {
                PError::Default("C_DestroyObject not available on library".to_string())
            })?(self.session_handle, object_handle as CK_OBJECT_HANDLE);
            if rv != CKR_OK {
                return Err(PError::Default("Failed to destroy object".to_string()));
            }
        }
        Ok(())
    }

    pub fn encrypt(
        &self,
        key_handle: CK_OBJECT_HANDLE,
        algorithm: EncryptionAlgorithm,
        plaintext: &[u8],
    ) -> PResult<Vec<u8>> {
        match algorithm {
            EncryptionAlgorithm::AesGcm => {
                let mut nonce = generate_random_nonce::<12>()?;
                let ciphertext = self.encrypt_with_mechanism(
                    key_handle,
                    &mut aes_mechanism!(&mut nonce),
                    plaintext,
                )?;
                Ok(nonce.into_iter().chain(ciphertext.into_iter()).collect())
            }
            _ => self.encrypt_with_mechanism(key_handle, &mut rsa_mechanism!(algorithm), plaintext),
        }
    }

    pub fn decrypt(
        &self,
        key_handle: CK_OBJECT_HANDLE,
        algorithm: EncryptionAlgorithm,
        ciphertext: &[u8],
    ) -> PResult<Vec<u8>> {
        match algorithm {
            EncryptionAlgorithm::AesGcm => {
                if ciphertext.len() < 12 {
                    return Err(PError::Default("Invalid AES GCM ciphertext".to_string()));
                }
                let mut nonce: [u8; 12] = ciphertext[..12]
                    .try_into()
                    .map_err(|_| PError::Default("Invalid AES GCM nonce".to_string()))?;
                let plaintext = self.decrypt_with_mechanism(
                    key_handle,
                    &mut aes_mechanism!(&mut nonce),
                    &ciphertext[12..],
                )?;
                Ok(plaintext)
            }
            _ => {
                self.decrypt_with_mechanism(key_handle, &mut rsa_mechanism!(algorithm), ciphertext)
            }
        }
    }

    fn encrypt_with_mechanism(
        &self,
        key_handle: CK_OBJECT_HANDLE,
        mechanism: &mut CK_MECHANISM,
        data: &[u8],
    ) -> PResult<Vec<u8>> {
        let mut data = data.to_vec();
        unsafe {
            let ck_fn = self.hsm.C_EncryptInit.ok_or_else(|| {
                PError::Default("C_EncryptInit not available on library".to_string())
            })?;

            let rv = ck_fn(self.session_handle, mechanism, key_handle);
            if rv != CKR_OK {
                return Err(PError::Default(
                    "Failed to initialize encryption".to_string(),
                ));
            }

            let ck_fn = self
                .hsm
                .C_Encrypt
                .ok_or_else(|| PError::Default("C_Encrypt not available on library".to_string()))?;

            let mut encrypted_data_len: CK_ULONG = 0;
            let rv = ck_fn(
                self.session_handle,
                data.as_mut_ptr(),
                data.len() as CK_ULONG,
                ptr::null_mut(),
                &mut encrypted_data_len,
            );
            if rv != CKR_OK {
                return Err(PError::Default(
                    "Failed to get encrypted data length".to_string(),
                ));
            }

            let mut encrypted_data = vec![0u8; encrypted_data_len as usize];
            let rv = ck_fn(
                self.session_handle,
                data.as_mut_ptr(),
                data.len() as CK_ULONG,
                encrypted_data.as_mut_ptr(),
                &mut encrypted_data_len,
            );
            if rv != CKR_OK {
                return Err(PError::Default("Failed to encrypt data".to_string()));
            }

            encrypted_data.truncate(encrypted_data_len as usize);
            Ok(encrypted_data)
        }
    }

    fn decrypt_with_mechanism(
        &self,
        key_handle: CK_OBJECT_HANDLE,
        mechanism: &mut CK_MECHANISM,
        encrypted_data: &[u8],
    ) -> PResult<Vec<u8>> {
        let mut encrypted_data = encrypted_data.to_vec();
        unsafe {
            let ck_fn = self.hsm.C_DecryptInit.ok_or_else(|| {
                PError::Default("C_DecryptInit not available on library".to_string())
            })?;

            let rv = ck_fn(self.session_handle, mechanism, key_handle);
            if rv != CKR_OK {
                return Err(PError::Default(
                    "Failed to initialize decryption".to_string(),
                ));
            }

            let ck_fn = self
                .hsm
                .C_Decrypt
                .ok_or_else(|| PError::Default("C_Decrypt not available on library".to_string()))?;

            let mut decrypted_data_len: CK_ULONG = 0;
            let rv = ck_fn(
                self.session_handle,
                encrypted_data.as_mut_ptr(),
                encrypted_data.len() as CK_ULONG,
                ptr::null_mut(),
                &mut decrypted_data_len,
            );
            if rv != CKR_OK {
                return Err(PError::Default(
                    "Failed to get decrypted data length".to_string(),
                ));
            }

            let mut decrypted_data = vec![0u8; decrypted_data_len as usize];
            let rv = ck_fn(
                self.session_handle,
                encrypted_data.as_mut_ptr(),
                encrypted_data.len() as CK_ULONG,
                decrypted_data.as_mut_ptr(),
                &mut decrypted_data_len,
            );
            if rv != CKR_OK {
                return Err(PError::Default("Failed to decrypt data".to_string()));
            }

            decrypted_data.truncate(decrypted_data_len as usize);
            Ok(decrypted_data)
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
