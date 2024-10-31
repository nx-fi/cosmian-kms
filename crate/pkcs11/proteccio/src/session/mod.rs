mod aes;
mod rsa;

use std::{ptr, sync::Arc};

pub use aes::AesKeySize;
use cosmian_hsm_traits::{HsmObject, HsmObjectFilter, HsmObjectType, KeyValue, RsaPrivateKeyValue};
use pkcs11_sys::*;
pub use rsa::RsaKeySize;
use zeroize::Zeroizing;

use crate::{aes_mechanism, generate_random_nonce, rsa_mechanism, PError, PResult};

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

    pub fn list_objects(&self, object_filter: HsmObjectFilter) -> PResult<Vec<u64>> {
        let mut object_handles: Vec<u64> = Vec::new();
        let mut template: Vec<CK_ATTRIBUTE> = Vec::new();
        match object_filter {
            HsmObjectFilter::Any => {}
            HsmObjectFilter::AesKey => {
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
            HsmObjectFilter::RsaKey => template.extend([CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: &CKK_RSA as *const _ as *mut _,
                ulValueLen: size_of::<CK_KEY_TYPE>() as CK_ULONG,
            }]),
            HsmObjectFilter::RsaPrivateKey => template.extend([
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
            HsmObjectFilter::RsaPublicKey => template.extend([
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

    pub fn export_key(&self, key_handle: CK_OBJECT_HANDLE) -> PResult<HsmObject> {
        let mut key_type: CK_KEY_TYPE = CKK_VENDOR_DEFINED;
        let mut private: CK_BBOOL = CK_FALSE;
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_LABEL,
                pValue: ptr::null_mut(),
                ulValueLen: 0,
            },
            CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: &mut key_type as *mut _ as CK_VOID_PTR,
                ulValueLen: size_of::<CK_ULONG>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_PRIVATE,
                pValue: &mut private as *mut _ as CK_VOID_PTR,
                ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
            },
        ];

        self.call_get_attributes(key_handle, &mut template)?;
        let label_len = template[0].ulValueLen;
        let mut label_bytes: Vec<u8> = vec![0_u8; label_len as usize];
        let object_type = match key_type {
            CKK_AES => HsmObjectType::Aes,
            CKK_RSA => {
                if private == CK_TRUE {
                    HsmObjectType::RsaPrivate
                } else {
                    HsmObjectType::RsaPublic
                }
            }
            x => {
                return Err(PError::Default(format!(
                    "Export: unsupported key type: {x}"
                )));
            }
        };

        match object_type {
            HsmObjectType::Aes => {
                // Get the key size
                let mut template = [
                    CK_ATTRIBUTE {
                        type_: CKA_VALUE,
                        pValue: ptr::null_mut(),
                        ulValueLen: 0,
                    },
                    CK_ATTRIBUTE {
                        type_: CKA_VALUE_LEN,
                        pValue: ptr::null_mut(),
                        ulValueLen: 0,
                    },
                ];
                self.call_get_attributes(key_handle, &mut template)?;
                // Export the value
                let key_value_len = template[0].ulValueLen;
                let key_len_in_bits = template[1].ulValueLen as usize * 8;
                let mut key_value: Vec<u8> = vec![0_u8; key_value_len as usize];
                let mut template = [
                    CK_ATTRIBUTE {
                        type_: CKA_VALUE,
                        pValue: key_value.as_mut_ptr() as CK_VOID_PTR,
                        ulValueLen: key_value_len,
                    },
                    CK_ATTRIBUTE {
                        type_: CKA_LABEL,
                        pValue: label_bytes.as_mut_ptr() as CK_VOID_PTR,
                        ulValueLen: label_len,
                    },
                ];
                self.call_get_attributes(key_handle, &mut template)?;
                let label = String::from_utf8(label_bytes).map_err(|e| {
                    PError::Default(format!("Failed to convert label to string: {}", e))
                })?;
                Ok(HsmObject::new(
                    object_type,
                    KeyValue::AesKey(Zeroizing::new(key_value)),
                    key_len_in_bits,
                    label,
                ))
            }
            HsmObjectType::RsaPrivate => {
                // Get the key size
                let mut template = [
                    CK_ATTRIBUTE {
                        type_: CKA_PUBLIC_EXPONENT,
                        pValue: ptr::null_mut(),
                        ulValueLen: 0,
                    },
                    CK_ATTRIBUTE {
                        type_: CKA_PRIVATE_EXPONENT,
                        pValue: ptr::null_mut(),
                        ulValueLen: 0,
                    },
                    CK_ATTRIBUTE {
                        type_: CKA_PRIME_1,
                        pValue: ptr::null_mut(),
                        ulValueLen: 0,
                    },
                    CK_ATTRIBUTE {
                        type_: CKA_PRIME_2,
                        pValue: ptr::null_mut(),
                        ulValueLen: 0,
                    },
                    CK_ATTRIBUTE {
                        type_: CKA_EXPONENT_1,
                        pValue: ptr::null_mut(),
                        ulValueLen: 0,
                    },
                    CK_ATTRIBUTE {
                        type_: CKA_EXPONENT_2,
                        pValue: ptr::null_mut(),
                        ulValueLen: 0,
                    },
                    CK_ATTRIBUTE {
                        type_: CKA_COEFFICIENT,
                        pValue: ptr::null_mut(),
                        ulValueLen: 0,
                    },
                    CK_ATTRIBUTE {
                        type_: CKA_MODULUS,
                        pValue: ptr::null_mut(),
                        ulValueLen: 0,
                    },
                ];
                self.call_get_attributes(key_handle, &mut template)?;
                let public_exponent_len = template[0].ulValueLen;
                let private_exponent_len = template[1].ulValueLen;
                let prime_1_len = template[2].ulValueLen;
                let prime_2_len = template[3].ulValueLen;
                let exponent_1_len = template[4].ulValueLen;
                let exponent_2_len = template[5].ulValueLen;
                let coefficient_len = template[6].ulValueLen;
                let modulus_len = template[7].ulValueLen;
                let mut public_exponent: Vec<u8> = vec![0_u8; public_exponent_len as usize];
                let mut private_exponent: Vec<u8> = vec![0_u8; private_exponent_len as usize];
                let mut prime_1: Vec<u8> = vec![0_u8; prime_1_len as usize];
                let mut prime_2: Vec<u8> = vec![0_u8; prime_2_len as usize];
                let mut exponent_1: Vec<u8> = vec![0_u8; exponent_1_len as usize];
                let mut exponent_2: Vec<u8> = vec![0_u8; exponent_2_len as usize];
                let mut coefficient: Vec<u8> = vec![0_u8; coefficient_len as usize];
                let mut modulus: Vec<u8> = vec![0_u8; modulus_len as usize];
                let mut template = [
                    CK_ATTRIBUTE {
                        type_: CKA_PUBLIC_EXPONENT,
                        pValue: public_exponent.as_mut_ptr() as CK_VOID_PTR,
                        ulValueLen: public_exponent_len,
                    },
                    CK_ATTRIBUTE {
                        type_: CKA_PRIVATE_EXPONENT,
                        pValue: private_exponent.as_mut_ptr() as CK_VOID_PTR,
                        ulValueLen: private_exponent_len,
                    },
                    CK_ATTRIBUTE {
                        type_: CKA_PRIME_1,
                        pValue: prime_1.as_mut_ptr() as CK_VOID_PTR,
                        ulValueLen: prime_1_len,
                    },
                    CK_ATTRIBUTE {
                        type_: CKA_PRIME_2,
                        pValue: prime_2.as_mut_ptr() as CK_VOID_PTR,
                        ulValueLen: prime_2_len,
                    },
                    CK_ATTRIBUTE {
                        type_: CKA_EXPONENT_1,
                        pValue: exponent_1.as_mut_ptr() as CK_VOID_PTR,
                        ulValueLen: exponent_1_len,
                    },
                    CK_ATTRIBUTE {
                        type_: CKA_EXPONENT_2,
                        pValue: exponent_2.as_mut_ptr() as CK_VOID_PTR,
                        ulValueLen: exponent_2_len,
                    },
                    CK_ATTRIBUTE {
                        type_: CKA_COEFFICIENT,
                        pValue: coefficient.as_mut_ptr() as CK_VOID_PTR,
                        ulValueLen: coefficient_len,
                    },
                    CK_ATTRIBUTE {
                        type_: CKA_LABEL,
                        pValue: label_bytes.as_mut_ptr() as CK_VOID_PTR,
                        ulValueLen: label_len,
                    },
                    CK_ATTRIBUTE {
                        type_: CKA_MODULUS,
                        pValue: modulus.as_mut_ptr() as CK_VOID_PTR,
                        ulValueLen: modulus_len,
                    },
                ];
                self.call_get_attributes(key_handle, &mut template)?;
                let label = String::from_utf8(label_bytes).map_err(|e| {
                    PError::Default(format!("Failed to convert label to string: {}", e))
                })?;
                let size = modulus.len() * 8;
                Ok(HsmObject::new(
                    object_type,
                    KeyValue::RsaPrivateKey(RsaPrivateKeyValue {
                        modulus,
                        public_exponent,
                        private_exponent: Zeroizing::new(private_exponent),
                        prime_1: Zeroizing::new(prime_1),
                        prime_2: Zeroizing::new(prime_2),
                        exponent_1: Zeroizing::new(exponent_1),
                        exponent_2: Zeroizing::new(exponent_2),
                        coefficient: Zeroizing::new(coefficient),
                    }),
                    size,
                    label,
                ))
            }
            HsmObjectType::RsaPublic => {
                todo!(
                    "Exporting RSA public key is not supported yet. key_handle: {}",
                    key_handle
                )
            }
        }
    }

    fn call_get_attributes(
        &self,
        key_handle: CK_OBJECT_HANDLE,
        template: &mut [CK_ATTRIBUTE],
    ) -> PResult<()> {
        unsafe {
            // Get the length of the key value
            let rv = self.hsm.C_GetAttributeValue.ok_or_else(|| {
                PError::Default("C_GetAttributeValue not available on library".to_string())
            })?(
                self.session_handle,
                key_handle,
                template.as_ptr() as *mut CK_ATTRIBUTE,
                template.len() as CK_ULONG,
            );
            if rv == CKR_ATTRIBUTE_SENSITIVE {
                return Err(PError::Default("This key cannot be exported".to_string()));
            }
            if rv != CKR_OK {
                return Err(PError::Default("Failed to get the attributes".to_string()));
            }
            Ok(())
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
