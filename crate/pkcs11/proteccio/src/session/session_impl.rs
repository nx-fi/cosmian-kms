use std::{ptr, sync::Arc};

use cosmian_kms_interfaces::{
    CryptographicAlgorithm, EncryptedContent, HsmObject, HsmObjectFilter, KeyMaterial, KeyMetadata,
    KeyType, RsaPrivateKeyMaterial, RsaPublicKeyMaterial,
};
use pkcs11_sys::*;
use tracing::debug;
use zeroize::Zeroizing;

pub use crate::session::{aes::AesKeySize, rsa::RsaKeySize};
use crate::{
    aes_mechanism, generate_random_nonce, rsa_mechanism, ObjectHandlesCache, PError, PResult,
};

pub enum ProteccioEncryptionAlgorithm {
    AesGcm,
    RsaPkcsV15,
    RsaOaep,
}

impl From<CryptographicAlgorithm> for ProteccioEncryptionAlgorithm {
    fn from(algorithm: CryptographicAlgorithm) -> Self {
        match algorithm {
            CryptographicAlgorithm::AesGcm => ProteccioEncryptionAlgorithm::AesGcm,
            CryptographicAlgorithm::RsaPkcsV15 => ProteccioEncryptionAlgorithm::RsaPkcsV15,
            CryptographicAlgorithm::RsaOaep => ProteccioEncryptionAlgorithm::RsaOaep,
        }
    }
}

pub struct Session {
    hsm: Arc<crate::proteccio::HsmLib>,
    session_handle: CK_SESSION_HANDLE,
    object_handles_cache: Arc<ObjectHandlesCache>,
    is_logged_in: bool,
}

impl Session {
    pub fn new(
        hsm: Arc<crate::proteccio::HsmLib>,
        session_handle: CK_SESSION_HANDLE,
        object_handles_cache: Arc<ObjectHandlesCache>,
        is_logged_in: bool,
    ) -> Self {
        Session {
            hsm,
            session_handle,
            object_handles_cache,
            is_logged_in,
        }
    }

    pub(crate) fn hsm(&self) -> Arc<crate::proteccio::HsmLib> {
        self.hsm.clone()
    }

    pub(crate) fn session_handle(&self) -> CK_SESSION_HANDLE {
        self.session_handle
    }

    pub(crate) fn object_handles_cache(&self) -> Arc<ObjectHandlesCache> {
        self.object_handles_cache.clone()
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

    pub fn get_object_handle(&self, object_id: &[u8]) -> PResult<CK_OBJECT_HANDLE> {
        if let Some(handle) = self.object_handles_cache.get(object_id) {
            return Ok(handle);
        }

        // Proteccio does not allow the ID for secret keys so we use the label
        let mut template = [CK_ATTRIBUTE {
            type_: CKA_LABEL,
            pValue: object_id.as_ptr() as CK_VOID_PTR,
            ulValueLen: object_id.len() as CK_ULONG,
        }];

        unsafe {
            let rv = self.hsm.C_FindObjectsInit.ok_or_else(|| {
                PError::Default("C_FindObjectsInit not available on library".to_string())
            })?(
                self.session_handle,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
            );
            if rv != CKR_OK {
                return Err(PError::Default(format!("C_FindObjectsInit failed: {}", rv)));
            }

            let mut object_handle: CK_OBJECT_HANDLE = 0;
            let mut object_count: CK_ULONG = 0;
            let rv = self.hsm.C_FindObjects.ok_or_else(|| {
                PError::Default("C_FindObjects not available on library".to_string())
            })?(
                self.session_handle,
                &mut object_handle,
                1,
                &mut object_count,
            );
            if rv != CKR_OK {
                return Err(PError::Default(format!("C_FindObjects failed: {}", rv)));
            }

            let rv = self.hsm.C_FindObjectsFinal.ok_or_else(|| {
                PError::Default("C_FindObjectsFinal not available on library".to_string())
            })?(self.session_handle);
            if rv != CKR_OK {
                return Err(PError::Default(format!(
                    "C_FindObjectsFinal failed: {}",
                    rv
                )));
            }

            if object_count == 0 {
                return Err(PError::Default("Object not found".to_string()));
            }

            //update cache
            self.object_handles_cache
                .insert(object_id.to_vec(), object_handle);

            Ok(object_handle)
        }
    }

    pub fn delete_object_handle(&self, id: &[u8]) {
        self.object_handles_cache.remove(id)
    }

    pub fn generate_random(&self, len: usize) -> PResult<Vec<u8>> {
        unsafe {
            let mut values = vec![0u8; len];
            let values_ptr: *mut u8 = values.as_mut_ptr();
            #[cfg(target_os = "windows")]
            let len = u32::try_from(len)?;
            #[cfg(not(target_os = "windows"))]
            let len = u64::try_from(len)?;
            let rv = self.hsm.C_GenerateRandom.ok_or_else(|| {
                PError::Default("C_GenerateRandom not available on library".to_string())
            })?(self.session_handle, values_ptr, len);
            if rv != CKR_OK {
                return Err(PError::Default("Failed generating random data".to_string()));
            }
            Ok(values)
        }
    }

    pub fn list_objects(&self, object_filter: HsmObjectFilter) -> PResult<Vec<CK_OBJECT_HANDLE>> {
        let mut object_handles: Vec<CK_OBJECT_HANDLE> = Vec::new();
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
                object_handles.push(object_handle);
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

    pub fn destroy_object(&self, object_handle: CK_OBJECT_HANDLE) -> PResult<()> {
        unsafe {
            let rv = self.hsm.C_DestroyObject.ok_or_else(|| {
                PError::Default("C_DestroyObject not available on library".to_string())
            })?(self.session_handle, object_handle);
            if rv != CKR_OK {
                return Err(PError::Default("Failed to destroy object".to_string()));
            }
        }
        Ok(())
    }

    pub fn encrypt(
        &self,
        key_handle: CK_OBJECT_HANDLE,
        algorithm: ProteccioEncryptionAlgorithm,
        plaintext: &[u8],
    ) -> PResult<EncryptedContent> {
        Ok(match algorithm {
            ProteccioEncryptionAlgorithm::AesGcm => {
                let mut nonce = generate_random_nonce::<12>()?;
                let ciphertext = self.encrypt_with_mechanism(
                    key_handle,
                    &mut aes_mechanism!(&mut nonce),
                    plaintext,
                )?;
                EncryptedContent {
                    iv: Some(nonce.to_vec()),
                    ciphertext: ciphertext[..ciphertext.len() - 16].to_vec(),
                    tag: Some(ciphertext[ciphertext.len() - 16..].to_vec()),
                }
            }
            _ => EncryptedContent {
                ciphertext: self.encrypt_with_mechanism(
                    key_handle,
                    &mut rsa_mechanism!(algorithm),
                    plaintext,
                )?,
                ..Default::default()
            },
        })
    }

    pub fn decrypt(
        &self,
        key_handle: CK_OBJECT_HANDLE,
        algorithm: ProteccioEncryptionAlgorithm,
        ciphertext: &[u8],
    ) -> PResult<Zeroizing<Vec<u8>>> {
        match algorithm {
            ProteccioEncryptionAlgorithm::AesGcm => {
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
    ) -> PResult<Zeroizing<Vec<u8>>> {
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
            Ok(Zeroizing::new(decrypted_data))
        }
    }

    pub fn export_key(&self, key_handle: CK_OBJECT_HANDLE) -> PResult<Option<HsmObject>> {
        let mut key_type: CK_KEY_TYPE = CKK_VENDOR_DEFINED;
        let mut class: CK_OBJECT_CLASS = CKO_VENDOR_DEFINED;
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_CLASS,
                pValue: &mut class as *mut _ as CK_VOID_PTR,
                ulValueLen: size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: &mut key_type as *mut _ as CK_VOID_PTR,
                ulValueLen: size_of::<CK_ULONG>() as CK_ULONG,
            },
        ];

        self.call_get_attributes(key_handle, &mut template)?;
        let object_type = match key_type {
            CKK_AES => KeyType::AesKey,
            CKK_RSA => {
                if class == CKO_PRIVATE_KEY {
                    KeyType::RsaPrivateKey
                } else {
                    KeyType::RsaPublicKey
                }
            }
            x => {
                return Err(PError::Default(format!(
                    "Export: unsupported key type: {x}"
                )));
            }
        };

        match object_type {
            KeyType::AesKey => self.export_aes_key(key_handle),
            KeyType::RsaPrivateKey => self.export_rsa_private_key(key_handle),
            KeyType::RsaPublicKey => self.export_rsa_public_key(key_handle),
        }
    }

    fn export_rsa_private_key(&self, key_handle: CK_OBJECT_HANDLE) -> PResult<Option<HsmObject>> {
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
            CK_ATTRIBUTE {
                type_: CKA_LABEL,
                pValue: ptr::null_mut(),
                ulValueLen: 0,
            },
        ];
        if self
            .call_get_attributes(key_handle, &mut template)?
            .is_none()
        {
            return Ok(None);
        }
        let public_exponent_len = template[0].ulValueLen;
        let private_exponent_len = template[1].ulValueLen;
        let prime_1_len = template[2].ulValueLen;
        let prime_2_len = template[3].ulValueLen;
        let exponent_1_len = template[4].ulValueLen;
        let exponent_2_len = template[5].ulValueLen;
        let coefficient_len = template[6].ulValueLen;
        let modulus_len = template[7].ulValueLen;
        let label_len = template[8].ulValueLen;
        let mut public_exponent: Vec<u8> = vec![0_u8; public_exponent_len as usize];
        let mut private_exponent: Vec<u8> = vec![0_u8; private_exponent_len as usize];
        let mut prime_1: Vec<u8> = vec![0_u8; prime_1_len as usize];
        let mut prime_2: Vec<u8> = vec![0_u8; prime_2_len as usize];
        let mut exponent_1: Vec<u8> = vec![0_u8; exponent_1_len as usize];
        let mut exponent_2: Vec<u8> = vec![0_u8; exponent_2_len as usize];
        let mut coefficient: Vec<u8> = vec![0_u8; coefficient_len as usize];
        let mut label_bytes: Vec<u8> = vec![0_u8; label_len as usize];
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
        if self
            .call_get_attributes(key_handle, &mut template)?
            .is_none()
        {
            return Ok(None);
        }
        let label = String::from_utf8(label_bytes)
            .map_err(|e| PError::Default(format!("Failed to convert label to string: {}", e)))?;
        Ok(Some(HsmObject::new(
            KeyMaterial::RsaPrivateKey(RsaPrivateKeyMaterial {
                modulus,
                public_exponent,
                private_exponent: Zeroizing::new(private_exponent),
                prime_1: Zeroizing::new(prime_1),
                prime_2: Zeroizing::new(prime_2),
                exponent_1: Zeroizing::new(exponent_1),
                exponent_2: Zeroizing::new(exponent_2),
                coefficient: Zeroizing::new(coefficient),
            }),
            label,
        )))
    }

    fn export_rsa_public_key(&self, key_handle: CK_OBJECT_HANDLE) -> PResult<Option<HsmObject>> {
        // Get the key size
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_PUBLIC_EXPONENT,
                pValue: ptr::null_mut(),
                ulValueLen: 0,
            },
            CK_ATTRIBUTE {
                type_: CKA_MODULUS,
                pValue: ptr::null_mut(),
                ulValueLen: 0,
            },
            CK_ATTRIBUTE {
                type_: CKA_LABEL,
                pValue: ptr::null_mut(),
                ulValueLen: 0,
            },
        ];
        if self
            .call_get_attributes(key_handle, &mut template)?
            .is_none()
        {
            return Ok(None);
        }
        let public_exponent_len = template[0].ulValueLen;
        let modulus_len = template[1].ulValueLen;
        let label_len = template[2].ulValueLen;
        let mut public_exponent: Vec<u8> = vec![0_u8; public_exponent_len as usize];
        let mut label_bytes: Vec<u8> = vec![0_u8; label_len as usize];
        let mut modulus: Vec<u8> = vec![0_u8; modulus_len as usize];
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_PUBLIC_EXPONENT,
                pValue: public_exponent.as_mut_ptr() as CK_VOID_PTR,
                ulValueLen: public_exponent_len,
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
        if self
            .call_get_attributes(key_handle, &mut template)?
            .is_none()
        {
            return Ok(None);
        }
        let label = String::from_utf8(label_bytes)
            .map_err(|e| PError::Default(format!("Failed to convert label to string: {}", e)))?;
        Ok(Some(HsmObject::new(
            KeyMaterial::RsaPublicKey(RsaPublicKeyMaterial {
                modulus,
                public_exponent,
            }),
            label,
        )))
    }

    fn export_aes_key(&self, key_handle: CK_OBJECT_HANDLE) -> PResult<Option<HsmObject>> {
        // Get the key size
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_VALUE,
                pValue: ptr::null_mut(),
                ulValueLen: 0,
            },
            CK_ATTRIBUTE {
                type_: CKA_LABEL,
                pValue: ptr::null_mut(),
                ulValueLen: 0,
            },
        ];
        if self
            .call_get_attributes(key_handle, &mut template)?
            .is_none()
        {
            return Ok(None);
        }
        // Export the value
        let value_len = template[0].ulValueLen;
        let label_len = template[1].ulValueLen;
        let mut key_value: Vec<u8> = vec![0_u8; value_len as usize];
        let mut label_bytes: Vec<u8> = vec![0_u8; label_len as usize];
        let mut key_size: CK_ULONG = 0;
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_VALUE,
                pValue: key_value.as_mut_ptr() as CK_VOID_PTR,
                ulValueLen: value_len,
            },
            CK_ATTRIBUTE {
                type_: CKA_LABEL,
                pValue: label_bytes.as_mut_ptr() as CK_VOID_PTR,
                ulValueLen: label_len,
            },
            CK_ATTRIBUTE {
                type_: CKA_VALUE_LEN,
                pValue: &mut key_size as *mut _ as CK_VOID_PTR,
                ulValueLen: size_of::<CK_ULONG>() as CK_ULONG,
            },
        ];
        if self
            .call_get_attributes(key_handle, &mut template)?
            .is_none()
        {
            return Ok(None);
        }
        let label = String::from_utf8(label_bytes)
            .map_err(|e| PError::Default(format!("Failed to convert label to string: {}", e)))?;
        Ok(Some(HsmObject::new(
            KeyMaterial::AesKey(Zeroizing::new(key_value)),
            label,
        )))
    }

    fn call_get_attributes(
        &self,
        key_handle: CK_OBJECT_HANDLE,
        template: &mut [CK_ATTRIBUTE],
    ) -> PResult<Option<()>> {
        unsafe {
            debug!("Retrieving Proteccio key attributes for key: {key_handle}");
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
                return Err(PError::Default(format!(
                    "This key {key_handle} cannot be exported from the HSM."
                )));
            }
            if rv == CKR_OBJECT_HANDLE_INVALID {
                // The key was not found
                return Ok(None);
            }
            if rv != CKR_OK {
                return Err(PError::Default(format!(
                    "Failed to get the HSM attributes for key {key_handle}"
                )));
            }
            Ok(Some(()))
        }
    }

    pub fn get_key_metadata(&self, key_handle: CK_OBJECT_HANDLE) -> PResult<Option<KeyMetadata>> {
        let key_type = match self.get_key_type(key_handle)? {
            None => return Ok(None),
            Some(key_type) => key_type,
        };
        let mut template = [CK_ATTRIBUTE {
            type_: CKA_LABEL,
            pValue: ptr::null_mut(),
            ulValueLen: 0,
        }]
        .to_vec();
        match key_type {
            KeyType::AesKey => {
                let mut key_size: CK_ULONG = 0;
                let mut sensitive: CK_BBOOL = CK_FALSE;
                template.extend([
                    CK_ATTRIBUTE {
                        type_: CKA_VALUE_LEN,
                        pValue: &mut key_size as *mut _ as CK_VOID_PTR,
                        ulValueLen: size_of::<CK_ULONG>() as CK_ULONG,
                    },
                    CK_ATTRIBUTE {
                        type_: CKA_SENSITIVE,
                        pValue: &mut sensitive as *mut _ as CK_VOID_PTR,
                        ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
                    },
                ]);
                if self
                    .call_get_attributes(key_handle, &mut template)?
                    .is_none()
                {
                    return Ok(None);
                }
                let label_len = template[0].ulValueLen;
                let label = if label_len == 0 {
                    String::new()
                } else {
                    let mut label_bytes: Vec<u8> = vec![0_u8; label_len as usize];
                    let mut template = [CK_ATTRIBUTE {
                        type_: CKA_LABEL,
                        pValue: label_bytes.as_mut_ptr() as CK_VOID_PTR,
                        ulValueLen: label_len,
                    }];
                    if self
                        .call_get_attributes(key_handle, &mut template)?
                        .is_none()
                    {
                        return Ok(None);
                    }
                    String::from_utf8(label_bytes).map_err(|e| {
                        PError::Default(format!("Failed to convert label to string: {}", e))
                    })?
                };
                Ok(Some(KeyMetadata {
                    key_type,
                    key_length_in_bits: usize::try_from(key_size).map_err(|e| {
                        PError::Default(format!("Failed to convert key size to usize: {}", e))
                    })? * 8,
                    sensitive: sensitive == CK_TRUE,
                    id: label,
                }))
            }
            KeyType::RsaPrivateKey | KeyType::RsaPublicKey => {
                template.push(CK_ATTRIBUTE {
                    type_: CKA_MODULUS,
                    pValue: ptr::null_mut(),
                    ulValueLen: 0,
                });
                if self
                    .call_get_attributes(key_handle, &mut template)?
                    .is_none()
                {
                    return Ok(None);
                }
                let label_len = template[0].ulValueLen;
                let mut label_bytes: Vec<u8> = vec![0_u8; label_len as usize];
                let modulus_len = template[1].ulValueLen;
                let mut modulus: Vec<u8> = vec![0_u8; modulus_len as usize];
                let mut sensitive: CK_BBOOL = CK_FALSE;
                let mut template = vec![CK_ATTRIBUTE {
                    type_: CKA_MODULUS,
                    pValue: modulus.as_mut_ptr() as CK_VOID_PTR,
                    ulValueLen: modulus_len,
                }];
                if label_len > 0 {
                    template.push(CK_ATTRIBUTE {
                        type_: CKA_LABEL,
                        pValue: label_bytes.as_mut_ptr() as CK_VOID_PTR,
                        ulValueLen: label_len,
                    });
                }
                if key_type == KeyType::RsaPrivateKey {
                    template.push(CK_ATTRIBUTE {
                        type_: CKA_SENSITIVE,
                        pValue: &mut sensitive as *mut _ as CK_VOID_PTR,
                        ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
                    });
                }
                if self
                    .call_get_attributes(key_handle, &mut template)?
                    .is_none()
                {
                    return Ok(None);
                }
                let key_length_in_bits = modulus.len() * 8;

                let label = if label_len == 0 {
                    String::new()
                } else {
                    String::from_utf8(label_bytes).map_err(|e| {
                        PError::Default(format!("Failed to convert label to string: {}", e))
                    })?
                };
                let sensitive = sensitive == CK_TRUE;
                Ok(Some(KeyMetadata {
                    key_type,
                    key_length_in_bits,
                    sensitive,
                    id: label,
                }))
            }
        }
    }

    ///  Get the key type, sensitivity and label length
    /// # Arguments
    /// * `key_handle` - The key handle
    /// # Returns
    /// * `Result<Option<KeyType>>` - The key type if the key exists
    pub(crate) fn get_key_type(&self, key_handle: CK_OBJECT_HANDLE) -> PResult<Option<KeyType>> {
        let mut key_type: CK_KEY_TYPE = CKK_VENDOR_DEFINED;
        let mut class: CK_OBJECT_CLASS = CKO_VENDOR_DEFINED;
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_CLASS,
                pValue: &mut class as *mut _ as CK_VOID_PTR,
                ulValueLen: size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: &mut key_type as *mut _ as CK_VOID_PTR,
                ulValueLen: size_of::<CK_ULONG>() as CK_ULONG,
            },
        ];

        if self
            .call_get_attributes(key_handle, &mut template)?
            .is_none()
        {
            return Ok(None);
        }
        let key_type = match key_type {
            CKK_AES => KeyType::AesKey,
            CKK_RSA => {
                if class == CKO_PRIVATE_KEY {
                    KeyType::RsaPrivateKey
                } else {
                    KeyType::RsaPublicKey
                }
            }
            x => {
                return Err(PError::Default(format!(
                    "Export: unsupported key type: {x}"
                )));
            }
        };
        Ok(Some(key_type))
    }

    /// Get the Object id
    /// # Arguments
    /// * `object_handle` - The object handle
    /// # Returns
    /// * `Result<Option<Vec<u8>>>` - The key object id if the object exists
    pub(crate) fn get_object_id(
        &self,
        object_handle: CK_OBJECT_HANDLE,
    ) -> PResult<Option<Vec<u8>>> {
        let mut template = [CK_ATTRIBUTE {
            type_: CKA_ID,
            pValue: ptr::null_mut(),
            ulValueLen: 0,
        }];
        if self
            .call_get_attributes(object_handle, &mut template)?
            .is_none()
        {
            return Ok(None);
        }
        let id_len = template[0].ulValueLen;
        let mut id: Vec<u8> = vec![0_u8; id_len as usize];
        let mut template = [CK_ATTRIBUTE {
            type_: CKA_ID,
            pValue: id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: id_len,
        }];
        if self
            .call_get_attributes(object_handle, &mut template)?
            .is_none()
        {
            return Ok(None);
        }
        Ok(Some(id))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
