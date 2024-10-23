use std::{pin::Pin, ptr};

use pkcs11_sys::{
    CKA_CLASS, CKA_DECRYPT, CKA_ENCRYPT, CKA_EXTRACTABLE, CKA_KEY_TYPE, CKA_LABEL,
    CKA_MODULUS_BITS, CKA_PRIVATE, CKA_SENSITIVE, CKA_TOKEN, CKA_UNWRAP, CKA_WRAP, CKG_MGF1_SHA256,
    CKK_AES, CKK_RSA, CKM_RSA_PKCS, CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_RSA_PKCS_OAEP, CKM_SHA256,
    CKO_SECRET_KEY, CKR_OK, CKZ_DATA_SPECIFIED, CK_ATTRIBUTE, CK_BBOOL, CK_KEY_TYPE, CK_MECHANISM,
    CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_RSA_PKCS_OAEP_PARAMS, CK_TRUE, CK_ULONG, CK_VOID_PTR,
};

use crate::{session::Session, PError, PResult};

pub enum RsaKeySize {
    Rsa1024,
    Rsa2048,
    Rsa3072,
    Rsa4096,
}

impl Session {
    /// Generate RSA key pair and return the private and public key handles
    pub fn generate_rsa_key_pair(
        &self,
        key_size: RsaKeySize,
        label: &str,
    ) -> PResult<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)> {
        let key_size = match key_size {
            RsaKeySize::Rsa1024 => 1024,
            RsaKeySize::Rsa2048 => 2048,
            RsaKeySize::Rsa3072 => 3072,
            RsaKeySize::Rsa4096 => 4096,
        };
        unsafe {
            let mut pub_key_template = vec![
                CK_ATTRIBUTE {
                    type_: CKA_KEY_TYPE,
                    pValue: &CKK_RSA as *const _ as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_KEY_TYPE>() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_TOKEN,
                    pValue: &CK_TRUE as *const _ as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_ENCRYPT,
                    pValue: &CK_TRUE as *const _ as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_MODULUS_BITS,
                    pValue: &key_size as *const _ as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_ULONG>() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_LABEL,
                    pValue: label.as_ptr() as CK_VOID_PTR,
                    ulValueLen: label.len() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_WRAP,
                    pValue: &CK_TRUE as *const _ as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
                },
            ];

            let mut priv_key_template = vec![
                CK_ATTRIBUTE {
                    type_: CKA_KEY_TYPE,
                    pValue: &CKK_RSA as *const _ as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_KEY_TYPE>() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_TOKEN,
                    pValue: &CK_TRUE as *const _ as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_PRIVATE,
                    pValue: &CK_TRUE as *const _ as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_DECRYPT,
                    pValue: &CK_TRUE as *const _ as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_LABEL,
                    pValue: label.as_ptr() as CK_VOID_PTR,
                    ulValueLen: label.len() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_UNWRAP,
                    pValue: &CK_TRUE as *const _ as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
                },
            ];

            let mut mechanism = CK_MECHANISM {
                mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
                pParameter: ptr::null_mut(),
                ulParameterLen: 0,
            };

            let mut pub_key_handle = CK_OBJECT_HANDLE::default();
            let mut priv_key_handle = CK_OBJECT_HANDLE::default();
            let pMechanism: CK_MECHANISM_PTR = &mut mechanism;

            let rv = self.hsm.C_GenerateKeyPair.ok_or_else(|| {
                PError::Default("C_GenerateKeyPair not available on library".to_string())
            })?(
                self.session_handle,
                pMechanism,
                pub_key_template.as_mut_ptr(),
                pub_key_template.len() as CK_ULONG,
                priv_key_template.as_mut_ptr(),
                priv_key_template.len() as CK_ULONG,
                &mut pub_key_handle,
                &mut priv_key_handle,
            );

            if rv != CKR_OK {
                return Err(PError::Default(
                    "Failed generating RSA key pair".to_string(),
                ));
            }

            Ok((priv_key_handle, pub_key_handle))
        }
    }

    pub fn wrap_aes_key_with_rsa_oaep(
        &self,
        wrapping_key_handle: CK_OBJECT_HANDLE,
        aes_key_handle: CK_OBJECT_HANDLE,
    ) -> PResult<Vec<u8>> {
        unsafe {
            // Initialize the RSA-OAEP mechanism
            let mut oaep_params = CK_RSA_PKCS_OAEP_PARAMS {
                hashAlg: CKM_SHA256,
                mgf: CKG_MGF1_SHA256,
                source: CKZ_DATA_SPECIFIED,
                pSourceData: ptr::null_mut(),
                ulSourceDataLen: 0,
            };

            let mut mechanism = CK_MECHANISM {
                mechanism: CKM_RSA_PKCS_OAEP,
                pParameter: &mut oaep_params as *mut _ as CK_VOID_PTR,
                ulParameterLen: size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
            };

            // Determine the length of the wrapped key
            let mut wrapped_key_len: CK_ULONG = 0;
            let rv = self
                .hsm
                .C_WrapKey
                .ok_or_else(|| PError::Default("C_WrapKey not available on library".to_string()))?(
                self.session_handle,
                &mut mechanism,
                wrapping_key_handle,
                aes_key_handle,
                ptr::null_mut(),
                &mut wrapped_key_len,
            );

            if rv != CKR_OK {
                return Err(PError::Default(
                    "Failed to get wrapped key length".to_string(),
                ));
            }

            // Allocate buffer for the wrapped key
            let mut wrapped_key = vec![0u8; wrapped_key_len as usize];

            // Wrap the key
            let rv = self
                .hsm
                .C_WrapKey
                .ok_or_else(|| PError::Default("C_WrapKey not available on library".to_string()))?(
                self.session_handle,
                &mut mechanism,
                wrapping_key_handle,
                aes_key_handle,
                wrapped_key.as_mut_ptr(),
                &mut wrapped_key_len,
            );

            if rv != CKR_OK {
                return Err(PError::Default("Failed to wrap key".to_string()));
            }

            // Truncate the buffer to the actual size of the wrapped key
            wrapped_key.truncate(wrapped_key_len as usize);
            Ok(wrapped_key)
        }
    }

    pub fn unwrap_aes_key_with_rsa_oaep(
        &self,
        unwrapping_key_handle: CK_OBJECT_HANDLE,
        wrapped_aes_key: &[u8],
        aes_key_label: &str,
    ) -> PResult<CK_OBJECT_HANDLE> {
        let mut wrapped_key = wrapped_aes_key.to_vec();
        unsafe {
            // Initialize the RSA-OAEP mechanism
            let mut oaep_params = CK_RSA_PKCS_OAEP_PARAMS {
                hashAlg: CKM_SHA256,
                mgf: CKG_MGF1_SHA256,
                source: CKZ_DATA_SPECIFIED,
                pSourceData: ptr::null_mut(),
                ulSourceDataLen: 0,
            };

            let mut mechanism = CK_MECHANISM {
                mechanism: CKM_RSA_PKCS_OAEP,
                pParameter: &mut oaep_params as *mut _ as CK_VOID_PTR,
                ulParameterLen: size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
            };

            // Unwrap the key
            let mut aes_key_template = aes_unwrap_key_template("unwrapped_aes_key");
            let mut unwrapped_key_handle: CK_OBJECT_HANDLE = 0;
            let rv = self.hsm.C_UnwrapKey.ok_or_else(|| {
                PError::Default("C_UnwrapKey not available on library".to_string())
            })?(
                self.session_handle,
                &mut mechanism,
                unwrapping_key_handle,
                wrapped_key.as_mut_ptr(),
                wrapped_key.len() as CK_ULONG,
                aes_key_template.as_mut_ptr(),
                aes_key_template.len() as CK_ULONG,
                &mut unwrapped_key_handle,
            );

            if rv != CKR_OK {
                return Err(PError::Default("Failed to unwrap key".to_string()));
            }

            Ok(unwrapped_key_handle)
        }
    }

    pub fn encrypt_with_rsa_oaep(
        &self,
        public_key_handle: CK_OBJECT_HANDLE,
        data: &[u8],
    ) -> PResult<Vec<u8>> {
        let mut params = CK_RSA_PKCS_OAEP_PARAMS {
            hashAlg: CKM_SHA256,
            mgf: CKG_MGF1_SHA256,
            source: CKZ_DATA_SPECIFIED,
            pSourceData: ptr::null_mut(),
            ulSourceDataLen: 0,
        };
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_OAEP,
            pParameter: &mut params as *mut _ as CK_VOID_PTR,
            ulParameterLen: size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
        };
        self.encrypt_with_mechanism(public_key_handle, data, &mut mechanism)
    }

    fn encrypt_with_mechanism(
        &self,
        public_key_handle: CK_OBJECT_HANDLE,
        data: &[u8],
        mechanism: &mut CK_MECHANISM,
    ) -> PResult<Vec<u8>> {
        let mut data = data.to_vec();
        unsafe {
            // Initialize the encryption operation
            let rv = self.hsm.C_EncryptInit.ok_or_else(|| {
                PError::Default("C_EncryptInit not available on library".to_string())
            })?(self.session_handle, mechanism, public_key_handle);

            if rv != CKR_OK {
                return Err(PError::Default(
                    "Failed to initialize encryption".to_string(),
                ));
            }

            // Determine the length of the encrypted data
            let mut encrypted_data_len: CK_ULONG = 0;
            let rv = self
                .hsm
                .C_Encrypt
                .ok_or_else(|| PError::Default("C_Encrypt not available on library".to_string()))?(
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

            // Allocate buffer for the encrypted data
            let mut encrypted_data = vec![0u8; encrypted_data_len as usize];

            // Perform the encryption
            let rv = self
                .hsm
                .C_Encrypt
                .ok_or_else(|| PError::Default("C_Encrypt not available on library".to_string()))?(
                self.session_handle,
                data.as_mut_ptr(),
                data.len() as CK_ULONG,
                encrypted_data.as_mut_ptr(),
                &mut encrypted_data_len,
            );

            if rv != CKR_OK {
                return Err(PError::Default("Failed to encrypt data".to_string()));
            }

            // Truncate the buffer to the actual size of the encrypted data
            encrypted_data.truncate(encrypted_data_len as usize);
            Ok(encrypted_data)
        }
    }

    pub fn decrypt_with_rsa_oaep(
        &self,
        private_key_handle: CK_OBJECT_HANDLE,
        ciphertext: &[u8],
    ) -> PResult<Vec<u8>> {
        let mut params = CK_RSA_PKCS_OAEP_PARAMS {
            hashAlg: CKM_SHA256,
            mgf: CKG_MGF1_SHA256,
            source: CKZ_DATA_SPECIFIED,
            pSourceData: ptr::null_mut(),
            ulSourceDataLen: 0,
        };
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_OAEP,
            pParameter: &mut params as *mut _ as CK_VOID_PTR,
            ulParameterLen: size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
        };
        self.decrypt_with_mechanism(private_key_handle, ciphertext, &mut mechanism)
    }

    pub fn decrypt_with_mechanism(
        &self,
        private_key_handle: CK_OBJECT_HANDLE,
        ciphertex: &[u8],
        mechanism: &mut CK_MECHANISM,
    ) -> PResult<Vec<u8>> {
        let mut encrypted_data = ciphertex.to_vec();
        unsafe {
            // Initialize the decryption operation
            let rv = self.hsm.C_DecryptInit.ok_or_else(|| {
                PError::Default("C_DecryptInit not available on library".to_string())
            })?(self.session_handle, mechanism, private_key_handle);

            if rv != CKR_OK {
                return Err(PError::Default(
                    "Failed to initialize decryption".to_string(),
                ));
            }

            // Determine the length of the decrypted data
            let mut decrypted_data_len: CK_ULONG = 0;
            let rv = self
                .hsm
                .C_Decrypt
                .ok_or_else(|| PError::Default("C_Decrypt not available on library".to_string()))?(
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

            // Allocate buffer for the decrypted data
            let mut decrypted_data = vec![0u8; decrypted_data_len as usize];

            // Perform the decryption
            let rv = self
                .hsm
                .C_Decrypt
                .ok_or_else(|| PError::Default("C_Decrypt not available on library".to_string()))?(
                self.session_handle,
                encrypted_data.as_mut_ptr(),
                encrypted_data.len() as CK_ULONG,
                decrypted_data.as_mut_ptr(),
                &mut decrypted_data_len,
            );

            if rv != CKR_OK {
                return Err(PError::Default("Failed to decrypt data".to_string()));
            }

            // Truncate the buffer to the actual size of the decrypted data
            decrypted_data.truncate(decrypted_data_len as usize);
            Ok(decrypted_data)
        }
    }
}

pub(crate) const fn aes_unwrap_key_template(label: &str) -> [CK_ATTRIBUTE; 9] {
    [
        CK_ATTRIBUTE {
            type_: CKA_CLASS,
            pValue: &CKO_SECRET_KEY as *const _ as CK_VOID_PTR,
            ulValueLen: size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE,
            pValue: &CKK_AES as *const _ as CK_VOID_PTR,
            ulValueLen: size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_TOKEN,
            pValue: &CK_TRUE as *const _ as CK_VOID_PTR,
            ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_LABEL,
            pValue: label.as_ptr() as CK_VOID_PTR,
            ulValueLen: label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_PRIVATE,
            pValue: &CK_TRUE as *const _ as CK_VOID_PTR,
            ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_SENSITIVE,
            pValue: &CK_TRUE as *const _ as CK_VOID_PTR,
            ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_EXTRACTABLE,
            pValue: &CK_TRUE as *const _ as CK_VOID_PTR,
            ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ENCRYPT,
            pValue: &CK_TRUE as *const _ as CK_VOID_PTR,
            ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_DECRYPT,
            pValue: &CK_TRUE as *const _ as CK_VOID_PTR,
            ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ]
}

struct Mechanism {
    params: Option<CK_RSA_PKCS_OAEP_PARAMS>,
    mechanism: CK_MECHANISM,
}

impl Mechanism {
    pub fn oaep() -> Self {
        let mut params = CK_RSA_PKCS_OAEP_PARAMS {
            hashAlg: CKM_SHA256,
            mgf: CKG_MGF1_SHA256,
            source: CKZ_DATA_SPECIFIED,
            pSourceData: ptr::null_mut(),
            ulSourceDataLen: 0,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_OAEP,
            pParameter: &mut params as *mut _ as CK_VOID_PTR,
            ulParameterLen: size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
        };
        Self {
            params: Some(params),
            mechanism,
        }
    }

    pub fn pkcs_v15() -> Self {
        let mechanism = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };
        Self {
            params: None,
            mechanism,
        }
    }

    pub fn mechanism(&self) -> CK_MECHANISM {
        self.mechanism
    }
}
