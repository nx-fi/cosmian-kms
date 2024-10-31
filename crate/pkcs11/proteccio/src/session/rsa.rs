use std::ptr;

use pkcs11_sys::{
    CKA_CLASS, CKA_DECRYPT, CKA_ENCRYPT, CKA_EXTRACTABLE, CKA_KEY_TYPE, CKA_LABEL,
    CKA_MODULUS_BITS, CKA_PRIVATE, CKA_PUBLIC_EXPONENT, CKA_SENSITIVE, CKA_SIGN, CKA_TOKEN,
    CKA_UNWRAP, CKA_VERIFY, CKA_WRAP, CKG_MGF1_SHA256, CKK_AES, CKK_RSA, CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_RSA_PKCS_OAEP, CKM_SHA256, CKO_SECRET_KEY, CKR_OK, CKZ_DATA_SPECIFIED, CK_ATTRIBUTE,
    CK_BBOOL, CK_KEY_TYPE, CK_MECHANISM, CK_MECHANISM_PTR, CK_OBJECT_HANDLE,
    CK_RSA_PKCS_OAEP_PARAMS, CK_TRUE, CK_ULONG, CK_VOID_PTR,
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
        let public_exponent: [u8; 3] = [0x01, 0x00, 0x01];
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
                    type_: CKA_PUBLIC_EXPONENT,
                    pValue: public_exponent.as_ptr() as CK_VOID_PTR,
                    ulValueLen: public_exponent.len() as CK_ULONG,
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
                CK_ATTRIBUTE {
                    type_: CKA_VERIFY,
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
                CK_ATTRIBUTE {
                    type_: CKA_SIGN,
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
            let mut aes_key_template = aes_unwrap_key_template(aes_key_label);
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
