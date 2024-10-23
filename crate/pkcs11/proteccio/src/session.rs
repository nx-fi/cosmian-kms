use std::{ptr, sync::Arc};

use pkcs11_sys::*;

use crate::{PError, PResult};

pub struct Session {
    hsm: Arc<crate::hsm::HsmLib>,
    session_handle: CK_SESSION_HANDLE,
    is_logged_in: bool,
}

impl Session {
    pub fn new(
        hsm: Arc<crate::hsm::HsmLib>,
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

    pub fn generate_aes_key(&self, size: usize, label: &str) -> PResult<u64> {
        unsafe {
            let ck_fn = self.hsm.C_GenerateKey.ok_or_else(|| {
                PError::Default("C_GenerateKey not available on library".to_string())
            })?;
            let size = size as CK_ULONG;
            let mut mechanism = CK_MECHANISM {
                mechanism: CKM_AES_KEY_GEN,
                pParameter: ptr::null_mut(),
                ulParameterLen: 0,
            };
            let mut template = vec![
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
                    type_: CKA_VALUE_LEN,
                    pValue: &size as *const _ as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_ULONG>() as CK_ULONG,
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
                    pValue: &CK_FALSE as *const _ as CK_VOID_PTR,
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
            ];
            let pMechanism: CK_MECHANISM_PTR = &mut mechanism;
            let pMutTemplate: CK_ATTRIBUTE_PTR = template.as_mut_ptr();
            let mut aes_key_handle = CK_OBJECT_HANDLE::default();
            let rv = ck_fn(
                self.session_handle,
                pMechanism,
                pMutTemplate,
                template.len() as u64,
                &mut aes_key_handle,
            );
            if rv != CKR_OK {
                return Err(PError::Default("Failed generating key".to_string()));
            }
            Ok(aes_key_handle)
        }
    }

    pub fn generate_rsa_key_pair(
        &self,
        key_size: CK_ULONG,
        label: &str,
    ) -> PResult<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)> {
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

            Ok((pub_key_handle, priv_key_handle))
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
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
