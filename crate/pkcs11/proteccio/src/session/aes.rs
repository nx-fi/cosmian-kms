use std::ptr;

use pkcs11_sys::{
    CKA_CLASS, CKA_DECRYPT, CKA_ENCRYPT, CKA_EXTRACTABLE, CKA_KEY_TYPE, CKA_LABEL, CKA_PRIVATE,
    CKA_SENSITIVE, CKA_TOKEN, CKA_VALUE_LEN, CKK_AES, CKM_AES_GCM, CKM_AES_KEY_GEN, CKO_SECRET_KEY,
    CKR_OK, CK_ATTRIBUTE, CK_ATTRIBUTE_PTR, CK_BBOOL, CK_MECHANISM, CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE, CK_TRUE, CK_ULONG, CK_VOID_PTR,
};

use crate::{session::Session, PError, PResult};

pub enum AesKeySize {
    Aes128,
    Aes256,
}

pub(crate) const fn aes_key_template(label: &str, size: CK_ULONG) -> [CK_ATTRIBUTE; 10] {
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

impl Session {
    pub fn generate_aes_key(&self, size: AesKeySize, label: &str) -> PResult<u64> {
        unsafe {
            let ck_fn = self.hsm.C_GenerateKey.ok_or_else(|| {
                PError::Default("C_GenerateKey not available on library".to_string())
            })?;
            let size = match size {
                AesKeySize::Aes128 => 16,
                AesKeySize::Aes256 => 32,
            } as CK_ULONG;
            let mut mechanism = CK_MECHANISM {
                mechanism: CKM_AES_KEY_GEN,
                pParameter: ptr::null_mut(),
                ulParameterLen: 0,
            };
            let mut template = aes_key_template(label, size);
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

    pub fn encrypt_with_aes_key(
        &self,
        key_handle: CK_OBJECT_HANDLE,
        data: &[u8],
    ) -> PResult<Vec<u8>> {
        let mut data = data.to_vec();
        unsafe {
            let ck_fn = self.hsm.C_EncryptInit.ok_or_else(|| {
                PError::Default("C_EncryptInit not available on library".to_string())
            })?;

            let mut mechanism = CK_MECHANISM {
                mechanism: CKM_AES_GCM,
                pParameter: ptr::null_mut(),
                ulParameterLen: 0,
            };

            let rv = ck_fn(self.session_handle, &mut mechanism, key_handle);
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
}
