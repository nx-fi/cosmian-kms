use std::{ffi::CStr, ptr, sync::Arc};

use libloading::Library;
use pkcs11_sys::{
    CKF_OS_LOCKING_OK, CKF_RW_SESSION, CKF_SERIAL_SESSION, CKO_SECRET_KEY, CK_ATTRIBUTE_PTR,
    CK_BBOOL, CK_C_INITIALIZE_ARGS, CK_FLAGS, CK_INFO, CK_MECHANISM_PTR, CK_OBJECT_HANDLE,
    CK_SLOT_ID, CK_ULONG, CK_UTF8CHAR_PTR, CK_VOID_PTR,
};

use crate::{PError, PResult};

pub struct Hsm {
    hsm: Arc<HsmLib>,
}

impl Hsm {
    pub fn instantiate<P>(path: P) -> PResult<Self>
    where
        P: AsRef<std::ffi::OsStr>,
    {
        let hsmLib = HsmLib::load_from_path(path)?;
        Ok(Hsm {
            hsm: Arc::new(hsmLib),
        })
    }

    pub fn get_manager(&self) -> PResult<HsmManager> {
        let hsmLib = self.hsm.clone();
        let manager = HsmManager {
            hsm: self.hsm.clone(),
        };
        manager.initialize()?;
        Ok(manager)
    }
}

struct HsmLib {
    library: Library,
    C_Initialize: pkcs11_sys::CK_C_Initialize,
    C_OpenSession: pkcs11_sys::CK_C_OpenSession,
    C_CloseSession: pkcs11_sys::CK_C_CloseSession,
    C_GenerateKey: pkcs11_sys::CK_C_GenerateKey,
    C_GenerateKeyPair: pkcs11_sys::CK_C_GenerateKeyPair,
    C_GenerateRandom: pkcs11_sys::CK_C_GenerateRandom,
    C_GetInfo: pkcs11_sys::CK_C_GetInfo,
    C_Login: pkcs11_sys::CK_C_Login,
    C_Logout: pkcs11_sys::CK_C_Logout,
}

impl HsmLib {
    fn load_from_path<P>(path: P) -> PResult<Self>
    where
        P: AsRef<std::ffi::OsStr>,
    {
        unsafe {
            let library = Library::new(path)?;
            Ok(HsmLib {
                C_Initialize: Some(*library.get(b"C_Initialize")?),
                C_OpenSession: Some(*library.get(b"C_OpenSession")?),
                C_CloseSession: Some(*library.get(b"C_CloseSession")?),
                C_GenerateKey: Some(*library.get(b"C_GenerateKey")?),
                C_GenerateKeyPair: Some(*library.get(b"C_GenerateKeyPair")?),
                C_GenerateRandom: Some(*library.get(b"C_GenerateRandom")?),
                C_GetInfo: Some(*library.get(b"C_GetInfo")?),
                C_Login: Some(*library.get(b"C_Login")?),
                C_Logout: Some(*library.get(b"C_Logout")?),
                library,
            })
        }
    }
}

pub struct HsmManager {
    hsm: Arc<HsmLib>,
}

impl HsmManager {
    pub fn initialize(&self) -> PResult<()> {
        let pInitArgs = CK_C_INITIALIZE_ARGS {
            CreateMutex: None,
            DestroyMutex: None,
            LockMutex: None,
            UnlockMutex: None,
            flags: CKF_OS_LOCKING_OK,
            pReserved: ptr::null_mut(),
        };
        // let pInitArgsPtr = &pInitArgs as *const CK_C_INITIALIZE_ARGS as *mut c_void;
        unsafe {
            // let rv = self.hsm.C_Initialize.deref()(&pInitArgs);
            let rv = self.hsm.C_Initialize.ok_or_else(|| {
                PError::Default("C_Initialize not available on library".to_string())
            })?(&pInitArgs as *const CK_C_INITIALIZE_ARGS as CK_VOID_PTR);
            if rv != pkcs11_sys::CKR_OK {
                return Err(PError::Default("Failed initializing the HSM".to_string()));
            }
            Ok(())
        }
    }

    pub fn get_info(&self) -> PResult<Info> {
        unsafe {
            let mut info = CK_INFO::default();
            let rv =
                self.hsm.C_GetInfo.ok_or_else(|| {
                    PError::Default("C_GetInfo not available on library".to_string())
                })?(&mut info);
            if rv != pkcs11_sys::CKR_OK {
                return Err(PError::Default("Failed getting HSM info".to_string()));
            }
            Ok(info.into())
        }
    }

    pub fn open_session(
        &self,
        slot_id: usize,
        read_write: bool,
        login_password: Option<String>,
    ) -> PResult<Session> {
        let slot_id: CK_SLOT_ID = slot_id as CK_SLOT_ID;
        let flags: CK_FLAGS = if read_write {
            CKF_RW_SESSION | CKF_SERIAL_SESSION
        } else {
            CKF_SERIAL_SESSION
        };
        let mut session_handle: pkcs11_sys::CK_SESSION_HANDLE = 0;

        unsafe {
            let rv = self.hsm.C_OpenSession.ok_or_else(|| {
                PError::Default("C_OpenSession not available on library".to_string())
            })?(slot_id, flags, ptr::null_mut(), None, &mut session_handle);
            if rv != pkcs11_sys::CKR_OK {
                return Err(PError::Default("Failed opening a session".to_string()));
            }
            if let Some(password) = &login_password {
                let mut pwd_bytes = password.as_bytes().to_vec();
                let rv = self.hsm.C_Login.ok_or_else(|| {
                    PError::Default("C_Login not available on library".to_string())
                })?(
                    session_handle,
                    pkcs11_sys::CKU_USER,
                    pwd_bytes.as_mut_ptr() as CK_UTF8CHAR_PTR,
                    pwd_bytes.len() as CK_ULONG,
                );
                if rv != pkcs11_sys::CKR_OK {
                    return Err(PError::Default("Failed logging in".to_string()));
                }
            }
            Ok(Session {
                hsm: self.hsm.clone(),
                session_handle,
                is_logged: login_password.is_some(),
            })
        }
    }
}

pub struct Session {
    hsm: Arc<HsmLib>,
    session_handle: pkcs11_sys::CK_SESSION_HANDLE,
    is_logged: bool,
}

impl Session {
    pub fn close(&self) -> PResult<()> {
        unsafe {
            if self.is_logged {
                let rv = self.hsm.C_Logout.ok_or_else(|| {
                    PError::Default("C_Logout not available on library".to_string())
                })?(self.session_handle);
                if rv != pkcs11_sys::CKR_OK {
                    return Err(PError::Default("Failed logging out".to_string()));
                }
            }
            let rv = self.hsm.C_CloseSession.ok_or_else(|| {
                PError::Default("C_CloseSession not available on library".to_string())
            })?(self.session_handle);
            if rv != pkcs11_sys::CKR_OK {
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
            let mut mechanism = pkcs11_sys::CK_MECHANISM {
                mechanism: pkcs11_sys::CKM_AES_KEY_GEN,
                pParameter: ptr::null_mut(),
                ulParameterLen: 0,
            };
            let mut template = vec![
                pkcs11_sys::CK_ATTRIBUTE {
                    type_: pkcs11_sys::CKA_CLASS,
                    pValue: &CKO_SECRET_KEY as *const _ as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_ULONG>() as CK_ULONG,
                },
                pkcs11_sys::CK_ATTRIBUTE {
                    type_: pkcs11_sys::CKA_KEY_TYPE,
                    pValue: &pkcs11_sys::CKK_AES as *const _ as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_ULONG>() as CK_ULONG,
                },
                pkcs11_sys::CK_ATTRIBUTE {
                    type_: pkcs11_sys::CKA_TOKEN,
                    pValue: &pkcs11_sys::CK_TRUE as *const _ as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
                },
                pkcs11_sys::CK_ATTRIBUTE {
                    type_: pkcs11_sys::CKA_VALUE_LEN,
                    pValue: &size as *const _ as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_ULONG>() as CK_ULONG,
                },
                pkcs11_sys::CK_ATTRIBUTE {
                    type_: pkcs11_sys::CKA_LABEL,
                    pValue: label.as_ptr() as CK_VOID_PTR,
                    ulValueLen: label.len() as CK_ULONG,
                },
                pkcs11_sys::CK_ATTRIBUTE {
                    type_: pkcs11_sys::CKA_PRIVATE,
                    pValue: &pkcs11_sys::CK_TRUE as *const _ as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
                },
                pkcs11_sys::CK_ATTRIBUTE {
                    type_: pkcs11_sys::CKA_SENSITIVE,
                    pValue: &pkcs11_sys::CK_TRUE as *const _ as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
                },
                pkcs11_sys::CK_ATTRIBUTE {
                    type_: pkcs11_sys::CKA_EXTRACTABLE,
                    pValue: &pkcs11_sys::CK_FALSE as *const _ as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
                },
                pkcs11_sys::CK_ATTRIBUTE {
                    type_: pkcs11_sys::CKA_ENCRYPT,
                    pValue: &pkcs11_sys::CK_TRUE as *const _ as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
                },
                pkcs11_sys::CK_ATTRIBUTE {
                    type_: pkcs11_sys::CKA_DECRYPT,
                    pValue: &pkcs11_sys::CK_TRUE as *const _ as CK_VOID_PTR,
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
            if rv != pkcs11_sys::CKR_OK {
                return Err(PError::Default("Failed generating key".to_string()));
            }
            Ok(aes_key_handle)
        }
    }

    pub fn generate_random(&self, len: usize) -> PResult<Vec<u8>> {
        unsafe {
            let mut values = vec![0u8; len];
            let values_ptr: *mut u8 = values.as_mut_ptr();
            let rv = self.hsm.C_GenerateRandom.ok_or_else(|| {
                PError::Default("C_GenerateRandom not available on library".to_string())
            })?(self.session_handle, values_ptr, len as u64);
            if rv != pkcs11_sys::CKR_OK {
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

#[derive(Debug)]
pub struct Info {
    pub cryptokiVersion: (u8, u8),
    pub manufacturerID: String,
    pub flags: u64,
    pub libraryDescription: String,
    pub libraryVersion: (u8, u8),
}

impl From<CK_INFO> for Info {
    fn from(info: CK_INFO) -> Self {
        unsafe {
            Info {
                cryptokiVersion: (info.cryptokiVersion.major, info.cryptokiVersion.minor),
                manufacturerID: CStr::from_bytes_until_nul(&info.manufacturerID)
                    .unwrap()
                    .to_string_lossy()
                    .to_string(),
                flags: info.flags,
                libraryDescription: CStr::from_bytes_until_nul(&info.libraryDescription)
                    .unwrap()
                    .to_string_lossy()
                    .to_string(),
                libraryVersion: (info.libraryVersion.major, info.libraryVersion.minor),
            }
        }
    }
}
